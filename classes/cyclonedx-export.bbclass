# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Michael Kirsche - Codewerk GmbH <michael.kirsche@codewerk.de>.
# Copyright (C) 2024 Savoir-faire Linux Inc. (<www.savoirfairelinux.com>).
# Copyright (C) 2022 BG Networks, Inc.

# The product name that the CVE database uses. Defaults to BPN, but may need to
# be overriden per recipe (for example tiff.bb sets CVE_PRODUCT=libtiff).
CVE_PRODUCT ??= "${BPN}"
CVE_VERSION ??= "${PV}"

CYCLONEDX_EXPORT_DIR ??= "${DEPLOY_DIR}/cyclonedx-export"
CYCLONEDX_EXPORT_SBOM ??= "${CYCLONEDX_EXPORT_DIR}/bom.json"
CYCLONEDX_EXPORT_TMP ??= "${TMPDIR}/cyclonedx-export"
CYCLONEDX_EXPORT_LOCK ??= "${CYCLONEDX_EXPORT_TMP}/bom.lock"

SBOM_MAPPING_PATH ?= "${LAYERDIR}/conf/mapping.json"

def _replace_name_in_field(field_value: str, old_name: str, new_name: str) -> str:
    if not field_value:
        return field_value
    # Simple, robust text replacement (case-sensitive)
    return field_value.replace(old_name, new_name)


def _apply_mapping(component: dict, old_name: str, new_name: str, description: str | None = None) -> dict:
    import copy

    updated = copy.deepcopy(component)

    # name
    if "name" in updated:
        updated["name"] = new_name

    # cpe  – e.g. cpe:2.3:a:vendor:old-lib:1.0:*:*:*:*:*:*:*
    if "cpe" in updated:
        updated["cpe"] = _replace_name_in_field(updated["cpe"], old_name, new_name)

    # purl – e.g. pkg:npm/old-lib@1.0.0
    if "purl" in updated:
        updated["purl"] = _replace_name_in_field(updated["purl"], old_name, new_name)

    # description – only replaced if provided in the mapping entry
    if description is not None:
        updated["description"] = description

    return updated


def process_components(sbom: dict, mapping: list[dict]) -> tuple[dict, list[str]]:
    import copy

    result = copy.deepcopy(sbom)
    components: list = result.get("components", [])

    # Build index for faster lookup: name -> [indices]
    def build_index(comps):
        idx: dict[str, list[int]] = {}
        for i, c in enumerate(comps):
            n = c.get("name", "")
            idx.setdefault(n, []).append(i)
        return idx

    for entry in mapping:
        search_name: str       = entry.get("search_name", "")
        new_name: str          = entry.get("new_name", "")
        action: str            = entry.get("action", "replace").lower()
        description: str | None = entry.get("description", None)

        if not search_name or not new_name:
            print(f"[WARN] Invalid mapping entry skipped: {entry}")
            continue

        if action not in ("replace", "append"):
            print(f"[WARN] Unknown action '{action}' for '{search_name}' – skipped.")
            continue

        # Rebuild index (insert operations shift positions)
        name_index = build_index(components)
        found_indices = name_index.get(search_name, [])

        if not found_indices:
            print(f"[INFO] Component '{search_name}' not found – no entry modified.")
            continue

        if action == "replace":
            for i in found_indices:
                components[i] = _apply_mapping(components[i], search_name, new_name, description)
                print(f"[REPLACE] '{search_name}' → '{new_name}' (index {i})"
                      + (f" [description updated]" if description is not None else ""))

        elif action == "append":
            # Iterate in reverse to keep insertion positions stable
            for i in sorted(found_indices, reverse=True):
                new_component = _apply_mapping(components[i], search_name, new_name, description)
                insert_pos = i + 1
                components.insert(insert_pos, new_component)
                print(f"[APPEND] Copy of '{search_name}' inserted as '{new_name}' at index {insert_pos}."
                      + (f" [description updated]" if description is not None else ""))

    result["components"] = components
    return result

def read_json(path):
    import json
    from pathlib import Path
    return json.loads(Path(path).read_text(encoding="utf-8"))

def write_json(path, content):
    import json
    from pathlib import Path

    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(content, indent=2, sort_keys=False), encoding="utf-8")

python do_cyclonedx_init() {
    import uuid
    from datetime import datetime, timezone

    timestamp = datetime.now(timezone.utc).isoformat()
    sbom_dir = d.getVar("CYCLONEDX_EXPORT_DIR")
    bb.debug(2, "CycloneDX: creating cyclonedx directory: %s" % sbom_dir)
    bb.utils.mkdirhier(sbom_dir)

    metadata_component = {
    "bom-ref": "BomRef.485485485584318.384648452452532",
    "name": d.getVar("PN") or "image",
    "type": "library",
    "version": d.getVar("PV") or ""
    }

    # Generate unique serial numbers for sbom document
    sbom_serial_number = str(uuid.uuid4())
    bb.debug(2, f"CycloneDX: creating empty sbom file with serial number {sbom_serial_number}")
    write_json(d.getVar("CYCLONEDX_EXPORT_SBOM"), {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "serialNumber": f"urn:uuid:{sbom_serial_number}",
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": [{"name": "yocto"}],
            "component": metadata_component
        },
        "components": []
    })
}
addhandler do_cyclonedx_init
do_cyclonedx_init[eventmask] = "bb.event.BuildStarted"

def classify_component_kind(pn, section):
    """
    Return a coarse-grained component kind string based on Yocto SECTION / PN.

    This is later mapped to CycloneDX component.type.
    """
    s = (section or "").lower()
    p = (pn or "").lower()

    # OS / distro level
    if s.startswith("images") or p.endswith("-image"):
        return "operating-system"

    # firmware / bootloader-ish
    if s.startswith("bootloaders") or "u-boot" in p or "barebox" in p:
        return "firmware"

    # kernel / modules
    if s.startswith("kernel") or p.startswith("linux-"):
        return "library"

    # libs
    if s.startswith("libs") or p.startswith(("lib", "python-", "perl-", "ruby-")):
        return "library"

    # tools / applications
    if s.startswith(("devel", "console", "utils", "x11", "network", "debug", "base")):
        return "application"

    # default fallback
    return "application"

def normalize_license_expression(expr):
    """
    Normalize Yocto license operators to SPDX-style operators: '|' -> 'OR', '&' -> 'AND'.
    """
    if not expr:
        return ""
    normalized = expr.replace("|", "OR").replace("&", "AND")
    # collapse whitespace
    return " ".join(normalized.split())

def map_component_kind_to_cdx_type(kind):
    """
    Map internal component kind to a CycloneDX component.type.
    """
    kind = (kind or "application").lower()
    if kind in ("os", "operating-system", "image"):
        return "operating-system"
    if kind in ("firmware", "bootloader"):
        return "firmware"
    if kind in ("lib", "library", "module"):
        return "library"
    return "application"

def generate_packages_list(products_names, version, component_kind, license_expr, description, repo_url):
    """
    Get a list of products and generate CPE and PURL identifiers for each of them.
    """
    import uuid

    packages = []

    # keep only the short version which can be matched against vulnerabilities databases
    version = (version or "").split("+git")[0]

    cdx_type = map_component_kind_to_cdx_type(component_kind)
    license_expr = normalize_license_expression(license_expr)

    # some packages have alternative names, so we split CVE_PRODUCT
    for product in (products_names or "").split():
        # CVE_PRODUCT in recipes may include vendor information for CPE identifiers. If not,
        # use wildcard for vendor.
        if ":" in product:
            vendor, product = product.split(":", 1)
        else:
            vendor = ""

        # SBOM main component elements:
        pkg = {
            "type": cdx_type,
            "bom-ref": str(uuid.uuid4()),
            "name": product,
            "version": version,
        }

        if vendor:
            pkg["group"] = vendor

        # per-package description
        if description:
            pkg["description"] = description

        # per-package license expression (can contain multiple licenses with operators)
        if license_expr:
            pkg["licenses"] = [
                {
                    "expression": license_expr
                }
            ]

        # per-package CPE
        pkg["cpe"] = 'cpe:2.3:*:{}:{}:{}:*:*:*:*:*:*:*'.format(
            vendor or "*", product, version
        )

        # per-package PURL
        pkg["purl"] = 'pkg:generic/{}{}@{}'.format(
            f"{vendor}/" if vendor else "", product, version
        )

        # per-package repository / homepage URL (if available)
        if repo_url:
            # crude guess: treat Git-like URLs as vcs, others as website
            ref_type = "vcs" if any(
                repo_url.startswith(pfx) for pfx in ("git://", "git+", "ssh://")
            ) else "website"
            pkg["externalReferences"] = [
                {
                    "type": ref_type,
                    "url": repo_url,
                }
            ]

        packages.append(pkg)
    return packages

def cyclonedx_collect_recipe_metadata(d, pn):
    """
    Collects per-recipe metadata needed to build CycloneDX components.
    Returns a dict with keys:
      - cve_product, cve_version, license_expr, description, repo_url, component_kind
    """
    # CVE product / version
    name = d.getVar("CVE_PRODUCT") or pn
    version = d.getVar("CVE_VERSION") or d.getVar("PV") or ""

    # SECTION -> component kind
    section = d.getVar("SECTION") or ""
    component_kind = classify_component_kind(pn, section)

    # license: prefer per-PN overrides
    license_expr = (
        d.getVar(f"LICENSE:{pn}")
        or d.getVar(f"LICENSE_{pn}")
        or d.getVar("LICENSE")
        or ""
    )

    # description: prefer per-PN overrides
    description = (
        d.getVar(f"DESCRIPTION:{pn}")
        or d.getVar(f"DESCRIPTION_{pn}")
        or d.getVar("DESCRIPTION")
        or ""
    )

    # homepage / repo URL
    homepage = d.getVar("HOMEPAGE") or ""
    src_uri = d.getVar("SRC_URI") or ""
    repo_url = ""

    if homepage:
        repo_url = homepage.strip()
    else:
        for entry in src_uri.split():
            e = entry.strip()
            if not e or e.startswith("file://"):
                continue
            if e.startswith(("http://", "https://", "git://", "ssh://", "git+")):
                repo_url = e.split(";", 1)[0]
                break

    return {
        "cve_product": name,
        "cve_version": version,
        "license_expr": license_expr,
        "description": description,
        "repo_url": repo_url,
        "component_kind": component_kind,
    }

python do_cyclonedx_rootfs_sbom() {
    """
    Image-level task that generates the CycloneDX SBOM based on the
    final rootfs manifest in ${IMAGE_MANIFEST}.
    """
    import os
    import bb
    import glob
    ### --> for newer Yocto releases > v4.1 <-- ###
    # from oe.package_data import read_pkgdatafile, pkgdatadir
    ### --> for Yocto release kirkstone <-- ###
    import oe.packagedata
    import Path

    pn = d.getVar("PN") or ""
    taskhash = d.getVar("BB_TASKHASH_do_cyclonedx_rootfs_sbom") or ""
    bb.note(f"CycloneDX: do_cyclonedx_rootfs_sbom start (PN={pn}, taskhash={taskhash})")

     # Run only for image recipes (skip native, -native, -cross, etc.)
    image_fstypes = d.getVar("IMAGE_FSTYPES") or ""
    if not image_fstypes:
        # Not an image (no filesystem types defined)
        return

    manifest_path = d.getVar("IMAGE_MANIFEST") or ""
    bb.note(f"CycloneDX: expecting rootfs manifest at {manifest_path}")
    bb.note(f"CycloneDX: manifest exists: {os.path.exists(manifest_path)}")

    if not (manifest_path and os.path.exists(manifest_path)):
        bb.warn(f"CycloneDX: rootfs manifest not found at {manifest_path}, skipping SBOM generation")
        return

    sbom_path = d.getVar("CYCLONEDX_EXPORT_SBOM")

    # Ensure SBOM file exists; create skeleton if missing
    if not os.path.exists(sbom_path):
        import uuid
        from datetime import datetime, timezone
        timestamp = datetime.now(timezone.utc).isoformat()
        sbom_serial_number = str(uuid.uuid4())
        bb.note(f"CycloneDX: SBOM not found at {sbom_path}, creating new skeleton")


        metadata_component = {
        "bom-ref": "BomRef.485485485584318.384648452452532",
        "name": d.getVar("PN") or "image",
        "type": "library",
        "version": d.getVar("PV") or ""
        }

        write_json(sbom_path, {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "serialNumber": f"urn:uuid:{sbom_serial_number}",
            "version": 1,
            "metadata": {
                "timestamp": timestamp,
                "tools": [{"name": "yocto"}],
                "component": metadata_component
            },
            "components": []
        })

    sbom = read_json(sbom_path)

    # extract the sbom serial number without "urn:uuid:" prefix
    serial = sbom.get("serialNumber", "")
    prefix = "urn:uuid:"
    if serial.startswith(prefix):
        sbom_serial_number = serial[len(prefix):]
    else:
        sbom_serial_number = serial

    ### --> for newer Yocto releases > v4.1 <-- ###
    # Build a mapping from package name -> pkgdata file
    # pkgdata_dir = os.path.join(pkgdatadir(d), "runtime")
    ### !! Check if we need to use the runtime subdirectory of the PKGDATA_DIR !!
    # if not os.path.isdir(pkgdata_dir):
    #     bb.fatal(f"CycloneDX: pkgdata directory not found: {pkgdata_dir}")

    ### --> for Yocto release kirkstone <-- ###
    # We use the runtime subdirectory of the PKGDATA_DIR !!
    base_pkgdata_dir = d.getVar("PKGDATA_DIR")
    runtime_pkgdata_dir = os.path.join(base_pkgdata_dir, "runtime")
    if not runtime_pkgdata_dir or not os.path.isdir(runtime_pkgdata_dir):
        bb.fatal(f"CycloneDX: runtime pkgdata directory not found: {runtime_pkgdata_dir}")

    # Read manifest lines: "<pkg> <arch> <version>"
    manifest_pkgs = []
    with open(manifest_path, "r", encoding="utf-8") as mf:
        for line in mf:
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            pkgname = parts[0]
            manifest_pkgs.append(pkgname)

    # Debug counters
    total_manifest_pkgs = len(manifest_pkgs)
    processed_pkgs = 0
    skipped_no_pkgdata = 0
    skipped_no_pn = 0
    skipped_duplicate_cpe = 0

    # ------------------------------------------------------------------------
    # Build mapping from binary package name -> pkgvars, using runtime pkgdata
    # ------------------------------------------------------------------------
    binpkg_to_pkgvars = {}
    runtime_files = glob.glob(os.path.join(runtime_pkgdata_dir, "*"))

    for rfile in runtime_files:
        if not os.path.isfile(rfile):
            continue

        ### --> for newer Yocto releases > v4.1 <-- ###
        # pkgvars = read_pkgdatafile(rfile)
        ### --> for Yocto release kirkstone <-- ###
        pkgvars = oe.packagedata.read_pkgdatafile(rfile)
        
        # primary name is the runtime file basename
        bpkg_name = os.path.basename(rfile)
        if bpkg_name not in binpkg_to_pkgvars:
            binpkg_to_pkgvars[bpkg_name] = pkgvars

        # optional: parse any PKG:* lines as additional names
        for k, v in pkgvars.items():
            if not k.startswith("PKG:"):
                continue
            # value is the actual binary package name used in feeds/rootfs
            alt_pkgname = v.strip()
            if alt_pkgname and alt_pkgname not in binpkg_to_pkgvars:
                binpkg_to_pkgvars[alt_pkgname] = pkgvars
    
    # Track existing CPEs from previously generated components to avoid duplicates
    existing_cpes = {
        c["cpe"]
        for c in sbom.get("components", [])
        if isinstance(c, dict) and "cpe" in c
    }

    # Ensure SBOM has a valid components list
    if "components" not in sbom or not isinstance(sbom["components"], list):
        sbom["components"] = []

    # ------------------------------------------------------------------------
    # For each manifest package, look up its runtime pkgdata entry
    # ------------------------------------------------------------------------
    for pkgname in manifest_pkgs:
        pkgvars = binpkg_to_pkgvars.get(pkgname)
        if not pkgvars:
            bb.debug(2, f"CycloneDX: no runtime pkgvars mapping for manifest package {pkgname}, skipping")
            skipped_no_pkgdata += 1
            continue

        # PN is the recipe name; PKG (if present) can be another alias
        pn = pkgvars.get("PN") or pkgvars.get("PKG") or pkgname
        if not pn:
            bb.debug(2, f"CycloneDX: runtime pkgvars for {pkgname} has no PN/PKG, skipping")
            skipped_no_pn += 1
            continue

        processed_pkgs += 1

        # Create a sub-datastore for this recipe to reuse helper functions
        d_recipe = d.createCopy()
        # Ensure PN in the sub-datastore matches the recipe
        d_recipe.setVar("PN", pn)
        # Import selected metadata from pkgdata (PV, LICENSE, DESCRIPTION, SECTION, HOMEPAGE, SRC_URI, etc.)
        for key in (
            "PV",
            "LICENSE",
            "DESCRIPTION",
            "HOMEPAGE",
            "SECTION",
            "SRC_URI",
            "CVE_PRODUCT",
            "CVE_VERSION",
            "CVE_CHECK_IGNORE",
        ):
            if key in pkgvars:
                d_recipe.setVar(key, pkgvars[key])

        meta = cyclonedx_collect_recipe_metadata(d_recipe, pn)

        # Generate component(s) for this package
        components = generate_packages_list(
            meta["cve_product"],
            meta["cve_version"],
            meta["component_kind"],
            meta["license_expr"],
            meta["description"],
            meta["repo_url"],
        )

        for comp in components:
            cpe = comp.get("cpe")

            # Apply optional duplicate-CPE filtering
            if cpe and cpe in existing_cpes:
                skipped_duplicate_cpe += 1
                continue

            sbom["components"].append(comp)
            if cpe:
                existing_cpes.add(cpe)

    # Process component mapping 
    mapping_path_str = d.getVar("SBOM_MAPPING_PATH")

    if not mapping_path_str:
        bb.fatal("SBOM_MAPPING_PATH is not set. Please define it in your configuration.")

    mapping_path = Path(mapping_path_str)

    if not mapping_path.exists():
        bb.fatal(f"SBOM mapping file not found at '{mapping_path}'. Please check SBOM_MAPPING_PATH.")

    mapping = read_json(MAPPING_PATH)

    if not isinstance(mapping, list):
        raise ValueError("The mapping file must be a JSON list.")

    updated_sbom = process_components(sbom, mapping)

    # Write back SBOM
    write_json(sbom_path, updated_sbom)

    bb.note(
        "CycloneDX: manifest packages: %d, processed with pkgdata: %d, "
        "skipped (no pkgdata): %d, skipped (no PN): %d, skipped duplicate CPEs: %d"
        % (total_manifest_pkgs, processed_pkgs, skipped_no_pkgdata, skipped_no_pn, skipped_duplicate_cpe)
    )
    bb.note(f"CycloneDX: final component count: {len(sbom['components'])}")
    bb.note(f"CycloneDX: SBOM written to {sbom_path}")
}

# Add the sbom generation function as a task to bitbake
addtask do_cyclonedx_rootfs_sbom after do_image before do_image_ext4
do_cyclonedx_rootfs_sbom[nostamp] = "1"
do_cyclonedx_rootfs_sbom[lockfiles] += "${CYCLONEDX_EXPORT_LOCK}"
