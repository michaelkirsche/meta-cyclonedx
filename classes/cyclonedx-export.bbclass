# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Michael Kirsche - Codewerk GmbH <michael.kirsche@codewerk.de>.
# Copyright (C) 2024 Savoir-faire Linux Inc. (<www.savoirfairelinux.com>).
# Copyright (C) 2022 BG Networks, Inc.

# The product name that the CVE database uses. Defaults to BPN, but may need to
# be overriden per recipe (for example tiff.bb sets CVE_PRODUCT=libtiff).
CVE_PRODUCT ??= "${BPN}"
CVE_VERSION ??= "${PV}"

# Runtime pkgdata lacks CVE_PRODUCT/CVE_VERSION/HOMEPAGE/SRC_URI, so have emit_pkgdata
# write them per package for do_cyclonedx_rootfs_sbom to read back. Only the derived,
# credential-free repo URL is stored, never raw SRC_URI. emit_pkgdata reads these values
# dynamically, hence the explicit vardeps so sstate notices when they change.
# Weak default: set CYCLONEDX_REPO_URL = "" (globally, per recipe or via :pn-<recipe>) to keep
# e.g. internal Git hosts out of the SBOM.
CYCLONEDX_REPO_URL ??= "${@cyclonedx_repo_url(d.getVar('HOMEPAGE'), d.getVar('SRC_URI'))}"
PKGDATA_VARS:append = " CVE_PRODUCT CVE_VERSION CYCLONEDX_REPO_URL"
do_package[vardeps] += "CVE_PRODUCT CVE_VERSION CYCLONEDX_REPO_URL"

CYCLONEDX_EXPORT_DIR ??= "${DEPLOY_DIR}/cyclonedx-export"
# One SBOM per image (<image>-<machine>.bom.json); PN if IMAGE_LINK_NAME is disabled ("").
CYCLONEDX_EXPORT_SBOM ??= "${CYCLONEDX_EXPORT_DIR}/${@d.getVar('IMAGE_LINK_NAME') or d.getVar('PN')}.bom.json"
CYCLONEDX_EXPORT_LOCK ??= "${TMPDIR}/cyclonedx-export/bom.lock"

# SPDX license list used to validate license IDs (same weak default as create-spdx.bbclass)
SPDX_LICENSES ??= "${COREBASE}/meta/files/spdx-licenses.json"

# Optional SBOM post-processing. Empty = feature off. Point at your own rules
# file (see conf/mapping.json.example) to rename/append components.
SBOM_MAPPING_PATH ?= ""

def cyclonedx_metadata_component(d):
    # The top-level component the BOM describes (the image itself).
    import uuid
    return {
        "bom-ref": str(uuid.uuid4()),
        "name": d.getVar("PN") or "image",
        "type": "operating-system",
        "version": d.getVar("PV") or "",
    }

def cyclonedx_skeleton(d):
    # Empty CycloneDX 1.4 document with a fresh serial number.
    import uuid
    from datetime import datetime, timezone
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": [{"name": "yocto"}],
            "component": cyclonedx_metadata_component(d),
        },
        "components": [],
    }

def _apply_mapping(component, old_name, new_name, description=None):
    import copy

    updated = copy.deepcopy(component)

    # name
    if "name" in updated:
        updated["name"] = new_name

    # cpe - e.g. cpe:2.3:a:vendor:old-lib:1.0:*:*:*:*:*:*:* (case-sensitive text swap)
    if updated.get("cpe"):
        updated["cpe"] = updated["cpe"].replace(old_name, new_name)

    # purl - e.g. pkg:npm/old-lib@1.0.0
    if updated.get("purl"):
        updated["purl"] = updated["purl"].replace(old_name, new_name)

    # description - only replaced if provided in the mapping entry
    if description is not None:
        updated["description"] = description

    return updated


def process_components(sbom, mapping):
    import copy
    import uuid

    result = copy.deepcopy(sbom)
    components = result.get("components", [])

    for entry in mapping:
        search_name = entry.get("search_name", "")
        new_name    = entry.get("new_name", "")
        action      = entry.get("action", "replace").lower()
        description = entry.get("description", None)

        if not search_name or not new_name:
            print(f"[WARN] Invalid mapping entry skipped: {entry}")
            continue

        if action not in ("replace", "append"):
            print(f"[WARN] Unknown action '{action}' for '{search_name}' - skipped.")
            continue

        # Scan fresh each rule (insert operations shift positions)
        found_indices = [i for i, c in enumerate(components) if c.get("name") == search_name]

        if not found_indices:
            print(f"[INFO] Component '{search_name}' not found - no entry modified.")
            continue

        if action == "replace":
            for i in found_indices:
                components[i] = _apply_mapping(components[i], search_name, new_name, description)
                print(f"[REPLACE] '{search_name}' -> '{new_name}' (index {i})"
                      + (f" [description updated]" if description is not None else ""))

        elif action == "append":
            # Iterate in reverse to keep insertion positions stable
            for i in sorted(found_indices, reverse=True):
                new_component = _apply_mapping(components[i], search_name, new_name, description)
                # The copy is a separate component; bom-refs must be unique within a BOM
                new_component["bom-ref"] = str(uuid.uuid4())
                insert_pos = i + 1
                components.insert(insert_pos, new_component)
                print(f"[APPEND] Copy of '{search_name}' inserted as '{new_name}' at index {insert_pos}."
                      + (f" [description updated]" if description is not None else ""))

    # A rule can rename a component onto one already listed; keep the first.
    seen = set()
    deduped = []
    for c in components:
        key = c.get("cpe") or (c.get("name"), c.get("version"))
        if key not in seen:
            seen.add(key)
            deduped.append(c)

    result["components"] = deduped
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

def classify_component_kind(pn, section):
    """
    Return a coarse-grained component kind string based on Yocto SECTION / PN.

    This is later mapped to CycloneDX component.type.
    """
    s = (section or "").lower()
    p = (pn or "").lower()

    # OS / distro level
    if s.startswith("images"):
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

def normalize_license_expression(expr, spdx_ids=None, spdx_map=None):
    """
    Yocto LICENSE -> SPDX expression: '|' -> 'OR', '&' -> 'AND'. With spdx_ids (lower-case
    SPDX ID -> SPDX ID) license names are also mapped like oe-core's create-spdx: through
    spdx_map (SPDXLICENSEMAP aliases), kept if an SPDX ID (deprecated IDs included), else
    LicenseRef-<name> (PD, CLOSED, custom licenses).
    """
    import re
    if not expr:
        return ""
    toks = expr.replace("|", " OR ").replace("&", " AND ").replace("(", " ( ").replace(")", " ) ").split()
    if spdx_ids is not None:
        def spdx(tok):
            if tok in ("(", ")", "AND", "OR", "WITH") or tok.startswith(("LicenseRef-", "DocumentRef-")):
                return tok
            tok = (spdx_map or {}).get(tok) or tok
            return spdx_ids.get(tok.lower()) or "LicenseRef-" + re.sub(r"[^A-Za-z0-9.-]", "-", tok)
        toks = [spdx(t) for t in toks]
    # Yocto reads whitespace between two operands as '&' (oe.license); SPDX needs it explicit
    ops = ("AND", "OR", "WITH")
    out = []
    for tok in toks:
        if out and out[-1] not in ops + ("(",) and tok not in ops + (")",):
            out.append("AND")
        out.append(tok)
    return " ".join(out).replace("( ", "(").replace(" )", ")")

def merge_license_expressions(exprs):
    """
    AND-join normalized license expressions, listing each top-level AND term once.
    """
    # key: term as AND-joined (an OR term parenthesized, so "A OR B" from an input and
    # "(A OR B)" from an earlier merge match); value: the bare term
    terms = {}
    for expr in exprs:
        toks = (expr or "").replace("(", " ( ").replace(")", " ) ").split()
        parts, cur, depth, has_or = [], [], 0, False
        for tok in toks:
            depth += (tok == "(") - (tok == ")")
            if depth == 0 and tok == "AND":
                parts.append(cur)
                cur = []
            else:
                has_or |= depth == 0 and tok == "OR"
                cur.append(tok)
        parts.append(cur)
        # AND binds tighter than OR: "A OR B AND C" is one term, not "A OR B" and "C"
        if has_or:
            parts = [toks]
        for part in parts:
            term = " ".join(part).replace("( ", "(").replace(" )", ")")
            if term:
                terms.setdefault(f"({term})" if has_or else term, term)
    if len(terms) == 1:
        return next(iter(terms.values()))
    return " AND ".join(terms)

def generate_packages_list(products_names, version, component_kind, license_expr, description, repo_url):
    """
    Get a list of products and generate CPE and PURL identifiers for each of them.
    """
    import uuid

    packages = []

    # keep only the short version which can be matched against vulnerabilities databases
    version = (version or "").split("+git")[0]

    # component_kind already carries a valid CycloneDX component.type
    cdx_type = component_kind or "application"
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

def cyclonedx_repo_url(homepage, src_uri):
    """
    HOMEPAGE, else the first http(s)/git/ssh SRC_URI entry stripped of ;params,
    ?query, #fragment and user:password@ credentials (the result is published in the SBOM).
    """
    if (homepage or "").strip():
        return homepage.strip()
    for entry in (src_uri or "").split():
        if entry.startswith(("http://", "https://", "git://", "ssh://", "git+")):
            url = entry.split(";", 1)[0].split("#", 1)[0].split("?", 1)[0]
            scheme, sep, rest = url.partition("://")
            host, slash, path = rest.partition("/")
            return f"{scheme}{sep}{host.rpartition('@')[2]}{slash}{path}"
    return ""

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

    # per-package overrides (LICENSE:<pkg> etc.) are already collapsed by read_subpkgdata_dict
    license_expr = d.getVar("LICENSE") or ""
    description = d.getVar("DESCRIPTION") or ""

    # homepage / repo URL, derived in the package's recipe context (see PKGDATA_VARS above)
    repo_url = d.getVar("CYCLONEDX_REPO_URL") or ""

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
    import json
    import oe.packagedata
    import oe.path

    pn = d.getVar("PN") or ""
    bb.note(f"CycloneDX: do_cyclonedx_rootfs_sbom start (PN={pn})")

     # Run only for image recipes (skip native, -native, -cross, etc.)
    image_fstypes = d.getVar("IMAGE_FSTYPES") or ""
    if not image_fstypes:
        # Not an image (no filesystem types defined)
        return

    sbom_path = d.getVar("CYCLONEDX_EXPORT_SBOM")

    # IMAGE_MANIFEST carries this invocation's DATETIME, so it only exists when do_rootfs
    # ran in this build. Otherwise (nothing changed, task re-runs due to nostamp) use the
    # deployed ${IMAGE_LINK_NAME}.manifest link, which points at the unchanged rootfs's manifest.
    manifest_path = d.getVar("IMAGE_MANIFEST") or ""
    link_name = d.getVar("IMAGE_LINK_NAME") or ""
    if not os.path.exists(manifest_path) and link_name:
        manifest_path = os.path.join(d.getVar("DEPLOY_DIR_IMAGE"), link_name + ".manifest")
    bb.note(f"CycloneDX: using rootfs manifest {manifest_path}")

    if not os.path.exists(manifest_path):
        # Don't leave a previous build's (possibly another image's) SBOM behind as this image's
        if os.path.exists(sbom_path):
            os.remove(sbom_path)
        bb.warn(f"CycloneDX: rootfs manifest not found at {manifest_path}, no SBOM generated")
        return

    # This task writes the image's complete SBOM, so always start from a fresh skeleton
    # (metadata.component = this image). Never read the previous file: that carried over
    # components of earlier builds and other images.
    sbom = cyclonedx_skeleton(d)

    # Per-package metadata lives in the runtime subdirectory of PKGDATA_DIR
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

        # primary name is the runtime file basename. read_subpkgdata_dict reads
        # ${PKGDATA_DIR}/runtime/<pkg> and collapses per-package "VAR:<pkg>" keys
        # (written instead of VAR when a recipe sets e.g. LICENSE:<pkg>) into VAR.
        # Same API on kirkstone and newer releases.
        bpkg_name = os.path.basename(rfile)
        pkgvars = oe.packagedata.read_subpkgdata_dict(bpkg_name, d)
        # real runtime files win over PKG aliases registered by earlier files
        binpkg_to_pkgvars[bpkg_name] = pkgvars

        # PKG is the actual binary package name used in feeds/rootfs (renamed packages).
        # Skip PN-less files: multilib stubs that only hold a PKG line pointing at the
        # real package would otherwise shadow its pkgdata.
        alt_pkgname = (pkgvars.get("PKG") or "").strip()
        if alt_pkgname and "PN" in pkgvars:
            binpkg_to_pkgvars.setdefault(alt_pkgname, pkgvars)
    
    # SPDX license IDs for normalize_license_expression; without them only operators are mapped
    spdx_ids = None
    try:
        with open(d.getVar("SPDX_LICENSES"), encoding="utf-8") as f:
            spdx_ids = {l["licenseId"].lower(): l["licenseId"] for l in json.load(f)["licenses"]}
    except (OSError, TypeError, ValueError, KeyError) as e:
        bb.warn(f"CycloneDX: cannot read SPDX license list {d.getVar('SPDX_LICENSES')} ({e}), license names left unmapped")
    spdx_map = d.getVarFlags("SPDXLICENSEMAP") or {}

    # CPE -> component already emitted, to collapse packages of one recipe into one component
    existing_cpes = {}
    # CPEs whose description comes from a recipe's base package (runtime name = PN)
    base_described = set()

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
        # base package: the runtime file named PN (this is it, or its PKG alias)
        is_base = binpkg_to_pkgvars.get(pn) is pkgvars

        # Create a sub-datastore for this recipe to reuse helper functions
        d_recipe = d.createCopy()
        # Ensure PN in the sub-datastore matches the recipe
        d_recipe.setVar("PN", pn)
        # Import selected metadata from pkgdata (CVE_* and CYCLONEDX_REPO_URL via PKGDATA_VARS).
        # Set unconditionally: emit_pkgdata omits empty values (and pkgdata written before this
        # layer was enabled lacks our keys), so a conditional set would leak the image recipe's
        # values into every component.
        for key in (
            "PV",
            "LICENSE",
            "DESCRIPTION",
            "SECTION",
            "CVE_PRODUCT",
            "CVE_VERSION",
            "CYCLONEDX_REPO_URL",
        ):
            d_recipe.setVar(key, pkgvars.get(key, ""))

        meta = cyclonedx_collect_recipe_metadata(d_recipe, pn)

        # Generate component(s) for this package
        components = generate_packages_list(
            meta["cve_product"],
            meta["cve_version"],
            meta["component_kind"],
            normalize_license_expression(meta["license_expr"], spdx_ids, spdx_map),
            meta["description"],
            meta["repo_url"],
        )

        for comp in components:
            cpe = comp.get("cpe")

            # Packages of one recipe share the CPE and collapse into one component, which
            # stands for all of them: AND-join every package's license (LICENSE:<pkg> can be
            # narrower than the recipe's) and prefer the base package's (recipe-level) description.
            prev = existing_cpes.get(cpe) if cpe else None
            if prev is not None:
                skipped_duplicate_cpe += 1
                licenses = [c["licenses"][0]["expression"] for c in (prev, comp) if c.get("licenses")]
                if licenses:
                    prev["licenses"] = [{"expression": merge_license_expressions(licenses)}]
                if is_base and comp.get("description") and cpe not in base_described:
                    prev["description"] = comp["description"]
                    base_described.add(cpe)
                continue

            sbom["components"].append(comp)
            if cpe:
                existing_cpes[cpe] = comp
                if is_base and comp.get("description"):
                    base_described.add(cpe)

    # Optional component post-processing via a user-supplied mapping file.
    # Off by default: if SBOM_MAPPING_PATH is unset or the file is absent/empty,
    # the SBOM is written unchanged. See conf/mapping.json.example.
    mapping_path = d.getVar("SBOM_MAPPING_PATH") or ""
    updated_sbom = sbom
    if mapping_path and os.path.exists(mapping_path) and os.path.getsize(mapping_path) > 0:
        mapping = read_json(mapping_path)
        if not isinstance(mapping, list):
            bb.fatal(f"CycloneDX: mapping file {mapping_path} must contain a JSON list")
        updated_sbom = process_components(sbom, mapping)
        bb.note(f"CycloneDX: applied {len(mapping)} mapping rule(s) from {mapping_path}")
    elif mapping_path:
        bb.note(f"CycloneDX: mapping file not found or empty ({mapping_path}), SBOM left unchanged")

    # Never write through a leftover compat link into another image's SBOM
    if os.path.islink(sbom_path):
        os.unlink(sbom_path)
    write_json(sbom_path, updated_sbom)

    # ponytail: deprecated compat link for consumers of the old fixed bom.json name; points at
    # the last SBOM written (last image wins). Drop once consumers read <image>.bom.json.
    # Compare names, not paths: "dir//bom.json" != "dir/bom.json" would replace the SBOM itself.
    if os.path.basename(sbom_path) != "bom.json":
        compat_link = os.path.join(os.path.dirname(sbom_path), "bom.json")
        oe.path.symlink(os.path.basename(sbom_path), compat_link, force=True)

    bb.note(
        "CycloneDX: manifest packages: %d, processed with pkgdata: %d, "
        "skipped (no pkgdata): %d, skipped (no PN): %d, merged duplicate CPEs: %d"
        % (total_manifest_pkgs, processed_pkgs, skipped_no_pkgdata, skipped_no_pn, skipped_duplicate_cpe)
    )
    bb.note(f"CycloneDX: final component count: {len(updated_sbom['components'])}")
    bb.note(f"CycloneDX: SBOM written to {sbom_path}")
}

# Add the sbom generation function as a task to bitbake
addtask do_cyclonedx_rootfs_sbom after do_image before do_image_ext4
do_cyclonedx_rootfs_sbom[nostamp] = "1"
do_cyclonedx_rootfs_sbom[lockfiles] += "${CYCLONEDX_EXPORT_LOCK}"
