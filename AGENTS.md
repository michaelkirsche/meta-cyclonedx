# AGENTS.md

This file provides guidance to AI coding agents when working with code in this repository.
`CLAUDE.md` only imports this file — edit here, not there.

> **Keep this file current.** Whenever you change code in a way that makes anything
> below inaccurate (task flow, variables, version handling, output paths, etc.),
> update the affected section in the same change. Check this file against the code
> before finishing any task and fix drift as you find it.

## What this is

A Yocto/OpenEmbedded meta-layer that generates a CycloneDX SBOM (`<IMAGE_LINK_NAME>.bom.json`) from
the packages actually installed into an image's root filesystem. All logic lives in
one BitBake class: [classes/cyclonedx-export.bbclass](classes/cyclonedx-export.bbclass).
Everything else (`conf/layer.conf`, the dummy recipe) is layer plumbing.

Forked from BG Networks' `meta-dependencytrack`, then from Savoir-faire Linux'
`meta-cyclonedx`. DependencyTrack upload was dropped upstream (1881a28); commit 8566b63
switched to manifest-based collection and removed VEX. The README is current for user
docs (variables, mapping rules). If the README and the class disagree, the class wins —
fix the README in the same change.

## How the SBOM is built

One task in the class, tied to the image build:

`do_cyclonedx_rootfs_sbom` — `addtask ... after do_image before do_image_ext4`,
`[nostamp]`, `[lockfiles]` = `CYCLONEDX_EXPORT_LOCK`. Starts from a fresh
`cyclonedx_skeleton(d)` (CycloneDX 1.4, new `urn:uuid:` serial and timestamp,
`metadata.component` = the image's PN/PV) and writes the image's complete SBOM to
`CYCLONEDX_EXPORT_SBOM`, overwriting it. **Never read the previous file back** — that
carried components of earlier builds and other images into the SBOM, and there is no
reliable reset point: a `BuildStarted` handler only fires for classes in the global
`INHERIT`, never for a recipe-level `inherit`. Reads `${IMAGE_MANIFEST}` (the `<pkg> <arch>
<version>` list of what landed in the rootfs). Its name embeds this invocation's `DATETIME`,
so when `do_rootfs` didn't re-run the task falls back to the deployed
`${DEPLOY_DIR_IMAGE}/${IMAGE_LINK_NAME}.manifest` link; if neither exists it deletes
`CYCLONEDX_EXPORT_SBOM` and warns (never leave another build's SBOM behind). Maps each binary package name back
to its recipe metadata via **runtime pkgdata** (`${PKGDATA_DIR}/runtime/*`, parsed
with `oe.packagedata.read_subpkgdata_dict`, which collapses per-package `VAR:<pkg>` keys
into `VAR`; renamed packages matched via the `PKG` alias, PN-less multilib stub files
ignored), and appends one component per `CVE_PRODUCT` entry to the SBOM. Deduplicates by
CPE: a recipe's binary packages collapse to one component per `CVE_PRODUCT` entry, and
recipes sharing a `CVE_PRODUCT`+version merge into the first-seen component. Merging
AND-joins the licenses (`merge_license_expressions`; `LICENSE:<pkg>` can be narrower than the
recipe's, e.g. util-linux's libraries) and switches to the description of the recipe's base
package (runtime file named `PN`, possibly installed under its `PKG` alias) when one arrives
— sub-packages often carry their own (`util-linux libblkid`). Finally, if
`SBOM_MAPPING_PATH` points at a mapping file, applies component name transformations
before writing (see below).

Because it keys off the manifest, only packages present in the final image appear —
native/cross/-dev artifacts are excluded automatically.

Stock runtime pkgdata has no `CVE_PRODUCT`/`CVE_VERSION`/`HOMEPAGE`/`SRC_URI`. The class
appends `CVE_PRODUCT CVE_VERSION CYCLONEDX_REPO_URL` to `PKGDATA_VARS`, so each target
recipe's `emit_pkgdata` (inside `do_package`) writes them into its runtime pkgdata.
`CYCLONEDX_REPO_URL` (weak default `??=`, so `local.conf`, a recipe or `:pn-<recipe>` can clear
it) is derived in recipe context by `cyclonedx_repo_url` (HOMEPAGE, else
first http(s)/git/ssh SRC_URI entry without `;params`, `?query`, `#fragment` or `user:pass@`) — never store raw `SRC_URI`, it can
carry credentials into sstate and the SBOM. `do_package[vardeps]` lists the same three vars
because `emit_pkgdata` reads values dynamically; keep both lists in sync. Consequence:
enabling the class (or changing these lists) re-runs `do_package` for every target recipe once.

Per-package metadata comes from `d.createCopy()` of the image datastore, with pkgdata
keys set **unconditionally** (`setVar(key, pkgvars.get(key, ""))`). Never make that
conditional — `emit_pkgdata` omits empty values, so the image recipe's values would leak
into every component (fixed in 8a70cdf).

Per-component derivation sits above the task. Pure helpers: `cyclonedx_repo_url`,
`classify_component_kind` (SECTION/PN → CycloneDX type; `operating-system` only for SECTION
`images` — never match PN `*-image`, that catches packages like `fstab-production-image`),
`normalize_license_expression` (`|`/`&` → ` OR `/` AND `; given the SPDX ID list, also
names like oe-core's `convert_license_to_spdx`: `SPDXLICENSEMAP` alias → SPDX ID
(case-insensitive, deprecated IDs kept) → else `LicenseRef-<name>` sanitized to `[A-Za-z0-9.-]`;
the task loads `SPDX_LICENSES` once and passes it, `generate_packages_list` re-normalizes
operators only — keep it idempotent), `merge_license_expressions` (AND-join,
each top-level AND term once; an expression with a top-level OR stays one term because AND binds
tighter), `generate_packages_list` (one component per `CVE_PRODUCT` entry; CPE
`cpe:2.3:*:<vendor|*>:<product>:<ver>:...`, purl `pkg:generic/[vendor/]product@ver`,
strips `+git...` from the version). `cyclonedx_collect_recipe_metadata(d, pn)` reads the
per-package datastore copy.

### Gotchas

- **Scheduling:** the task joins the image build only through `before do_image_ext4`.
  If ext4 is not in `IMAGE_FSTYPES` (directly or as a typedep), a normal image build
  skips it — run `bitbake <image> -c cyclonedx_rootfs_sbom` or change the anchor. The
  `IMAGE_FSTYPES` early-return in the task is only a sanity guard; scheduling is what
  keeps it to images (the global `INHERIT` adds the task to every recipe).
- **Output naming:** `CYCLONEDX_EXPORT_SBOM` defaults to one file per image,
  `${IMAGE_LINK_NAME}.bom.json` (`PN` if `IMAGE_LINK_NAME` is empty). `bom.json` next to it
  is a deprecated compat symlink to the last SBOM written (last image wins; skipped if the
  user points `CYCLONEDX_EXPORT_SBOM` at a file literally named `bom.json` — compare
  basenames, never full paths). A symlink at `CYCLONEDX_EXPORT_SBOM` is unlinked before
  writing, never written through. The task's lockfile still guards that shared link.
- **Global `INHERIT` required for full metadata:** a recipe-level `inherit` in the image
  recipe runs the task, but other recipes then don't write `CVE_PRODUCT`/`CVE_VERSION`/
  `CYCLONEDX_REPO_URL` to pkgdata — components fall back to `PN`/`PV`, no vendor, no repo
  URL. Still a supported mode (README documents both); don't break it.

## Component mapping (optional post-processing)

`SBOM_MAPPING_PATH` (default `""` = off) may point at a JSON file of rules that
rename or duplicate components after collection, keyed by component name. `replace`
rewrites `name`/`cpe`/`purl` (and optionally `description`) in place; `append` inserts
a renamed copy (with a fresh `bom-ref`) after the original. Afterwards components are de-duplicated again (by CPE,
else name+version) since a rule can rename one onto another. Implemented by
`process_components` / `_apply_mapping`. The feature is skipped entirely when the var is empty or the
file is missing/empty. `conf/mapping.json.example` is a template only — it is never
loaded unless the user explicitly points the var at it. Full rule reference is in the
README ("Mapping File Reference").

## Version portability

The class targets **kirkstone** only (see `LAYERSERIES_COMPAT_cyclonedx`); there are no
code paths for other releases. The pkgdata APIs it relies on (`oe.packagedata.read_subpkgdata_dict`,
`PKGDATA_VARS`) also exist in scarthgap, but no newer release has been built or tested.

## Enabling / running

In `local.conf`:

```conf
INHERIT += "cyclonedx-export"
```

Then build the image normally. Output: `${DEPLOY_DIR}/cyclonedx-export/${IMAGE_LINK_NAME}.bom.json`
(plus the deprecated `bom.json` compat symlink).

There is no local test harness — validation means running an actual BitBake image
build in a Yocto environment. Key vars: `CYCLONEDX_EXPORT_DIR`, `CYCLONEDX_EXPORT_SBOM`,
`CYCLONEDX_EXPORT_LOCK`.
