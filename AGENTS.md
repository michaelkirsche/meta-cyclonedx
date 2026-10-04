# AGENTS.md

This file provides guidance to AI coding agents when working with code in this repository.
`CLAUDE.md` only imports this file — edit here, not there.

> **Keep this file current.** Whenever you change code in a way that makes anything
> below inaccurate (task flow, variables, version handling, output paths, etc.),
> update the affected section in the same change. Check this file against the code
> before finishing any task and fix drift as you find it.

## What this is

A Yocto/OpenEmbedded meta-layer that generates a CycloneDX SBOM (`bom.json`) from
the packages actually installed into an image's root filesystem. All logic lives in
one BitBake class: [classes/cyclonedx-export.bbclass](classes/cyclonedx-export.bbclass).
Everything else (`conf/layer.conf`, the dummy recipe) is layer plumbing.

Forked from BG Networks' `meta-dependencytrack`, then from Savoir-faire Linux'
`meta-cyclonedx`. DependencyTrack upload was dropped upstream (1881a28); commit 8566b63
switched to manifest-based collection and removed VEX. The README is current for user
docs (variables, mapping rules). If the README and the class disagree, the class wins —
fix the README in the same change.

## How the SBOM is built

An event handler plus one task in the class, tied to the image build:

1. `do_cyclonedx_init` — event handler on `bb.event.BuildStarted`. Writes
   `cyclonedx_skeleton(d)` to `CYCLONEDX_EXPORT_SBOM`: CycloneDX 1.4, `components: []`,
   fresh `urn:uuid:` serial. Its `metadata.component` is a generic placeholder (runs on
   the global datastore, no image PN).
2. `do_cyclonedx_rootfs_sbom` — `addtask ... after do_image before do_image_ext4`,
   `[nostamp]`, `[lockfiles]` = `CYCLONEDX_EXPORT_LOCK`. Recreates the skeleton if the
   file is missing, then replaces `metadata.component` with the image recipe's PN/PV via
   `cyclonedx_metadata_component(d)`. Reads `${IMAGE_MANIFEST}` (the `<pkg> <arch>
   <version>` list of what landed in the rootfs), maps each binary package name back
   to its recipe metadata via **runtime pkgdata** (`${PKGDATA_DIR}/runtime/*`, parsed
   with `oe.packagedata.read_pkgdatafile`; renamed packages matched via `PKG:*` keys),
   and appends components to the SBOM. Deduplicates by CPE, so all binary packages of one
   recipe collapse into a single component. Finally, if `SBOM_MAPPING_PATH` points at a
   mapping file, applies component name transformations before writing (see below).

Because it keys off the manifest, only packages present in the final image appear —
native/cross/-dev artifacts are excluded automatically.

Per-package metadata comes from `d.createCopy()` of the image datastore, with pkgdata
keys set **unconditionally** (`setVar(key, pkgvars.get(key, ""))`). Never make that
conditional — the image recipe's values would leak into every component (fixed in
8a70cdf). Kirkstone runtime pkgdata has no `CVE_PRODUCT`/`CVE_VERSION`/`HOMEPAGE`/`SRC_URI`,
so in practice components are named after pkgdata `PN`, versioned from `PV`, carry no
`externalReferences`, and recipe `CVE_PRODUCT` overrides are not honored.

Per-component derivation sits above the task. Pure helpers: `classify_component_kind`
(SECTION/PN → CycloneDX type), `normalize_license_expression` (`|`/`&` → OR/AND),
`generate_packages_list` (CPE `cpe:2.3:*:<vendor|*>:<product>:<ver>:...`, purl
`pkg:generic/[vendor/]product@ver`, strips `+git...` from the version).
`cyclonedx_collect_recipe_metadata(d, pn)` reads the per-package datastore copy.

### Gotchas

- **Scheduling:** the task joins the image build only through `before do_image_ext4`.
  If ext4 is not in `IMAGE_FSTYPES` (directly or as a typedep), a normal image build
  skips it — run `bitbake <image> -c cyclonedx_rootfs_sbom` or change the anchor. The
  `IMAGE_FSTYPES` early-return in the task is only a sanity guard; scheduling is what
  keeps it to images (the global `INHERIT` adds the task to every recipe).
- **Reset on every build:** `do_cyclonedx_init` fires on every `BuildStarted`, including
  non-image invocations (`bitbake -c clean foo`, single recipes), and resets `bom.json`
  to an empty skeleton. Copy the SBOM away before running further builds.
- **Multi-image builds:** `bom.json` is shared. Several images in one bitbake invocation
  accumulate components; dedup also checks CPEs already in the file, so a package from
  image A is skipped for image B. `metadata.component` names only the last image. Build
  one image per invocation for a clean per-image SBOM.

## Component mapping (optional post-processing)

`SBOM_MAPPING_PATH` (default `""` = off) may point at a JSON file of rules that
rename or duplicate components after collection, keyed by component name. `replace`
rewrites `name`/`cpe`/`purl` (and optionally `description`) in place; `append` inserts
a renamed copy after the original. Implemented by `process_components` / `_apply_mapping`.
The feature is skipped entirely when the var is empty or the
file is missing/empty. `conf/mapping.json.example` is a template only — it is never
loaded unless the user explicitly points the var at it. Full rule reference is in the
README ("Mapping File Reference").

## Version portability

The class targets **kirkstone** (see `LAYERSERIES_COMPAT_cyclonedx`). Code paths that
differ on newer Yocto (> 4.1) are left in place as commented alternatives marked
`### --> for newer Yocto releases > v4.1 <-- ###` — mainly the pkgdata import
(`oe.packagedata` vs `oe.package_data` + `pkgdatadir`). Keep both variants in sync when
editing pkgdata access.

## Enabling / running

In `local.conf`:

```conf
INHERIT += "cyclonedx-export"
```

Then build the image normally. Output: `${DEPLOY_DIR}/cyclonedx-export/bom.json`.

There is no local test harness — validation means running an actual BitBake image
build in a Yocto environment. Key vars: `CYCLONEDX_EXPORT_DIR`, `CYCLONEDX_EXPORT_SBOM`,
`CYCLONEDX_EXPORT_LOCK`.
