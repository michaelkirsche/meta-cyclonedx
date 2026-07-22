# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

> **Keep this file current.** Whenever you change code in a way that makes anything
> below inaccurate (task flow, variables, version handling, output paths, etc.),
> update the affected section in the same change. Check this file against the code
> before finishing any task and fix drift as you find it.

## What this is

A Yocto/OpenEmbedded meta-layer that generates a CycloneDX SBOM (`bom.json`) from
the packages actually installed into an image's root filesystem. All logic lives in
one BitBake class: [classes/cyclonedx-export.bbclass](classes/cyclonedx-export.bbclass).
Everything else (`conf/layer.conf`, the dummy recipe) is layer plumbing.

Forked from BG Networks' `meta-dependencytrack`; the DependencyTrack integration and
the VEX file were removed. **The README is stale** — it still describes `vex.json`,
DependencyTrack upload, and the old whole-build (per-recipe) collection model. The
current code is manifest-based and VEX-free (see commit 8566b63). Trust the class, not
the README.

## How the SBOM is built

An event handler plus one task in the class, tied to the image build:

1. `do_cyclonedx_init` — event handler on `bb.event.BuildStarted`. Writes an empty
   CycloneDX 1.4 skeleton (`components: []`) with a fresh UUID serial number to
   `CYCLONEDX_EXPORT_SBOM`.
2. `do_cyclonedx_rootfs_sbom` — `addtask ... after do_image before do_image_ext4`,
   `nostamp`, guarded by a lockfile. Reads `${IMAGE_MANIFEST}` (the `<pkg> <arch>
   <version>` list of what landed in the rootfs), maps each binary package name back
   to its recipe metadata via **runtime pkgdata** (`${PKGDATA_DIR}/runtime/*`, parsed
   with `oe.packagedata.read_pkgdatafile`), and appends one component per CVE_PRODUCT
   to the SBOM. Deduplicates by CPE.

Because it keys off the manifest, only packages present in the final image appear —
native/cross/-dev artifacts are excluded automatically. Recipes without an
`IMAGE_FSTYPES` return early (the task only does real work for image recipes).

Per-component CPE/purl/type/license derivation lives in the pure helpers above the task.

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
