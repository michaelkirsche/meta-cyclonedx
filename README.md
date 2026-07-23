# meta-cyclonedx

`meta-cyclonedx` is a [Yocto](https://www.yoctoproject.org/) meta-layer which produces [CycloneDX](https://cyclonedx.org/) Software Bill of Materials (aka [SBOM](https://www.ntia.gov/SBOM)) from your root filesystem.

This repository is forked from [BG Networks repository](https://github.com/bgnetworks/meta-dependencytrack) but differs by the following:
- Removed direct integration with DependencyTrack.
- Exported CycloneDX include packages, but also vulnerabilities found by Yocto.
- Generation of CPE is fixed and also generate purl for packages.
- Added generation of an additional CycloneDX VEX file which contains information on patched and ignored CVEs from within the Yocto Build System.

## Installation

To install this meta-layer simply clone the repository into the `sources` directory and add it to your `build/conf/bblayers.conf` file:

```sh
$ cd sources
$ git clone https://github.com/savoirfairelinux/meta-cyclonedx.git
```

and in your `bblayers.conf` file:

```sh
BBLAYERS += "${BSPDIR}/sources/meta-cyclonedx"
```

## Configuration

To enable and configure the layer simply inherit the `cyclonedx-export` class in your `local.conf` file and then set the following variable:

```sh
INHERIT += "cyclonedx-export"
```

## Building

Once everything is configured simply build your image as you normally would.

Alternatively, if you are only interested in the CycloneDX files, you may append your bitbake command with `--runonly=do_cyclonedx_package_collect` which will limit bitbake to run only the required tasks for creating the CycloneDX output.

By default the final CycloneDX SBOMs are saved in the folder `${DEPLOY_DIR}/cyclonedx-export` as `bom.json` and `vex.json` respectively.

## Uploading to DependencyTrack (tested against DT v4.11.4)

While this layer does not offer a direct integration with DependencyTrack (we consider that a feature, since it removes dependencies to external infrastructure in your build), it is perfectly possible to use the produced SBOMs within DependencyTrack.

At the time of writing DependencyTrack does not support uploading component and vulnerability information in one go (which is why we currently create two separate files). The status on this may be tracked [here](https://github.com/DependencyTrack/dependency-track/issues/919).

### Manual Upload

1. Go into an existing project in your DependencyTrack instance or create a new one.
2. Go to the *Components* tab and click *Upload BOM*.
3. Select the `bom.json` file from your deploy directory.
4. Wait for the vulnerability analysis to complete.
5. Go to the *Audit Vulnerabilities* tab and click *Apply VEX*.
6. Select the `vex.json` file from your deploy directory.

### Automated Upload

You may want to script the upload of the SBOMs to DependencyTrack, e.g. as part of a CI job that runs after your build is complete.

This is possible by leveraging DependencyTracks REST API.

At the time of writing this can be done by leveraging the following API endpoints:

1. `/v1/bom` for uploading the `bom.json`.
2. `/v1/event/token/{uuid}` for checking the status on the `bom.json` processing.
3. `/v1/vex` for uploading the `vex.json`.

Please refer to [DependencyTracks REST API documentation](https://docs.dependencytrack.org/integrations/rest-api/) for the usage of these endpoints as well as the required token permissions.

In the future we might include an example script in this repository.


## Mapping File Reference

Component mapping is **optional and off by default**. To enable it, copy
`conf/mapping.json.example` to a file of your own and point `SBOM_MAPPING_PATH` at it
in your `local.conf`:

```sh
SBOM_MAPPING_PATH = "${TOPDIR}/conf/my-sbom-mapping.json"
```

When `SBOM_MAPPING_PATH` is unset (the default) or the file is missing/empty, the SBOM
is written unchanged.

The mapping file controls how components in the SBOM are modified.
It is a JSON array where each entry defines one transformation rule.

---

### Structure

```json
[
  {
    "search_name": "old-lib",
    "new_name":    "new-lib",
    "action":      "replace",
    "description": "Optional description text."
  }
]
```

---

### Fields

| Field | Required | Description |
|---|---|---|
| `search_name` | ✅ Yes | The exact component name to search for in the SBOM. |
| `new_name` | ✅ Yes | The name to use as a replacement. Applied to `name`, `cpe`, and `purl`. |
| `action` | ✅ Yes | What to do with the found component. Either `replace` or `append` (see below). |
| `description` | ❌ No | If provided, overwrites the component's `description` field. If omitted, the existing description is left unchanged. |

---

### Actions

#### `replace`
The matched component is modified **in place**.
The `name`, `cpe`, and `purl` fields are updated to use `new_name`.

**Before:**
```json
{
  "name": "old-lib",
  "cpe":  "cpe:2.3:a:vendor:old-lib:1.0:*:*:*:*:*:*:*",
  "purl": "pkg:npm/old-lib@1.0.0"
}
```

**After** (with `"new_name": "new-lib"`):
```json
{
  "name": "new-lib",
  "cpe":  "cpe:2.3:a:vendor:new-lib:1.0:*:*:*:*:*:*:*",
  "purl": "pkg:npm/new-lib@1.0.0"
}
```

---

#### `append`
The matched component is **kept unchanged**. A deep copy is created with
`name`, `cpe`, and `purl` updated to use `new_name`, and inserted
directly after the original in the component list.

**Before:**
```json
[
  { "name": "legacy-framework", "purl": "pkg:maven/com.acme/legacy-framework@3.0.0" }
]
```

**After** (with `"new_name": "modern-framework"`):
```json
[
  { "name": "legacy-framework",  "purl": "pkg:maven/com.acme/legacy-framework@3.0.0" },
  { "name": "modern-framework",  "purl": "pkg:maven/com.acme/modern-framework@3.0.0" }
]
```

---

### The `description` Field

When `description` is provided in a mapping entry, it overwrites the
`description` field of the affected component (or its copy in the case of `append`).

```json
{
  "search_name": "old-lib",
  "new_name":    "new-lib",
  "action":      "replace",
  "description": "Migrated to the vendor-approved version in Q2 2026."
}
```

If `description` is **omitted**, the component's existing description remains untouched.

---

### Full Example

```json
[
  {
    "search_name": "old-lib",
    "new_name":    "new-lib",
    "action":      "replace",
    "description": "Replaced with the patched version."
  },
  {
    "search_name": "legacy-framework",
    "new_name":    "modern-framework",
    "action":      "append"
  },
  {
    "search_name": "util-core",
    "new_name":    "util-core-hardened",
    "action":      "replace"
  }
]
```

---

### Notes

- **`search_name` is case-sensitive.** `Old-Lib` and `old-lib` are treated as different components.
- **Multiple matches:** If the same name appears more than once in the SBOM, the rule is applied to all occurrences.
- **Multiple rules:** Rules are applied in order from top to bottom. A component can be affected by more than one rule if the names match.
- **Name substitution in `cpe` and `purl`** is a simple text replacement — every occurrence of `search_name` within the field value is replaced with `new_name`.

