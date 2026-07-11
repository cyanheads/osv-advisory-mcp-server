# osv-advisory-mcp-server — Design

## MCP Surface

### Tools

| Name | Description | Key Inputs | Annotations | Errors |
|:-----|:------------|:-----------|:------------|:-------|
| `osv_query_package` | Query vulnerabilities for a single package version. Returns all known vulns: OSV IDs, CVE aliases, severity (CVSS string), affected ranges, fix versions, CWE IDs. The primary "is this package version vulnerable?" tool. | `name` (package name), `ecosystem` (exact string — use `osv_list_ecosystems` to validate), `version` | `readOnlyHint: true`, `idempotentHint: true`, `openWorldHint: false` | `invalid_ecosystem` (InvalidParams) |
| `osv_query_batch` | Batch vulnerability query over an array of `{name, ecosystem, version}` tuples — one call covers a full dependency list. Per-package results with `vulnCount`, `vulnIds`, and `aliases` (CVE IDs) for each. The differentiator for SBOM/lockfile audits. | `packages` (array of `{name, ecosystem, version}`, max 1000) | `readOnlyHint: true`, `openWorldHint: false` | `invalid_ecosystem` (InvalidParams), `batch_too_large` (InvalidParams) |
| `osv_get_vulnerability` | Fetch the full record for a single OSV ID (`GHSA-…`, `PYSEC-…`, `RUSTSEC-…`, `GO-…`, `CVE-…`). Returns: summary, details, aliases (CVE IDs), severity, affected packages/ranges, fix versions, CWE IDs, references, credits. | `id` (OSV vulnerability ID) | `readOnlyHint: true`, `idempotentHint: true`, `openWorldHint: false` | `vulnerability_not_found` (NotFound) |
| `osv_list_ecosystems` | Return the list of supported ecosystem strings. Use before querying to validate the `ecosystem` parameter — ecosystem strings are case-sensitive exact matches. | none | `readOnlyHint: true`, `idempotentHint: true`, `openWorldHint: false` | — |

### Resources

None. All data is available through the tool surface; resources add no coverage the tools don't already provide, and this server's primary audience (automated DevSecOps agents) is tool-only.

### Prompts

None. Data-oriented server with no recurring message templates warranted.

---

## Overview

osv-advisory-mcp-server wraps the Google OSV.dev REST API v1. It maps package-version tuples to known vulnerabilities across 20+ ecosystems — npm, PyPI, crates.io, Go, Maven, NuGet, Packagist, RubyGems, Debian, Alpine, and more. Where NVD maps vulnerabilities to CPEs (product-level), OSV maps them directly to package-version ranges, eliminating the CPE matching problem for dependency audit workflows.

Primary audience: developers, DevSecOps engineers, and SREs maintaining dependencies. The server is the "fast, direct answer" layer for lockfile scanning; it composes with `nist-nvd-mcp-server` by surfacing `aliases` (CVE IDs) that chain into NVD for CVSS scoring, EPSS, and CISA KEV status.

---

## Requirements

- Read-only. No authentication. No API key required.
- No published rate limit — API key not supported. Be respectful; `osv_query_batch` exists precisely to reduce call volume.
- All endpoints respond with JSON. Error shape: `{ code: number, message: string }` (Google APIs error model).
- `POST /v1/query` — single package+version lookup. Returns `{ vulns: [...] }` or `{}` (empty object, not `{ vulns: [] }`) when nothing found.
- `POST /v1/querybatch` — batch lookup. Returns `{ results: [...] }` where each entry corresponds positionally to the input query. Empty entries are `{}` (no `vulns` key), not `{ vulns: [] }`.
- `GET /v1/vulns/{id}` — full vuln record. Returns 404 with `{ code: 5, message: "Bug not found." }` for unknown IDs.
- `/v1/vulns POST` (list-by-ecosystem) — **NOT a real endpoint.** Returns `{ code: 404, message: "The current request is not defined by this API." }`. Confirmed by live probe. `osv_list_ecosystems` returns a static list.
- Ecosystem strings are case-sensitive exact matches: `npm`, `PyPI`, `crates.io`, `Go`, `Maven`, `NuGet`, `Packagist`, `Pub`, `RubyGems`, `Hex`, `Debian`, `Alpine`, `Ubuntu`, `Azure Linux`, `Linux`, `OSS-Fuzz`, `GIT`, `GitHub Actions`, `Bitnami`, `Android`, `Rocky Linux`, `AlmaLinux`, `Chainguard`, `Wolfi`, `CRAN`, `Hackage`, `SwiftURL`, and others. The canonical set is the `$defs.ecosystemName` enum (49 names) plus `GIT` in the OSV schema `validation/schema.json`; `GSD` is a vulnerability-ID prefix, not an ecosystem.
- Invalid ecosystem returns HTTP 400 with body `{ "code": 3, "message": "Invalid ecosystem." }`. This is a real 4xx — live-confirmed. For `POST /v1/querybatch`, a single invalid ecosystem in any entry causes the ENTIRE batch to return HTTP 400 (no partial success). Pre-validate ecosystems client-side before submitting a batch.
- Severity encoding: `severity` field on a vuln record is an array of `{ type: "CVSS_V3" | "CVSS_V4" | "CVSS_V2", score: "<vector string>" }`. `database_specific.severity` contains the human label (`"MODERATE"`, `"HIGH"`, etc.) for GHSA records; absent for non-GHSA records.
- Affected ranges: `affected[].ranges[].type` is `"SEMVER"`, `"ECOSYSTEM"`, or `"GIT"`. Events are `{ introduced: "..." }` and `{ fixed: "..." }` or `{ last_affected: "..." }`. `fixed` is the first safe version; `last_affected` means no fixed version exists yet.
- `aliases` field: array of strings on the vuln record — typically CVE IDs (e.g., `["CVE-2020-28500"]`). Some vulns have multiple aliases or none.
- `querybatch` returns abbreviated records in the results array (`{ id, modified }` per vuln) — not full records. `osv_get_vulnerability` is required for full detail on a specific finding.

---

## Services

| Service | Wraps | Used By |
|:--------|:------|:--------|
| `OsvApiService` | OSV.dev REST API v1 (`/v1/query`, `/v1/querybatch`, `/v1/vulns/{id}`) | `osv_query_package`, `osv_query_batch`, `osv_get_vulnerability` |

Single service, single API. No shared auth state; every call is anonymous HTTP. The service handles fetch + parse + retry. No rate-limit queuing required (no published limit), but exponential backoff on 5xx.

---

## Config

No server-specific env vars required. OSV.dev is keyless and fully public.

Framework env vars (`MCP_TRANSPORT_TYPE`, `MCP_HTTP_PORT`, `STORAGE_PROVIDER_TYPE`, etc.) apply as normal. No `server-config.ts` needed.

| Env Var | Required | Description |
|:--------|:---------|:------------|
| `OSV_REQUEST_TIMEOUT_MS` | No | HTTP request timeout in milliseconds. Default: 10000. |

---

## Implementation Order

1. Service setup: `OsvApiService` with `fetchWithTimeout`, retry on 5xx, error body parsing
2. `osv_list_ecosystems` — static list, no API call; validates inputs for other tools
3. `osv_query_package` — single package+version query, normalized output
4. `osv_get_vulnerability` — full record fetch by OSV ID
5. `osv_query_batch` — batch query with partial-success output

Each step is independently testable. Steps 3 and 4 can be developed in parallel after the service is up.

---

## Domain Mapping

| Noun | Operations | API Endpoint |
|:-----|:-----------|:-------------|
| Vulnerability | query-by-package-version, query-by-commit, get-by-id | `POST /v1/query`, `GET /v1/vulns/{id}` |
| Batch lookup | query-multiple-packages | `POST /v1/querybatch` |
| Ecosystem | list (static) | — (hardcoded from OSV schema spec) |

---

## Design Decisions

### querybatch returns abbreviated records — full detail requires a follow-up call

The `POST /v1/querybatch` response contains abbreviated vuln entries (`{ id, modified }`) for each found vulnerability, not full records. This is intentional API design: the batch endpoint is for "does any vuln exist for this package?" triage, not "give me the full advisory text for every vuln in my dependency tree."

`osv_query_batch` output therefore surfaces: `vulnCount`, abbreviated `vulnIds`, and critically, `aliases` extracted from the full `osv_query_package` response (since querybatch only gives IDs, the `aliases` field is NOT available in batch results). This is a key design tension:

**Resolution:** `osv_query_batch` calls `POST /v1/querybatch` for the ID list, then for packages with ≤ N vulns (configurable, default: packages with any findings), it fetches full records via individual `GET /v1/vulns/{id}` calls (or `POST /v1/query` per-package) to surface `aliases`. For large batches where this would be too many follow-up calls, the tool surfaces `vulnIds` only and notes that `osv_get_vulnerability` should be called for CVE aliases on specific findings.

**Simpler path:** For the first implementation, `osv_query_batch` calls `POST /v1/query` per package (not `querybatch`) in parallel with `Promise.allSettled`. This gives full records including `aliases` in one pass, avoids the ID-only limitation, and lets us use proper partial-success semantics. The upstream `querybatch` endpoint adds complexity without benefit when we need full data.

### osv_list_ecosystems is static, not an API call

The `/v1/vulns POST` endpoint (list by ecosystem) does not exist — live probe confirmed HTTP 200 with error body `{ code: 404, message: "The current request is not defined by this API." }`. Ecosystem enumeration is not available via the REST API. The list is maintained in the OSV schema spec and changes slowly; a static hardcoded list with a last-updated note is correct here. The tool warns that the list may drift and links to the OSV schema spec for canonical reference.

### Handlers throw via ctx.fail, not service factories

Per the requirements: tool handlers declare `errors: [...]` and throw via `ctx.fail('reason', ...)` for domain failures. Service-layer code uses `throw serviceUnavailable(...)` or `throw notFound(...)` for infrastructure/HTTP failures (these auto-classify and don't need contract entries). Contract errors (`invalid_ecosystem`, `vulnerability_not_found`) are thrown in the handler after service response, not in the service.

### Severity normalization

OSV severity is an array of CVSS vector strings (`severity[].score`), not pre-computed labels. `database_specific.severity` carries a human label (`"HIGH"`, `"MODERATE"`, etc.) but only for GHSA-sourced records. The output exposes both: the raw `severity` array (CVSS vectors for agent chaining to NVD) and a derived `severityLabel` computed from `database_specific.severity` when present, otherwise derived by parsing the CVSS base score from the vector string. Never fabricate a severity label when neither source is available — surface `null`.

### aliases field is the NVD bridge

Every vuln output prominently surfaces `aliases` as a first-class field alongside the OSV ID. This is the primary composition point: an agent calls `osv_query_package` or `osv_query_batch`, gets `aliases: ["CVE-2020-28500"]`, and chains to `nvd_get_cve` on `nist-nvd-mcp-server` for CVSS scoring, EPSS, and CISA KEV status. The `format()` function renders aliases in bold at the top of each vuln entry so `content[]`-only clients see them without having to scan the full record.

---

## API Reference (Confirmed via Live Probing — 2026-05-30)

### Response Envelopes

**`POST /v1/query` — success:**
```json
{
  "vulns": [
    {
      "id": "GHSA-29mw-wpgm-hmr9",
      "summary": "...",
      "details": "...",
      "aliases": ["CVE-2020-28500"],
      "modified": "2025-09-29T21:12:31.102523Z",
      "published": "2022-01-06T20:30:46Z",
      "database_specific": {
        "cwe_ids": ["CWE-1333", "CWE-400"],
        "severity": "MODERATE",
        "github_reviewed": true,
        "nvd_published_at": "...",
        "github_reviewed_at": "..."
      },
      "references": [{"type": "ADVISORY", "url": "..."}],
      "affected": [
        {
          "package": {"name": "lodash", "ecosystem": "npm", "purl": "..."},
          "ranges": [
            {
              "type": "SEMVER",
              "events": [{"introduced": "4.0.0"}, {"fixed": "4.17.21"}]
            }
          ],
          "database_specific": {"source": "..."}
        }
      ],
      "schema_version": "1.7.3",
      "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L"}]
    }
  ]
}
```

**`POST /v1/query` — no results:** `{}` (empty object, NOT `{ "vulns": [] }`)

**`POST /v1/querybatch` — success:**
```json
{
  "results": [
    { "vulns": [{"id": "GHSA-29mw-wpgm-hmr9", "modified": "..."}, ...] },
    {}
  ]
}
```
Each `results[i]` corresponds positionally to `queries[i]`. Empty entry is `{}` (no `vulns` key).

**`GET /v1/vulns/{id}` — success:** Full vuln record (same shape as single entry in `/v1/query` response).

**`GET /v1/vulns/{id}` — not found:** HTTP 404, `{ "code": 5, "message": "Bug not found." }`

**`POST /v1/query` — invalid ecosystem:** HTTP 400, `{ "code": 3, "message": "Invalid ecosystem." }` (live-confirmed — real 4xx, not HTTP 200). For `POST /v1/querybatch`, a single invalid ecosystem entry causes the entire batch to fail HTTP 400 — no per-entry partial success. Pre-validate all ecosystem strings before calling querybatch.

### Severity Encoding

`severity` is an array; each entry has `type` and `score`:
- `type`: `"CVSS_V3"`, `"CVSS_V4"`, `"CVSS_V2"`
- `score`: full CVSS vector string (e.g., `"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L"`)
- `database_specific.severity`: human label (`"LOW"`, `"MODERATE"`, `"HIGH"`, `"CRITICAL"`) — present on GHSA records only

### Affected Ranges

`affected[].ranges[].type`: `"SEMVER"` | `"ECOSYSTEM"` | `"GIT"`

Events:
- `{ "introduced": "X.Y.Z" }` — first affected version
- `{ "fixed": "X.Y.Z" }` — first safe version (not affected)
- `{ "last_affected": "X.Y.Z" }` — last affected version (no fix exists)
- `{ "introduced": "0" }` — affected from the beginning

---

## Tool Detail

### `osv_query_package`

**Description:** Query known vulnerabilities for a single package version across any supported ecosystem. Returns all matching OSV advisories with severity (CVSS vectors), CVE aliases, affected version ranges, and first safe version. Use `osv_list_ecosystems` to validate the ecosystem string before querying — ecosystem strings are case-sensitive exact matches and an invalid value returns an error, not empty results.

**Input:**
```ts
z.object({
  name: z.string().describe('Package name as it appears in the ecosystem (e.g. "express", "requests", "serde"). Case-sensitive.'),
  ecosystem: z.string().describe('Ecosystem identifier. Must be an exact match (case-sensitive). Use osv_list_ecosystems to see valid values. Examples: "npm", "PyPI", "crates.io", "Go", "Maven", "NuGet".'),
  version: z.string().describe('Package version to check (e.g. "4.17.1", "3.1.4", "1.0.0"). Must be an exact version string, not a range.'),
})
```

**Output:**
```ts
z.object({
  vulns: z.array(z.object({
    id: z.string().describe('OSV vulnerability ID (e.g. "GHSA-29mw-wpgm-hmr9", "PYSEC-2024-1"). Use with osv_get_vulnerability for full details.'),
    summary: z.string().describe('One-line vulnerability description.'),
    aliases: z.array(z.string()).describe('Alternative IDs — typically CVE IDs (e.g. ["CVE-2020-28500"]). Use these to query nist-nvd-mcp-server for CVSS scores, EPSS, and CISA KEV status.'),
    severity: z.array(z.object({
      type: z.string().describe('CVSS version: "CVSS_V3", "CVSS_V4", or "CVSS_V2".'),
      score: z.string().describe('CVSS vector string (e.g. "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L").'),
    })).describe('CVSS severity entries. May be empty for advisories not yet scored.'),
    severityLabel: z.string().nullable().describe('Human-readable severity label ("LOW", "MODERATE", "HIGH", "CRITICAL"). Derived from database_specific.severity when present, otherwise from the highest CVSS base score. Null when neither source is available.'),
    fixedVersions: z.array(z.string()).describe('First safe version(s) per affected package entry. Empty if no fix exists yet.'),
    affectedRanges: z.array(z.object({
      packageName: z.string().describe('Affected package name (may differ from queried name for umbrella advisories).'),
      ecosystem: z.string().describe('Affected package ecosystem.'),
      rangeType: z.string().describe('"SEMVER", "ECOSYSTEM", or "GIT".'),
      introduced: z.string().optional().describe('First affected version.'),
      fixed: z.string().optional().describe('First safe version — the version to upgrade to.'),
      lastAffected: z.string().optional().describe('Last affected version. Present when no fix exists.'),
    })).describe('Version ranges affected by this vulnerability.'),
    cweIds: z.array(z.string()).describe('CWE weakness IDs (e.g. ["CWE-79", "CWE-94"]). From database_specific.cwe_ids on GHSA records; empty otherwise.'),
    published: z.string().describe('ISO 8601 timestamp when the advisory was published.'),
    modified: z.string().describe('ISO 8601 timestamp of last modification.'),
  })).describe('Vulnerabilities matching this package version. Empty array means no known vulnerabilities.'),
  queryMeta: z.object({
    package: z.string().describe('Queried package name.'),
    ecosystem: z.string().describe('Queried ecosystem.'),
    version: z.string().describe('Queried version.'),
    vulnCount: z.number().describe('Number of vulnerabilities found.'),
  }).describe('Echo of query parameters for verification.'),
})
```

**Errors:**
```ts
errors: [
  {
    reason: 'invalid_ecosystem',
    code: JsonRpcErrorCode.InvalidParams,
    when: 'Ecosystem string is not recognized by OSV (API returns code 3). Ecosystem names are case-sensitive exact matches.',
    recovery: 'Call osv_list_ecosystems to see valid ecosystem strings, then retry with the correct value.',
  },
]
```

**Annotations:** `readOnlyHint: true`, `idempotentHint: true`, `openWorldHint: false`

---

### `osv_query_batch`

**Description:** Query vulnerabilities for multiple packages in one call — the primary tool for dependency audits, SBOM scanning, and lockfile triage. Pass an array of `{name, ecosystem, version}` tuples (up to 1000). Each entry in the response corresponds positionally to the input. For 200 or more packages, results spill to a DataCanvas table (returned as `canvas_id`) for SQL aggregation across the full set. Always surfaces `aliases` (CVE IDs) per finding so results can be chained to `nist-nvd-mcp-server` for CVSS scoring.

**Input:**
```ts
z.object({
  packages: z.array(z.object({
    name: z.string().describe('Package name as it appears in the ecosystem.'),
    ecosystem: z.string().describe('Ecosystem identifier. Case-sensitive exact match. Use osv_list_ecosystems to validate.'),
    version: z.string().describe('Exact version string to check.'),
  })).min(1).max(1000).describe('Packages to audit. One entry per dependency. Positional: result[i] corresponds to packages[i].'),
  canvas_id: z.string().optional().describe('Reuse an existing DataCanvas table token to append results. Omit to create a new canvas.'),
})
```

**Output:**
```ts
z.object({
  results: z.array(z.object({
    name: z.string().describe('Package name from input.'),
    ecosystem: z.string().describe('Ecosystem from input.'),
    version: z.string().describe('Version from input.'),
    vulnerable: z.boolean().describe('True if any vulnerabilities were found.'),
    error: z.string().nullable().describe('Per-package error message (e.g. invalid ecosystem). Null on success.'),
    vulnCount: z.number().describe('Number of vulnerabilities found. 0 when not vulnerable or on error.'),
    vulns: z.array(z.object({
      id: z.string().describe('OSV vulnerability ID.'),
      summary: z.string().describe('One-line advisory description.'),
      aliases: z.array(z.string()).describe('CVE IDs and other aliases. Chain to nist-nvd-mcp-server via these IDs for CVSS/KEV/EPSS context.'),
      severityLabel: z.string().nullable().describe('Severity label: "LOW", "MODERATE", "HIGH", "CRITICAL", or null.'),
      fixedVersions: z.array(z.string()).describe('First safe version(s) to upgrade to. Empty if no fix exists.'),
    })).describe('Vulnerabilities found. Empty array when clean.'),
  })).describe('Per-package results, positionally matching the input array.'),
  summary: z.object({
    totalPackages: z.number().describe('Total packages queried.'),
    vulnerableCount: z.number().describe('Packages with at least one vulnerability.'),
    cleanCount: z.number().describe('Packages with no vulnerabilities.'),
    errorCount: z.number().describe('Packages that returned an error (e.g. invalid ecosystem).'),
    totalVulns: z.number().describe('Total vulnerability instances across all packages (may double-count shared advisories).'),
    worstSeverity: z.string().nullable().describe('Highest severity label seen across all findings, or null if no severity data available.'),
  }).describe('Aggregate statistics across the full batch.'),
  canvas_id: z.string().optional().describe('DataCanvas table token. Present when the package count is >= 200 or a canvas_id was provided. Use to run SQL queries across the full result set via the canvas tools.'),
})
```

**Errors:**
```ts
errors: [
  {
    reason: 'batch_too_large',
    code: JsonRpcErrorCode.InvalidParams,
    when: 'packages array exceeds 1000 entries.',
    recovery: 'Split the package list into chunks of 1000 or fewer and call osv_query_batch multiple times.',
  },
]
```

Ecosystem validation is pre-flight: any invalid ecosystem in the `packages` array throws `invalid_ecosystem` at the tool level (before calling the API) rather than surfacing as a per-entry `results[i].error`. This is required because `POST /v1/querybatch` returns HTTP 400 for the entire batch if any entry has an invalid ecosystem — there is no per-entry partial success for ecosystem errors. The `results[i].error` field is reserved for other per-package failure modes (e.g., package not found in the ecosystem), not ecosystem validation.

**Annotations:** `readOnlyHint: true`, `openWorldHint: false`

---

### `osv_get_vulnerability`

**Description:** Fetch the full advisory record for an OSV vulnerability ID. Returns the complete record: summary, full details text, CVE aliases, all affected packages and version ranges, fix versions, CVSS severity vectors, CWE weakness IDs, and references. Use when `osv_query_package` or `osv_query_batch` returns a vuln ID and you need the full advisory context — eligibility criteria, scope of affected packages, or remediation guidance.

**Input:**
```ts
z.object({
  id: z.string().describe('OSV vulnerability ID. Accepts any prefix: "GHSA-" (GitHub), "PYSEC-" (Python), "RUSTSEC-" (Rust), "GO-" (Go), "DSA-"/"DLA-" (Debian), "CVE-" (fallback direct lookups). Example: "GHSA-29mw-wpgm-hmr9".'),
})
```

**Output:**
```ts
z.object({
  id: z.string().describe('OSV vulnerability ID.'),
  summary: z.string().describe('One-line advisory description.'),
  details: z.string().describe('Full advisory text, typically in Markdown. May include proof-of-concept, reproduction steps, or remediation guidance.'),
  aliases: z.array(z.string()).describe('Alternative IDs — usually CVE IDs. Pass to nvd_get_cve on nist-nvd-mcp-server for CVSS base score, EPSS exploitation probability, and CISA KEV status.'),
  published: z.string().describe('ISO 8601 timestamp when published.'),
  modified: z.string().describe('ISO 8601 timestamp of last modification.'),
  severity: z.array(z.object({
    type: z.string().describe('CVSS version: "CVSS_V3", "CVSS_V4", or "CVSS_V2".'),
    score: z.string().describe('CVSS vector string.'),
  })).describe('CVSS severity entries. Empty for unscored advisories.'),
  severityLabel: z.string().nullable().describe('Human-readable severity label. Derived from database_specific.severity (GHSA) or the highest CVSS base score. Null when not available.'),
  affected: z.array(z.object({
    packageName: z.string().describe('Affected package name.'),
    ecosystem: z.string().describe('Affected package ecosystem.'),
    purl: z.string().optional().describe('Package URL (e.g. "pkg:npm/lodash").'),
    ranges: z.array(z.object({
      rangeType: z.string().describe('"SEMVER", "ECOSYSTEM", or "GIT".'),
      introduced: z.string().optional().describe('First affected version.'),
      fixed: z.string().optional().describe('First safe version.'),
      lastAffected: z.string().optional().describe('Last affected version when no fix exists.'),
    })).describe('Version ranges affected.'),
  })).describe('All affected packages and their version ranges. An advisory may span multiple packages or ecosystems.'),
  cweIds: z.array(z.string()).describe('CWE weakness classifications (e.g. ["CWE-79"]). Present on GitHub Advisory Database records; empty otherwise.'),
  references: z.array(z.object({
    type: z.string().describe('Reference type: "ADVISORY", "WEB", "PACKAGE", "REPORT", "FIX", "GIT", etc.'),
    url: z.string().describe('URL of the reference.'),
  })).describe('Advisory references — NVD links, patches, vendor advisories, PoC reports.'),
  schemaVersion: z.string().describe('OSV schema version this record conforms to (e.g. "1.7.3").'),
})
```

**Errors:**
```ts
errors: [
  {
    reason: 'vulnerability_not_found',
    code: JsonRpcErrorCode.NotFound,
    when: 'OSV returns HTTP 404 with code 5. The ID does not exist in the OSV database.',
    recovery: 'Verify the OSV ID from osv_query_package or osv_query_batch results. CVE IDs like "CVE-2020-28500" may be resolvable as an alias — check the nist-nvd-mcp-server instead.',
  },
]
```

**Annotations:** `readOnlyHint: true`, `idempotentHint: true`, `openWorldHint: false`

---

### `osv_list_ecosystems`

**Description:** Return the list of supported ecosystem identifier strings. Ecosystem strings are case-sensitive exact matches — passing `"pypi"` instead of `"PyPI"` returns an error from the API. Use this tool to discover valid ecosystem strings before querying, or to verify an ecosystem identifier from a lockfile format. The list is static (maintained from the OSV schema spec) and may occasionally lag newly added ecosystems.

**Input:** none (empty object)

**Output:**
```ts
z.object({
  ecosystems: z.array(z.string()).describe('Supported ecosystem identifier strings. Pass these values exactly (case-sensitive) in the ecosystem parameter of other tools.'),
  note: z.string().describe('Advisory note about list currency and canonical source.'),
})
```

**Errors:** None declared (static response, no upstream call).

**Annotations:** `readOnlyHint: true`, `idempotentHint: true`, `openWorldHint: false`

---

## Known Limitations

- **`aliases` field is absent in batch-only queries.** The `POST /v1/querybatch` endpoint returns only `{ id, modified }` per vuln — no `aliases`. `osv_query_batch` works around this by calling `POST /v1/query` per package in parallel (full records), sacrificing the batch endpoint's network efficiency for data completeness.
- **No ecosystem listing via API.** `POST /v1/vulns` with an ecosystem filter does not exist (live-confirmed: returns `{ code: 404, message: "The current request is not defined by this API." }`). `osv_list_ecosystems` returns a static hardcoded list that may drift from the live supported set.
- **Severity absent for some records.** Non-GHSA records (e.g., `PYSEC-`, `RUSTSEC-`) often lack `database_specific.severity` and may have no `severity` array. `severityLabel` will be null in those cases.
- **No CVSS base score direct field.** CVSS scores are in vector string form only (`"CVSS:3.1/AV:N/AC:L/..."`) — the service layer must parse the base score for severity derivation.
- **Pagination on `/v1/query`.** The single-package query supports `page_token` for packages with very large numbers of advisories. This is extremely rare in practice (no known real-world case) — the `osv_query_package` handler does not paginate and returns whatever the first page provides.
