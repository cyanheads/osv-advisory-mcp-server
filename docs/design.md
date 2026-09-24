# osv-advisory-mcp-server — Design

## MCP Surface

### Tools

| Name | Description | Key Inputs | Annotations | Errors |
|:-----|:------------|:-----------|:------------|:-------|
| `osv_query_package` | Query vulnerabilities for a single package version. Returns all known vulns: OSV IDs, CVE aliases, severity (CVSS string), affected ranges, fix versions, CWE IDs. The primary "is this package version vulnerable?" tool. | `name` (package name), `ecosystem` (exact string — use `osv_list_ecosystems` to validate), `version` | `readOnlyHint: true`, `idempotentHint: true`, `openWorldHint: false` | `invalid_ecosystem` (ValidationError) |
| `osv_query_batch` | Batch vulnerability query over an array of `{name, ecosystem, version}` tuples — one call covers a full dependency list. Per-package results with `vulnCount` and `vulns` (IDs, `aliases`, `severityLabel`, `fixedVersions`) for each. The differentiator for SBOM/lockfile audits. | `packages` (array of `{name, ecosystem, version}`, max 1000) | `readOnlyHint: true`, `idempotentHint: true`, `openWorldHint: false` | — (an invalid ecosystem or upstream failure sets that row's `error`) |
| `osv_get_vulnerability` | Fetch the full record for one exact OSV advisory ID (`GHSA-…`, `PYSEC-…`, `RUSTSEC-…`, `GO-…`, `DSA-…-1`, `USN-…-1`, `RHSA-…`, `CVE-…`). Returns: summary, details, aliases (CVE IDs), severity, affected packages/ranges, fix versions, CWE IDs, references. | `id` (one complete OSV advisory ID) | `readOnlyHint: true`, `idempotentHint: true`, `openWorldHint: false` | `vulnerability_not_found` (NotFound) |
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
- `GET /v1/vulns/{id}` — full vuln record. Returns 404 with `{ code: 5, message: "Vulnerability not found" }` for unknown IDs. IDs match exactly, including case; Debian, Ubuntu, and SUSE IDs carry a revision suffix (`DSA-5678` is 404, `DSA-5678-1` resolves). There is no list or prefix lookup (`GET /v1/vulns/*` is 404).
- `/v1/vulns POST` (list-by-ecosystem) — **NOT a real endpoint.** Returns `{ code: 404, message: "The current request is not defined by this API." }`. Confirmed by live probe. `osv_list_ecosystems` returns a static list.
- Ecosystem strings are case-sensitive exact matches: `npm`, `PyPI`, `crates.io`, `Go`, `Maven`, `NuGet`, `Packagist`, `Pub`, `RubyGems`, `Hex`, `Debian`, `Alpine`, `Ubuntu`, `Azure Linux`, `Linux`, `OSS-Fuzz`, `GIT`, `GitHub Actions`, `Bitnami`, `Android`, `Rocky Linux`, `AlmaLinux`, `Chainguard`, `Wolfi`, `CRAN`, `Hackage`, `SwiftURL`, and others. The supported set is every member of the `$defs.ecosystemName` enum in the OSV schema `validation/schema.json` that `POST /v1/query` accepts, plus `GIT` — 51 of the 52 enum names as of 2026-09-24, with `Red Hat Lightwell` listed in the schema but rejected. `GSD` is a vulnerability-ID prefix, not an ecosystem.
- Invalid ecosystem returns HTTP 400 with body `{ "code": 3, "message": "invalid ecosystem" }`. This is a real 4xx — live-confirmed. `POST /v1/querybatch` fails the ENTIRE batch with HTTP 400 when any entry has an invalid ecosystem, which is one reason `osv_query_batch` sends one `POST /v1/query` per package instead: a bad ecosystem fails only that row.
- Severity encoding: `severity` field on a vuln record is an array of `{ type: "CVSS_V2" | "CVSS_V3" | "CVSS_V4" | "Ubuntu", score }` — a vector string, or a lowercase Ubuntu priority. When packages carry differing severities it moves to `affected[].severity`, and the record-level array is then absent. `database_specific.severity` holds a human label on some databases (GHSA `MODERATE`, openEuler `Medium`, curl `High`, Bitnami `Critical`).
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
| Ecosystem | list (static) | — (schema ecosystems OSV.dev accepts, plus `GIT`) |

---

## Design Decisions

### querybatch returns abbreviated records — full detail requires a follow-up call

The `POST /v1/querybatch` response contains abbreviated vuln entries (`{ id, modified }`) for each found vulnerability, not full records. This is intentional API design: the batch endpoint is for "does any vuln exist for this package?" triage, not "give me the full advisory text for every vuln in my dependency tree."

`osv_query_batch` output therefore surfaces: `vulnCount`, abbreviated `vulnIds`, and critically, `aliases` extracted from the full `osv_query_package` response (since querybatch only gives IDs, the `aliases` field is NOT available in batch results). This is a key design tension:

**Resolution:** `osv_query_batch` calls `POST /v1/querybatch` for the ID list, then for packages with ≤ N vulns (configurable, default: packages with any findings), it fetches full records via individual `GET /v1/vulns/{id}` calls (or `POST /v1/query` per-package) to surface `aliases`. For large batches where this would be too many follow-up calls, the tool surfaces `vulnIds` only and notes that `osv_get_vulnerability` should be called for CVE aliases on specific findings.

**Simpler path:** For the first implementation, `osv_query_batch` calls `POST /v1/query` per package (not `querybatch`) in parallel with `Promise.allSettled`. This gives full records including `aliases` in one pass, avoids the ID-only limitation, and lets us use proper partial-success semantics. The upstream `querybatch` endpoint adds complexity without benefit when we need full data.

### osv_list_ecosystems is static, not an API call

The `/v1/vulns POST` endpoint (list by ecosystem) does not exist — a live probe returns HTTP 404 `{ code: 404, message: "The current request is not defined by this API." }`. Ecosystem enumeration is not available via the REST API. The catalog is every `$defs.ecosystemName` member in the OSV schema that `POST /v1/query` accepts, plus `GIT`; it changes slowly, so a static list with one verification date (header comment, handler `note`, and tool `description`) is correct here. The tool warns that the list may drift and links to the OSV schema spec for canonical reference.

- **Acceptance, not schema membership** — the schema has listed ecosystems OSV.dev still rejects (`WordPress` for a while after it entered the schema; `Red Hat Lightwell` as of 2026-09-24), so copying the enum would advertise values that fail. A rejected member is withheld until it is accepted.
- **Drift check is a standalone script, not a devcheck step** — `bun run check:ecosystems` (`scripts/check-ecosystems.ts`) probes every enum member, `GIT`, and every catalog entry and prints add / withhold / remove lists, exiting non-zero on add or remove and on any failed request. `scripts/devcheck.ts` is a framework copy the maintenance sync overwrites, and an upstream-dependent verdict would fail every local gate the day OSV.dev changes. The pinning test in `tests/tools/osv-list-ecosystems.tool.test.ts` stays as the offline guard.

### Handlers throw via ctx.fail, not service factories

Per the requirements: tool handlers declare `errors: [...]` and throw via `ctx.fail('reason', ...)` for domain failures. Service-layer code uses `throw serviceUnavailable(...)` or `throw notFound(...)` for infrastructure/HTTP failures (these auto-classify and don't need contract entries). Contract errors (`invalid_ecosystem`, `vulnerability_not_found`) are thrown in the handler after service response, not in the service.

### Severity normalization

OSV severity is an array of `{ type, score }` entries — CVSS vectors and Ubuntu priorities — not pre-computed labels; some databases add a human label in `database_specific.severity`. The output keeps the raw `severity` array (vectors for chaining to NVD) and derives `severityLabel` (`services/osv-api/severity.ts`) from the first source that yields one:

1. `database_specific.severity` of low, moderate, medium, high, or critical, in any case (`Medium` → `MODERATE`).
2. An `Ubuntu` entry: negligible or low → `LOW`, medium → `MODERATE`, high → `HIGH`, critical → `CRITICAL`; other priorities (`untriaged`) are skipped.
3. The highest score among parseable `CVSS_V3`/`CVSS_V4` vectors, banded 0.1–3.9 `LOW`, 4.0–6.9 `MODERATE`, 7.0–8.9 `HIGH`, 9.0–10.0 `CRITICAL`. A 0.0 score has no band.
4. Otherwise `null` — never fabricated.

Entries come from the record-level `severity[]`, or when it is empty, from `affected[].severity`: the entries matching the queried package (the `fixedVersions` matcher) in `osv_query_package` and `osv_query_batch`, every entry in `osv_get_vulnerability`. `severitySource` (`{ type, score, computedScore? }`, `null` without a label) on package vulns and full records names the entry used; `osv_get_vulnerability` also returns each affected package's own `severity`. Batch rows carry the label only, and `summary.worstSeverity` ranks those labels.

- **Scored as published, not base-only** — `computedScore` includes the temporal (CVSS 3.x) or threat and environmental (CVSS 4.0) metrics a vector carries, matching the score its publisher states: `CVE-2026-34743`'s `…/E:U` vector scores 1.7 (`LOW`), the CNA's figure; stripping `E:U` would give 6.3. CVSS 3.x environmental metrics are not applied.
- **A provider label outranks a higher CVSS score** — `UBUNTU-CVE-2025-31115` is `MODERATE` (Ubuntu `medium`) although its CVSS 4.0 vector scores 8.7; `severitySource` makes the basis visible.
- **`CVSS_V2` sets no label** — no live record relies on it alone, and its scale has no CRITICAL band.
- **`@turingpointde/cvss.js` scores the vectors** — CVSS 4.0 needs the specification's macro-vector tables, so a hand-rolled calculator was rejected; the library throws on a malformed vector, which is then skipped.

### fixedVersions are scoped to the queried package

`fixedVersions` (package and batch tools) lists every `fixed` event from the SEMVER/ECOSYSTEM ranges of the `affected[]` entries that match the queried package, deduplicated in record order. An entry matches the way OSV.dev indexes it for `/v1/query`: the queried ecosystem equals the entry's ecosystem, its base (text before the first `:`), or for Ubuntu the ecosystem without `:Pro`/`:LTS`; names are equal, PEP 503-normalized for `PyPI`/`Echo:PyPI` (`services/osv-api/affected-match.ts`). It is computed in `queryPackage()`, the only place holding the query, so batch rows inherit it; `osv_get_vulnerability` has no query and returns no `fixedVersions`.

- **Exact-string matching rejected** — `Ubuntu:22.04`, bare `Debian`, and non-normalized PyPI names (`Django`, `PyYAML`) match no entry exactly, which reads as "no fix".
- **No fallback to other entries** — falling back to advisory-wide fixes recommends another package's release (gzip's fix for an xz-utils query) — the defect this replaced.
- **Every interval's fix, not the one covering the version** — choosing needs per-ecosystem version ordering (dpkg, PEP 440, Maven). `affectedRanges` stays complete, GIT ranges included, so the interval is recoverable.

### Render-boundary escape for advisory text

OSV strings are upstream-controlled Markdown. `format()` passes every OSV-sourced string through `mcp-server/tools/render-escape.ts`; `structuredContent` stays verbatim. The inline escape (summaries, IDs, versions, URLs, timestamps, error text) turns line breaks into a space and `<` that could start raw HTML or an autolink (before an ASCII letter, `/`, `!`, `?`, or an email local part ending in `@`) into `&lt;`, backslash-escapes the `]` of an inline link or image whose destination is not an `http(s)://` URL, and backslash-escapes a leading reference-definition `[` or fence run. The block escape (`details`) applies the same rules line by line, keeps column-0 fenced code literal except for the frame tags, closes a fence the text leaves open, and stops exempting fences after one opens indented 1–3 spaces.

- **Not the framework's `escapeHtml`** — it re-escapes `&` and quotes, which changes rendered prose (`&lt;script&gt;` would show as entity text).
- **Code spans and indented code are not exempt** — telling them apart safely needs a full CommonMark parse (a code span can end at a list-item boundary), so they take the text rule and show `&lt;` in a rendered view.
- **Indented fences end the exemption** — a fence opened with 1–3 spaces may sit in a list item that CommonMark closes without a closing fence; a scanner tracking it would misread a later column-0 fence line as an opener and leave raw HTML unescaped. Code after such a fence renders `&lt;`.
- **Link destinations are allowlisted, not parsed** — `[x](javascript:…)`, its entity-encoded forms (`javascript&#58;`), `data:`, and a range or reference type ending `x](javascript:…)` (which would close the server's own `[SEMVER]` / `[ADVISORY]` label into a link) all lose their `](`; `http(s)://` links in details keep working. Decoding each destination the way a renderer does would need a CommonMark inline parse. The reference-definition check runs after this escape, because `[a](x]: javascript:…` turns into a definition once its `]` is escaped.
- **Out of scope** — emphasis bleeding into server lines and backticks breaking out of identifier code spans; neither hides text, forges the frame, or makes a link once `<` and link destinations are escaped. A fence opened indented 1–3 spaces and never closed still runs to the end of the response in a rendered view.

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

**`GET /v1/vulns/{id}` — not found:** HTTP 404, `{ "code": 5, "message": "Vulnerability not found" }`

**`POST /v1/query` — invalid ecosystem:** HTTP 400, `{ "code": 3, "message": "invalid ecosystem" }` (live-confirmed — real 4xx, not HTTP 200). For `POST /v1/querybatch`, a single invalid ecosystem entry fails the entire batch with HTTP 400 (`"error in query at index N: … invalid ecosystem"`) — no per-entry partial success. `osv_query_batch` does not call querybatch; see the Design Decisions.

### Severity Encoding

`severity` is an array; each entry has `type` and `score`:
- `type`: `"CVSS_V3"`, `"CVSS_V4"`, `"CVSS_V2"`, `"Ubuntu"`
- `score`: full CVSS vector string (e.g., `"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L"`), or for `Ubuntu` a lowercase priority (`negligible`, `low`, `medium`, `high`, `critical`, `untriaged`)
- `affected[].severity`: same shape, set per package instead of the record-level array when packages have differing severities (e.g. `HSEC-*`, `BIT-*`)
- `database_specific.severity`: human label on some databases, spelled per database — GHSA `LOW`/`MODERATE`/`HIGH`/`CRITICAL`, openEuler `Low`/`Medium`/`High`/`Critical`

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

**Description:** Query known vulnerabilities for a single package version across any supported ecosystem. Returns all matching OSV advisories with severity (CVSS vectors), CVE aliases, affected version ranges, and the fixed versions listed for the queried package. Use `osv_list_ecosystems` to validate the ecosystem string before querying — ecosystem strings are case-sensitive exact matches and an invalid value returns an error, not empty results.

**Input:**
```ts
z.object({
  name: z.string().describe('Package name as it appears in the ecosystem (e.g. "express", "requests", "serde"). Case-sensitive.'),
  ecosystem: z.string().describe('Ecosystem identifier. Must be an exact match (case-sensitive). Use osv_list_ecosystems to see valid values. Examples: "npm", "PyPI", "crates.io", "Go", "Maven", "NuGet".'),
  version: z.string().describe('Package version to check (e.g. "4.17.1", "3.1.4", "1.0.0"). Must be an exact version string, not a range.'),
})
```

Each field is `z.string().trim().regex(/\S/, '… must not be blank …')`, and the `osv_query_batch` row fields use the same chain.

- **Trim before the request** — OSV.dev does not trim, so `" lodash "` matched nothing and read as clean. No package name, ecosystem, or version carries surrounding whitespace, so trimming changes no valid query; interior whitespace (`Rocky Linux`) is kept. The handler, the request, `queryMeta`, the batch rows, and the enrichment echo all see the trimmed value.
- **One constraint shape, one message** — `.trim()` is a Zod overwrite, not a transform: `tools/list` still advertises a single `pattern: "\\S"` per field (no `minLength`, no `allOf`), and it runs before the blank check, so `""` and whitespace-only values fail `-32602` `invalid_arguments` with one message. A `.min(1)` + `.regex(/\S/)` pair would fire both checks on `""` and repeat the message.

**Output:**
```ts
z.object({
  vulns: z.array(z.object({
    id: z.string().describe('OSV vulnerability ID (e.g. "GHSA-29mw-wpgm-hmr9", "PYSEC-2024-1"). Use with osv_get_vulnerability for full details.'),
    summary: z.string().describe('One-line vulnerability description.'),
    aliases: z.array(z.string()).describe('Alternative IDs — typically CVE IDs (e.g. ["CVE-2020-28500"]). Use these to query nist-nvd-mcp-server for CVSS scores, EPSS, and CISA KEV status.'),
    severity: z.array(z.object({
      type: z.string().describe('Severity type: "CVSS_V3", "CVSS_V4", "CVSS_V2", or "Ubuntu".'),
      score: z.string().describe('CVSS vector string (e.g. "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L"), or the Ubuntu priority for type "Ubuntu".'),
    })).describe('Record-level severity entries. Empty for unscored advisories and for advisories that score each affected package separately.'),
    severityLabel: z.string().nullable().describe('Severity label ("LOW", "MODERATE", "HIGH", "CRITICAL") from the first source that yields one: database_specific.severity, an Ubuntu priority, then the highest CVSS v3/v4 score. Uses the queried package\'s affected-level entries when the record-level list is empty. Null when no source yields a label.'),
    severitySource: z.object({
      type: z.enum(['database_specific', 'Ubuntu', 'CVSS_V3', 'CVSS_V4']),
      score: z.string(),               // the published label, priority, or vector
      computedScore: z.number().optional(), // CVSS sources only — scored as published
    }).nullable().describe('The severity entry severityLabel was derived from. Null exactly when the label is.'),
    fixedVersions: z.array(z.string()).describe("Every fixed version the advisory lists for the queried package, in record order. A multi-interval range contributes one per interval (typically one per release line); affectedRanges shows which interval each one closes. Excludes other packages' fixes and GIT commits. Empty when the advisory lists no fix for this package."),
    affectedRanges: z.array(z.object({
      packageName: z.string().describe('Affected package name (may differ from queried name for umbrella advisories).'),
      ecosystem: z.string().describe('Affected package ecosystem.'),
      rangeType: z.string().describe('"SEMVER", "ECOSYSTEM", or "GIT".'),
      introduced: z.string().optional().describe('First affected version.'),
      fixed: z.string().optional().describe('The last "fixed" event of this range (convenience view — a multi-interval range carries several; see events[]).'),
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
    code: JsonRpcErrorCode.ValidationError,
    when: 'Ecosystem string is not recognized by OSV (API returns code 3). Ecosystem names are case-sensitive exact matches.',
    recovery: 'Call osv_list_ecosystems to see valid ecosystem strings, then retry with the correct value.',
  },
]
```

**Annotations:** `readOnlyHint: true`, `idempotentHint: true`, `openWorldHint: false`

---

### `osv_query_batch`

**Description:** Query vulnerabilities for multiple packages in one call — the primary tool for dependency audits, SBOM scanning, and lockfile triage. Pass an array of `{name, ecosystem, version}` tuples (up to 1000). Each entry in the response corresponds positionally to the input. Always surfaces `aliases` (CVE IDs) per finding so results can be chained to `nist-nvd-mcp-server` for CVSS scoring.

**Input:**
```ts
z.object({
  packages: z.array(z.object({
    name: z.string().describe('Package name as it appears in the ecosystem.'),
    ecosystem: z.string().describe('Ecosystem identifier. Case-sensitive exact match. Use osv_list_ecosystems to validate.'),
    version: z.string().describe('Exact version string to check.'),
  })).min(1).max(1000).describe('Packages to audit. One entry per dependency. Positional: result[i] corresponds to packages[i].'),
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
      severityLabel: z.string().nullable().describe('Severity label: "LOW", "MODERATE", "HIGH", "CRITICAL", or null. Same derivation as osv_query_package, scoped to this row\'s package.'),
      fixedVersions: z.array(z.string()).describe("Every fixed version the advisory lists for this row's package, in record order — one per affected interval, typically one per release line. Excludes other packages' fixes and GIT commits. Empty when the advisory lists no fix for this package."),
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
})
```

**Errors:** None declared. A `packages` array outside 1–1000 entries, or a blank field in any row, fails the input schema (`-32602` `invalid_arguments`) before any OSV call.

Ecosystems are not pre-validated: each row is its own `POST /v1/query`, so OSV.dev is the authority for every ecosystem string, and an invalid ecosystem (or any other upstream failure) fails only that row — `results[i].error` carries the message and `summary.errorCount` counts it. The rest of the batch completes.

**Annotations:** `readOnlyHint: true`, `idempotentHint: true`, `openWorldHint: false`

---

### `osv_get_vulnerability`

**Description:** Fetch the full advisory record for an OSV vulnerability ID. Returns the complete record: summary, full details text, CVE aliases, all affected packages and version ranges, fix versions, CVSS severity vectors, CWE weakness IDs, and references. Use when `osv_query_package` or `osv_query_batch` returns a vuln ID and you need the full advisory context — eligibility criteria, scope of affected packages, or remediation guidance.

**Input:**
```ts
z.object({
  id: z.string()
    .trim()
    .regex(/^[A-Za-z][A-Za-z0-9_]*-\S(.*\S)?$/, 'Vulnerability ID must be one complete OSV advisory ID — … Take IDs from osv_query_package or osv_query_batch results.')
    .describe('One exact, complete OSV advisory ID from any OSV source database, matched case-sensitively. Prefixes include "GHSA-", "PYSEC-", "RUSTSEC-", "GO-", "DSA-"/"DLA-", "USN-", "RHSA-", and "CVE-". No wildcards or partial IDs — take IDs from osv_query_package or osv_query_batch results. Example: "GHSA-29mw-wpgm-hmr9".'),
})
```

`.trim()` first strips surrounding whitespace, as on the query tools' package fields, so `" GHSA-29mw-wpgm-hmr9 "` resolves; it is a Zod overwrite and changes nothing in `tools/list`. The single `.regex()` then reaches `tools/list` as one `pattern` and rejects input that can never be an OSV ID — no `PREFIX-` head, or an empty tail — as `-32602` `invalid_arguments` before any upstream call; the Zod message is the recovery hint the caller receives. It accepts every one of the 1,968,324 distinct IDs in OSV.dev's `modified_id.csv` export (2026-09-24).

- **Underscore and digits in the prefix** — `BIT-apisix_dashboard-…`, `V8-FRESHNESS`, and the schema's `x_` custom prefixes.
- **Internal spaces allowed** — OSV.dev serves `SUSE-SU-403 Forbidden-1`; the tail only has to start and end with a non-space character.
- **No case normalization** — real IDs are mixed-case (`openSUSE-SU-…`, `BIT-gitlab-…`), and OSV.dev matches case-sensitively.
- **Well-formed but unknown IDs stay upstream** — `DSA-5678` (missing its `-1` revision), wrong-case IDs, and nonexistent IDs reach OSV.dev and return `vulnerability_not_found`, whose recovery names both mistakes.
- **Schema, not handler** — a handler check with its own contract reason would advertise nothing in `tools/list`, and `.refine()` emits no JSON Schema.

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
    type: z.string().describe('Severity type: "CVSS_V3", "CVSS_V4", "CVSS_V2", or "Ubuntu".'),
    score: z.string().describe('CVSS vector string, or the Ubuntu priority for type "Ubuntu".'),
  })).describe('Record-level severity entries. Empty for unscored advisories and for advisories that score each affected package separately.'),
  severityLabel: z.string().nullable().describe('Severity label from the first source that yields one: database_specific.severity, an Ubuntu priority, then the highest CVSS v3/v4 score. Uses every affected package severity entry when the record-level list is empty. Null when no source yields a label.'),
  severitySource: /* same shape as osv_query_package */,
  affected: z.array(z.object({
    packageName: z.string().describe('Affected package name.'),
    ecosystem: z.string().describe('Affected package ecosystem.'),
    purl: z.string().optional().describe('Package URL (e.g. "pkg:npm/lodash").'),
    severity: z.array(/* severity entry */).optional().describe('Severity entries scoped to this package. Present only when the advisory scores packages separately.'),
    ranges: z.array(z.object({
      rangeType: z.string().describe('"SEMVER", "ECOSYSTEM", or "GIT".'),
      introduced: z.string().optional().describe('First affected version.'),
      fixed: z.string().optional().describe('The last "fixed" event of this range (convenience view — see events[]).'),
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
    recovery: 'IDs match exactly, including case. Debian, Ubuntu, and SUSE advisories carry a revision suffix ("DSA-5678-1", "USN-6000-1", "SUSE-SU-2015:0011-2"), so add it if it was dropped. Otherwise take the ID from osv_query_package or osv_query_batch results; a CVE ID OSV does not hold may still resolve on nist-nvd-mcp-server.',
  },
]
```

**Annotations:** `readOnlyHint: true`, `idempotentHint: true`, `openWorldHint: false`

---

### `osv_list_ecosystems`

**Description:** Return the supported ecosystem identifier strings for `osv_query_package` and `osv_query_batch`: every ecosystem the OSV schema names that OSV.dev accepts at query time, plus `GIT`, as verified on a stated date. Ecosystem strings are case-sensitive exact matches — passing `"pypi"` instead of `"PyPI"` returns an error from the API. Use this tool to discover valid ecosystem strings before querying, or to verify an ecosystem identifier from a lockfile format. The list is static and may lag ecosystems added after that date.

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
- **No ecosystem listing via API.** `POST /v1/vulns` with an ecosystem filter does not exist (live-confirmed: returns `{ code: 404, message: "The current request is not defined by this API." }`). `osv_list_ecosystems` returns a static list that may drift from the live supported set; `bun run check:ecosystems` reports the drift.
- **Severity absent for some records.** Some records (e.g. `PYSEC-2022-190`, many `USN-` notices) carry neither `database_specific.severity` nor any severity entry; `severityLabel` and `severitySource` are null for them. A record whose only entries are `CVSS_V2`, malformed vectors, or unrecognized Ubuntu priorities is null too.
- **No CVSS score field.** OSV carries CVSS as vector strings only (`"CVSS:3.1/AV:N/AC:L/..."`); the service scores them with `@turingpointde/cvss.js` and reports the result as `severitySource.computedScore`.
- **Debian urgency and other `ecosystem_specific` severities are not read.** Only `database_specific.severity`, `Ubuntu` entries, and CVSS v3/v4 vectors produce a label.
- **Pagination on `/v1/query`.** OSV paginates above 1,000 results or when query processing runs long, sometimes returning a bare `next_page_token` with no vulns. `osv_query_package` (and each batch row) follows tokens up to `OSV_QUERY_MAX_PAGES` and reports `truncated: true` when a token remains — never a clean result.
- **`fixedVersions` lists every interval's fix.** A multi-interval advisory (Django `PYSEC-2022-190`: `4.0.4, 3.2.13, 2.2.28`) lists one fix per release line; picking the one that covers the queried version needs per-ecosystem version ordering. `affectedRanges[].events` carries the intervals.
