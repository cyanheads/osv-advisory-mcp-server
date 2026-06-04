# osv-advisory-mcp-server — Idea & Requirements

Package-ecosystem vulnerability lookups via Google's OSV.dev — "is `express@4.17.1` vulnerable?" answered directly, across 20+ ecosystems, no CPE matching required.

| | |
|---|---|
| **Status** | Pre-build design · scaffolded on `@cyanheads/mcp-ts-core@0.9.16` |
| **Category** | security |
| **Auth** | none |
| **API cost** | free — no key, no published rate limit (be respectful) |
| **Pattern** | single-source |
| **Complexity** | low–medium |
| **Composes with** | `nist-nvd-mcp-server` |

## Overview

Package-ecosystem vulnerability database via Google's [OSV.dev](https://osv.dev). Where NVD maps vulnerabilities to CPEs (product-level), OSV maps them to package-version tuples across 20+ ecosystems — npm, PyPI, crates.io, Go, Maven, NuGet, Debian, Alpine, the Linux kernel, and more. A developer asks "is `express@4.17.1` vulnerable?" and gets a direct answer.

It serves **developer / DevSecOps workflows** — dependency audit, lockfile scanning, upgrade decisions — complementing `nist-nvd-mcp-server`'s analyst workflows (CVE research, CVSS scoring). Every OSV record carries `aliases` (usually CVE IDs), so a finding here chains cleanly into NVD for CVSS / EPSS / KEV context.

## Audience

Developers, DevSecOps, SRE — anyone maintaining dependencies. Broad: every project with a lockfile is a potential query.

## User Goals

- Check whether a specific package version has known vulnerabilities
- Scan a set of dependencies (SBOM / lockfile equivalent) for vulns in one batch call
- Get details on an OSV vulnerability ID (`GHSA-`, `PYSEC-`, `RUSTSEC-`, …)
- Browse vulnerabilities by ecosystem to understand exposure surface
- Chain with NVD: OSV finding → CVE alias → NVD for CVSS / EPSS / KEV context

## API Surface

OSV.dev REST API v1. No authentication. JSON throughout.

| Endpoint | Purpose |
|:---|:---|
| `POST /v1/query` | Query vulns by package + version, or by commit hash |
| `POST /v1/querybatch` | Batch query — multiple packages in one call |
| `GET /v1/vulns/{id}` | Fetch full vulnerability record by OSV ID |
| `POST /v1/vulns` | Query-by-filter (ecosystem, etc.) |

`query` accepts either `{ package: { name, ecosystem }, version }` for version lookups or `{ commit }` for commit-hash lookups. `querybatch` takes an array of these.

## Tool Surface (planned)

| Tool | Behavior |
|:---|:---|
| `osv_query_package` | **Primary.** Package name + ecosystem + version → all known vulns for that version: severity, affected ranges, aliases (CVE IDs), fix versions. The "is this vulnerable?" tool. |
| `osv_query_batch` | Batch `osv_query_package` over an array of `{package, ecosystem, version}` tuples — one call covers a whole dependency tree. Per-package results. High value for SBOM / lockfile audits. |
| `osv_get_vulnerability` | Full record for an OSV ID (`GHSA-…`, `PYSEC-…`, `RUSTSEC-…`): affected packages/versions, severity, references, credits, database-specific fields, CVE aliases. |
| `osv_list_ecosystems` | Enumerate supported ecosystems — discovery + validating ecosystem strings before querying. |

## Design Notes & Requirements

- **`osv_query_batch` is the differentiator** — bulk dependency auditing. Route large batch results (200+ deps) to DataCanvas for SQL/aggregation.
- **Surface `aliases` prominently** — they're the bridge to NVD (CVSS, EPSS, KEV). Composition: OSV finds the vuln, NVD scores it.
- **Ecosystem strings are exact** — `npm`, `PyPI`, `crates.io`, `Go`, `Maven`, `NuGet`, `Packagist`, `Pub`, `RubyGems`, `Hex`, `Debian`, `Alpine`, `Linux`, … `osv_list_ecosystems` prevents bad queries.
- **OSV IDs use ecosystem-specific prefixes** — `GHSA-` (GitHub), `PYSEC-` (Python), `RUSTSEC-` (Rust), `GO-` (Go), `DSA-`/`DLA-` (Debian), `CVE-` (fallback). `osv_get_vulnerability` accepts any.
- **No auth, no published rate limit** — but be respectful; the batch endpoint exists to reduce call volume.
- Low complexity: clean REST, documented schema, no pagination for query endpoints (vulns per package are bounded), no auth flow.

## Build Constraints

- Framework: `@cyanheads/mcp-ts-core@0.9.16`
- No credentials or env keys required → fully hostable
- Respectful client: prefer `querybatch` for multi-package work; reasonable caching
- DataCanvas for large batch outputs
