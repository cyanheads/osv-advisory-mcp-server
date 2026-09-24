<div align="center">
  <h1>@cyanheads/osv-advisory-mcp-server</h1>
  <p><b>Query OSV.dev for package vulnerabilities, batch-audit dependency lists, and fetch full advisory records via MCP. STDIO or Streamable HTTP.</b>
  <div>4 Tools</div>
  </p>
</div>

<div align="center">

[![Version](https://img.shields.io/badge/Version-0.1.15-blue.svg?style=flat-square)](./CHANGELOG.md) [![License](https://img.shields.io/badge/License-Apache%202.0-orange.svg?style=flat-square)](./LICENSE) [![Docker](https://img.shields.io/badge/Docker-ghcr.io-2496ED?style=flat-square&logo=docker&logoColor=white)](https://github.com/users/cyanheads/packages/container/package/osv-advisory-mcp-server) [![MCP SDK](https://img.shields.io/badge/MCP%20SDK-^2.0.0-green.svg?style=flat-square)](https://modelcontextprotocol.io/) [![npm](https://img.shields.io/npm/v/@cyanheads/osv-advisory-mcp-server?style=flat-square&logo=npm&logoColor=white)](https://www.npmjs.com/package/@cyanheads/osv-advisory-mcp-server) [![TypeScript](https://img.shields.io/badge/TypeScript-^7.0.2-3178C6.svg?style=flat-square)](https://www.typescriptlang.org/) [![Bun](https://img.shields.io/badge/Bun-v1.4.0%2B-blueviolet.svg?style=flat-square)](https://bun.sh/)

</div>

<div align="center">

[![Install in Claude Desktop](https://img.shields.io/badge/Install_in-Claude_Desktop-D97757?style=for-the-badge&logo=anthropic&logoColor=white)](https://github.com/cyanheads/osv-advisory-mcp-server/releases/latest/download/osv-advisory-mcp-server.mcpb) [![Install in Cursor](https://cursor.com/deeplink/mcp-install-dark.svg)](https://cursor.com/en/install-mcp?name=osv-advisory-mcp-server&config=eyJjb21tYW5kIjoibnB4IiwiYXJncyI6WyIteSIsIkBjeWFuaGVhZHMvb3N2LWFkdmlzb3J5LW1jcC1zZXJ2ZXIiXX0=) [![Install in VS Code](https://img.shields.io/badge/VS_Code-Install_Server-0098FF?style=for-the-badge&logo=visualstudiocode&logoColor=white)](https://vscode.dev/redirect?url=vscode:mcp/install?%7B%22name%22%3A%22osv-advisory-mcp-server%22%2C%22command%22%3A%22npx%22%2C%22args%22%3A%5B%22-y%22%2C%22%40cyanheads%2Fosv-advisory-mcp-server%22%5D%7D)

[![Framework](https://img.shields.io/badge/Built%20on-@cyanheads/mcp--ts--core-67E8F9?style=flat-square)](https://www.npmjs.com/package/@cyanheads/mcp-ts-core)

</div>

<div align="center">

**Public Hosted Server:** [https://osv-advisory.caseyjhand.com/mcp](https://osv-advisory.caseyjhand.com/mcp)

</div>

---

## Overview

Vulnerability data from OSV.dev, the open-source vulnerability database. Query a single package version, batch-audit a full dependency list or SBOM, and fetch complete advisory records with CVSS severity, CVE aliases, and affected version ranges. Runs as a stdio process, a local Streamable HTTP server, or the public hosted endpoint above.

### Tools

| Tool | Description |
|:---|:---|
| `osv_query_package` | Query known vulnerabilities for a single package version by name, ecosystem, and version |
| `osv_query_batch` | Batch vulnerability query for an array of package tuples — one call for a full dependency list or SBOM audit |
| `osv_get_vulnerability` | Fetch the full advisory record for a single OSV vulnerability ID |
| `osv_list_ecosystems` | Return the list of supported ecosystem identifier strings |

## Capability reference

### `osv_query_package` <sub>tool</sub>

- Accepts `name`, `ecosystem` (case-sensitive exact match), and `version` — an exact version string, not a range
- Surrounding whitespace is trimmed from all three before the request, and `queryMeta` echoes the trimmed values; interior whitespace (`Rocky Linux`) is kept. Blank or whitespace-only values are rejected before any upstream call
- Returns matching advisories with OSV IDs, CVE `aliases`, severity entries (CVSS vectors, Ubuntu priorities), `severityLabel` with its `severitySource`, `fixedVersions`, `affectedRanges` (SEMVER/ECOSYSTEM/GIT), and `cweIds`
- `fixedVersions` lists every fix the advisory records for the queried package (one per affected interval), matched the way OSV matches the query — release-suffixed ecosystems (`Debian` → `Debian:12`, `Ubuntu:22.04` → `Ubuntu:22.04:LTS`) and PEP 503 names on PyPI. Other packages' fixes and GIT commits stay out of it; `affectedRanges` keeps every range
- `truncated: true` means OSV paginated beyond `OSV_QUERY_MAX_PAGES` (default 10) — an empty `vulns` array with `truncated: true` is NOT a confirmed clean result
- Typed `invalid_ecosystem` error when the ecosystem string isn't recognized by OSV — call `osv_list_ecosystems` for valid values, then retry
- `aliases` on each vuln chain to `nist-nvd-mcp-server` for CVSS base scores, EPSS exploitation probability, and CISA KEV status

---

### `osv_query_batch` <sub>tool</sub>

- Accepts an array of `{name, ecosystem, version}` tuples, 1–1000 per call; `results[i]` corresponds positionally to `packages[i]`
- Each row's fields are trimmed of surrounding whitespace the same way as `osv_query_package`, and `results[i]` echoes the trimmed values; a blank field in any row rejects the call
- Per-package `vulnerable`, `vulnCount`, `vulns` (with `aliases`, `severityLabel`, and the row package's `fixedVersions`), and a nullable `error` — one bad ecosystem or upstream failure fails only that row, not the whole batch
- Aggregate `summary`: `totalPackages`, `vulnerableCount`, `cleanCount`, `truncatedCount`, `errorCount`, `totalVulns`, `worstSeverity`
- `cleanCount` excludes truncated rows — a per-package `truncated: true` result is never counted clean even with zero findings
- Per-package requests run in parallel, capped by `OSV_BATCH_CONCURRENCY` (default 10)

---

### `osv_get_vulnerability` <sub>tool</sub>

- Accepts one exact, complete advisory ID from any OSV source database, matched case-sensitively — `GHSA-` (GitHub), `PYSEC-` (PyPI), `RUSTSEC-` (Rust), `GO-` (Go), `DSA-`/`DLA-` (Debian), `USN-` (Ubuntu), `RHSA-` (Red Hat), `CVE-`, and the rest. IDs come from `osv_query_package` / `osv_query_batch` results
- Surrounding whitespace is trimmed before the request (`" GHSA-29mw-wpgm-hmr9 "` resolves); input that can't be an OSV ID (wildcards, a bare package name, a prefix with no ID) is rejected before any upstream call, with a message naming the expected form
- Returns the full record — `details` text, all CVE `aliases`, every affected package with its version ranges, ordered `fixed` events, and any package-level severity, severity entries with `severityLabel` and `severitySource`, `cweIds`, and `references` (ADVISORY, FIX, REPORT, etc.)
- Typed `vulnerability_not_found` error when the ID doesn't exist in OSV — the recovery covers case and the Debian/Ubuntu/SUSE revision suffix (`DSA-5678-1`, not `DSA-5678`); a CVE-style alias may still resolve via `nist-nvd-mcp-server`
- `withdrawn` is present only on retracted advisories — treat as no longer active, not as an error

---

### `osv_list_ecosystems` <sub>tool</sub>

- No input; returns the static list of valid `ecosystem` identifier strings plus an advisory `note` on currency
- Ecosystem strings are case-sensitive exact matches — `"pypi"` fails where `"PyPI"` succeeds
- Every ecosystem in the OSV schema's `ecosystemName` enum that OSV.dev accepts at query time, plus `GIT` (accepted via the `ecosystemWithSuffix` pattern); a schema ecosystem OSV.dev still rejects is left out. The `note` carries the verification date; the list may lag later additions

## Features

Built on [`@cyanheads/mcp-ts-core`](https://github.com/cyanheads/mcp-ts-core): stdio and Streamable HTTP transports, pluggable auth (`none` / `jwt` / `oauth`), swappable storage (`in-memory`, `filesystem`, `Supabase`, `Cloudflare KV/R2/D1`), structured logging with optional OpenTelemetry tracing.

OSV-specific:

- No API key required — OSV.dev is fully public, keyless, and has no published rate limit
- `osv_query_batch` issues parallel per-package requests (capped by `OSV_BATCH_CONCURRENCY`) and returns full records, including `aliases`, that the upstream OSV batch endpoint omits
- Per-package failures are isolated in `osv_query_batch` — one invalid ecosystem or upstream error surfaces as that row's `error` without failing the whole batch
- Ecosystem discovery via `osv_list_ecosystems` — the OSV schema's ecosystems that OSV.dev accepts, checked against both with `bun run check:ecosystems`

Agent-friendly output:

- `aliases` (CVE IDs) surfaced on every vuln entry — the composition point for chaining to `nist-nvd-mcp-server` for CVSS base scores, EPSS, and CISA KEV status
- `severityLabel` from the first source that yields one: `database_specific.severity` (GHSA, openEuler, and others; `Medium` reads as `MODERATE`), an Ubuntu priority, then the highest CVSS v3/v4 score computed from the vector as published. Package-level severity counts when the record has none. `severitySource` names the entry used, with the computed score for CVSS; both are `null` rather than fabricated when no source yields a label
- Truncation is never silently treated as clean — `truncated` (single query) and per-package `truncated` plus `truncatedCount` (batch) flag incomplete OSV pagination, and truncated rows are excluded from `cleanCount`
- Query echo (`queryMeta` / `effectiveQuery`) and aggregate batch `summary` (`worstSeverity`, `vulnerableCount`, `cleanCount`) let agents verify requests and triage without reading every row
- Advisory text is framed as untrusted data in `content[]` and escaped at the render boundary: tag-shaped text (`<template>`, `<script`), autolinks, reference definitions, non-`http(s)` link destinations (`javascript:`), and forged frame tags can't turn into live HTML or links in a Markdown client. `structuredContent` keeps every OSV string verbatim

## Getting started

### Public Hosted Instance

A public instance is available at `https://osv-advisory.caseyjhand.com/mcp` — no installation required. Point any MCP client at it via Streamable HTTP:

```json
{
  "mcpServers": {
    "osv-advisory-mcp-server": {
      "type": "streamable-http",
      "url": "https://osv-advisory.caseyjhand.com/mcp"
    }
  }
}
```

### Self-Hosted / Local

Add the following to your MCP client configuration file. No API key is required — OSV.dev is fully public.

```json
{
  "mcpServers": {
    "osv-advisory-mcp-server": {
      "type": "stdio",
      "command": "bunx",
      "args": ["@cyanheads/osv-advisory-mcp-server@latest"],
      "env": {
        "MCP_TRANSPORT_TYPE": "stdio",
        "MCP_LOG_LEVEL": "info"
      }
    }
  }
}
```

Or with npx (no Bun required):

```json
{
  "mcpServers": {
    "osv-advisory-mcp-server": {
      "type": "stdio",
      "command": "npx",
      "args": ["-y", "@cyanheads/osv-advisory-mcp-server@latest"],
      "env": {
        "MCP_TRANSPORT_TYPE": "stdio",
        "MCP_LOG_LEVEL": "info"
      }
    }
  }
}
```

Or with Docker:

```json
{
  "mcpServers": {
    "osv-advisory-mcp-server": {
      "type": "stdio",
      "command": "docker",
      "args": [
        "run", "-i", "--rm",
        "-e", "MCP_TRANSPORT_TYPE=stdio",
        "ghcr.io/cyanheads/osv-advisory-mcp-server:latest"
      ]
    }
  }
}
```

For Streamable HTTP, set the transport and start the server:

```sh
MCP_TRANSPORT_TYPE=http MCP_HTTP_PORT=3010 bun run start:http
# Server listens at http://localhost:3010/mcp
```

### Prerequisites

- [Bun v1.4.0](https://bun.sh/) or higher (or Node.js v24+).
- No API key required — OSV.dev is fully public.

### Installation

1. **Clone the repository:**

```sh
git clone https://github.com/cyanheads/osv-advisory-mcp-server.git
```

2. **Navigate into the directory:**

```sh
cd osv-advisory-mcp-server
```

3. **Install dependencies:**

```sh
bun install
```

4. **Configure environment:**

```sh
cp .env.example .env
# edit .env if needed (no required vars)
```

## Configuration

All configuration is validated at startup. No server-specific env vars are required — OSV.dev is keyless and fully public.

| Variable | Description | Default |
|:---------|:------------|:--------|
| `OSV_REQUEST_TIMEOUT_MS` | HTTP request timeout for OSV.dev API calls, in milliseconds. | `10000` |
| `OSV_BATCH_CONCURRENCY` | Maximum concurrent OSV.dev requests issued by `osv_query_batch`. | `10` |
| `OSV_QUERY_MAX_PAGES` | Maximum OSV.dev result pages `osv_query_package` follows before marking a result truncated. | `10` |
| `MCP_TRANSPORT_TYPE` | Transport: `stdio` or `http`. | `stdio` |
| `MCP_HTTP_PORT` | Port for HTTP server. | `3010` |
| `MCP_HTTP_ENDPOINT_PATH` | HTTP endpoint path. | `/mcp` |
| `MCP_PUBLIC_URL` | Public origin override for TLS-terminating reverse-proxy deployments. | none |
| `MCP_SESSION_MODE` | HTTP session mode: `stateful`, `stateless`, or `auto`. `createApp()` declares `stateless` — no tool has a multi-round input flow — and setting this overrides it. | `stateless` |
| `MCP_AUTH_MODE` | Auth mode: `none`, `jwt`, or `oauth`. | `none` |
| `MCP_LOG_LEVEL` | Log level (RFC 5424). | `info` |
| `LOGS_DIR` | Directory for log files (Node.js only). | `<project-root>/logs` |
| `STORAGE_PROVIDER_TYPE` | Storage backend. | `in-memory` |
| `OTEL_ENABLED` | Enable [OpenTelemetry instrumentation](https://github.com/cyanheads/mcp-ts-core/tree/main/docs/telemetry) (spans, metrics, completion logs). | `false` |

See [`.env.example`](./.env.example) for the full list of optional overrides.

## Running the server

### Local development

- **Build and run:**

  ```sh
  # One-time build
  bun run rebuild

  # Run the built server
  bun run start:stdio
  # or
  bun run start:http
  ```

- **Run checks and tests:**

  ```sh
  bun run devcheck   # Lint, format, typecheck, security
  bun run test       # Vitest test suite
  bun run lint:mcp   # Validate MCP definitions against spec
  bun run check:ecosystems  # Compare osv_list_ecosystems with the live OSV schema and API
  ```

### Docker

```sh
docker build -t osv-advisory-mcp-server .
docker run --rm -p 3010:3010 osv-advisory-mcp-server
```

The Dockerfile defaults to HTTP transport, stateless session mode, and logs to `/var/log/osv-advisory-mcp-server`. OpenTelemetry peer dependencies are installed by default — build with `--build-arg OTEL_ENABLED=false` to omit them.

## Project structure

| Directory | Purpose |
|:----------|:--------|
| `src/index.ts` | `createApp()` entry point — registers tools and inits services. |
| `src/config` | Server-specific environment variable parsing and validation with Zod. |
| `src/mcp-server/tools` | Tool definitions (`*.tool.ts`) — `osv_query_package`, `osv_query_batch`, `osv_get_vulnerability`, `osv_list_ecosystems`. |
| `src/services/osv-api` | OSV.dev REST API service — fetch, retry, response normalization. |
| `tests/` | Unit and integration tests mirroring `src/`. |

## Development guide

See [`CLAUDE.md`/`AGENTS.md`](./CLAUDE.md) for development guidelines and architectural rules. The short version:

- Handlers throw, framework catches — no `try/catch` in tool logic
- Use `ctx.log` for request-scoped logging, `ctx.enrich` for response context, and `ctx.signal` for cancellable OSV requests
- Register new tools via the barrel in `src/mcp-server/tools/definitions/index.ts`
- Wrap external API calls: validate raw → normalize to domain type → return output schema; never fabricate missing fields

## Contributing

Issues are welcome. Run checks and tests before submitting:

```sh
bun run devcheck
bun run test
```

## License

Apache-2.0 — see [LICENSE](LICENSE) for details.
