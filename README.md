<div align="center">
  <h1>@cyanheads/osv-advisory-mcp-server</h1>
  <p><b>Query OSV.dev for package vulnerabilities, batch-audit dependency lists, and fetch full advisory records via MCP. STDIO or Streamable HTTP.</b>
  <div>5 Tools · 1 Skill</div>
  </p>
</div>

<div align="center">

[![Version](https://img.shields.io/badge/Version-0.5.1-blue.svg?style=flat-square)](./CHANGELOG.md) [![License](https://img.shields.io/badge/License-Apache%202.0-orange.svg?style=flat-square)](./LICENSE) [![Docker](https://img.shields.io/badge/Docker-ghcr.io-2496ED?style=flat-square&logo=docker&logoColor=white)](https://github.com/users/cyanheads/packages/container/package/osv-advisory-mcp-server) [![MCP SDK](https://img.shields.io/badge/MCP%20SDK-^2.4.0-green.svg?style=flat-square)](https://modelcontextprotocol.io/) [![npm](https://img.shields.io/npm/v/@cyanheads/osv-advisory-mcp-server?style=flat-square&logo=npm&logoColor=white)](https://www.npmjs.com/package/@cyanheads/osv-advisory-mcp-server) [![TypeScript](https://img.shields.io/badge/TypeScript-^7.0.2-3178C6.svg?style=flat-square)](https://www.typescriptlang.org/) [![Bun](https://img.shields.io/badge/Bun-v1.4.4%2B-blueviolet.svg?style=flat-square)](https://bun.sh/)

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

Vulnerability data from OSV.dev, the open-source vulnerability database. Query a package version or Git commit, batch-audit a dependency list or SBOM, and fetch complete advisory records with CVSS severity, CVE aliases, and affected version ranges.

### Tools

| Tool | Description |
|:---|:---|
| `osv_query_package` | Query a package version by name/ecosystem/version or Package URL (PURL) |
| `osv_query_batch` | Audit the first 1,000 package versions in a submission of up to 5,000 |
| `osv_query_commit` | Query known vulnerabilities for a full Git commit hash |
| `osv_get_vulnerability` | Fetch the full advisory record for a single OSV vulnerability ID |
| `osv_list_ecosystems` | Return the list of supported ecosystem identifier strings |

## Capability reference

### `osv_query_package` <sub>tool</sub>

- Provide `name`, `ecosystem`, and `version`, or a `purl` such as `pkg:pypi/jinja2@3.1.4`. Known ecosystem bases normalize case (`pypi` → `PyPI`); release and repository suffixes retain their spelling. A PURL needs exactly one version: embedded in the URL or supplied separately. Versions are exact, never ranges
- Alpine needs a release branch, such as `Alpine:v3.17` or `pkg:apk/alpine/openssl@3.0.8-r0?distro=3.17.3`. Maven needs `groupId:artifactId` (a single `groupId/artifactId` slash normalizes). Composer PURLs map to Packagist; an optional `repository_url` keeps repository scope
- Unsupported ecosystem-specific constraints fail as `invalid_version`; npm/crates.io exact pins with `=` or `==` normalize to the installed version
- Each advisory carries CVE `aliases`, optional `upstream` IDs, `severityLabel` with its `severitySource`, the queried package's `fixedVersions`, `affectedRanges`, and `cweIds`
- `truncated: true` indicates more OSV pages remain. Pass `nextCursor` as `cursor` with the same identifier to continue. Repeat that input cursor alongside `page` when retrieving fields from a resumed reply. An empty initial complete result confirms no known vulnerabilities. An empty terminal resume only confirms exhaustion of the continuation

---

### `osv_query_batch` <sub>tool</sub>

- Submit 1–5,000 `{name, ecosystem, version}` tuples or `{purl, version?}` entries. The call processes the first 1,000. Set `OSV_BATCH_SERVE_OVER_CAP=false` to reject submissions above 1,000
- `summary.submittedPackages`, `unprocessedCount`, and `nextInputOffset` account for the input. If `nextInputOffset` is set, submit `packages.slice(nextInputOffset)` in a new call and add that offset to its row indices. All outcome counts describe the processed prefix
- Each row carries `vulnerable`, `vulnCount`, `vulns`, `truncated`, and `error`; a failure lands in the affected rows' `error` instead of failing the call
- `summary` totals the scan (`vulnerableCount`, `cleanCount`, `truncatedCount`, `errorCount`, `totalVulns`, `worstSeverity`), and truncated rows never count as clean. The whole scan has a 50-second deadline
- `vulnerableRows`, `errorRows`, and `truncatedRows` in `summary` retain original zero-based indices even when the preview omits those rows. Lists can overlap; retrieve a row with `/results/<index>`
- Resume a row through `osv_query_package` with its original identifier and `nextCursor` as `cursor`

---

### `osv_query_commit` <sub>tool</sub>

- One full `commit`: 40 hexadecimal characters for SHA-1 or 64 for SHA-256; either letter case is accepted, abbreviations are rejected
- Advisories retain record-wide severity, aliases, upstream IDs, and GIT ranges with repository URLs and ordered events. Readable advisory sections retain complex values in fenced JSON. No package-specific `fixedVersions` are inferred
- Pass `nextCursor` as `cursor` with the same commit to continue a truncated result. An empty terminal resume confirms the continuation is exhausted

---

### `osv_get_vulnerability` <sub>tool</sub>

- One exact advisory ID from any OSV source (`GHSA-`, `PYSEC-`, `RUSTSEC-`, `GO-`, `DSA-`, `USN-`, `CVE-`, …), matched case-sensitively
- Full record: `details`, `aliases`, optional `upstream` and `related` IDs, every affected package with its ranges and source metadata, `severityLabel`, `cweIds`, and `references`
- An unknown ID fails as `vulnerability_not_found`; `withdrawn` is set only on retracted advisories

---

### `osv_list_ecosystems` <sub>tool</sub>

- No input; returns the `ecosystems` strings the query tools accept, plus a `note` with the date the list was last checked against OSV.dev
- Returns canonical spellings. Query tools normalize known base names case-insensitively and forward unknown names to OSV.dev; release and repository suffixes remain unchanged

## Features

Built on [`@cyanheads/mcp-ts-core`](https://github.com/cyanheads/mcp-ts-core): stdio and Streamable HTTP transports, pluggable auth (`none` / `jwt` / `oauth`), swappable storage (`in-memory`, `filesystem`, `Supabase`, `Cloudflare KV/R2/D1`), structured logging with optional OpenTelemetry tracing.

OSV-specific:

- No API key required — OSV.dev is public and keyless, with no published rate limit
- `osv_query_batch` finds matching advisory IDs through OSV's `/v1/querybatch`, then fetches each unique advisory once, so batch rows carry the full records (`aliases` included) the batch endpoint omits; requests are capped by `OSV_BATCH_CONCURRENCY`
- `osv_list_ecosystems` is checked against the live OSV schema and API with `bun run check:ecosystems`

Agent-friendly output:

- Truncation is never read as clean — `truncated` flags incomplete OSV pagination, and truncated batch rows are left out of `cleanCount`
- CVE-shaped `aliases` and `upstream` IDs chain to `nist-nvd-mcp-server` for CVSS base scores and CISA KEV status. The lists remain separate; a distribution advisory can cover several upstream vulnerabilities
- Response fields are bounded to 24,000 bytes; upstream cursors are returned intact outside that budget. Start retrieval by repeating the original input with `page: overflow.page`. Continue the same `path` with `offset: page.nextOffset` and `revision: page.revision` until `nextOffset` is null. Fetch each `entries[].deferred.path` separately at offset zero without a revision; never copy the whole output `page` object into the input
- Advisory text in `content[]` escapes HTML and unsafe-link constructs while preserving HTTP(S) links; caller coordinates render literally. Commit data and affected metadata use reversible JSON where literal rendering needs it. `structuredContent` keeps every OSV string verbatim

## Getting started

Use the public hosted instance with Claude Code:

```sh
claude mcp add --transport http osv-advisory-mcp-server https://osv-advisory.caseyjhand.com/mcp
```

Or run locally through npm:

```sh
claude mcp add osv-advisory-mcp-server -- npx -y @cyanheads/osv-advisory-mcp-server
```

For other MCP clients, add this to the client configuration:

```json
{
  "mcpServers": {
    "osv-advisory-mcp-server": {
      "command": "npx",
      "args": ["-y", "@cyanheads/osv-advisory-mcp-server"]
    }
  }
}
```

No API key is required. For Docker or a source build, see [Running the server](#running-the-server).

## Configuration

All configuration is validated at startup, and every variable is optional.

| Variable | Description | Default |
|:---------|:------------|:--------|
| `OSV_REQUEST_TIMEOUT_MS` | Timeout per OSV.dev HTTP attempt, in milliseconds. Package, commit and batch queries share a 50-second per-operation deadline across requests, retries, response reads and hydration. | `40000` |
| `OSV_BATCH_CONCURRENCY` | Maximum concurrent OSV.dev requests issued by `osv_query_batch`. | `10` |
| `OSV_QUERY_MAX_PAGES` | Maximum OSV.dev result pages followed per package or commit before a result is marked `truncated`. | `10` |
| `OSV_BATCH_SERVE_OVER_CAP` | Accept up to 5,000 packages and process the first 1,000. Set `false` to restore the 1,000-entry submission ceiling. | `true` |
| `MCP_TRANSPORT_TYPE` | Transport: `stdio` or `http`. | `stdio` |
| `MCP_HTTP_PORT` | Port for HTTP server. | `3010` |
| `MCP_HTTP_ENDPOINT_PATH` | HTTP endpoint path. | `/mcp` |
| `MCP_PUBLIC_URL` | Public origin override for TLS-terminating reverse-proxy deployments. | none |
| `MCP_SESSION_MODE` | HTTP session mode: `stateless`, `stateful`, or `auto`. | `stateless` |
| `MCP_AUTH_MODE` | Auth mode: `none`, `jwt`, or `oauth`. | `none` |
| `MCP_LOG_LEVEL` | Log level (RFC 5424). | `info` |
| `LOGS_DIR` | Directory for log files. Relative paths resolve from the server package root. | `<server-package-root>/logs` |
| `LOG_TOOL_FAILURE_PAYLOADS` | Log each failed tool call's arguments and result, redacted by key name and capped at `LOG_TOOL_FAILURE_PAYLOAD_MAX_BYTES` (default `16384`). A secret inside a free-form value is not redacted. | `false` |
| `STORAGE_PROVIDER_TYPE` | Storage backend. | `in-memory` |
| `OTEL_ENABLED` | Enable [OpenTelemetry instrumentation](https://github.com/cyanheads/mcp-ts-core/tree/main/docs/telemetry) (spans, metrics, completion logs). | `false` |

See [`.env.example`](./.env.example) for the full list of optional overrides.

## Running the server

### Local development

Requires [Bun v1.4.4](https://bun.sh/) or higher (or Node.js v24+).

```sh
git clone https://github.com/cyanheads/osv-advisory-mcp-server.git
cd osv-advisory-mcp-server
bun install
cp .env.example .env
```

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
docker run --rm -p 3010:3010 ghcr.io/cyanheads/osv-advisory-mcp-server:latest
```

The image defaults to HTTP transport, stateless session mode, and logs to `/var/log/osv-advisory-mcp-server`. For stdio, use `docker run -i --rm -e MCP_TRANSPORT_TYPE=stdio ghcr.io/cyanheads/osv-advisory-mcp-server:latest`. Build locally with `docker build -t osv-advisory-mcp-server .`; OpenTelemetry peers are installed by default — use `--build-arg OTEL_ENABLED=false` to omit them.

## Project structure

| Directory | Purpose |
|:----------|:--------|
| `src/index.ts` | `createApp()` entry point — registers tools and inits services. |
| `src/config` | Server-specific environment variable parsing and validation with Zod. |
| `src/mcp-server/tools` | Tool definitions (`*.tool.ts`) — `osv_query_package`, `osv_query_batch`, `osv_query_commit`, `osv_get_vulnerability`, `osv_list_ecosystems`. |
| `src/services/osv-api` | OSV.dev REST API service — fetch, retry, response normalization. |
| `tests/` | Unit and integration tests mirroring `src/`. |
| `skills/` | Published dependency-audit and advisory-retrieval guide, also served over MCP. |

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
