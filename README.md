<div align="center">
  <h1>@cyanheads/osv-advisory-mcp-server</h1>
  <p><b>Query OSV.dev for package vulnerabilities, batch-audit dependency lists, and fetch full advisory records via MCP. STDIO or Streamable HTTP.</b>
  <div>4 Tools</div>
  </p>
</div>

<div align="center">

[![Version](https://img.shields.io/badge/Version-0.2.0-blue.svg?style=flat-square)](./CHANGELOG.md) [![License](https://img.shields.io/badge/License-Apache%202.0-orange.svg?style=flat-square)](./LICENSE) [![Docker](https://img.shields.io/badge/Docker-ghcr.io-2496ED?style=flat-square&logo=docker&logoColor=white)](https://github.com/users/cyanheads/packages/container/package/osv-advisory-mcp-server) [![MCP SDK](https://img.shields.io/badge/MCP%20SDK-^2.3.1-green.svg?style=flat-square)](https://modelcontextprotocol.io/) [![npm](https://img.shields.io/npm/v/@cyanheads/osv-advisory-mcp-server?style=flat-square&logo=npm&logoColor=white)](https://www.npmjs.com/package/@cyanheads/osv-advisory-mcp-server) [![TypeScript](https://img.shields.io/badge/TypeScript-^7.0.2-3178C6.svg?style=flat-square)](https://www.typescriptlang.org/) [![Bun](https://img.shields.io/badge/Bun-v1.4.3%2B-blueviolet.svg?style=flat-square)](https://bun.sh/)

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

Vulnerability data from OSV.dev, the open-source vulnerability database. Query a single package version, batch-audit a full dependency list or SBOM, and fetch complete advisory records with CVSS severity, CVE aliases, and affected version ranges.

### Tools

| Tool | Description |
|:---|:---|
| `osv_query_package` | Query known vulnerabilities for a single package version by name, ecosystem, and version |
| `osv_query_batch` | Audit up to 1000 package versions in one call — a full dependency list or SBOM |
| `osv_get_vulnerability` | Fetch the full advisory record for a single OSV vulnerability ID |
| `osv_list_ecosystems` | Return the list of supported ecosystem identifier strings |

## Capability reference

### `osv_query_package` <sub>tool</sub>

- `name`, `ecosystem` (case-sensitive exact match), and `version` — an exact version, not a range
- Each advisory carries CVE `aliases`, `severityLabel` with its `severitySource`, the queried package's `fixedVersions`, `affectedRanges`, and `cweIds`
- `truncated: true` means OSV had more pages than `OSV_QUERY_MAX_PAGES` follows, so an empty `vulns` list is not a clean result; an unrecognized ecosystem fails as `invalid_ecosystem`

---

### `osv_query_batch` <sub>tool</sub>

- 1–1000 `{name, ecosystem, version}` tuples per call; `results[i]` matches `packages[i]`
- Each row carries `vulnerable`, `vulnCount`, `vulns`, `truncated`, and `error`; a failure lands in the affected rows' `error` instead of failing the call
- `summary` totals the scan (`vulnerableCount`, `cleanCount`, `truncatedCount`, `errorCount`, `totalVulns`, `worstSeverity`), and truncated rows never count as clean. The whole scan has a 50-second deadline

---

### `osv_get_vulnerability` <sub>tool</sub>

- One exact advisory ID from any OSV source (`GHSA-`, `PYSEC-`, `RUSTSEC-`, `GO-`, `DSA-`, `USN-`, `CVE-`, …), matched case-sensitively
- Full record: `details`, `aliases`, every affected package with its ranges and fixes, `severityLabel`, `cweIds`, and `references`
- An unknown ID fails as `vulnerability_not_found`; `withdrawn` is set only on retracted advisories

---

### `osv_list_ecosystems` <sub>tool</sub>

- No input; returns the `ecosystems` strings the query tools accept, plus a `note` with the date the list was last checked against OSV.dev
- Strings are case-sensitive exact matches: `PyPI` works, `pypi` fails

## Features

Built on [`@cyanheads/mcp-ts-core`](https://github.com/cyanheads/mcp-ts-core): stdio and Streamable HTTP transports, pluggable auth (`none` / `jwt` / `oauth`), swappable storage (`in-memory`, `filesystem`, `Supabase`, `Cloudflare KV/R2/D1`), structured logging with optional OpenTelemetry tracing.

OSV-specific:

- No API key required — OSV.dev is public and keyless, with no published rate limit
- `osv_query_batch` finds matching advisory IDs through OSV's `/v1/querybatch`, then fetches each unique advisory once, so batch rows carry the full records (`aliases` included) the batch endpoint omits; requests are capped by `OSV_BATCH_CONCURRENCY`
- `osv_list_ecosystems` is checked against the live OSV schema and API with `bun run check:ecosystems`

Agent-friendly output:

- Truncation is never read as clean — `truncated` flags incomplete OSV pagination, and truncated batch rows are left out of `cleanCount`
- `aliases` (CVE IDs) on every advisory chain to `nist-nvd-mcp-server` for CVSS base scores and CISA KEV status
- Responses are capped at 24,000 bytes; a larger one returns an `overflow` preview with `page` arguments for fetching the rest
- Advisory text in `content[]` is escaped so it can't render as live HTML or links; `structuredContent` keeps every OSV string verbatim

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

Add the following to your MCP client configuration file.

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

All configuration is validated at startup, and every variable is optional.

| Variable | Description | Default |
|:---------|:------------|:--------|
| `OSV_REQUEST_TIMEOUT_MS` | HTTP request timeout for OSV.dev API calls, in milliseconds. | `10000` |
| `OSV_BATCH_CONCURRENCY` | Maximum concurrent OSV.dev requests issued by `osv_query_batch`. | `10` |
| `OSV_QUERY_MAX_PAGES` | Maximum OSV.dev result pages followed per package before a result is marked `truncated`. | `10` |
| `MCP_TRANSPORT_TYPE` | Transport: `stdio` or `http`. | `stdio` |
| `MCP_HTTP_PORT` | Port for HTTP server. | `3010` |
| `MCP_HTTP_ENDPOINT_PATH` | HTTP endpoint path. | `/mcp` |
| `MCP_PUBLIC_URL` | Public origin override for TLS-terminating reverse-proxy deployments. | none |
| `MCP_SESSION_MODE` | HTTP session mode: `stateless`, `stateful`, or `auto`. | `stateless` |
| `MCP_AUTH_MODE` | Auth mode: `none`, `jwt`, or `oauth`. | `none` |
| `MCP_LOG_LEVEL` | Log level (RFC 5424). | `info` |
| `LOGS_DIR` | Directory for log files (Node.js only). | `<project-root>/logs` |
| `LOG_TOOL_FAILURE_PAYLOADS` | Log each failed tool call's arguments and result, redacted by key name and capped at `LOG_TOOL_FAILURE_PAYLOAD_MAX_BYTES` (default `16384`). A secret inside a free-form value is not redacted. | `false` |
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
