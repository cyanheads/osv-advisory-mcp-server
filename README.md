<div align="center">
  <h1>@cyanheads/osv-advisory-mcp-server</h1>
  <p><b>Query OSV.dev for package vulnerabilities, batch-audit dependency lists, and fetch full advisory records via MCP. STDIO or Streamable HTTP.</b>
  <div>4 Tools</div>
  </p>
</div>

<div align="center">

[![Version](https://img.shields.io/badge/Version-0.1.3-blue.svg?style=flat-square)](./CHANGELOG.md) [![License](https://img.shields.io/badge/License-Apache%202.0-orange.svg?style=flat-square)](./LICENSE) [![Docker](https://img.shields.io/badge/Docker-ghcr.io-2496ED?style=flat-square&logo=docker&logoColor=white)](https://github.com/users/cyanheads/packages/container/package/osv-advisory-mcp-server) [![MCP SDK](https://img.shields.io/badge/MCP%20SDK-^1.29.0-green.svg?style=flat-square)](https://modelcontextprotocol.io/) [![npm](https://img.shields.io/npm/v/@cyanheads/osv-advisory-mcp-server?style=flat-square&logo=npm&logoColor=white)](https://www.npmjs.com/package/@cyanheads/osv-advisory-mcp-server) [![TypeScript](https://img.shields.io/badge/TypeScript-^5.9.3-3178C6.svg?style=flat-square)](https://www.typescriptlang.org/) [![Bun](https://img.shields.io/badge/Bun->=1.3.0-blueviolet.svg?style=flat-square)](https://bun.sh/)

</div>

<div align="center">

[![Install in Claude Desktop](https://img.shields.io/badge/Install_in-Claude_Desktop-D97757?style=for-the-badge&logo=anthropic&logoColor=white)](https://github.com/cyanheads/osv-advisory-mcp-server/releases/latest/download/osv-advisory-mcp-server.mcpb) [![Install in Cursor](https://cursor.com/deeplink/mcp-install-dark.svg)](https://cursor.com/en/install-mcp?name=osv-advisory-mcp-server&config=eyJjb21tYW5kIjoibnB4IiwiYXJncyI6WyIteSIsIkBjeWFuaGVhZHMvb3N2LWFkdmlzb3J5LW1jcC1zZXJ2ZXIiXX0=) [![Install in VS Code](https://img.shields.io/badge/VS_Code-Install_Server-0098FF?style=for-the-badge&logo=visualstudiocode&logoColor=white)](https://vscode.dev/redirect?url=vscode:mcp/install?%7B%22name%22%3A%22osv-advisory-mcp-server%22%2C%22command%22%3A%22npx%22%2C%22args%22%3A%5B%22-y%22%2C%22%40cyanheads%2Fosv-advisory-mcp-server%22%5D%7D)

[![Framework](https://img.shields.io/badge/Built%20on-@cyanheads/mcp--ts--core-67E8F9?style=flat-square)](https://www.npmjs.com/package/@cyanheads/mcp-ts-core)

</div>

<div align="center">

**Public Hosted Server:** [https://osv-advisory.caseyjhand.com/mcp](https://osv-advisory.caseyjhand.com/mcp)

</div>

---

## Tools

4 tools for querying the OSV.dev vulnerability database — single package lookups, batch dependency audits, and full advisory fetch:

| Tool | Description |
|:---|:---|
| `osv_query` | Query known vulnerabilities for a single package version by name, ecosystem, and version |
| `osv_query_batch` | Batch vulnerability query for an array of package tuples — one call for a full dependency list or SBOM audit |
| `osv_get_vulnerability` | Fetch the full advisory record for a single OSV vulnerability ID |
| `osv_list_ecosystems` | Return the list of supported ecosystem identifier strings |

### `osv_query`

The primary "is this package version vulnerable?" tool.

- Accepts `name`, `ecosystem` (case-sensitive exact match — use `osv_list_ecosystems` to validate), and `version`
- Returns all matching advisories: OSV IDs, CVE aliases, CVSS severity vectors, derived severity label, first safe versions, affected version ranges (SEMVER/ECOSYSTEM/GIT), and CWE IDs
- `aliases` field surfaces CVE IDs for chaining to `nist-nvd-mcp-server` for CVSS base scores, EPSS exploitation probability, and CISA KEV status
- No API key required — OSV.dev is fully public and keyless

---

### `osv_query_batch`

The primary tool for dependency audits, SBOM scanning, and lockfile triage.

- Accepts an array of `{name, ecosystem, version}` tuples (1–1000 packages per call)
- All ecosystems are pre-validated before the API call — a single invalid ecosystem string fails the batch (OSV API behavior)
- Returns per-package results positionally matching the input, with `vulnerable`, `vulnCount`, `vulns` (including `aliases` and `severityLabel`), and `fixedVersions`
- Includes aggregate summary: `totalPackages`, `vulnerableCount`, `cleanCount`, `errorCount`, `totalVulns`, `worstSeverity`

---

### `osv_get_vulnerability`

Fetch the complete advisory record by OSV ID.

- Accepts any OSV ID prefix: `GHSA-` (GitHub), `PYSEC-` (Python), `RUSTSEC-` (Rust), `GO-` (Go), `DSA-`/`DLA-` (Debian), `CVE-` (direct CVE fallbacks)
- Returns: summary, full advisory details text, all CVE aliases, all affected packages and their version ranges, fix versions, CVSS severity vectors, CWE weakness IDs, and references (ADVISORY, FIX, REPORT, etc.)
- Use after `osv_query` or `osv_query_batch` returns a vuln ID and you need the full advisory context — remediation guidance, scope of affected packages, or eligibility criteria

---

### `osv_list_ecosystems`

Return the list of valid ecosystem identifier strings. Ecosystem strings are **case-sensitive exact matches** — `"pypi"` is not `"PyPI"`. Call this tool before querying to validate ecosystem strings from lockfiles or user input. The list is static (sourced from the OSV schema spec) and may occasionally lag newly added ecosystems.

## Features

Built on [`@cyanheads/mcp-ts-core`](https://www.npmjs.com/package/@cyanheads/mcp-ts-core):

- Declarative tool definitions — single file per tool, framework handles registration and validation
- Unified error handling — handlers throw, framework catches, classifies, and formats
- Pluggable auth: `none`, `jwt`, `oauth`
- Swappable storage backends: `in-memory`, `filesystem`, `Supabase`, `Cloudflare KV/R2/D1`
- Structured logging with optional OpenTelemetry tracing
- STDIO and Streamable HTTP transports

OSV-specific:

- No API key required — OSV.dev is fully public, keyless, and has no published rate limit
- Parallel single-package queries in `osv_query_batch` return full records including `aliases` (CVE IDs) that the upstream batch endpoint omits
- Ecosystem pre-validation guards against OSV's all-or-nothing batch rejection behavior

Agent-friendly output:

- `aliases` (CVE IDs) prominently surfaced on every vuln entry — the primary composition point for chaining to `nist-nvd-mcp-server` for CVSS base scores, EPSS, and CISA KEV status
- `severityLabel` derived from `database_specific.severity` (GHSA records) or the highest CVSS base score; `null` rather than fabricated when neither source is available
- Echo of query parameters (`queryMeta`) on `osv_query` output so agents can verify the request was applied correctly
- Batch aggregate summary (`worstSeverity`, `vulnerableCount`, `cleanCount`) for quick triage without reading per-package rows

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

- [Bun v1.3.0](https://bun.sh/) or higher (or Node.js v24+).
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
| `OSV_REQUEST_TIMEOUT_MS` | HTTP request timeout in milliseconds for OSV.dev API calls. | `10000` |
| `MCP_TRANSPORT_TYPE` | Transport: `stdio` or `http`. | `stdio` |
| `MCP_HTTP_PORT` | Port for HTTP server. | `3010` |
| `MCP_HTTP_ENDPOINT_PATH` | HTTP endpoint path. | `/mcp` |
| `MCP_PUBLIC_URL` | Public origin override for TLS-terminating reverse-proxy deployments. | none |
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
| `src/mcp-server/tools` | Tool definitions (`*.tool.ts`) — `osv_query`, `osv_query_batch`, `osv_get_vulnerability`, `osv_list_ecosystems`. |
| `src/services/osv-api` | OSV.dev REST API service — fetch, retry, response normalization. |
| `tests/` | Unit and integration tests mirroring `src/`. |

## Development guide

See [`CLAUDE.md`/`AGENTS.md`](./CLAUDE.md) for development guidelines and architectural rules. The short version:

- Handlers throw, framework catches — no `try/catch` in tool logic
- Use `ctx.log` for request-scoped logging, `ctx.state` for tenant-scoped storage
- Register new tools via the barrel in `src/mcp-server/tools/definitions/index.ts`
- Wrap external API calls: validate raw → normalize to domain type → return output schema; never fabricate missing fields

## Contributing

Issues and pull requests are welcome. Run checks and tests before submitting:

```sh
bun run devcheck
bun run test
```

## License

Apache-2.0 — see [LICENSE](LICENSE) for details.
