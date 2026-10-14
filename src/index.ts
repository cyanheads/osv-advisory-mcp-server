#!/usr/bin/env node
/**
 * @fileoverview osv-advisory-mcp-server MCP server entry point.
 * Registers OSV tools and initializes the OSV API service.
 * @module index
 */

import { createApp } from '@cyanheads/mcp-ts-core';
import { getServerConfig } from './config/server-config.js';
import {
  osvGetVulnerability,
  osvListEcosystems,
  osvQueryBatch,
  osvQueryPackage,
} from './mcp-server/tools/definitions/index.js';
import { initOsvApiService } from './services/osv-api/osv-api-service.js';

await createApp({
  name: 'osv-advisory-mcp-server',
  title: 'osv-advisory-mcp-server',
  /**
   * Every tool is a pure read against OSV.dev with no cross-call state and no
   * `ctx.requestInput` gate, so a session store buys nothing. `MCP_SESSION_MODE`
   * still overrides this when a deployment sets a meaningful value.
   */
  sessionMode: 'stateless',
  tools: [osvListEcosystems, osvQueryPackage, osvGetVulnerability, osvQueryBatch],
  resources: [],
  prompts: [],
  instructions:
    'This server provides read-only access to the OSV.dev vulnerability database.\n' +
    '- Use osv_list_ecosystems to discover valid ecosystem identifier strings before querying.\n' +
    '- Use osv_query_package to check if a single package version is vulnerable.\n' +
    '- Use osv_query_batch for dependency audits — pass a full lockfile as {name, ecosystem, version} tuples.\n' +
    '- Use osv_get_vulnerability for the full advisory record when osv_query_package returns a vuln ID.\n' +
    '- Large advisory replies carry overflow and omitted pointers. Reuse the original input and add page; follow nextOffset until null, retrieving deferred child paths separately.\n' +
    '- Package advisoryId pages fetch one announced advisory with package-scoped fixes/severity. Batch pages select /results or an original-index descendant only; they do not recompute the initial summary.\n' +
    '- Pages are fresh lookups, not saved snapshots. Use returned node revisions; restart without revision if data changed. Transmission overflow is separate from upstream truncated, and neither confirms clean.\n' +
    '- OSV results include aliases (CVE IDs) — chain these to nist-nvd-mcp-server for CVSS scoring, EPSS, and CISA KEV status.\n' +
    '- No API key required. No rate limit published — prefer batch queries over repeated single queries.',

  setup() {
    const { requestTimeoutMs, batchConcurrency, maxQueryPages } = getServerConfig();
    initOsvApiService({ timeoutMs: requestTimeoutMs, batchConcurrency, maxQueryPages });
  },
});
