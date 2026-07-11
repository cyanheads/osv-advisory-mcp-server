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
  tools: [osvListEcosystems, osvQueryPackage, osvGetVulnerability, osvQueryBatch],
  resources: [],
  prompts: [],
  instructions:
    'This server provides read-only access to the OSV.dev vulnerability database.\n' +
    '- Use osv_list_ecosystems to discover valid ecosystem identifier strings before querying.\n' +
    '- Use osv_query_package to check if a single package version is vulnerable.\n' +
    '- Use osv_query_batch for dependency audits — pass a full lockfile as {name, ecosystem, version} tuples.\n' +
    '- Use osv_get_vulnerability for the full advisory record when osv_query_package returns a vuln ID.\n' +
    '- OSV results include aliases (CVE IDs) — chain these to nist-nvd-mcp-server for CVSS scoring, EPSS, and CISA KEV status.\n' +
    '- No API key required. No rate limit published — prefer batch queries over repeated single queries.',

  setup() {
    const { requestTimeoutMs, batchConcurrency, maxQueryPages } = getServerConfig();
    initOsvApiService({ timeoutMs: requestTimeoutMs, batchConcurrency, maxQueryPages });
  },
});
