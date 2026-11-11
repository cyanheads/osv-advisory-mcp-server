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
  osvQueryCommit,
  osvQueryPackage,
} from './mcp-server/tools/definitions/index.js';
import { createOsvQueryBatch } from './mcp-server/tools/definitions/osv-query-batch.tool.js';
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
  get tools() {
    return [
      osvListEcosystems,
      osvQueryPackage,
      osvGetVulnerability,
      createOsvQueryBatch(getServerConfig().batchServeOverCap),
      osvQueryCommit,
    ];
  },
  resources: [],
  skills: 'skills',
  prompts: [],
  instructions:
    'Read-only, keyless access to OSV.dev for exact package versions and full Git commits. Discover case-sensitive ecosystem names with osv_list_ecosystems; query packages by tuple or PURL with exactly one version. Prefer osv_query_batch for dependency audits and submit remaining input using summary.nextInputOffset. Use returned advisory IDs with osv_get_vulnerability for full records. Resume upstream matching with nextCursor as cursor; batch rows resume through osv_query_package. For field retrieval, repeat the original query and its input cursor, if any, with the announced page. Check row errors, incomplete upstream results and omitted fields before concluding a scan is clean. CVE aliases compose with nist-nvd-mcp-server for CVSS scoring and CISA KEV status.',

  setup() {
    const { requestTimeoutMs, batchConcurrency, maxQueryPages } = getServerConfig();
    initOsvApiService({ timeoutMs: requestTimeoutMs, batchConcurrency, maxQueryPages });
  },
});
