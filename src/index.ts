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
  osvQueryCommit,
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
  tools: [osvListEcosystems, osvQueryPackage, osvGetVulnerability, osvQueryBatch, osvQueryCommit],
  resources: [],
  skills: 'skills',
  prompts: [],
  instructions:
    'Read-only, keyless access to OSV.dev for exact package versions and full Git commits. Discover case-sensitive ecosystem names with osv_list_ecosystems; query packages by tuple or PURL with exactly one version. Prefer osv_query_batch for dependency audits, then use returned advisory IDs with osv_get_vulnerability for full records. Commit queries retain GIT events and record-wide severity without package fixedVersions. Follow announced overflow paths with the original query; pages are fresh lookups, and row errors, upstream truncation, and transmission overflow must be checked before concluding a scan is clean. CVE aliases compose with nist-nvd-mcp-server for CVSS scoring and CISA KEV status. No rate limit is published; prefer batch calls over repeated single queries.',

  setup() {
    const { requestTimeoutMs, batchConcurrency, maxQueryPages } = getServerConfig();
    initOsvApiService({ timeoutMs: requestTimeoutMs, batchConcurrency, maxQueryPages });
  },
});
