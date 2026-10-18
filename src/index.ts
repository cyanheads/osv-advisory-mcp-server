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
  prompts: [],
  instructions:
    'This server provides read-only access to the OSV.dev vulnerability database.\n' +
    '- Use osv_list_ecosystems to discover valid ecosystem identifier strings before querying.\n' +
    '- Use osv_query_package for a single package version: provide {name, ecosystem, version} or {purl, version?}, with exactly one embedded or separate version.\n' +
    '- Use osv_query_batch for dependency audits — mix those tuple and PURL identifiers in the packages array.\n' +
    '- Use osv_query_commit for one full 40- or 64-character hexadecimal Git commit; results retain GIT fix events and record-wide severity without package fixedVersions.\n' +
    '- Use osv_get_vulnerability for the full advisory record when osv_query_package returns a vuln ID.\n' +
    '- For overflow, repeat the original input with page: overflow.page. Continue the same path with offset: page.nextOffset and revision: page.revision until nextOffset is null. Retrieve each entries[].deferred.path separately at offset zero without a revision; do not pass the output page object as input.\n' +
    '- Set page.advisoryId to an announced package advisory ID and retain it on later pages for that advisory’s fixes and severity for the original package. Batch /results/17/... selects original input row 17; row pages do not recompute the initial summary.\n' +
    '- Pages are fresh lookups, not saved snapshots. Use returned node revisions; restart without revision if data changed. Transmission overflow is separate from upstream truncated, and neither confirms clean.\n' +
    '- OSV results include aliases (CVE IDs) — chain these to nist-nvd-mcp-server for CVSS scoring and CISA KEV status.\n' +
    '- No API key required. No rate limit published — prefer batch queries over repeated single queries.',

  setup() {
    const { requestTimeoutMs, batchConcurrency, maxQueryPages } = getServerConfig();
    initOsvApiService({ timeoutMs: requestTimeoutMs, batchConcurrency, maxQueryPages });
  },
});
