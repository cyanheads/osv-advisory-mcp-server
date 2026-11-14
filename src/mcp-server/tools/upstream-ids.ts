/**
 * @fileoverview Shared schema for upstream advisory IDs.
 * @module mcp-server/tools/upstream-ids
 */
import { z } from '@cyanheads/mcp-ts-core';

/** IDs of vulnerabilities covered by an advisory, kept separately from equivalent aliases. */
export const UpstreamIds = z
  .array(z.string().describe('Upstream vulnerability ID.'))
  .optional()
  .describe(
    'IDs of upstream vulnerabilities covered by this advisory, in OSV order. Use CVE IDs for NVD lookup. Absent when OSV supplies no upstream list.',
  );
