/**
 * @fileoverview Tool that returns the static list of supported OSV ecosystem identifiers.
 * @module mcp-server/tools/definitions/osv-list-ecosystems
 */

import { tool, z } from '@cyanheads/mcp-ts-core';
import { SUPPORTED_ECOSYSTEMS } from '../../../services/osv-api/ecosystem-catalog.js';

export const osvListEcosystems = tool('osv_list_ecosystems', {
  description:
    'Return the supported ecosystem base names for osv_query_package and osv_query_batch: every ecosystem the OSV schema names that OSV.dev accepts at query time, plus GIT, as verified on 2026-10-31. Known base names are case-insensitive. Preserve suffix spelling. Alpine needs a release branch, such as Alpine:v3.17. The list is static and may lag ecosystems added after that date.',
  annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: false },

  input: z.object({}),

  output: z.object({
    ecosystems: z
      .array(z.string().describe('A supported ecosystem identifier string.'))
      .describe(
        'Canonical ecosystem base names recognized by osv_query_package and osv_query_batch.',
      ),
    note: z.string().describe('Advisory note about list currency and canonical source.'),
  }),

  handler(_input, ctx) {
    ctx.log.info('Listing OSV ecosystems', { count: SUPPORTED_ECOSYSTEMS.length });
    return {
      ecosystems: [...SUPPORTED_ECOSYSTEMS],
      note: 'Every ecosystem the OSV schema (validation/schema.json) names that OSV.dev accepts at query time, plus GIT, as verified on 2026-10-31. Known base names are case-insensitive. Preserve suffix spelling. For Alpine, add a colon, v, and the major.minor release branch, such as Alpine:v3.17. The list may lag later additions. Canonical reference: https://ossf.github.io/osv-schema/#affectedpackageecosystem-field',
    };
  },

  format: (result) => {
    const lines: string[] = [];
    lines.push(`**Supported Ecosystems (${result.ecosystems.length}):**\n`);
    lines.push(result.ecosystems.map((e) => `- \`${e}\``).join('\n'));
    lines.push(`\n_${result.note}_`);
    return [{ type: 'text', text: lines.join('\n') }];
  },
});
