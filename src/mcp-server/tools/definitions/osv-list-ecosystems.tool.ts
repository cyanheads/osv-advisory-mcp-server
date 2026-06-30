/**
 * @fileoverview Tool that returns the static list of supported OSV ecosystem identifiers.
 * @module mcp-server/tools/definitions/osv-list-ecosystems
 */

import { tool, z } from '@cyanheads/mcp-ts-core';

/**
 * Supported ecosystem strings as of OSV schema spec, last verified 2026-05-30.
 * Strings are case-sensitive exact matches required by the OSV API.
 * Source: https://ossf.github.io/osv-schema/#affectedpackageecosystem-field
 */
export const SUPPORTED_ECOSYSTEMS: readonly string[] = [
  'AlmaLinux',
  'Alpine',
  'Android',
  'Bitnami',
  'Chainguard',
  'CRAN',
  'Debian',
  'GIT',
  'GitHub Actions',
  'Go',
  'GSD',
  'Hackage',
  'Hex',
  'Linux',
  'Maven',
  'NuGet',
  'npm',
  'OSS-Fuzz',
  'Packagist',
  'Pub',
  'PyPI',
  'Rocky Linux',
  'RubyGems',
  'SwiftURL',
  'Wolfi',
  'crates.io',
] as const;

export const osvListEcosystems = tool('osv_list_ecosystems', {
  description:
    'Return the list of supported ecosystem identifier strings for use with osv_query_package and osv_query_batch. ' +
    'Ecosystem strings are case-sensitive exact matches — passing "pypi" instead of "PyPI" returns an error from the API. ' +
    'Use this tool to discover valid ecosystem strings before querying, or to verify an ecosystem identifier ' +
    'from a lockfile format. The list is static (maintained from the OSV schema spec) and may occasionally ' +
    'lag newly added ecosystems.',
  annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: false },

  input: z.object({}),

  output: z.object({
    ecosystems: z
      .array(z.string().describe('A supported ecosystem identifier string.'))
      .describe(
        'Supported ecosystem identifier strings. These are case-sensitive exact matches required by the ecosystem parameter of osv_query_package and osv_query_batch.',
      ),
    note: z.string().describe('Advisory note about list currency and canonical source.'),
  }),

  handler(_input, ctx) {
    ctx.log.info('Listing OSV ecosystems', { count: SUPPORTED_ECOSYSTEMS.length });
    return {
      ecosystems: [...SUPPORTED_ECOSYSTEMS],
      note:
        'This list is maintained from the OSV schema spec as of 2026-05-30 and may lag ' +
        'newly added ecosystems. Canonical reference: ' +
        'https://ossf.github.io/osv-schema/#affectedpackageecosystem-field',
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
