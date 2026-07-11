/**
 * @fileoverview Tool that returns the static list of supported OSV ecosystem identifiers.
 * @module mcp-server/tools/definitions/osv-list-ecosystems
 */

import { tool, z } from '@cyanheads/mcp-ts-core';

/**
 * Supported ecosystem strings from the OSV schema, last verified 2026-07-11.
 * The 49 named ecosystems are the `$defs.ecosystemName` enum in the OSV schema's
 * `validation/schema.json`; `GIT` is additionally accepted through the
 * `$defs.ecosystemWithSuffix` pattern (it is NOT in the named enum) — 50 total.
 * `GSD` is deliberately excluded: it is an OSV vulnerability-ID home-database
 * prefix (e.g. `GSD-2020-1000`, `$defs.prefix`), not an ecosystem — OSV rejects
 * it as one (HTTP 400 `Invalid ecosystem.`).
 * Strings are case-sensitive exact matches required by the OSV API.
 * Source: https://github.com/ossf/osv-schema/blob/main/validation/schema.json
 *         (rendered: https://ossf.github.io/osv-schema/#affectedpackageecosystem-field)
 */
export const SUPPORTED_ECOSYSTEMS: readonly string[] = [
  'AlmaLinux',
  'Alpaquita',
  'Alpine',
  'Android',
  'Azure Linux',
  'BellSoft Hardened Containers',
  'Bioconductor',
  'Bitnami',
  'Chainguard',
  'CleanStart',
  'ConanCenter',
  'CRAN',
  'crates.io',
  'Debian',
  'Docker Hardened Images',
  'Echo',
  'FreeBSD',
  'GHC',
  'GitHub Actions',
  'Go',
  'Hackage',
  'Hex',
  'Julia',
  'Kubernetes',
  'Linux',
  'Mageia',
  'Maven',
  'MinimOS',
  'npm',
  'NuGet',
  'opam',
  'openEuler',
  'openSUSE',
  'OSS-Fuzz',
  'Packagist',
  'Photon OS',
  'Pub',
  'PyPI',
  'Red Hat',
  'Rocky Linux',
  'Root',
  'RubyGems',
  'SUSE',
  'SwiftURL',
  'TuxCare',
  'Ubuntu',
  'vcpkg',
  'VSCode',
  'Wolfi',
  // Accepted via the ecosystemWithSuffix pattern, not the named ecosystemName enum.
  'GIT',
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
        'This list mirrors the OSV schema (validation/schema.json) as of 2026-07-11 — the ' +
        'ecosystemName enum plus GIT. It may lag newly added ecosystems; OSV.dev is the ' +
        'authority at query time. Canonical reference: ' +
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
