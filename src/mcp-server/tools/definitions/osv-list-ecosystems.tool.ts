/**
 * @fileoverview Tool that returns the static list of supported OSV ecosystem identifiers.
 * @module mcp-server/tools/definitions/osv-list-ecosystems
 */

import { tool, z } from '@cyanheads/mcp-ts-core';

/**
 * Supported ecosystem strings, last verified 2026-09-24. The rule: every member of the
 * `$defs.ecosystemName` enum in the OSV schema's `validation/schema.json` that live
 * `POST /v1/query` accepts, plus `GIT` — 51 named + `GIT` = 52. Schema membership alone
 * is not enough: a member OSV.dev still rejects (`Red Hat Lightwell` as of that date,
 * HTTP 400 `invalid ecosystem`) is withheld until it is accepted. `GIT` is valid through
 * the `$defs.ecosystemWithSuffix` pattern, not the named enum. `GSD` is excluded: it is
 * a vulnerability-ID prefix (`GSD-2020-1000`, `$defs.prefix`), not an ecosystem.
 * `bun run check:ecosystems` reports drift against the live schema and API.
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
  'Homebrew',
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
  'WordPress',
  // Accepted via the ecosystemWithSuffix pattern, not the named ecosystemName enum.
  'GIT',
] as const;

export const osvListEcosystems = tool('osv_list_ecosystems', {
  description:
    'Return the supported ecosystem identifier strings for osv_query_package and osv_query_batch: every ecosystem the OSV schema names that OSV.dev accepts at query time, plus GIT, as verified on 2026-09-24. Ecosystem strings are case-sensitive exact matches — passing "pypi" instead of "PyPI" returns an error from the API. Use this tool to discover valid ecosystem strings before querying, or to verify an ecosystem identifier from a lockfile format. The list is static and may lag ecosystems added after that date.',
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
      note: 'Every ecosystem the OSV schema (validation/schema.json) names that OSV.dev accepts at query time, plus GIT, as verified on 2026-09-24. A schema ecosystem OSV.dev does not yet accept is left out until it does. The list may lag later additions; OSV.dev is the authority at query time. Canonical reference: https://ossf.github.io/osv-schema/#affectedpackageecosystem-field',
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
