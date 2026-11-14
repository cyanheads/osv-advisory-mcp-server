/** @fileoverview Canonical names used by OSV queries and ecosystem discovery. */
/**
 * Supported ecosystem strings, last verified 2026-10-31. The rule: every member of the
 * `$defs.ecosystemName` enum in the OSV schema's `validation/schema.json` that live
 * `POST /v1/query` accepts, plus `GIT` — 53 named + `GIT` = 54. Schema membership alone
 * is not enough: a member OSV.dev still rejects is withheld until it is accepted. `GIT` is valid through
 * the `$defs.ecosystemWithSuffix` pattern, not the named enum. `GSD` is excluded: it is
 * a vulnerability-ID prefix (`GSD-2020-1000`, `$defs.prefix`), not an ecosystem.
 * `bun run check:ecosystems` reports drift against the live schema and API.
 * Entries use the canonical case OSV.dev requires on the wire.
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
  'Raspberry Pi OS',
  'Red Hat',
  'Red Hat Lightwell',
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

const byFoldedName = new Map<string, string | undefined>();
for (const ecosystem of SUPPORTED_ECOSYSTEMS) {
  const folded = ecosystem.toLowerCase();
  byFoldedName.set(folded, byFoldedName.has(folded) ? undefined : ecosystem);
}

/** Fold a known base name to its canonical spelling, preserving any suffix verbatim. */
export function canonicalEcosystem(ecosystem: string): string {
  const separator = ecosystem.indexOf(':');
  const base = separator < 0 ? ecosystem : ecosystem.slice(0, separator);
  const canonical = byFoldedName.get(base.toLowerCase());
  if (canonical === undefined || canonical === base) return ecosystem;
  return separator < 0 ? canonical : canonical + ecosystem.slice(separator);
}
