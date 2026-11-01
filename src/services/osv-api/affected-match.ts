/**
 * @fileoverview Decides which `affected[]` entries of an OSV record belong to a queried
 * package, mirroring OSV.dev's Go ecosystem NormalizeMatchName behavior.
 * Every entry that could have made OSV return the record for the query matches.
 * @module services/osv-api/affected-match
 */

import type { RawOsvPackage } from './types.js';

/** The package a query named, as sent to OSV. */
export interface PackageQuery {
  ecosystem: string;
  name: string;
}

/** Ecosystems whose package names OSV compares after PEP 503 normalization. */
const PEP_503_ECOSYSTEMS = new Set(['PyPI', 'Echo:PyPI', 'Red Hat Lightwell:PyPI']);

/** PEP 503 name normalization: runs of `-`, `_`, `.` become `-`, then lowercase. */
function normalizePep503(name: string): string {
  return name.replace(/[-_.]+/g, '-').toLowerCase();
}

/** Match-name folding leaves non-ASCII letters distinct, as OSV's Go adapter does. */
function normalizeMatchName(name: string, ecosystem: string): string {
  if (PEP_503_ECOSYSTEMS.has(ecosystem)) return normalizePep503(name);
  const base = ecosystem.split(':', 1)[0];
  if (base !== 'NuGet' && base !== 'crates.io') return name;
  const folded = name.replace(/[A-Z]/g, (letter) => letter.toLowerCase());
  return base === 'crates.io' ? folded.replace(/_/g, '-') : folded;
}

/**
 * The query ecosystems OSV indexes an entry ecosystem under: itself, its base (text before the
 * first `:`), and for Ubuntu the ecosystem without its `:Pro` / `:LTS` variants.
 */
function ecosystemMatches(entryEcosystem: string, queriedEcosystem: string): boolean {
  if (queriedEcosystem === entryEcosystem) return true;
  if (queriedEcosystem === entryEcosystem.split(':', 1)[0]) return true;
  return (
    entryEcosystem.startsWith('Ubuntu') &&
    queriedEcosystem === entryEcosystem.replace(':Pro', '').replace(':LTS', '')
  );
}

/**
 * True when an OSV `affected[].package` belongs to the queried package: the queried ecosystem
 * is one the entry is indexed under, and registry-normalized names are equal.
 * Package-less entries (GIT-only source ranges) never match.
 */
export function matchesQueriedPackage(
  entry: RawOsvPackage | undefined,
  query: PackageQuery,
): boolean {
  if (!entry?.name || !entry.ecosystem) return false;
  if (!ecosystemMatches(entry.ecosystem, query.ecosystem)) return false;
  return (
    normalizeMatchName(entry.name, entry.ecosystem) ===
    normalizeMatchName(query.name, entry.ecosystem)
  );
}
