/**
 * @fileoverview Decides which `affected[]` entries of an OSV record belong to a queried
 * package, mirroring how OSV.dev indexes entries for POST /v1/query (osv.dev
 * `osv/models.py` `_affected_versions_from_affected_proto`, `osv/ecosystems/_ecosystems.py`).
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
const PEP_503_ECOSYSTEMS = new Set(['PyPI', 'Echo:PyPI']);

/** PEP 503 name normalization: runs of `-`, `_`, `.` become `-`, then lowercase. */
function normalizePep503(name: string): string {
  return name.replace(/[-_.]+/g, '-').toLowerCase();
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
 * is one the entry is indexed under, and the names are equal — PEP 503-normalized for PyPI.
 * Package-less entries (GIT-only source ranges) never match.
 */
export function matchesQueriedPackage(
  entry: RawOsvPackage | undefined,
  query: PackageQuery,
): boolean {
  if (!entry?.name || !entry.ecosystem) return false;
  if (!ecosystemMatches(entry.ecosystem, query.ecosystem)) return false;
  return PEP_503_ECOSYSTEMS.has(entry.ecosystem)
    ? normalizePep503(entry.name) === normalizePep503(query.name)
    : entry.name === query.name;
}
