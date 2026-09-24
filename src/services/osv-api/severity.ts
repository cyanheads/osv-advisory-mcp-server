/**
 * @fileoverview Derives an OSV record's severity label and names the entry it came from.
 * The first source that yields a label wins: `database_specific.severity`, then an `Ubuntu`
 * priority, then the highest score among the parseable `CVSS_V3`/`CVSS_V4` vectors.
 * @module services/osv-api/severity
 */

import { CVSS } from '@turingpointde/cvss.js';
import type {
  OsvSeveritySource,
  RawOsvAffected,
  RawOsvSeverity,
  RawOsvVulnerability,
} from './types.js';

/** A normalized severity label, highest last. */
type SeverityLabel = 'LOW' | 'MODERATE' | 'HIGH' | 'CRITICAL';

/** `database_specific.severity` spellings (lowercased): GHSA, openEuler, curl, Bitnami. */
const PROVIDER_LABELS = new Map<string, SeverityLabel>([
  ['low', 'LOW'],
  ['moderate', 'MODERATE'],
  ['medium', 'MODERATE'],
  ['high', 'HIGH'],
  ['critical', 'CRITICAL'],
]);

/** Ubuntu priorities with a label; others (`untriaged`, unknown values) are skipped. */
const UBUNTU_PRIORITIES = new Map<string, SeverityLabel>([
  ['negligible', 'LOW'],
  ['low', 'LOW'],
  ['medium', 'MODERATE'],
  ['high', 'HIGH'],
  ['critical', 'CRITICAL'],
]);

/** The derived label and its source — both null when no source yields a label. */
export interface DerivedSeverity {
  severityLabel: SeverityLabel | null;
  severitySource: OsvSeveritySource | null;
}

const NO_SEVERITY: DerivedSeverity = { severityLabel: null, severitySource: null };

/** FIRST qualitative bands. A 0.0 score (no impact) has no label. */
function bandScore(score: number): SeverityLabel | null {
  if (score >= 9) return 'CRITICAL';
  if (score >= 7) return 'HIGH';
  if (score >= 4) return 'MODERATE';
  return score > 0 ? 'LOW' : null;
}

/**
 * Score a vector as published: CVSS 4.0 yields one score over every metric group the vector
 * carries (threat metrics included); CVSS 3.x applies its temporal metrics to the base score.
 * Throws on a malformed vector or an unsupported version.
 */
function scoreVector(vector: string): number {
  const cvss = CVSS(vector);
  return cvss.getVersion() === '4.0' ? cvss.getScore() : cvss.getTemporalScore();
}

/** The highest-scoring parseable CVSS v3/v4 entry. Malformed vectors are skipped. */
function highestCvss(
  entries: RawOsvSeverity[],
): (OsvSeveritySource & { computedScore: number }) | undefined {
  let best: (OsvSeveritySource & { computedScore: number }) | undefined;
  for (const { type, score } of entries) {
    if (type !== 'CVSS_V3' && type !== 'CVSS_V4') continue;
    let computedScore: number;
    try {
      computedScore = scoreVector(score);
    } catch {
      continue;
    }
    if (!best || computedScore > best.computedScore) best = { type, score, computedScore };
  }
  return best;
}

/**
 * Derive the severity label of `raw`. Entries come from the record-level `severity[]`, or when
 * it is empty, from the `severity[]` of the `scope` entries — the affected entries matching a
 * queried package, or every affected entry for a record fetched by ID. `CVSS_V2` sets no label.
 */
export function deriveSeverity(
  raw: RawOsvVulnerability,
  scope: RawOsvAffected[] | undefined,
): DerivedSeverity {
  const published = raw.database_specific?.severity;
  const providerLabel = published && PROVIDER_LABELS.get(published.toLowerCase());
  if (published && providerLabel) {
    return {
      severityLabel: providerLabel,
      severitySource: { type: 'database_specific', score: published },
    };
  }

  const entries = raw.severity?.length
    ? raw.severity
    : (scope ?? []).flatMap((entry) => entry.severity ?? []);

  for (const { type, score } of entries) {
    const ubuntuLabel = type === 'Ubuntu' ? UBUNTU_PRIORITIES.get(score) : undefined;
    if (ubuntuLabel) {
      return { severityLabel: ubuntuLabel, severitySource: { type: 'Ubuntu', score } };
    }
  }

  const cvss = highestCvss(entries);
  const cvssLabel = cvss && bandScore(cvss.computedScore);
  return cvss && cvssLabel ? { severityLabel: cvssLabel, severitySource: cvss } : NO_SEVERITY;
}
