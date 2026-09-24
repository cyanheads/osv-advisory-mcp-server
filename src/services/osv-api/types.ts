/**
 * @fileoverview Domain types for the OSV.dev API v1 service.
 * Covers raw API shapes, normalized output shapes, and service params.
 * @module services/osv-api/types
 */

// ---------------------------------------------------------------------------
// Raw API response shapes
// ---------------------------------------------------------------------------

/**
 * Raw severity entry from OSV API. The schema defines `CVSS_V2`, `CVSS_V3`, `CVSS_V4` (score is
 * a vector) and `Ubuntu` (score is an Ubuntu priority); other types pass through untouched.
 */
export interface RawOsvSeverity {
  score: string;
  type: string;
}

/** Raw event in an affected range. Each event object carries exactly one boundary key. */
export interface RawOsvEvent {
  fixed?: string;
  introduced?: string;
  last_affected?: string;
  /** OSV's fourth event type — an upper bound on a fuzzed range (rare). */
  limit?: string;
}

/** Raw version range in an affected entry. */
export interface RawOsvRange {
  events?: RawOsvEvent[];
  /** Source repository URL — populated on GIT ranges, absent on version ranges. */
  repo?: string;
  type: 'SEMVER' | 'ECOSYSTEM' | 'GIT';
}

/** Raw package descriptor. */
export interface RawOsvPackage {
  ecosystem?: string;
  name?: string;
  purl?: string;
}

/** Raw affected entry. */
export interface RawOsvAffected {
  package?: RawOsvPackage;
  ranges?: RawOsvRange[];
  /** Package-level severity — set only when the record-level `severity` is not. */
  severity?: RawOsvSeverity[];
  /** Explicitly enumerated affected versions, when the advisory lists them. */
  versions?: string[];
}

/** Raw reference entry. */
export interface RawOsvReference {
  type?: string;
  url?: string;
}

/** Database-specific fields (GHSA-sourced). */
export interface RawOsvDatabaseSpecific {
  cwe_ids?: string[];
  severity?: string;
}

/** Full vulnerability record as returned by POST /v1/query and GET /v1/vulns/{id}. */
export interface RawOsvVulnerability {
  affected?: RawOsvAffected[];
  aliases?: string[];
  database_specific?: RawOsvDatabaseSpecific;
  details?: string;
  id?: string;
  modified?: string;
  published?: string;
  references?: RawOsvReference[];
  schema_version?: string;
  severity?: RawOsvSeverity[];
  summary?: string;
  /** ISO 8601 timestamp present only on withdrawn advisories. */
  withdrawn?: string;
}

/** Abbreviated vuln entry as returned inside POST /v1/querybatch results. */
export interface RawOsvBatchVulnEntry {
  id?: string;
  modified?: string;
}

/** Response envelope from POST /v1/query (success). */
export interface RawOsvQueryResponse {
  /** Opaque continuation token — present when more result pages remain. */
  next_page_token?: string;
  vulns?: RawOsvVulnerability[];
}

/** Single positional result inside POST /v1/querybatch response. */
export interface RawOsvBatchResultEntry {
  vulns?: RawOsvBatchVulnEntry[];
}

/** Response envelope from POST /v1/querybatch. */
export interface RawOsvQueryBatchResponse {
  results?: RawOsvBatchResultEntry[];
}

/** Google API error body. */
export interface OsvApiError {
  code: number;
  message: string;
}

// ---------------------------------------------------------------------------
// Normalized output shapes
// ---------------------------------------------------------------------------

/** Normalized severity entry. */
export interface OsvSeverityEntry {
  score: string;
  type: string;
}

/** Where a `severityLabel` came from. */
export type OsvSeveritySourceType = 'database_specific' | 'Ubuntu' | 'CVSS_V3' | 'CVSS_V4';

/** The severity entry a `severityLabel` was derived from. */
export interface OsvSeveritySource {
  /** Score computed from a CVSS vector as published: every CVSS 4.0 metric group it carries, CVSS 3.x temporal metrics. */
  computedScore?: number;
  /** The published value: `database_specific.severity`, an Ubuntu priority, or a CVSS vector. */
  score: string;
  type: OsvSeveritySourceType;
}

/**
 * Ordered event within an affected range. Preserves interval boundaries the
 * collapsed scalar fields (`introduced`/`fixed`/`lastAffected`) cannot express
 * when a range carries multiple introduced/fixed pairs.
 */
export interface OsvRangeEvent {
  /** Boundary type: 'introduced', 'fixed', 'last_affected', or 'limit'. */
  type: string;
  /** Version string or commit identifier at this boundary. */
  value: string;
}

/** Normalized affected version range for output. */
export interface OsvAffectedRange {
  ecosystem: string;
  /** Ordered event boundaries — the loss-free view of the range's intervals. */
  events?: OsvRangeEvent[];
  fixed?: string;
  introduced?: string;
  lastAffected?: string;
  packageName: string;
  rangeType: string;
  /** Source repository URL for GIT ranges (absent for version ranges). */
  repo?: string;
  /** Explicit affected versions listed on the parent affected entry. */
  versions?: string[];
}

/** Normalized vulnerability record (full). */
export interface OsvVulnerability {
  affected: Array<{
    packageName: string;
    ecosystem: string;
    purl?: string;
    /** Package-level severity entries — present only when the record carries them here. */
    severity?: OsvSeverityEntry[];
    /** Explicitly enumerated affected versions, when the advisory lists them. */
    versions?: string[];
    ranges: Array<{
      rangeType: string;
      introduced?: string;
      fixed?: string;
      lastAffected?: string;
      /** Source repository URL for GIT ranges (absent for version ranges). */
      repo?: string;
      /** Ordered event boundaries — the loss-free interval view. */
      events?: OsvRangeEvent[];
    }>;
  }>;
  /** Flat ranges extracted for query output. */
  affectedRanges: OsvAffectedRange[];
  aliases: string[];
  cweIds: string[];
  details: string;
  id: string;
  modified: string;
  published: string;
  references: Array<{ type: string; url: string }>;
  schemaVersion: string;
  severity: OsvSeverityEntry[];
  severityLabel: string | null;
  /** The entry `severityLabel` was derived from; null exactly when the label is. */
  severitySource: OsvSeveritySource | null;
  summary: string;
  /** ISO 8601 timestamp present only on withdrawn advisories. */
  withdrawn?: string;
}

/** A vulnerability returned for a package query, with fields scoped to that package. */
export interface OsvPackageVulnerability extends OsvVulnerability {
  /**
   * Every `fixed` event of the SEMVER/ECOSYSTEM ranges on the `affected[]` entries matching
   * the queried package, deduplicated in record order. Other packages' fixes and GIT commits
   * are excluded; empty when no matching entry lists a fix.
   */
  fixedVersions: string[];
}

/** Brief per-package vuln entry for batch output. */
export interface BatchVulnBrief {
  aliases: string[];
  /** The queried package's fixed versions — see {@link OsvPackageVulnerability.fixedVersions}. */
  fixedVersions: string[];
  id: string;
  severityLabel: string | null;
  summary: string;
}
