/**
 * @fileoverview Service wrapping the OSV.dev REST API v1.
 * Handles HTTP fetch, timeout, retry, error body parsing, and normalization of
 * raw API responses to typed domain objects.
 * @module services/osv-api/osv-api-service
 */

import type { Context } from '@cyanheads/mcp-ts-core';
import { McpError, serviceUnavailable } from '@cyanheads/mcp-ts-core/errors';
import { fetchWithTimeout, withRetry } from '@cyanheads/mcp-ts-core/utils';
import type {
  BatchVulnBrief,
  OsvAffectedRange,
  OsvApiError,
  OsvRangeEvent,
  OsvSeverityEntry,
  OsvVulnerability,
  RawOsvAffected,
  RawOsvEvent,
  RawOsvQueryResponse,
  RawOsvVulnerability,
} from './types.js';

const OSV_BASE_URL = 'https://api.osv.dev';

/** Default request timeout in milliseconds. */
const DEFAULT_TIMEOUT_MS = 10_000;

/** Default maximum concurrent per-package queries in {@link OsvApiService.queryBatch}. */
const DEFAULT_BATCH_CONCURRENCY = 10;

/**
 * Default cap on OSV result pages {@link OsvApiService.queryPackage} will follow
 * before marking a result truncated. OSV paginates above 1,000 results or when
 * query processing exceeds ~20s, and may return a bare `next_page_token` with no
 * vulns; the cap bounds total work per logical query (the per-attempt HTTP
 * timeout is not cumulative). A remaining token at the cap surfaces as truncated.
 */
const DEFAULT_MAX_QUERY_PAGES = 10;

/** Maximum retries after the initial request. */
const MAX_RETRIES = 2;

/** Base delay for exponential backoff. */
const BASE_DELAY_MS = 500;

// ---------------------------------------------------------------------------
// Normalization helpers
// ---------------------------------------------------------------------------

/**
 * Convert a raw OSV event array into ordered {@link OsvRangeEvent} tuples. Each
 * raw event object carries exactly one boundary key; iteration order is preserved
 * so multiple introduced/fixed intervals survive instead of collapsing to one.
 */
function extractEvents(events: RawOsvEvent[] | undefined): OsvRangeEvent[] {
  const out: OsvRangeEvent[] = [];
  for (const evt of events ?? []) {
    if (evt.introduced !== undefined) out.push({ type: 'introduced', value: evt.introduced });
    else if (evt.fixed !== undefined) out.push({ type: 'fixed', value: evt.fixed });
    else if (evt.last_affected !== undefined)
      out.push({ type: 'last_affected', value: evt.last_affected });
    else if (evt.limit !== undefined) out.push({ type: 'limit', value: evt.limit });
  }
  return out;
}

/**
 * Extract all flat affected ranges from an affected array. Package-less entries
 * (e.g. GIT-range-only CVE records) are surfaced with empty packageName/ecosystem
 * rather than dropped, so no affected source range is silently lost. Each range
 * carries the ordered `events` array, the GIT `repo`, and the parent entry's
 * explicit `versions` alongside the collapsed introduced/fixed/lastAffected view.
 */
function extractAffectedRanges(affected: RawOsvAffected[] | undefined): OsvAffectedRange[] {
  const out: OsvAffectedRange[] = [];
  for (const entry of affected ?? []) {
    const pkgName = entry.package?.name ?? '';
    const ecosystem = entry.package?.ecosystem ?? '';
    const versions = entry.versions ?? [];
    for (const range of entry.ranges ?? []) {
      const rangeType = range.type ?? '';
      let introduced: string | undefined;
      let fixed: string | undefined;
      let lastAffected: string | undefined;
      for (const evt of range.events ?? []) {
        if (evt.introduced !== undefined) introduced = evt.introduced;
        if (evt.fixed !== undefined) fixed = evt.fixed;
        if (evt.last_affected !== undefined) lastAffected = evt.last_affected;
      }
      const rangeEntry: OsvAffectedRange = {
        packageName: pkgName,
        ecosystem,
        rangeType,
        events: extractEvents(range.events),
        versions,
      };
      if (introduced !== undefined) rangeEntry.introduced = introduced;
      if (fixed !== undefined) rangeEntry.fixed = fixed;
      if (lastAffected !== undefined) rangeEntry.lastAffected = lastAffected;
      if (range.repo !== undefined) rangeEntry.repo = range.repo;
      out.push(rangeEntry);
    }
  }
  return out;
}

/** Extract distinct fixed versions from affected ranges. */
function extractFixedVersions(ranges: OsvAffectedRange[]): string[] {
  const seen = new Set<string>();
  for (const r of ranges) {
    if (r.fixed) seen.add(r.fixed);
  }
  return [...seen];
}

/** Derive severity label from database_specific. Returns null when absent or unrecognizable. */
function deriveSeverityLabel(raw: RawOsvVulnerability): string | null {
  const label = raw.database_specific?.severity;
  if (!label) return null;
  const normalized = label.toUpperCase();
  if (['LOW', 'MODERATE', 'HIGH', 'CRITICAL'].includes(normalized)) return normalized;
  return null;
}

/** Normalize a raw vuln record into a typed OsvVulnerability. */
function normalizeVuln(raw: RawOsvVulnerability): OsvVulnerability {
  const affectedRanges = extractAffectedRanges(raw.affected);
  const fixedVersions = extractFixedVersions(affectedRanges);
  const severityLabel = deriveSeverityLabel(raw);
  const severity: OsvSeverityEntry[] = (raw.severity ?? []).map((s) => ({
    type: s.type,
    score: s.score,
  }));

  // Package-less entries (GIT-range-only CVE records) are surfaced with empty
  // packageName/ecosystem — they carry the only affected source range and must
  // not be dropped. Each range keeps the ordered events, GIT repo, and explicit
  // versions in addition to the collapsed introduced/fixed/lastAffected scalars.
  const affected = (raw.affected ?? []).map((a) => ({
    packageName: a.package?.name ?? '',
    ecosystem: a.package?.ecosystem ?? '',
    ...(a.package?.purl ? { purl: a.package.purl } : {}),
    versions: a.versions ?? [],
    ranges: (a.ranges ?? []).map((r) => {
      const out: {
        rangeType: string;
        introduced?: string;
        fixed?: string;
        lastAffected?: string;
        repo?: string;
        events?: OsvRangeEvent[];
      } = { rangeType: r.type ?? '', events: extractEvents(r.events) };
      for (const evt of r.events ?? []) {
        if (evt.introduced !== undefined) out.introduced = evt.introduced;
        if (evt.fixed !== undefined) out.fixed = evt.fixed;
        if (evt.last_affected !== undefined) out.lastAffected = evt.last_affected;
      }
      if (r.repo !== undefined) out.repo = r.repo;
      return out;
    }),
  }));

  const references = (raw.references ?? []).map((ref) => ({
    type: ref.type ?? '',
    url: ref.url ?? '',
  }));

  return {
    id: raw.id ?? '',
    summary: raw.summary ?? '',
    details: raw.details ?? '',
    aliases: raw.aliases ?? [],
    published: raw.published ?? '',
    modified: raw.modified ?? '',
    severity,
    severityLabel,
    affected,
    cweIds: raw.database_specific?.cwe_ids ?? [],
    references,
    schemaVersion: raw.schema_version ?? '',
    affectedRanges,
    fixedVersions,
    ...(raw.withdrawn ? { withdrawn: raw.withdrawn } : {}),
  };
}

/** Trim a full OsvVulnerability to a batch-output brief. */
function toBrief(vuln: OsvVulnerability): BatchVulnBrief {
  return {
    id: vuln.id,
    summary: vuln.summary,
    aliases: vuln.aliases,
    severityLabel: vuln.severityLabel,
    fixedVersions: vuln.fixedVersions,
  };
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

/** Parse an OSV response body, preserving malformed upstream payloads as typed failures. */
function parseJson<T>(text: string, url: string): T {
  try {
    return JSON.parse(text) as T;
  } catch (error) {
    throw serviceUnavailable('OSV API returned malformed JSON.', { url }, { cause: error });
  }
}

/** Fetch and parse JSON with framework timeout, cancellation, status, and retry handling. */
function requestJson<T>(
  url: string,
  init: RequestInit,
  expectedStatuses: number[],
  timeoutMs: number,
  ctx: Context,
): Promise<{ status: number; data: T | OsvApiError }> {
  return withRetry(
    async () => {
      try {
        const response = await fetchWithTimeout(url, timeoutMs, ctx, {
          ...init,
          expectedStatuses,
          signal: ctx.signal,
        });
        return {
          status: response.status,
          data: parseJson<T>(await response.text(), url),
        };
      } catch (error) {
        if (!(error instanceof McpError)) throw error;
        const status = error.data?.status;
        if (
          typeof status !== 'number' ||
          !expectedStatuses.includes(status) ||
          typeof error.data?.body !== 'string'
        ) {
          throw error;
        }
        return {
          status,
          data: parseJson<OsvApiError>(error.data.body, url),
        };
      }
    },
    {
      operation: 'OsvApiService.requestJson',
      context: ctx,
      baseDelayMs: BASE_DELAY_MS,
      maxRetries: MAX_RETRIES,
      signal: ctx.signal,
    },
  );
}

/** POST JSON to an OSV endpoint, parse the response body. */
function postJson<T>(
  path: string,
  body: unknown,
  timeoutMs: number,
  ctx: Context,
): Promise<{ status: number; data: T | OsvApiError }> {
  const url = `${OSV_BASE_URL}${path}`;
  return requestJson<T>(
    url,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify(body),
    },
    [400],
    timeoutMs,
    ctx,
  );
}

/** GET from an OSV endpoint, parse the response body. */
function getJson<T>(
  path: string,
  timeoutMs: number,
  ctx: Context,
): Promise<{ status: number; data: T | OsvApiError }> {
  const url = `${OSV_BASE_URL}${path}`;
  return requestJson<T>(
    url,
    { method: 'GET', headers: { Accept: 'application/json' } },
    [404],
    timeoutMs,
    ctx,
  );
}

// ---------------------------------------------------------------------------
// Service class
// ---------------------------------------------------------------------------

/** Construction options for {@link OsvApiService}. */
export interface OsvApiServiceOptions {
  /** Maximum concurrent per-package queries in {@link OsvApiService.queryBatch}. Defaults to {@link DEFAULT_BATCH_CONCURRENCY}. */
  batchConcurrency?: number;
  /** Maximum OSV result pages followed per logical query in {@link OsvApiService.queryPackage}. Defaults to {@link DEFAULT_MAX_QUERY_PAGES}. */
  maxQueryPages?: number;
  /** HTTP request timeout in milliseconds. Defaults to {@link DEFAULT_TIMEOUT_MS}. */
  timeoutMs?: number;
}

export class OsvApiService {
  private readonly timeoutMs: number;
  private readonly batchConcurrency: number;
  private readonly maxQueryPages: number;

  constructor(options: OsvApiServiceOptions = {}) {
    this.timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.batchConcurrency = options.batchConcurrency ?? DEFAULT_BATCH_CONCURRENCY;
    this.maxQueryPages = options.maxQueryPages ?? DEFAULT_MAX_QUERY_PAGES;
  }

  /**
   * Query vulnerabilities for a single package+version.
   * Returns the full vulnerability list or an empty array when none found.
   * Throws for network errors; returns { invalid: true } when OSV returns HTTP 400 (invalid ecosystem).
   */
  async queryPackage(
    name: string,
    ecosystem: string,
    version: string,
    ctx: Context,
  ): Promise<
    | { vulns: OsvVulnerability[]; invalid: false; truncated: boolean }
    | { invalid: true; message: string }
  > {
    const vulns: OsvVulnerability[] = [];
    let pageToken: string | undefined;

    // Follow OSV's next_page_token across pages, accumulating vulns, until the
    // token disappears (result complete) or the page cap is reached. OSV may
    // return a bare token with no vulns on a page, so an empty first page is
    // never assumed clean — a pending token at the cap surfaces as truncated.
    for (let page = 0; page < this.maxQueryPages; page++) {
      const body: {
        version: string;
        package: { name: string; ecosystem: string };
        page_token?: string;
      } = { version, package: { name, ecosystem } };
      if (pageToken) body.page_token = pageToken;

      const { status, data } = await postJson<RawOsvQueryResponse>(
        '/v1/query',
        body,
        this.timeoutMs,
        ctx,
      );

      if (status === 400) {
        const err = data as OsvApiError;
        return { invalid: true, message: err.message ?? 'Invalid ecosystem.' };
      }
      if (status !== 200) {
        throw serviceUnavailable(`OSV API returned HTTP ${status}.`, { status });
      }

      const raw = data as RawOsvQueryResponse;
      // Empty object `{}` means no vulns on this page — treat missing `vulns` as empty.
      for (const v of raw.vulns ?? []) vulns.push(normalizeVuln(v));
      pageToken = raw.next_page_token || undefined;
      if (!pageToken) break;
    }

    // A token still in hand means OSV had more pages than the cap allowed.
    const truncated = pageToken !== undefined;

    ctx.log.debug('OSV query result', {
      name,
      ecosystem,
      version,
      vulnCount: vulns.length,
      truncated,
    });
    return { invalid: false, vulns, truncated };
  }

  /**
   * Fetch the full record for a single OSV vulnerability ID.
   * Returns null when the ID does not exist (HTTP 404).
   */
  async getVulnerability(id: string, ctx: Context): Promise<OsvVulnerability | null> {
    const { status, data } = await getJson<RawOsvVulnerability>(
      `/v1/vulns/${encodeURIComponent(id)}`,
      this.timeoutMs,
      ctx,
    );

    if (status === 404) return null;

    if (status !== 200) {
      throw serviceUnavailable(`OSV API returned HTTP ${status} for vuln ${id}.`, { id, status });
    }

    return normalizeVuln(data as RawOsvVulnerability);
  }

  /**
   * Batch vulnerability query over multiple packages using per-package POST /v1/query.
   * This approach (vs /v1/querybatch) gives full records including `aliases` in one pass.
   *
   * Queries run through a bounded worker pool of at most `batchConcurrency` in-flight
   * requests, so a large batch (up to 1000 packages) never turns one MCP call into an
   * unbounded upstream burst. Results are positional (`result[i]` ↔ `packages[i]`).
   *
   * Returns per-package results with partial-success semantics:
   * a per-package error (e.g. invalid ecosystem) is reported inline without aborting the batch.
   */
  async queryBatch(
    packages: Array<{ name: string; ecosystem: string; version: string }>,
    ctx: Context,
  ): Promise<
    Array<{
      name: string;
      ecosystem: string;
      version: string;
      vulns: BatchVulnBrief[];
      error: string | null;
      truncated: boolean;
    }>
  > {
    // Bounded concurrency: drain packages through a worker pool of at most
    // `batchConcurrency` in-flight queries instead of fanning out all at once.
    // Each worker pulls the next index off a shared cursor and writes its outcome
    // positionally, preserving `settledResults[i]` ↔ `packages[i]` and the same
    // per-package partial-success semantics as Promise.allSettled.
    type PackageQueryResult = Awaited<ReturnType<OsvApiService['queryPackage']>>;
    const settledResults = new Array<PromiseSettledResult<PackageQueryResult>>(packages.length);
    let cursor = 0;
    const worker = async (): Promise<void> => {
      while (cursor < packages.length) {
        const i = cursor++;
        // biome-ignore lint/style/noNonNullAssertion: i is bounded by cursor < packages.length
        const pkg = packages[i]!;
        try {
          settledResults[i] = {
            status: 'fulfilled',
            value: await this.queryPackage(pkg.name, pkg.ecosystem, pkg.version, ctx),
          };
        } catch (reason) {
          settledResults[i] = { status: 'rejected', reason };
        }
      }
    };
    const poolSize = Math.min(this.batchConcurrency, packages.length);
    await Promise.all(Array.from({ length: poolSize }, () => worker()));

    return settledResults.map((settled, i) => {
      // packages and results are same-length (results derives from packages.map)
      // biome-ignore lint/style/noNonNullAssertion: same-length guarantee
      const pkg = packages[i]!;
      if (settled.status === 'rejected') {
        return {
          name: pkg.name,
          ecosystem: pkg.ecosystem,
          version: pkg.version,
          vulns: [],
          error: (settled.reason as Error).message ?? 'Unknown error',
          truncated: false,
        };
      }
      const result = settled.value;
      if (result.invalid) {
        return {
          name: pkg.name,
          ecosystem: pkg.ecosystem,
          version: pkg.version,
          vulns: [],
          error: result.message,
          truncated: false,
        };
      }
      return {
        name: pkg.name,
        ecosystem: pkg.ecosystem,
        version: pkg.version,
        vulns: result.vulns.map(toBrief),
        error: null,
        truncated: result.truncated,
      };
    });
  }
}

// ---------------------------------------------------------------------------
// Init / accessor pattern
// ---------------------------------------------------------------------------

let _service: OsvApiService | undefined;

export function initOsvApiService(options?: OsvApiServiceOptions): void {
  _service = new OsvApiService(options);
}

export function getOsvApiService(): OsvApiService {
  if (!_service) {
    throw new Error('OsvApiService not initialized — call initOsvApiService() in setup()');
  }
  return _service;
}

export type { BatchVulnBrief, OsvAffectedRange, OsvRangeEvent, OsvVulnerability };
