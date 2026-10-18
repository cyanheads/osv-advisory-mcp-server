/**
 * @fileoverview Service wrapping the OSV.dev REST API v1.
 * Handles HTTP fetch, timeout, retry, error body parsing, and normalization of
 * raw API responses to typed domain objects.
 * @module services/osv-api/osv-api-service
 */

import { type Context, z } from '@cyanheads/mcp-ts-core';
import { McpError, serviceUnavailable } from '@cyanheads/mcp-ts-core/errors';
import { fetchWithTimeout, withRetry } from '@cyanheads/mcp-ts-core/utils';
import { matchesQueriedPackage, type PackageQuery } from './affected-match.js';
import {
  type PackageIdentifier,
  packageBody,
  type ResolvedPackage,
  resolvePackage,
} from './package-identifier.js';
import { deriveSeverity } from './severity.js';
import type {
  BatchVulnBrief,
  OsvAffectedRange,
  OsvApiError,
  OsvPackageVulnerability,
  OsvRangeEvent,
  OsvSeverityEntry,
  OsvVulnerability,
  RawOsvAffected,
  RawOsvEvent,
  RawOsvQueryResponse,
  RawOsvSeverity,
  RawOsvVulnerability,
} from './types.js';

const OSV_BASE_URL = 'https://api.osv.dev';

/** Default request timeout in milliseconds. */
const DEFAULT_TIMEOUT_MS = 10_000;

/** Default maximum concurrent outbound requests in {@link OsvApiService.queryBatch}. */
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

/** Bound all batch stages together below the SDK's default 60-second request deadline. */
const BATCH_TIMEOUT_MS = 50_000;

/** Validate positional preflight records before missing fields can be interpreted as clean. */
const BatchResponseSchema = z.object({
  results: z.array(
    z.object({
      vulns: z
        .array(z.object({ id: z.string().min(1), modified: z.string().optional() }))
        .optional(),
      next_page_token: z.string().optional(),
    }),
  ),
});

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

/**
 * Every `fixed` event of the SEMVER/ECOSYSTEM ranges on the entries matching the queried
 * package, deduplicated in record order. GIT ranges carry commit hashes, not versions, and
 * stay visible only in `affectedRanges`. No fallback: with no matching entry the list is empty.
 */
function extractFixedVersions(matching: RawOsvAffected[]): string[] {
  const seen = new Set<string>();
  for (const entry of matching) {
    for (const range of entry.ranges ?? []) {
      if (range.type !== 'SEMVER' && range.type !== 'ECOSYSTEM') continue;
      for (const evt of range.events ?? []) {
        if (evt.fixed !== undefined) seen.add(evt.fixed);
      }
    }
  }
  return [...seen];
}

/** Copy raw severity entries to their normalized shape. */
function toSeverityEntries(entries: RawOsvSeverity[]): OsvSeverityEntry[] {
  return entries.map((s) => ({ type: s.type, score: s.score }));
}

/**
 * Normalize a raw vuln record into a typed OsvVulnerability. `severityScope` is the set of
 * affected entries whose package-level severity may label the record — every entry unless a
 * package query narrows it.
 */
function normalizeVuln(
  raw: RawOsvVulnerability,
  severityScope: RawOsvAffected[] | undefined = raw.affected,
): OsvVulnerability {
  const affectedRanges = extractAffectedRanges(raw.affected);
  const severity = toSeverityEntries(raw.severity ?? []);

  // Package-less entries (GIT-range-only CVE records) are surfaced with empty
  // packageName/ecosystem — they carry the only affected source range and must
  // not be dropped. Each range keeps the ordered events, GIT repo, and explicit
  // versions in addition to the collapsed introduced/fixed/lastAffected scalars.
  const affected = (raw.affected ?? []).map((a) => ({
    packageName: a.package?.name ?? '',
    ecosystem: a.package?.ecosystem ?? '',
    ...(a.package?.purl ? { purl: a.package.purl } : {}),
    ...(a.severity?.length ? { severity: toSeverityEntries(a.severity) } : {}),
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
    ...deriveSeverity(raw, severityScope),
    affected,
    cweIds: raw.database_specific?.cwe_ids ?? [],
    references,
    schemaVersion: raw.schema_version ?? '',
    affectedRanges,
    ...(raw.withdrawn ? { withdrawn: raw.withdrawn } : {}),
  };
}

/**
 * Normalize a vuln returned for a package query, scoping the package-level fields to the
 * queried package: `fixedVersions`, and the affected entries a severity label may come from.
 */
function normalizePackageVuln(
  raw: RawOsvVulnerability,
  query: PackageQuery,
): OsvPackageVulnerability {
  const matching = (raw.affected ?? []).filter((a) => matchesQueriedPackage(a.package, query));
  return {
    ...normalizeVuln(raw, matching),
    fixedVersions: extractFixedVersions(matching),
  };
}

/** Trim a package-query vuln to a batch-output brief. */
function toBrief(vuln: OsvPackageVulnerability): BatchVulnBrief {
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
  /** Maximum concurrent outbound batch requests. Defaults to {@link DEFAULT_BATCH_CONCURRENCY}. */
  batchConcurrency?: number;
  /** Maximum OSV result pages followed per package in either query path. Defaults to {@link DEFAULT_MAX_QUERY_PAGES}. */
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

  /** Query a full Git commit, retaining record-wide severity and source ranges. */
  async queryCommit(
    commit: string,
    ctx: Context,
  ): Promise<
    { vulns: OsvVulnerability[]; truncated: boolean } | { invalid: true; message: string }
  > {
    const boundedCtx = {
      ...ctx,
      signal: AbortSignal.any([ctx.signal, AbortSignal.timeout(BATCH_TIMEOUT_MS)]),
    };
    const vulns: OsvVulnerability[] = [];
    let pageToken: string | undefined;
    for (let page = 0; page < this.maxQueryPages; page++) {
      boundedCtx.signal.throwIfAborted();
      const { status, data } = await postJson<RawOsvQueryResponse>(
        '/v1/query',
        { commit, ...(pageToken ? { page_token: pageToken } : {}) },
        this.timeoutMs,
        boundedCtx,
      );
      if (status === 400) return { invalid: true, message: (data as OsvApiError).message };
      if (status !== 200) throw serviceUnavailable(`OSV API returned HTTP ${status}.`, { status });
      const raw = data as RawOsvQueryResponse;
      for (const record of raw.vulns ?? []) vulns.push(normalizeVuln(record));
      pageToken = raw.next_page_token || undefined;
      if (!pageToken) break;
    }
    return { vulns, truncated: pageToken !== undefined };
  }

  /**
   * Query vulnerabilities for a single package+version.
   * Returns the full vulnerability list or an empty array when none found; each vuln's
   * `fixedVersions` is scoped to the queried package.
   * Throws for network errors; returns { invalid: true } when OSV returns HTTP 400 (invalid ecosystem).
   */
  async queryPackage(
    name: string,
    ecosystem: string,
    version: string,
    ctx: Context,
    identifier?: ResolvedPackage,
  ): Promise<
    | { vulns: OsvPackageVulnerability[]; invalid: false; truncated: boolean }
    | { invalid: true; message: string }
  > {
    const query: PackageQuery = { name, ecosystem };
    const vulns: OsvPackageVulnerability[] = [];
    let pageToken: string | undefined;

    // Follow OSV's next_page_token across pages, accumulating vulns, until the
    // token disappears (result complete) or the page cap is reached. OSV may
    // return a bare token with no vulns on a page, so an empty first page is
    // never assumed clean — a pending token at the cap surfaces as truncated.
    for (let page = 0; page < this.maxQueryPages; page++) {
      const body: ReturnType<typeof packageBody> & { page_token?: string } = packageBody(
        identifier ?? { name, ecosystem, version },
      );
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
      for (const v of raw.vulns ?? []) vulns.push(normalizePackageVuln(v, query));
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

  /** Fetch one advisory and retain the original package matcher for fixes and severity. */
  async getPackageVulnerability(
    id: string,
    query: PackageQuery,
    ctx: Context,
  ): Promise<OsvPackageVulnerability | null> {
    const { status, data } = await getJson<RawOsvVulnerability>(
      `/v1/vulns/${encodeURIComponent(id)}`,
      this.timeoutMs,
      ctx,
    );
    if (status === 404) return null;
    if (status !== 200) throw serviceUnavailable('OSV advisory lookup failed.', { status });
    return normalizePackageVuln(data as RawOsvVulnerability, query);
  }

  /**
   * Positional native ID preflight with per-call raw advisory enrichment. Each row normalizes
   * shared records against its own package. Validation recovery, pagination and detail work
   * share a bounded request pool and operation deadline; caller cancellation propagates.
   */
  async queryBatch(
    packages: PackageIdentifier[],
    ctx: Context,
  ): Promise<
    Array<{
      name: string;
      ecosystem: string;
      version: string;
      purl?: string;
      vulns: BatchVulnBrief[];
      error: string | null;
      truncated: boolean;
    }>
  > {
    const deadline = new AbortController();
    const timer = setTimeout(
      () => deadline.abort(new Error('OSV batch exceeded its 50-second deadline.')),
      BATCH_TIMEOUT_MS,
    );
    const signal = AbortSignal.any([ctx.signal, deadline.signal]);
    const batchCtx = { ...ctx, signal };
    const rows = packages.map((input) => {
      let pkg: ResolvedPackage;
      let error: string | null = null;
      try {
        pkg = resolvePackage(input);
      } catch (cause) {
        pkg = {
          name: '',
          ecosystem: '',
          version: input.version ?? '',
          ...(input.purl === undefined ? {} : { purl: input.purl }),
        };
        error = cause instanceof Error ? cause.message : String(cause);
      }
      return {
        pkg,
        ids: new Set<string>(),
        pageToken: undefined as string | undefined,
        pages: 0,
        error,
      };
    });
    const rawRecords = new Map<string, RawOsvVulnerability>();
    const detailErrors = new Map<string, string>();
    const message = (error: unknown) => (error instanceof Error ? error.message : String(error));
    const checkCancelled = () => ctx.signal.throwIfAborted();
    const bodyFor = (row: (typeof rows)[number]) => ({
      ...packageBody(row.pkg),
      ...(row.pageToken ? { page_token: row.pageToken } : {}),
    });
    const pool = async <T>(items: T[], run: (item: T) => Promise<void>) => {
      let cursor = 0;
      await Promise.all(
        Array.from({ length: Math.min(this.batchConcurrency, items.length) }, async () => {
          while (cursor < items.length) {
            checkCancelled();
            if (signal.aborted) break;
            // biome-ignore lint/style/noNonNullAssertion: cursor is bounded by items.length
            await run(items[cursor++]!);
          }
        }),
      );
    };
    const fallback = async (unresolved: typeof rows) => {
      await pool(unresolved, async (row) => {
        try {
          while (row.pages < this.maxQueryPages) {
            signal.throwIfAborted();
            const { status, data } = await postJson<RawOsvQueryResponse>(
              '/v1/query',
              bodyFor(row),
              this.timeoutMs,
              batchCtx,
            );
            if (status === 400) {
              row.error = (data as OsvApiError).message ?? 'Invalid package query.';
              return;
            }
            if (status !== 200)
              throw serviceUnavailable(`OSV API returned HTTP ${status}.`, { status });
            const raw = data as RawOsvQueryResponse;
            if (
              !raw ||
              typeof raw !== 'object' ||
              Array.isArray(raw) ||
              (raw.vulns !== undefined && !Array.isArray(raw.vulns)) ||
              (raw.next_page_token !== undefined && typeof raw.next_page_token !== 'string')
            ) {
              throw serviceUnavailable('OSV API returned a malformed package page.');
            }
            for (const record of raw.vulns ?? []) {
              if (!record || typeof record.id !== 'string' || !record.id)
                throw serviceUnavailable('OSV API returned an advisory without an ID.');
              row.ids.add(record.id);
              if (!rawRecords.has(record.id)) rawRecords.set(record.id, record);
            }
            row.pages++;
            row.pageToken = raw.next_page_token || undefined;
            if (!row.pageToken) break;
          }
        } catch (error) {
          checkCancelled();
          row.error = message(error);
        }
      });
    };
    try {
      let pending = rows.filter((row) => !row.error);
      let recoveredIndex = false;
      while (pending.length) {
        checkCancelled();
        try {
          signal.throwIfAborted();
          const { status, data } = await postJson<unknown>(
            '/v1/querybatch',
            { queries: pending.map(bodyFor) },
            this.timeoutMs,
            batchCtx,
          );
          if (status === 400) {
            const error = data as OsvApiError;
            const indexMatch = /^error in query at index (\d+):/.exec(error.message ?? '');
            const index = indexMatch ? Number(indexMatch[1]) : -1;
            if (index >= 0 && index < pending.length && !recoveredIndex) {
              // biome-ignore lint/style/noNonNullAssertion: OSV index was checked against submitted cardinality
              pending[index]!.error = error.message;
              pending = pending.filter((_, i) => i !== index);
              recoveredIndex = true;
              continue;
            }
            await fallback(pending);
            break;
          }
          const parsed = BatchResponseSchema.safeParse(data);
          if (status !== 200 || !parsed.success || parsed.data.results.length !== pending.length) {
            throw serviceUnavailable('OSV API returned a malformed or misaligned batch response.', {
              status,
            });
          }
          parsed.data.results.forEach((result, i) => {
            // biome-ignore lint/style/noNonNullAssertion: validated positional cardinality
            const row = pending[i]!;
            for (const vuln of result.vulns ?? []) row.ids.add(vuln.id);
            row.pages++;
            row.pageToken = result.next_page_token || undefined;
          });
          pending = pending.filter((row) => row.pageToken && row.pages < this.maxQueryPages);
        } catch (error) {
          checkCancelled();
          for (const row of pending) row.error = message(error);
          break;
        }
      }
      const ids = [
        ...new Set(rows.filter((row) => !row.error).flatMap((row) => [...row.ids])),
      ].filter((id) => !rawRecords.has(id));
      await pool(ids, async (id) => {
        try {
          const { status, data } = await getJson<RawOsvVulnerability>(
            `/v1/vulns/${encodeURIComponent(id)}`,
            this.timeoutMs,
            batchCtx,
          );
          const record = data as RawOsvVulnerability;
          if (status !== 200 || !record || record.id !== id)
            throw serviceUnavailable(`OSV could not retrieve advisory ${id}.`, { id, status });
          rawRecords.set(id, record);
        } catch (error) {
          checkCancelled();
          detailErrors.set(id, message(error));
        }
      });
      checkCancelled();
      return rows.map((row) => {
        try {
          const error =
            row.error ??
            [...row.ids].map((id) => detailErrors.get(id)).find((value) => value !== undefined) ??
            (signal.aborted &&
            (row.pages === 0 ||
              (row.pageToken && row.pages < this.maxQueryPages) ||
              [...row.ids].some((id) => !rawRecords.has(id)))
              ? message(signal.reason)
              : null);
          if (error) return { ...row.pkg, vulns: [], error, truncated: Boolean(row.pageToken) };
          const vulns = [...row.ids].map((id) => {
            // biome-ignore lint/style/noNonNullAssertion: all IDs have records or a detail error above
            return toBrief(normalizePackageVuln(rawRecords.get(id)!, row.pkg));
          });
          return { ...row.pkg, vulns, error: null, truncated: Boolean(row.pageToken) };
        } catch (error) {
          return {
            ...row.pkg,
            vulns: [],
            error: message(error),
            truncated: Boolean(row.pageToken),
          };
        }
      });
    } finally {
      clearTimeout(timer);
    }
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

export type {
  BatchVulnBrief,
  OsvAffectedRange,
  OsvPackageVulnerability,
  OsvRangeEvent,
  OsvVulnerability,
};
