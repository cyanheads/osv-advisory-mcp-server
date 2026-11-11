/**
 * @fileoverview Service wrapping the OSV.dev REST API v1.
 * Handles HTTP fetch, timeout, retry, error body parsing, and normalization of
 * raw API responses to typed domain objects.
 * @module services/osv-api/osv-api-service
 */

import { type Context, z } from '@cyanheads/mcp-ts-core';
import { McpError, serviceUnavailable, timeout } from '@cyanheads/mcp-ts-core/errors';
import { fetchWithTimeout, withRetry } from '@cyanheads/mcp-ts-core/utils';
import { DEFAULT_REQUEST_TIMEOUT_MS } from '@/config/server-config.js';
import { matchesQueriedPackage, type PackageQuery } from './affected-match.js';
import {
  type PackageIdentifier,
  packageBody,
  type ResolvedPackage,
  resolvePackage,
} from './package-identifier.js';
import { decodeQueryCursor, encodeQueryCursor, invalidCursor } from './query-cursor.js';
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

/** Default maximum concurrent outbound requests in {@link OsvApiService.queryBatch}. */
const DEFAULT_BATCH_CONCURRENCY = 10;

/**
 * Default cap on OSV result pages {@link OsvApiService.queryPackage} will follow
 * before marking a result truncated. OSV can time-slice a query and return a
 * bare `next_page_token` with no vulns.
 */
const DEFAULT_MAX_QUERY_PAGES = 10;

/** Maximum retries after the initial request. */
const MAX_RETRIES = 2;

/** Base delay for exponential backoff. */
const BASE_DELAY_MS = 500;

/** Bound all query stages below the SDK's default 60-second request deadline. */
const QUERY_DEADLINE_MS = 50_000;

function startQueryDeadline(ctx: Context) {
  const deadline = new AbortController();
  const reason = new DOMException('OSV query exceeded its 50-second deadline.', 'TimeoutError');
  const timer = setTimeout(() => deadline.abort(reason), QUERY_DEADLINE_MS);
  return {
    ctx: { ...ctx, signal: AbortSignal.any([ctx.signal, deadline.signal]) },
    expired: () => deadline.signal.aborted,
    reason,
    stop: () => clearTimeout(timer),
  };
}

interface QueryFindings<T> {
  nextCursor?: string;
  truncated: boolean;
  vulns: T[];
}

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
      ctx.signal.throwIfAborted();
      try {
        const response = await fetchWithTimeout(url, timeoutMs, ctx, {
          ...init,
          expectedStatuses,
          signal: ctx.signal,
        });
        const text = await response.text();
        ctx.signal.throwIfAborted();
        return { status: response.status, data: parseJson<T>(text, url) };
      } catch (error) {
        ctx.signal.throwIfAborted();
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
  /** HTTP request timeout in milliseconds. Defaults to {@link DEFAULT_REQUEST_TIMEOUT_MS}. */
  timeoutMs?: number;
}

export class OsvApiService {
  private readonly timeoutMs: number;
  private readonly batchConcurrency: number;
  private readonly maxQueryPages: number;

  constructor(options: OsvApiServiceOptions = {}) {
    this.timeoutMs = options.timeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS;
    this.batchConcurrency = options.batchConcurrency ?? DEFAULT_BATCH_CONCURRENCY;
    this.maxQueryPages = options.maxQueryPages ?? DEFAULT_MAX_QUERY_PAGES;
  }

  /** Query a full Git commit, retaining record-wide severity and source ranges. */
  queryCommit(
    commit: string,
    ctx: Context,
    cursor?: string,
  ): Promise<QueryFindings<OsvVulnerability> | { invalid: true; message: string }> {
    return this.queryPages({ commit }, (record) => normalizeVuln(record), ctx, cursor, {
      commit: commit.toLowerCase(),
    });
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
    cursor?: string,
  ): Promise<
    | (QueryFindings<OsvPackageVulnerability> & { invalid: false })
    | { invalid: true; message: string }
  > {
    const query: PackageQuery = { name, ecosystem };
    const result = await this.queryPages(
      packageBody(identifier ?? { name, ecosystem, version }),
      (record) => normalizePackageVuln(record, query),
      ctx,
      cursor,
    );
    return 'invalid' in result ? result : { ...result, invalid: false };
  }

  private async queryPages<T>(
    body: object,
    normalize: (record: RawOsvVulnerability) => T,
    ctx: Context,
    cursor?: string,
    identity = body,
  ): Promise<QueryFindings<T> | { invalid: true; message: string }> {
    let pageToken = cursor === undefined ? undefined : decodeQueryCursor(identity, cursor);
    const deadline = startQueryDeadline(ctx);
    const vulns: T[] = [];
    let completed = 0;
    try {
      for (; completed < this.maxQueryPages; completed++) {
        const { status, data } = await postJson<RawOsvQueryResponse>(
          '/v1/query',
          { ...body, ...(pageToken ? { page_token: pageToken } : {}) },
          this.timeoutMs,
          deadline.ctx,
        );
        if (status === 400) {
          const { message } = data as OsvApiError;
          if (message?.trim().toLowerCase() === 'invalid cursor') throw invalidCursor();
          return { invalid: true, message: message ?? 'Invalid OSV query.' };
        }
        if (status !== 200)
          throw serviceUnavailable(`OSV API returned HTTP ${status}.`, { status });
        const raw = data as RawOsvQueryResponse;
        for (const record of raw.vulns ?? []) vulns.push(normalize(record));
        pageToken = raw.next_page_token || undefined;
        if (!pageToken) break;
      }
    } catch (error) {
      ctx.signal.throwIfAborted();
      if (!deadline.expired()) throw error;
      if (!completed || !pageToken) throw timeout(deadline.reason.message, {}, { cause: error });
    } finally {
      deadline.stop();
    }
    return {
      vulns,
      truncated: pageToken !== undefined,
      ...(pageToken === undefined ? {} : { nextCursor: encodeQueryCursor(identity, pageToken) }),
    };
  }

  /** Check a package cursor before a direct advisory lookup on a resumed result. */
  validatePackageCursor(pkg: ResolvedPackage, cursor: string): void {
    decodeQueryCursor(packageBody(pkg), cursor);
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
    Array<
      {
        name: string;
        ecosystem: string;
        version: string;
        purl?: string;
        error: string | null;
      } & QueryFindings<BatchVulnBrief>
    >
  > {
    const deadline = startQueryDeadline(ctx);
    const batchCtx = deadline.ctx;
    const { signal } = batchCtx;
    const rows = packages.map((input) => {
      let pkg: ResolvedPackage;
      let error: string | null = null;
      try {
        pkg = resolvePackage(input);
      } catch (cause) {
        pkg = {
          name: input.name ?? '',
          ecosystem: input.ecosystem ?? '',
          version: input.version ?? '',
          ...(input.purl === undefined ? {} : { purl: input.purl }),
        };
        error = cause instanceof Error ? cause.message : String(cause);
      }
      return {
        pkg,
        pages: [] as Array<{ ids: string[]; nextToken: string | undefined }>,
        error,
      };
    });
    const rawRecords = new Map<string, RawOsvVulnerability>();
    const detailErrors = new Map<string, string>();
    const message = (error: unknown) => (error instanceof Error ? error.message : String(error));
    const checkCancelled = () => ctx.signal.throwIfAborted();
    const latestToken = (row: (typeof rows)[number]) => row.pages.at(-1)?.nextToken;
    const bodyFor = (row: (typeof rows)[number]) => {
      const token = latestToken(row);
      return { ...packageBody(row.pkg), ...(token ? { page_token: token } : {}) };
    };
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
          while (row.pages.length < this.maxQueryPages) {
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
            const ids = (raw.vulns ?? []).map((record) => {
              if (!record || typeof record.id !== 'string' || !record.id)
                throw serviceUnavailable('OSV API returned an advisory without an ID.');
              if (!rawRecords.has(record.id)) rawRecords.set(record.id, record);
              return record.id;
            });
            const nextToken = raw.next_page_token || undefined;
            row.pages.push({ ids, nextToken });
            if (!nextToken) break;
          }
        } catch (error) {
          checkCancelled();
          if (!deadline.expired()) row.error = message(error);
        }
      });
    };
    const hydrate = async (ids: Iterable<string>) => {
      await pool(
        [...new Set(ids)].filter((id) => !rawRecords.has(id) && !detailErrors.has(id)),
        async (id) => {
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
            if (!deadline.expired()) detailErrors.set(id, message(error));
          }
        },
      );
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
          const pageIds = parsed.data.results.flatMap((result, i) => {
            // biome-ignore lint/style/noNonNullAssertion: validated positional cardinality
            const row = pending[i]!;
            const ids = (result.vulns ?? []).map(({ id }) => id);
            row.pages.push({ ids, nextToken: result.next_page_token || undefined });
            return ids;
          });
          if (pageIds.length > 0) await hydrate(pageIds);
          pending = pending.filter(
            (row) => latestToken(row) && row.pages.length < this.maxQueryPages,
          );
        } catch (error) {
          checkCancelled();
          if (!deadline.expired()) for (const row of pending) row.error = message(error);
          break;
        }
      }
      checkCancelled();
      return rows.map((row) => {
        try {
          const ids = new Set<string>();
          let error = row.error;
          let checkpoint: { nextToken: string | undefined } | undefined;
          for (const page of row.pages) {
            const missing = page.ids.find((id) => !rawRecords.has(id));
            if (missing !== undefined) {
              error ??= detailErrors.get(missing) ?? (!checkpoint ? deadline.reason.message : null);
              break;
            }
            for (const id of page.ids) ids.add(id);
            checkpoint = page;
          }
          if (!checkpoint && deadline.expired()) error ??= deadline.reason.message;
          if (error) return { ...row.pkg, vulns: [], error, truncated: Boolean(latestToken(row)) };
          const vulns = [...ids].map((id) => {
            // biome-ignore lint/style/noNonNullAssertion: all IDs have records or a detail error above
            return toBrief(normalizePackageVuln(rawRecords.get(id)!, row.pkg));
          });
          const token = checkpoint?.nextToken;
          return {
            ...row.pkg,
            vulns,
            error: null,
            truncated: token !== undefined,
            ...(token === undefined
              ? {}
              : { nextCursor: encodeQueryCursor(packageBody(row.pkg), token) }),
          };
        } catch (error) {
          return {
            ...row.pkg,
            vulns: [],
            error: message(error),
            truncated: Boolean(latestToken(row)),
          };
        }
      });
    } finally {
      deadline.stop();
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
