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
import {
  decodePackageCursor,
  decodeQueryCursor,
  encodeQueryCursor,
  encodeSourceCursor,
  invalidCursor,
  type PackageContinuation,
  type SourceCheckpoint,
} from './query-cursor.js';
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
import {
  resolveUbuntuSources,
  type UbuntuSourceResolution,
  ubuntuMappingRelease,
} from './ubuntu-source-resolution.js';

const OSV_BASE_URL = 'https://api.osv.dev';

/** Recovery for a package query whose ecosystem OSV does not recognize. */
export const INVALID_ECOSYSTEM_RECOVERY =
  'Call osv_list_ecosystems to see valid ecosystem strings, then retry with the correct value.';

/** Match the package tool's error message before the framework attaches recovery. */
export function invalidEcosystemMessage(ecosystem: string): string {
  return `Ecosystem "${ecosystem}" is not recognized by OSV.`;
}

function batchQueryRejection(
  ecosystem: string,
  detail: string | undefined,
  original = detail,
): string {
  if (
    detail === 'invalid ecosystem' ||
    detail === 'rpc error: code = InvalidArgument desc = invalid ecosystem'
  ) {
    return `${invalidEcosystemMessage(ecosystem)} ${INVALID_ECOSYSTEM_RECOVERY}`;
  }
  return original ?? 'Invalid package query.';
}

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

interface QueryDeadline {
  ctx: Context;
  expired: () => boolean;
  reason: DOMException;
  stop: () => void;
}

/** Start the total query budget separately from caller cancellation. The owner stops its timer. */
export function startQueryDeadline(ctx: Context): QueryDeadline {
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

interface BatchTarget {
  error: McpError | string | null;
  pageBudget: { remaining: number };
  pages: Array<{ ids: string[]; nextToken: string | undefined }>;
  pkg: ResolvedPackage;
}

const MAX_OSV_BATCH_QUERIES = 1000;

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
    ...(a.ecosystem_specific === undefined ? {} : { ecosystem_specific: a.ecosystem_specific }),
    ...(a.database_specific === undefined ? {} : { database_specific: a.database_specific }),
    versions: a.versions ?? [],
    ranges: (a.ranges ?? []).map((r) => {
      const out: OsvVulnerability['affected'][number]['ranges'][number] = {
        rangeType: r.type ?? '',
        events: extractEvents(r.events),
        ...(r.database_specific === undefined ? {} : { database_specific: r.database_specific }),
      };
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
    ...(raw.upstream === undefined ? {} : { upstream: raw.upstream }),
    ...(raw.related === undefined ? {} : { related: raw.related }),
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
  sourceNames?: string[],
): OsvPackageVulnerability {
  const matching = (raw.affected ?? []).filter((a) =>
    sourceNames === undefined
      ? matchesQueriedPackage(a.package, query)
      : sourceNames.some((name) => matchesQueriedPackage(a.package, { ...query, name })),
  );
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
    ...(vuln.upstream === undefined ? {} : { upstream: vuln.upstream }),
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
  async queryCommit(
    commit: string,
    ctx: Context,
    cursor?: string,
  ): Promise<QueryFindings<OsvVulnerability> | { invalid: true; message: string }> {
    const identity = { commit: commit.toLowerCase() };
    const token = cursor === undefined ? undefined : decodeQueryCursor(identity, cursor);
    return await this.queryPages(
      { commit },
      (record) => normalizeVuln(record),
      ctx,
      token,
      identity,
    );
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
    | (QueryFindings<OsvPackageVulnerability> &
        Partial<UbuntuSourceResolution> & { invalid: false })
    | { invalid: true; message: string }
  > {
    const pkg = identifier ?? { name, ecosystem, version };
    const body = packageBody(pkg);
    const continuation = cursor === undefined ? undefined : decodePackageCursor(body, cursor);
    if (ubuntuMappingRelease(ecosystem) && continuation?.version !== 1) {
      return this.queryUbuntuPackage(pkg, ctx, continuation);
    }
    if (continuation?.version === 2) throw invalidCursor();
    const query: PackageQuery = { name, ecosystem };
    const result = await this.queryPages(
      body,
      (record) => normalizePackageVuln(record, query),
      ctx,
      continuation?.token,
    );
    return 'invalid' in result ? result : { ...result, invalid: false };
  }

  private resolveUbuntu(packages: ResolvedPackage[], ctx: Context) {
    return resolveUbuntuSources(
      packages,
      (body) =>
        postJson<unknown>('/v1experimental/ubuntu/binary-to-source', body, this.timeoutMs, ctx),
      ctx.signal,
    );
  }

  private async ubuntuPackageResolution(
    pkg: ResolvedPackage,
    ctx: Context,
    continuation?: Extract<PackageContinuation, { version: 2 }>,
  ): Promise<UbuntuSourceResolution> {
    if (!ubuntuMappingRelease(pkg.ecosystem)) throw invalidCursor();
    if (
      continuation?.sourceResolutionUnavailable &&
      continuation.sources.length === 1 &&
      continuation.sources[0]?.name === pkg.name
    ) {
      return { sourceNames: [pkg.name], sourceResolutionUnavailable: true };
    }
    if (continuation?.sourceResolutionUnavailable) throw invalidCursor();
    const resolutions = await this.resolveUbuntu([pkg], ctx);
    const resolution = resolutions.get(pkg);
    if (resolution instanceof McpError) throw resolution;
    if (!resolution) throw new Error('Missing resolution for release-qualified Ubuntu package.');
    if (continuation) {
      if (resolution.sourceResolutionUnavailable) {
        throw serviceUnavailable('Ubuntu source resolution is required to resume this OSV cursor.');
      }
      if (
        continuation.sources.length !== resolution.sourceNames.length ||
        continuation.sources.some(({ name }, index) => name !== resolution.sourceNames[index])
      ) {
        throw invalidCursor();
      }
    }
    return resolution;
  }

  private async queryUbuntuPackage(
    pkg: ResolvedPackage,
    ctx: Context,
    continuation?: Extract<PackageContinuation, { version: 2 }>,
  ) {
    const deadline = startQueryDeadline(ctx);
    const records = new Map<string, RawOsvVulnerability>();
    const originalBody = packageBody(pkg);
    try {
      const { sourceNames, sourceResolutionUnavailable } = await this.ubuntuPackageResolution(
        pkg,
        deadline.ctx,
        continuation,
      );
      const sources: SourceCheckpoint[] =
        continuation?.sources ?? sourceNames.map((name) => ({ name }));
      let completed = false;
      const pageBudget = { remaining: this.maxQueryPages };
      for (const source of sources) {
        if (pageBudget.remaining === 0) break;
        if (source.token === null) continue;
        const body = packageBody({
          name: source.name,
          ecosystem: pkg.ecosystem,
          version: pkg.version,
        });
        try {
          const result = await this.fetchQueryPages(
            body,
            (record) => record,
            ctx,
            source.token,
            deadline,
            pageBudget,
          );
          if ('invalid' in result) return result;
          for (const record of result.vulns) {
            if (!record.id) throw serviceUnavailable('OSV API returned an advisory without an ID.');
            records.set(record.id, record);
          }
          source.token = result.nextToken ?? null;
          completed = true;
        } catch (error) {
          ctx.signal.throwIfAborted();
          if (!deadline.expired() || !completed) throw error;
          break;
        }
      }
      const truncated = sources.some(({ token }) => token !== null);
      return {
        invalid: false as const,
        vulns: [...records.values()].map((record) =>
          normalizePackageVuln(record, pkg, sourceNames),
        ),
        truncated,
        sourceNames,
        ...(sourceResolutionUnavailable ? { sourceResolutionUnavailable } : {}),
        ...(truncated
          ? { nextCursor: encodeSourceCursor(originalBody, sources, sourceResolutionUnavailable) }
          : {}),
      };
    } catch (error) {
      ctx.signal.throwIfAborted();
      if (deadline.expired()) throw timeout(deadline.reason.message, {}, { cause: error });
      throw error;
    } finally {
      deadline.stop();
    }
  }

  private async queryPages<T>(
    body: object,
    normalize: (record: RawOsvVulnerability) => T,
    ctx: Context,
    token?: string,
    identity = body,
  ): Promise<QueryFindings<T> | { invalid: true; message: string }> {
    const result = await this.fetchQueryPages(body, normalize, ctx, token);
    if ('invalid' in result) return result;
    const { vulns, nextToken } = result;
    return {
      vulns,
      truncated: nextToken !== undefined,
      ...(nextToken === undefined ? {} : { nextCursor: encodeQueryCursor(identity, nextToken) }),
    };
  }

  private async fetchQueryPages<T>(
    body: object,
    normalize: (record: RawOsvVulnerability) => T,
    ctx: Context,
    token?: string,
    operationDeadline?: QueryDeadline,
    pageBudget = { remaining: this.maxQueryPages },
  ): Promise<{ vulns: T[]; nextToken: string | undefined } | { invalid: true; message: string }> {
    let pageToken = token;
    const deadline = operationDeadline ?? startQueryDeadline(ctx);
    const vulns: T[] = [];
    let completed = 0;
    try {
      for (; pageBudget.remaining > 0; completed++) {
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
        pageBudget.remaining--;
        pageToken = raw.next_page_token || undefined;
        if (!pageToken) break;
      }
    } catch (error) {
      ctx.signal.throwIfAborted();
      if (!deadline.expired()) throw error;
      if (!completed || !pageToken) throw timeout(deadline.reason.message, {}, { cause: error });
    } finally {
      if (operationDeadline === undefined) deadline.stop();
    }
    return { vulns, nextToken: pageToken };
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
    query: ResolvedPackage,
    ctx: Context,
    cursor?: string,
  ): Promise<{ advisory: OsvPackageVulnerability | null } & Partial<UbuntuSourceResolution>> {
    const continuation =
      cursor === undefined ? undefined : decodePackageCursor(packageBody(query), cursor);
    const deadline = startQueryDeadline(ctx);
    try {
      const resolution =
        continuation?.version === 2
          ? await this.ubuntuPackageResolution(query, deadline.ctx, continuation)
          : continuation === undefined && ubuntuMappingRelease(query.ecosystem)
            ? await this.ubuntuPackageResolution(query, deadline.ctx)
            : undefined;
      const { status, data } = await getJson<RawOsvVulnerability>(
        `/v1/vulns/${encodeURIComponent(id)}`,
        this.timeoutMs,
        deadline.ctx,
      );
      if (status === 404) return { advisory: null };
      if (status !== 200) throw serviceUnavailable('OSV advisory lookup failed.', { status });
      return {
        advisory: normalizePackageVuln(data as RawOsvVulnerability, query, resolution?.sourceNames),
        ...resolution,
      };
    } catch (error) {
      ctx.signal.throwIfAborted();
      if (deadline.expired()) throw timeout(deadline.reason.message, {}, { cause: error });
      throw error;
    } finally {
      deadline.stop();
    }
  }

  /**
   * Positional native ID preflight with per-call raw advisory enrichment. Each row normalizes
   * shared records against its own package. Validation recovery, pagination and detail work
   * share a bounded request pool and operation deadline; caller cancellation propagates.
   */
  async queryBatch(
    packages: PackageIdentifier[],
    ctx: Context,
    operationDeadline?: QueryDeadline,
  ): Promise<
    Array<
      {
        name: string;
        ecosystem: string;
        version: string;
        purl?: string;
        error: string | null;
        lookupFailure?: McpError;
      } & QueryFindings<BatchVulnBrief> &
        Partial<UbuntuSourceResolution>
    >
  > {
    const deadline = operationDeadline ?? startQueryDeadline(ctx);
    const batchCtx = deadline.ctx;
    const { signal } = batchCtx;
    const inputs = packages.map((input) => {
      let pkg: ResolvedPackage;
      let error: McpError | string | null = null;
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
        error,
      };
    });
    const rawRecords = new Map<string, RawOsvVulnerability>();
    const message = (error: unknown) => (error instanceof Error ? error.message : String(error));
    const lookupError = (error: unknown) => (error instanceof McpError ? error : message(error));
    const detailErrors = new Map<string, McpError | string>();
    const checkCancelled = () => ctx.signal.throwIfAborted();
    const latestToken = (target: BatchTarget) => target.pages.at(-1)?.nextToken;
    const failedRow = (pkg: ResolvedPackage, error: McpError | string, truncated: boolean) => ({
      ...pkg,
      vulns: [],
      error: typeof error === 'string' ? error : error.message,
      ...(typeof error === 'string' ? {} : { lookupFailure: error }),
      truncated,
    });
    const bodyFor = (row: BatchTarget) => {
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
    const fallback = async (unresolved: BatchTarget[]) => {
      await pool(unresolved, async (row) => {
        try {
          while (row.pageBudget.remaining > 0) {
            signal.throwIfAborted();
            row.pageBudget.remaining--;
            const { status, data } = await postJson<RawOsvQueryResponse>(
              '/v1/query',
              bodyFor(row),
              this.timeoutMs,
              batchCtx,
            );
            if (status === 400) {
              row.error = batchQueryRejection(row.pkg.ecosystem, (data as OsvApiError).message);
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
          if (!deadline.expired()) row.error = lookupError(error);
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
            if (!deadline.expired()) detailErrors.set(id, lookupError(error));
          }
        },
      );
    };
    const queryTargets = async (targets: BatchTarget[]) => {
      let pending = targets.filter((target) => target.pageBudget.remaining > 0);
      let recoveredIndex = false;
      while (pending.length) {
        checkCancelled();
        const reserved = new Map<BatchTarget['pageBudget'], number>();
        const round = pending.filter(({ pageBudget }) => {
          const count = reserved.get(pageBudget) ?? 0;
          if (count === pageBudget.remaining) return false;
          reserved.set(pageBudget, count + 1);
          return true;
        });
        try {
          signal.throwIfAborted();
          const { status, data } = await postJson<unknown>(
            '/v1/querybatch',
            { queries: round.map(bodyFor) },
            this.timeoutMs,
            batchCtx,
          );
          if (status === 400) {
            const error = data as OsvApiError;
            const indexMatch = /^error in query at index (\d+):/.exec(error.message ?? '');
            const index = indexMatch ? Number(indexMatch[1]) : -1;
            const row = round[index];
            if (indexMatch && row && !recoveredIndex) {
              const detail = error.message.slice(indexMatch[0].length).trimStart();
              row.error = batchQueryRejection(row.pkg.ecosystem, detail, error.message);
              pending = pending.filter((target) => target !== row);
              recoveredIndex = true;
              continue;
            }
            await fallback(pending);
            break;
          }
          const parsed = BatchResponseSchema.safeParse(data);
          if (status !== 200 || !parsed.success || parsed.data.results.length !== round.length) {
            throw serviceUnavailable('OSV API returned a malformed or misaligned batch response.', {
              status,
            });
          }
          const pageIds = parsed.data.results.flatMap((result, i) => {
            // biome-ignore lint/style/noNonNullAssertion: validated positional cardinality
            const row = round[i]!;
            const ids = (result.vulns ?? []).map(({ id }) => id);
            row.pages.push({ ids, nextToken: result.next_page_token || undefined });
            row.pageBudget.remaining--;
            return ids;
          });
          if (pageIds.length > 0) await hydrate(pageIds);
          pending = pending.filter(
            (row) => row.pageBudget.remaining > 0 && (row.pages.length === 0 || latestToken(row)),
          );
        } catch (error) {
          checkCancelled();
          if (!deadline.expired()) for (const row of pending) row.error = lookupError(error);
          break;
        }
      }
    };
    try {
      const resolutions = await this.resolveUbuntu(
        inputs.filter(({ error }) => !error).map(({ pkg }) => pkg),
        batchCtx,
      ).catch((error: unknown) => {
        checkCancelled();
        if (!deadline.expired()) throw error;
        return new Map<ResolvedPackage, UbuntuSourceResolution | McpError>();
      });
      const rows = inputs.map(({ pkg, error }) => {
        const resolution = resolutions.get(pkg);
        const failure = error ?? (resolution instanceof McpError ? resolution : null);
        const mapping = resolution instanceof McpError ? undefined : resolution;
        const pageBudget = { remaining: this.maxQueryPages };
        const targets: BatchTarget[] = failure
          ? []
          : (mapping?.sourceNames ?? [pkg.name]).map((name) => ({
              pkg:
                mapping === undefined
                  ? pkg
                  : { name, ecosystem: pkg.ecosystem, version: pkg.version },
              pageBudget,
              pages: [],
              error: null,
            }));
        return { pkg, targets, mapping, failure };
      });
      const targets = rows.flatMap((row) => row.targets);
      for (let offset = 0; offset < targets.length; offset += MAX_OSV_BATCH_QUERIES) {
        await queryTargets(targets.slice(offset, offset + MAX_OSV_BATCH_QUERIES));
      }
      checkCancelled();
      return rows.map(({ pkg, targets: rowTargets, mapping, failure }) => {
        const truncated = rowTargets.some((target) => Boolean(latestToken(target)));
        try {
          if (failure) return failedRow(pkg, failure, false);
          const ids = new Set<string>();
          let error: McpError | string | null = null;
          let hasCheckpoint = false;
          const sources: SourceCheckpoint[] = [];
          for (const target of rowTargets) {
            error ??= target.error;
            let checkpoint: (typeof target.pages)[number] | undefined;
            for (const page of target.pages) {
              const missing = page.ids.find((id) => !rawRecords.has(id));
              if (missing !== undefined) {
                error ??= detailErrors.get(missing) ?? null;
                break;
              }
              for (const id of page.ids) ids.add(id);
              checkpoint = page;
            }
            hasCheckpoint ||= checkpoint !== undefined;
            sources.push({
              name: target.pkg.name,
              token: checkpoint === undefined ? undefined : (checkpoint.nextToken ?? null),
            });
          }
          if (!hasCheckpoint && deadline.expired()) error ??= timeout(deadline.reason.message);
          if (error) return { ...failedRow(pkg, error, truncated), ...mapping };
          const vulns = [...ids].map((id) => {
            // biome-ignore lint/style/noNonNullAssertion: all IDs have records or a detail error above
            return toBrief(normalizePackageVuln(rawRecords.get(id)!, pkg, mapping?.sourceNames));
          });
          const token = sources[0]?.token;
          const nextCursor = mapping
            ? sources.some((source) => source.token !== null)
              ? encodeSourceCursor(packageBody(pkg), sources, mapping.sourceResolutionUnavailable)
              : undefined
            : token
              ? encodeQueryCursor(packageBody(pkg), token)
              : undefined;
          return {
            ...pkg,
            ...mapping,
            vulns,
            error: null,
            truncated: nextCursor !== undefined,
            ...(nextCursor === undefined ? {} : { nextCursor }),
          };
        } catch (error) {
          return { ...failedRow(pkg, message(error), truncated), ...mapping };
        }
      });
    } finally {
      if (operationDeadline === undefined) deadline.stop();
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
