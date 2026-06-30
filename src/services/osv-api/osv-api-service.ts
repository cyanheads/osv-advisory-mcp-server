/**
 * @fileoverview Service wrapping the OSV.dev REST API v1.
 * Handles HTTP fetch, timeout, exponential backoff on 5xx, error body parsing,
 * and normalization of raw API responses to typed domain objects.
 * @module services/osv-api/osv-api-service
 */

import type { Context } from '@cyanheads/mcp-ts-core';
import { serviceUnavailable, timeout } from '@cyanheads/mcp-ts-core/errors';
import type {
  BatchVulnBrief,
  OsvAffectedRange,
  OsvApiError,
  OsvSeverityEntry,
  OsvVulnerability,
  RawOsvAffected,
  RawOsvQueryResponse,
  RawOsvVulnerability,
} from './types.js';

const OSV_BASE_URL = 'https://api.osv.dev';

/** Default request timeout in milliseconds. */
const DEFAULT_TIMEOUT_MS = 10_000;

/** Default maximum concurrent per-package queries in {@link OsvApiService.queryBatch}. */
const DEFAULT_BATCH_CONCURRENCY = 10;

/** Maximum backoff retries on 5xx. */
const MAX_RETRIES = 3;

/** Base delay for exponential backoff. */
const BASE_DELAY_MS = 500;

// ---------------------------------------------------------------------------
// Normalization helpers
// ---------------------------------------------------------------------------

/** Extract all flat affected ranges from an affected array.
 * Skips entries that lack package metadata (e.g. GIT-range-only CVE records). */
function extractAffectedRanges(affected: RawOsvAffected[] | undefined): OsvAffectedRange[] {
  const out: OsvAffectedRange[] = [];
  for (const entry of affected ?? []) {
    const pkgName = entry.package?.name ?? '';
    const ecosystem = entry.package?.ecosystem ?? '';
    // Skip entries with no package identity — these are GIT-range-only CVE records
    // that carry no useful package/ecosystem information for dependency audits.
    if (!pkgName && !ecosystem) continue;
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
      const rangeEntry: OsvAffectedRange = { packageName: pkgName, ecosystem, rangeType };
      if (introduced !== undefined) rangeEntry.introduced = introduced;
      if (fixed !== undefined) rangeEntry.fixed = fixed;
      if (lastAffected !== undefined) rangeEntry.lastAffected = lastAffected;
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

  const affected = (raw.affected ?? [])
    .filter((a) => {
      // Skip GIT-range-only entries that have no package identity (CVE records often have these).
      const name = a.package?.name ?? '';
      const eco = a.package?.ecosystem ?? '';
      return name !== '' || eco !== '';
    })
    .map((a) => ({
      packageName: a.package?.name ?? '',
      ecosystem: a.package?.ecosystem ?? '',
      ...(a.package?.purl ? { purl: a.package.purl } : {}),
      ranges: (a.ranges ?? []).map((r) => {
        const out: {
          rangeType: string;
          introduced?: string;
          fixed?: string;
          lastAffected?: string;
        } = { rangeType: r.type ?? '' };
        for (const evt of r.events ?? []) {
          if (evt.introduced !== undefined) out.introduced = evt.introduced;
          if (evt.fixed !== undefined) out.fixed = evt.fixed;
          if (evt.last_affected !== undefined) out.lastAffected = evt.last_affected;
        }
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

/** Sleep for ms milliseconds. */
function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Execute a fetch with a timeout and exponential backoff on 5xx.
 * Throws typed errors for network failures, timeouts, and upstream errors.
 */
async function fetchWithRetry(
  url: string,
  init: RequestInit,
  timeoutMs: number,
  ctx: Context,
): Promise<Response> {
  let lastErr: unknown;
  for (let attempt = 0; attempt < MAX_RETRIES; attempt++) {
    if (attempt > 0) {
      const delay = BASE_DELAY_MS * 2 ** (attempt - 1);
      await sleep(delay);
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    const onAbort = () => controller.abort();
    ctx.signal.addEventListener('abort', onAbort, { once: true });

    let response: Response;
    try {
      response = await fetch(url, { ...init, signal: controller.signal });
    } catch (err) {
      clearTimeout(timer);
      ctx.signal.removeEventListener('abort', onAbort);
      if ((err as Error).name === 'AbortError') {
        if (ctx.signal.aborted) throw timeout('OSV request cancelled by caller.');
        throw timeout(`OSV request timed out after ${timeoutMs}ms.`);
      }
      throw serviceUnavailable(
        `OSV API network error: ${(err as Error).message}`,
        { url },
        { cause: err as Error },
      );
    } finally {
      clearTimeout(timer);
      ctx.signal.removeEventListener('abort', onAbort);
    }

    // 5xx → retry with backoff
    if (response.status >= 500 && response.status < 600) {
      lastErr = new Error(`OSV API returned HTTP ${response.status}`);
      continue;
    }

    return response;
  }

  throw serviceUnavailable(
    `OSV API failed after ${MAX_RETRIES} attempts: ${(lastErr as Error).message}`,
    { url },
  );
}

/** POST JSON to an OSV endpoint, parse the response body. */
async function postJson<T>(
  path: string,
  body: unknown,
  timeoutMs: number,
  ctx: Context,
): Promise<{ status: number; data: T | OsvApiError }> {
  const url = `${OSV_BASE_URL}${path}`;
  const response = await fetchWithRetry(
    url,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify(body),
    },
    timeoutMs,
    ctx,
  );

  const text = await response.text();
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw serviceUnavailable('OSV API returned malformed JSON.', { url });
  }

  return { status: response.status, data: parsed as T | OsvApiError };
}

/** GET from an OSV endpoint, parse the response body. */
async function getJson<T>(
  path: string,
  timeoutMs: number,
  ctx: Context,
): Promise<{ status: number; data: T | OsvApiError }> {
  const url = `${OSV_BASE_URL}${path}`;
  const response = await fetchWithRetry(
    url,
    { method: 'GET', headers: { Accept: 'application/json' } },
    timeoutMs,
    ctx,
  );

  const text = await response.text();
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw serviceUnavailable('OSV API returned malformed JSON.', { url });
  }

  return { status: response.status, data: parsed as T | OsvApiError };
}

// ---------------------------------------------------------------------------
// Service class
// ---------------------------------------------------------------------------

/** Construction options for {@link OsvApiService}. */
export interface OsvApiServiceOptions {
  /** Maximum concurrent per-package queries in {@link OsvApiService.queryBatch}. Defaults to {@link DEFAULT_BATCH_CONCURRENCY}. */
  batchConcurrency?: number;
  /** HTTP request timeout in milliseconds. Defaults to {@link DEFAULT_TIMEOUT_MS}. */
  timeoutMs?: number;
}

export class OsvApiService {
  private readonly timeoutMs: number;
  private readonly batchConcurrency: number;

  constructor(options: OsvApiServiceOptions = {}) {
    this.timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.batchConcurrency = options.batchConcurrency ?? DEFAULT_BATCH_CONCURRENCY;
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
  ): Promise<{ vulns: OsvVulnerability[]; invalid: false } | { invalid: true; message: string }> {
    const { status, data } = await postJson<RawOsvQueryResponse>(
      '/v1/query',
      { version, package: { name, ecosystem } },
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
    // Empty object `{}` means no vulns — treat missing `vulns` as empty array
    const vulns = (raw.vulns ?? []).map(normalizeVuln);

    ctx.log.debug('OSV query result', { name, ecosystem, version, vulnCount: vulns.length });
    return { invalid: false, vulns };
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
        };
      }
      return {
        name: pkg.name,
        ecosystem: pkg.ecosystem,
        version: pkg.version,
        vulns: result.vulns.map(toBrief),
        error: null,
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

export type { BatchVulnBrief, OsvAffectedRange, OsvVulnerability };
