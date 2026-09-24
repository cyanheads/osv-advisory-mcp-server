#!/usr/bin/env bun
/**
 * @fileoverview Drift check for the `osv_list_ecosystems` catalog. The catalog is every
 * member of the OSV schema's `$defs.ecosystemName` enum that live `POST /v1/query`
 * accepts, plus `GIT`. This script fetches `validation/schema.json`, probes every enum
 * member, `GIT`, and every catalog entry against OSV.dev, and prints three lists:
 *
 *   add      — in the schema (or GIT), accepted, missing from the catalog
 *   withhold — in the schema, rejected, and not in the catalog
 *   remove   — a catalog entry OSV.dev rejects or the schema no longer lists
 *
 * Exit codes: 0 in sync (a withhold-only result included), 1 drift (add or remove is
 * non-empty), 2 a request failed — a network or HTTP failure never yields a clean report.
 *
 * Standalone on purpose, not a devcheck step: its verdict moves with upstream, and
 * `scripts/devcheck.ts` is a framework copy the maintenance sync overwrites.
 * Run with `bun run check:ecosystems`.
 *
 * @module scripts/check-ecosystems
 */

import process from 'node:process';
import { SUPPORTED_ECOSYSTEMS } from '../src/mcp-server/tools/definitions/osv-list-ecosystems.tool.js';

export const SCHEMA_URL =
  'https://raw.githubusercontent.com/ossf/osv-schema/main/validation/schema.json';
export const QUERY_URL = 'https://api.osv.dev/v1/query';

/** `GIT` is valid through `$defs.ecosystemWithSuffix`, not the named enum. */
const GIT = 'GIT';
const PROBE_CONCURRENCY = 8;
const REQUEST_TIMEOUT_MS = 20_000;

/** A catalog entry to drop, and why. */
export interface Removal {
  name: string;
  reason: 'not in the schema' | 'rejected by OSV.dev';
}

/** The three drift lists. */
export interface Classification {
  add: string[];
  remove: Removal[];
  withhold: string[];
}

/** Outcome of one check run. */
export type CheckResult =
  | ({ kind: 'checked'; probed: number } & Classification)
  | { kind: 'failed'; request: string; reason: string };

type ProbeOutcome =
  | { kind: 'probed'; name: string; accepted: boolean }
  | { kind: 'failed'; request: string; reason: string };

/** Sort the schema members (plus GIT) and catalog entries into add / withhold / remove. */
export function classifyEcosystems(input: {
  accepted: ReadonlyMap<string, boolean>;
  catalog: readonly string[];
  schema: readonly string[];
}): Classification {
  const candidates = [...new Set([...input.schema, GIT])];
  const inSchema = new Set(candidates);
  const inCatalog = new Set(input.catalog);
  const isAccepted = (name: string) => input.accepted.get(name) === true;

  return {
    add: candidates.filter((name) => isAccepted(name) && !inCatalog.has(name)),
    withhold: candidates.filter((name) => !isAccepted(name) && !inCatalog.has(name)),
    remove: input.catalog.flatMap((name): Removal[] => {
      if (!inSchema.has(name)) return [{ name, reason: 'not in the schema' }];
      if (!isAccepted(name)) return [{ name, reason: 'rejected by OSV.dev' }];
      return [];
    }),
  };
}

function describeError(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

async function fetchSchemaEcosystems(
  fetchFn: typeof fetch,
): Promise<{ kind: 'ok'; names: string[] } | { kind: 'failed'; request: string; reason: string }> {
  const request = `GET ${SCHEMA_URL}`;
  try {
    const response = await fetchFn(SCHEMA_URL, {
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
    if (!response.ok) return { kind: 'failed', request, reason: `HTTP ${response.status}` };
    const schema = (await response.json()) as {
      $defs?: { ecosystemName?: { enum?: unknown } };
    };
    const names = schema.$defs?.ecosystemName?.enum;
    if (!Array.isArray(names) || !names.every((name) => typeof name === 'string')) {
      return {
        kind: 'failed',
        request,
        reason: 'no string $defs.ecosystemName.enum in the schema',
      };
    }
    return { kind: 'ok', names };
  } catch (error) {
    return { kind: 'failed', request, reason: describeError(error) };
  }
}

/** 200 → accepted; 400 invalid-ecosystem → rejected; anything else is a failed request. */
async function probeEcosystem(name: string, fetchFn: typeof fetch): Promise<ProbeOutcome> {
  const request = `POST ${QUERY_URL} (ecosystem "${name}")`;
  try {
    const response = await fetchFn(QUERY_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ package: { name: 'x', ecosystem: name }, version: '1.0.0' }),
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
    if (response.status === 200) return { kind: 'probed', name, accepted: true };
    const body = await response.text();
    if (response.status === 400 && /invalid ecosystem/i.test(body)) {
      return { kind: 'probed', name, accepted: false };
    }
    return { kind: 'failed', request, reason: `HTTP ${response.status} ${body.trim()}` };
  } catch (error) {
    return { kind: 'failed', request, reason: describeError(error) };
  }
}

/** Run `task` over `items` with at most `limit` in flight; results keep input order. */
async function mapBounded<T, R>(
  items: readonly T[],
  limit: number,
  task: (item: T) => Promise<R>,
): Promise<R[]> {
  const results: R[] = [];
  let next = 0;
  const worker = async () => {
    for (let index = next++; index < items.length; index = next++) {
      results[index] = await task(items[index] as T);
    }
  };
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return results;
}

/** Fetch the schema, probe every candidate, and classify the catalog against the result. */
export async function checkEcosystems(options: {
  catalog: readonly string[];
  fetch: typeof fetch;
}): Promise<CheckResult> {
  const schema = await fetchSchemaEcosystems(options.fetch);
  if (schema.kind === 'failed') return schema;

  const candidates = [...new Set([...schema.names, GIT, ...options.catalog])];
  const outcomes = await mapBounded(candidates, PROBE_CONCURRENCY, (name) =>
    probeEcosystem(name, options.fetch),
  );

  const accepted = new Map<string, boolean>();
  for (const outcome of outcomes) {
    if (outcome.kind === 'failed') return outcome;
    accepted.set(outcome.name, outcome.accepted);
  }

  return {
    kind: 'checked',
    probed: candidates.length,
    ...classifyEcosystems({ schema: schema.names, catalog: options.catalog, accepted }),
  };
}

/** 0 in sync or withhold-only, 1 drift, 2 a failed request. */
export function exitCodeFor(result: CheckResult): 0 | 1 | 2 {
  if (result.kind === 'failed') return 2;
  return result.add.length > 0 || result.remove.length > 0 ? 1 : 0;
}

/** Human-readable report of one check run. */
export function renderReport(result: CheckResult): string {
  if (result.kind === 'failed') {
    return `Ecosystem check FAILED — no report.\n  request: ${result.request}\n  error:   ${result.reason}`;
  }
  const section = (title: string, entries: string[]) =>
    `${title} (${entries.length}):\n${entries.length > 0 ? entries.map((entry) => `  - ${entry}`).join('\n') : '  (none)'}`;
  const verdict =
    exitCodeFor(result) === 0
      ? 'In sync — the catalog matches the accepted schema set plus GIT.'
      : 'Drift — update SUPPORTED_ECOSYSTEMS in src/mcp-server/tools/definitions/osv-list-ecosystems.tool.ts, its verification date, and the pinning test.';
  return [
    `Probed ${result.probed} ecosystems against ${QUERY_URL}.`,
    section('add — in the schema, accepted, missing from the catalog', result.add),
    section('withhold — in the schema, rejected by OSV.dev', result.withhold),
    section(
      'remove — catalog entries OSV.dev rejects or the schema dropped',
      result.remove.map(({ name, reason }) => `${name} — ${reason}`),
    ),
    verdict,
  ].join('\n\n');
}

if (import.meta.main) {
  const result = await checkEcosystems({ catalog: SUPPORTED_ECOSYSTEMS, fetch: globalThis.fetch });
  console.log(renderReport(result));
  process.exitCode = exitCodeFor(result);
}
