/**
 * @fileoverview Live OSV.dev records saved under tests/fixtures/osv/, plus an HTTP stub
 * that serves them to a real OsvApiService so tool tests exercise normalization end to end.
 * @module tests/helpers/osv-fixtures
 */

import { readFileSync } from 'node:fs';
import { vi } from 'vitest';
import type { RawOsvVulnerability } from '@/services/osv-api/types.js';

/** Load a saved live OSV record (`GET /v1/vulns/{id}` shape) by ID. */
export function loadOsvRecord(id: string): RawOsvVulnerability {
  return JSON.parse(
    readFileSync(new URL(`../fixtures/osv/${id}.json`, import.meta.url), 'utf8'),
  ) as RawOsvVulnerability;
}

/** Queried package as sent in a `POST /v1/query` body. */
export interface QueriedPackage {
  ecosystem: string;
  name: string;
}

/** A `POST /v1/query` request body as the service sent it. */
export interface QueryRequestBody {
  package: QueriedPackage;
  page_token?: string;
  version: string;
}

/**
 * Stub global fetch so every `POST /v1/query` answers `records`; returns the
 * request bodies sent, in order.
 */
export function captureOsvQueries(records: RawOsvVulnerability[]): QueryRequestBody[] {
  const bodies: QueryRequestBody[] = [];
  vi.stubGlobal(
    'fetch',
    vi.fn((_url: string | URL, init?: RequestInit) => {
      bodies.push(JSON.parse(String(init?.body)) as QueryRequestBody);
      return Promise.resolve(Response.json({ vulns: records }));
    }),
  );
  return bodies;
}

/**
 * Stub global fetch with an OSV API fake: `POST /v1/query` answers with the records
 * `query` returns for the queried package, `GET /v1/vulns/{id}` with `vuln`.
 */
export function stubOsvApi(responders: {
  query?: (pkg: QueriedPackage) => RawOsvVulnerability[];
  vuln?: RawOsvVulnerability;
}): void {
  vi.stubGlobal(
    'fetch',
    vi.fn((url: string | URL, init?: RequestInit) => {
      const path = new URL(String(url)).pathname;
      if (path === '/v1/query' && responders.query) {
        const body = JSON.parse(String(init?.body)) as { package: QueriedPackage };
        return Promise.resolve(Response.json({ vulns: responders.query(body.package) }));
      }
      if (path.startsWith('/v1/vulns/') && responders.vuln) {
        return Promise.resolve(Response.json(responders.vuln));
      }
      return Promise.reject(new Error(`Unexpected OSV request: ${init?.method ?? 'GET'} ${path}`));
    }),
  );
}
