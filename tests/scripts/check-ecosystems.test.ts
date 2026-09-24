/**
 * @fileoverview Tests for the osv_list_ecosystems drift check (scripts/check-ecosystems.ts),
 * driven by a fake fetch — no live network.
 * @module tests/scripts/check-ecosystems.test
 */

import { describe, expect, it, vi } from 'vitest';
import {
  type CheckResult,
  checkEcosystems,
  classifyEcosystems,
  exitCodeFor,
  QUERY_URL,
  renderReport,
  SCHEMA_URL,
} from '../../scripts/check-ecosystems.js';

const INVALID_ECOSYSTEM = { code: 3, message: 'invalid ecosystem' };

/** Probe outcome the fake OSV.dev returns for one ecosystem. */
type ProbeReply = 'accept' | 'reject' | Response | Error;

/**
 * Fake fetch serving the schema and `POST /v1/query`. Ecosystems absent from
 * `probes` are accepted.
 */
function fakeFetch(options: {
  schema?: string[] | Response;
  probes?: Record<string, ProbeReply>;
}): typeof fetch {
  return vi.fn((url: string | URL | Request, init?: RequestInit) => {
    const target = String(url);
    if (target === SCHEMA_URL) {
      const { schema = [] } = options;
      if (schema instanceof Response) return Promise.resolve(schema);
      return Promise.resolve(Response.json({ $defs: { ecosystemName: { enum: schema } } }));
    }
    if (target === QUERY_URL && init?.method === 'POST') {
      const body = JSON.parse(String(init.body)) as { package: { ecosystem: string } };
      const reply = options.probes?.[body.package.ecosystem] ?? 'accept';
      if (reply === 'accept') return Promise.resolve(Response.json({}));
      if (reply === 'reject') {
        return Promise.resolve(Response.json(INVALID_ECOSYSTEM, { status: 400 }));
      }
      if (reply instanceof Error) return Promise.reject(reply);
      return Promise.resolve(reply);
    }
    return Promise.reject(new Error(`Unexpected request: ${init?.method ?? 'GET'} ${target}`));
  }) as unknown as typeof fetch;
}

/** Narrow a result to the checked variant. */
function checked(result: CheckResult) {
  if (result.kind !== 'checked') throw new Error(`Expected a checked result, got ${result.kind}`);
  return result;
}

describe('classifyEcosystems', () => {
  const accepted = (names: string[]) => new Map(names.map((name) => [name, true]));

  it('reports nothing when the catalog is exactly the accepted schema set plus GIT', () => {
    const result = classifyEcosystems({
      schema: ['npm', 'PyPI'],
      catalog: ['npm', 'PyPI', 'GIT'],
      accepted: accepted(['npm', 'PyPI', 'GIT']),
    });
    expect(result).toEqual({ add: [], withhold: [], remove: [] });
  });

  it('lists an accepted schema member missing from the catalog under add', () => {
    const result = classifyEcosystems({
      schema: ['npm', 'Homebrew'],
      catalog: ['npm', 'GIT'],
      accepted: accepted(['npm', 'Homebrew', 'GIT']),
    });
    expect(result.add).toEqual(['Homebrew']);
  });

  it('lists a rejected schema member outside the catalog under withhold only', () => {
    const result = classifyEcosystems({
      schema: ['npm', 'Red Hat Lightwell'],
      catalog: ['npm', 'GIT'],
      accepted: new Map([
        ['npm', true],
        ['Red Hat Lightwell', false],
        ['GIT', true],
      ]),
    });
    expect(result).toEqual({ add: [], withhold: ['Red Hat Lightwell'], remove: [] });
  });

  it('lists a rejected catalog entry and one the schema dropped under remove, with the reason', () => {
    const result = classifyEcosystems({
      schema: ['npm', 'Legacy'],
      catalog: ['npm', 'Legacy', 'Gone', 'GIT'],
      accepted: new Map([
        ['npm', true],
        ['Legacy', false],
        ['Gone', true],
        ['GIT', true],
      ]),
    });
    expect(result.remove).toEqual([
      { name: 'Legacy', reason: 'rejected by OSV.dev' },
      { name: 'Gone', reason: 'not in the schema' },
    ]);
    expect(result.withhold).toEqual([]);
  });

  it('treats GIT as a candidate even though the schema enum omits it', () => {
    const result = classifyEcosystems({
      schema: ['npm'],
      catalog: ['npm'],
      accepted: accepted(['npm', 'GIT']),
    });
    expect(result.add).toEqual(['GIT']);
  });
});

describe('checkEcosystems', () => {
  it('passes an in-sync catalog with exit code 0', async () => {
    const result = await checkEcosystems({
      catalog: ['npm', 'PyPI', 'GIT'],
      fetch: fakeFetch({ schema: ['npm', 'PyPI'] }),
    });
    expect(checked(result)).toMatchObject({ add: [], withhold: [], remove: [] });
    expect(exitCodeFor(result)).toBe(0);
  });

  it('probes every schema member, GIT, and every catalog entry once', async () => {
    const fetchFn = fakeFetch({ schema: ['npm', 'PyPI'] });
    await checkEcosystems({ catalog: ['npm', 'Extra', 'GIT'], fetch: fetchFn });
    const probed = vi
      .mocked(fetchFn)
      .mock.calls.filter(([url]) => String(url) === QUERY_URL)
      .map(([, init]) => JSON.parse(String(init?.body)) as { package: { ecosystem: string } })
      .map((body) => body.package.ecosystem)
      .sort();
    expect(probed).toEqual(['Extra', 'GIT', 'PyPI', 'npm'].sort());
  });

  it('exits 1 when the schema adds an accepted ecosystem', async () => {
    const result = await checkEcosystems({
      catalog: ['npm', 'GIT'],
      fetch: fakeFetch({ schema: ['npm', 'WordPress'] }),
    });
    expect(checked(result).add).toEqual(['WordPress']);
    expect(exitCodeFor(result)).toBe(1);
  });

  it('exits 0 on a withhold-only result', async () => {
    const result = await checkEcosystems({
      catalog: ['npm', 'GIT'],
      fetch: fakeFetch({
        schema: ['npm', 'Red Hat Lightwell'],
        probes: { 'Red Hat Lightwell': 'reject' },
      }),
    });
    expect(checked(result)).toMatchObject({ add: [], withhold: ['Red Hat Lightwell'], remove: [] });
    expect(exitCodeFor(result)).toBe(0);
  });

  it('exits 1 when OSV.dev starts rejecting a catalog entry', async () => {
    const result = await checkEcosystems({
      catalog: ['npm', 'Bitnami', 'GIT'],
      fetch: fakeFetch({ schema: ['npm', 'Bitnami'], probes: { Bitnami: 'reject' } }),
    });
    expect(checked(result).remove).toEqual([{ name: 'Bitnami', reason: 'rejected by OSV.dev' }]);
    expect(exitCodeFor(result)).toBe(1);
  });

  it('fails with exit code 2, naming the request, when the schema fetch returns an HTTP error', async () => {
    const result = await checkEcosystems({
      catalog: ['npm', 'GIT'],
      fetch: fakeFetch({ schema: new Response('upstream down', { status: 503 }) }),
    });
    expect(result).toMatchObject({ kind: 'failed', request: `GET ${SCHEMA_URL}` });
    expect(exitCodeFor(result)).toBe(2);
    expect(renderReport(result)).toContain(SCHEMA_URL);
    expect(renderReport(result)).toContain('HTTP 503');
  });

  it('fails when the schema has no $defs.ecosystemName enum', async () => {
    const result = await checkEcosystems({
      catalog: ['npm', 'GIT'],
      fetch: fakeFetch({ schema: Response.json({ $defs: {} }) }),
    });
    expect(result).toMatchObject({ kind: 'failed', request: `GET ${SCHEMA_URL}` });
    expect(exitCodeFor(result)).toBe(2);
  });

  it('fails, naming the ecosystem probed, when a probe hits a network error', async () => {
    const result = await checkEcosystems({
      catalog: ['npm', 'GIT'],
      fetch: fakeFetch({ schema: ['npm'], probes: { npm: new TypeError('fetch failed') } }),
    });
    expect(result).toMatchObject({
      kind: 'failed',
      request: `POST ${QUERY_URL} (ecosystem "npm")`,
    });
    expect(renderReport(result)).toContain('fetch failed');
    expect(exitCodeFor(result)).toBe(2);
  });

  it('fails on a probe status other than 200 or an invalid-ecosystem 400', async () => {
    const result = await checkEcosystems({
      catalog: ['npm', 'GIT'],
      fetch: fakeFetch({
        schema: ['npm'],
        probes: { GIT: new Response('rate limited', { status: 429 }) },
      }),
    });
    expect(result).toMatchObject({
      kind: 'failed',
      request: `POST ${QUERY_URL} (ecosystem "GIT")`,
    });
    expect(renderReport(result)).toContain('HTTP 429');
  });

  it('fails rather than withholding on a 400 whose body is not the invalid-ecosystem error', async () => {
    const result = await checkEcosystems({
      catalog: ['npm', 'GIT'],
      fetch: fakeFetch({
        schema: ['npm', 'Odd'],
        probes: { Odd: Response.json({ code: 3, message: 'invalid version' }, { status: 400 }) },
      }),
    });
    expect(result.kind).toBe('failed');
  });
});

describe('renderReport', () => {
  it('prints the three lists with their entries and the verdict', () => {
    const text = renderReport({
      kind: 'checked',
      add: ['Homebrew'],
      withhold: ['Red Hat Lightwell'],
      remove: [{ name: 'Gone', reason: 'not in the schema' }],
      probed: 4,
    });
    expect(text).toMatch(/^add\b.*\(1\):\n {2}- Homebrew$/m);
    expect(text).toMatch(/^withhold\b.*\(1\):\n {2}- Red Hat Lightwell$/m);
    expect(text).toMatch(/^remove\b.*\(1\):\n {2}- Gone — not in the schema$/m);
    expect(text).toContain('Drift');
  });

  it('prints "(none)" under empty lists and an in-sync verdict', () => {
    const text = renderReport({ kind: 'checked', add: [], withhold: [], remove: [], probed: 3 });
    expect(text.match(/\(none\)/g)).toHaveLength(3);
    expect(text).toContain('In sync');
  });
});
