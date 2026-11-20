/**
 * @fileoverview Ubuntu package resolution through the real tool and fetch boundary.
 * @module tests/tools/osv-ubuntu-resolution.test
 */

import { JsonRpcErrorCode } from '@cyanheads/mcp-ts-core/errors';
import { createMockContext, runToolContract } from '@cyanheads/mcp-ts-core/testing';
import { afterEach, expect, it, vi } from 'vitest';
import { osvQueryBatch } from '@/mcp-server/tools/definitions/osv-query-batch.tool.js';
import { osvQueryPackage } from '@/mcp-server/tools/definitions/osv-query-package.tool.js';
import { initOsvApiService, OsvApiService } from '@/services/osv-api/osv-api-service.js';
import { packageBody } from '@/services/osv-api/package-identifier.js';
import { encodeQueryCursor, encodeSourceCursor } from '@/services/osv-api/query-cursor.js';
import { contentText } from '../helpers/markdown.js';

const binary = { name: 'libssl3', ecosystem: 'Ubuntu:22.04:LTS', version: '3.0.2-0ubuntu1' };
const source = { ...binary, name: 'openssl' };

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

it('resumes an existing Ubuntu source cursor using its original query body', async () => {
  initOsvApiService();
  const body = {
    package: { name: source.name, ecosystem: source.ecosystem },
    version: source.version,
  };
  const fetch = vi.fn().mockResolvedValueOnce(Response.json({}));
  vi.stubGlobal('fetch', fetch);
  const response = await runToolContract(osvQueryPackage, {
    ...source,
    cursor: encodeQueryCursor(body, 'next'),
  });
  expect(response.structuredContent).toMatchObject({
    truncated: false,
    continuationExhausted: true,
  });
  expect(contentText(response)).toContain('exhausted');
  expect(fetch).toHaveBeenCalledTimes(1);
  expect(JSON.parse(fetch.mock.calls[0]?.[1].body)).toEqual({ ...body, page_token: 'next' });
});

it.each([
  { purl: 'pkg:deb/ubuntu/linux@5.15.0-25.25?distro=ubuntu-22.04' },
  { purl: 'pkg:deb/ubuntu/linux?distro=ubuntu-22.04', version: '5.15.0-25.25' },
])('gives restart guidance for a v0.5.1 Ubuntu PURL cursor ($purl)', async (input) => {
  initOsvApiService();
  const fetch = vi.fn();
  vi.stubGlobal('fetch', fetch);
  const oldBody = {
    package: { purl: input.purl },
    ...(input.version === undefined ? {} : { version: input.version }),
  };
  const cursor = encodeQueryCursor(oldBody, 'old-page');
  for (const page of [undefined, { advisoryId: 'UBUNTU-test', path: '/fixedVersions' }]) {
    const response = await runToolContract(osvQueryPackage, { ...input, cursor, page });
    const hint =
      'Omit cursor and repeat the original Ubuntu PURL query to start over with the requested release.';
    expect(response.structuredContent).toMatchObject({
      error: { data: { reason: 'invalid_cursor', recovery: { hint } } },
    });
    expect(contentText(response)).toContain(hint);
  }
  expect(fetch).not.toHaveBeenCalled();
});

it('queries the mapped source while echoing the original package on both output surfaces', async () => {
  initOsvApiService();
  const fetch = vi
    .fn()
    .mockResolvedValueOnce(Response.json({ results: [{ source_names: ['openssl'] }] }))
    .mockResolvedValueOnce(Response.json({ vulns: [{ id: 'UBUNTU-mapped' }] }));
  vi.stubGlobal('fetch', fetch);
  const response = await runToolContract(osvQueryPackage, binary);
  expect(response.structuredContent).toMatchObject({
    queryMeta: { package: binary.name, sourceNames: ['openssl'] },
    vulns: [{ id: 'UBUNTU-mapped' }],
  });
  expect(contentText(response)).toContain('openssl');
  expect(contentText(response)).toContain(binary.name);
  expect(fetch.mock.calls.map(([, init]) => JSON.parse(init.body))).toEqual([
    { ecosystem: 'Ubuntu:22.04', binary_names: ['libssl3'] },
    { package: { name: source.name, ecosystem: binary.ecosystem }, version: binary.version },
  ]);
});

it('deduplicates batch names by release and keeps one row per input across source lookups', async () => {
  initOsvApiService();
  const fetch = vi
    .fn()
    .mockResolvedValueOnce(
      Response.json({ results: [{ source_names: ['openssl', 'openssl-fips'] }] }),
    )
    .mockResolvedValueOnce(
      Response.json({
        results: [
          { vulns: [{ id: 'UBUNTU-mapped' }] },
          { vulns: [{ id: 'UBUNTU-mapped' }] },
          {},
          {},
        ],
      }),
    )
    .mockResolvedValueOnce(Response.json({ id: 'UBUNTU-mapped' }));
  vi.stubGlobal('fetch', fetch);
  const pro = { ...binary, ecosystem: 'Ubuntu:Pro:22.04:LTS' };
  const response = await runToolContract(osvQueryBatch, { packages: [binary, pro] });
  expect(response.structuredContent).toMatchObject({
    results: [
      {
        name: binary.name,
        sourceNames: ['openssl', 'openssl-fips'],
        vulns: [{ id: 'UBUNTU-mapped' }],
      },
      { name: pro.name, sourceNames: ['openssl', 'openssl-fips'], vulns: [] },
    ],
    summary: { cleanCount: 1, vulnerableRows: [0] },
  });
  expect(contentText(response)).toContain('openssl-fips');
  expect(fetch).toHaveBeenCalledTimes(3);
  expect(JSON.parse(fetch.mock.calls[0]?.[1].body)).toEqual({
    ecosystem: 'Ubuntu:22.04',
    binary_names: ['libssl3'],
  });
  expect(JSON.parse(fetch.mock.calls[1]?.[1].body)).toMatchObject({
    queries: [binary, pro].flatMap(({ ecosystem }) =>
      ['openssl', 'openssl-fips'].map((name) => ({ package: { name, ecosystem } })),
    ),
  });
});

it('spends one page per original row and continues across source boundaries from a native batch', async () => {
  initOsvApiService({ maxQueryPages: 1 });
  const record = {
    id: 'UBUNTU-shared',
    affected: [
      ['openssl', binary.ecosystem, '2'],
      ['openssl-fips', binary.ecosystem, '3'],
      ['openssl', 'Ubuntu:18.04:LTS', '4'],
    ].map(([name, ecosystem, fixed]) => ({
      package: { name, ecosystem },
      ranges: [{ type: 'ECOSYSTEM', events: [{ fixed }] }],
    })),
  };
  const queries: Array<{ package: { name: string }; page_token?: string }> = [];
  const fetch = vi.fn(async (url: string, init?: RequestInit) => {
    switch (new URL(url).pathname) {
      case '/v1experimental/ubuntu/binary-to-source':
        // Upstream order and duplicate names need not be stable.
        return Response.json({
          results: [{ source_names: ['openssl-fips', 'openssl', 'openssl'] }],
        });
      case '/v1/querybatch': {
        const body = JSON.parse(String(init?.body));
        expect(body.queries).toHaveLength(1);
        queries.push(...body.queries);
        return Response.json({ results: [{ next_page_token: 'openssl-token' }] });
      }
      case '/v1/query': {
        const query = JSON.parse(String(init?.body));
        queries.push(query);
        return Response.json(query.page_token ? {} : { vulns: [record] });
      }
      case '/v1/vulns/UBUNTU-shared':
        return Response.json(record);
      default:
        throw new Error('Unexpected request');
    }
  });
  vi.stubGlobal('fetch', fetch);

  const batch = await runToolContract(osvQueryBatch, { packages: [binary] });
  const firstCursor = osvQueryBatch.output.parse(batch.structuredContent).results?.[0]?.nextCursor;
  expect(batch.structuredContent).toMatchObject({ summary: { cleanCount: 0, truncatedRows: [0] } });
  expect(contentText(batch)).toContain(String(firstCursor));

  const second = await runToolContract(osvQueryPackage, { ...binary, cursor: firstCursor });
  const secondCursor = osvQueryPackage.output.parse(second.structuredContent).nextCursor;
  expect(second.structuredContent).toMatchObject({ truncated: true, vulns: [] });
  expect(contentText(second)).toContain(String(secondCursor));

  const third = await runToolContract(osvQueryPackage, { ...binary, cursor: secondCursor });
  expect(third.structuredContent).toMatchObject({
    truncated: false,
    vulns: [{ id: record.id, fixedVersions: ['2', '3'] }],
  });
  expect(contentText(third)).toContain('Fixed in 2, 3');
  expect(queries.map(({ package: { name }, page_token }) => [name, page_token])).toEqual([
    ['openssl', undefined],
    ['openssl', 'openssl-token'],
    ['openssl-fips', undefined],
  ]);

  const page = { advisoryId: record.id, path: '/fixedVersions' };
  const field = await runToolContract(osvQueryPackage, { ...binary, cursor: secondCursor, page });
  expect(field.structuredContent).toMatchObject({
    page: { entries: [{ value: '2' }, { value: '3' }] },
  });
  expect(contentText(field)).toContain('3');
  const pastEnd = await runToolContract(osvQueryPackage, {
    ...binary,
    cursor: secondCursor,
    page: { ...page, offset: 3 },
  });
  expect(pastEnd.structuredContent).toMatchObject({ page: { entries: [], nextOffset: null } });
});

it.each([false, true])(
  'rejects invented source names before advisory requests (field page: %s)',
  async (fieldPage) => {
    initOsvApiService();
    const fetch = vi
      .fn()
      .mockResolvedValueOnce(Response.json({ results: [{ source_names: ['openssl'] }] }));
    vi.stubGlobal('fetch', fetch);
    const cursor = encodeSourceCursor(packageBody(binary), [{ name: 'unverified-source' }]);
    const response = await runToolContract(osvQueryPackage, {
      ...binary,
      cursor,
      ...(fieldPage ? { page: { advisoryId: 'OSV-id', path: '/fixedVersions' } } : {}),
    });
    expect(response.structuredContent).toMatchObject({
      error: { data: { reason: 'invalid_cursor' } },
    });
    expect(contentText(response)).toContain('same effective package query');
    expect(fetch).toHaveBeenCalledTimes(1);
    expect(String(fetch.mock.calls[0]?.[0])).toContain('/binary-to-source');
  },
);

it('rejects v2 cursors for non-Ubuntu packages without I/O', async () => {
  initOsvApiService();
  const fetch = vi.fn();
  vi.stubGlobal('fetch', fetch);
  const input = { name: 'demo', ecosystem: 'npm', version: '1.0.0' };
  const cursor = encodeSourceCursor(packageBody(input), [{ name: 'unverified-source' }]);
  const response = await runToolContract(osvQueryPackage, {
    ...input,
    cursor,
    page: { advisoryId: 'OSV-id', path: '/fixedVersions' },
  });
  expect(response.structuredContent).toMatchObject({
    error: { data: { reason: 'invalid_cursor' } },
  });
  expect(fetch).not.toHaveBeenCalled();
});

it('reports malformed mapping fallbacks as inconclusive on both tools', async () => {
  initOsvApiService();
  const fetch = vi
    .fn()
    .mockResolvedValueOnce(Response.json({ results: [] }))
    .mockResolvedValueOnce(Response.json({}))
    .mockResolvedValueOnce(Response.json({ results: [] }))
    .mockResolvedValueOnce(Response.json({ results: [{}] }));
  vi.stubGlobal('fetch', fetch);
  const single = await runToolContract(osvQueryPackage, binary);
  expect(single.structuredContent).toMatchObject({
    queryMeta: { sourceNames: [binary.name], sourceResolutionUnavailable: true },
    vulns: [],
  });
  expect(contentText(single)).toContain('Ubuntu source resolution was unavailable');
  expect(contentText(single)).not.toContain('No known vulnerabilities');
  const batch = await runToolContract(osvQueryBatch, { packages: [binary] });
  expect(batch.structuredContent).toMatchObject({
    results: [{ ...binary, sourceResolutionUnavailable: true, vulnCount: 0 }],
    summary: { cleanCount: 0 },
  });
  expect(contentText(batch)).toContain(
    `\`${binary.name}\` @ \`${binary.version}\` (${binary.ecosystem}) — Ubuntu source resolution unavailable. No findings.`,
  );
  expect(contentText(batch)).toMatch(/resolution (?:was )?unavailable/i);
  expect(contentText(batch)).not.toContain('— clean');
  expect(fetch).toHaveBeenCalledTimes(4);
});

it('preserves rate-limit failure without attempting an original-name fallback', async () => {
  vi.useFakeTimers();
  initOsvApiService();
  const fetch = vi.fn(async (_url: string) => Response.json({}, { status: 429 }));
  vi.stubGlobal('fetch', fetch);
  const pending = runToolContract(osvQueryPackage, binary);
  await vi.runAllTimersAsync();
  const response = await pending;
  expect(response.structuredContent).toMatchObject({
    error: { code: JsonRpcErrorCode.RateLimited },
  });
  expect(contentText(response)).toContain('429');
  expect(fetch.mock.calls.every(([url]) => String(url).endsWith('/binary-to-source'))).toBe(true);
});

it('bounds mapping and native advisory request windows independently after source expansion', async () => {
  const mapSizes: number[] = [];
  const querySizes: number[] = [];
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body));
      if (new URL(url).pathname.endsWith('/binary-to-source')) {
        mapSizes.push(body.binary_names.length);
        return Response.json({
          results: body.binary_names.map((name: string) =>
            name === 'binary-0' ? { source_names: ['source-a', 'source-b'] } : {},
          ),
        });
      }
      expect(new URL(url).pathname).toBe('/v1/querybatch');
      querySizes.push(body.queries.length);
      return Response.json({ results: body.queries.map(() => ({})) });
    }),
  );
  const packages = Array.from({ length: 1001 }, (_, index) => ({
    ...binary,
    name: `binary-${index}`,
  }));
  const rows = await new OsvApiService().queryBatch(packages, createMockContext());
  expect(mapSizes).toEqual([1000, 1]);
  expect(querySizes).toEqual([1000, 2]);
  expect(rows).toHaveLength(1001);
  expect(rows[0]).toMatchObject({
    name: 'binary-0',
    sourceNames: ['source-a', 'source-b'],
    error: null,
  });
  expect(rows.at(-1)).toMatchObject({
    name: 'binary-1000',
    sourceNames: ['binary-1000'],
    error: null,
  });
});

it('propagates cancellation during mapping without performing advisory I/O', async () => {
  initOsvApiService();
  const controller = new AbortController();
  const fetch = vi.fn(async (_url: string) => {
    controller.abort();
    return Response.json({ results: [{}] });
  });
  vi.stubGlobal('fetch', fetch);
  const response = await runToolContract(osvQueryPackage, binary, {
    context: { signal: controller.signal },
  });
  expect(response.structuredContent).toMatchObject({
    error: { code: JsonRpcErrorCode.RequestCancelled },
  });
  expect(contentText(response)).toMatch(/cancel|abort/i);
  expect(fetch).toHaveBeenCalledTimes(1);
});
