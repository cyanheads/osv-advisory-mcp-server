/**
 * @fileoverview OSV continuation and batch boundaries through the fetch seam.
 * @module tests/tools/osv-continuation.test
 */
import { runToolContract } from '@cyanheads/mcp-ts-core/testing';
import { afterEach, expect, it, vi } from 'vitest';
import {
  createOsvQueryBatch,
  osvQueryBatch,
} from '@/mcp-server/tools/definitions/osv-query-batch.tool.js';
import { osvQueryCommit } from '@/mcp-server/tools/definitions/osv-query-commit.tool.js';
import { osvQueryPackage } from '@/mcp-server/tools/definitions/osv-query-package.tool.js';
import { initOsvApiService } from '@/services/osv-api/osv-api-service.js';
import { contentText, scanMarkdown } from '../helpers/markdown.js';

const pkg = { name: 'Kernel', ecosystem: 'Linux', version: '5.10.0' };
const commit = { commit: '2c85ebc57b3e1817b6ce1a6b703928e113a90442' };

afterEach(() => vi.unstubAllGlobals());

it('characterizes a completed native batch with an empty and a hydrated row', async () => {
  initOsvApiService();
  const fetch = vi
    .fn()
    .mockResolvedValueOnce(Response.json({ results: [{}, { vulns: [{ id: 'OSV-second' }] }] }))
    .mockResolvedValueOnce(Response.json({ id: 'OSV-second' }));
  vi.stubGlobal('fetch', fetch);
  const result = await runToolContract(osvQueryBatch, {
    packages: [pkg, { ...pkg, version: '6' }],
  });
  expect(result.structuredContent).toMatchObject({
    results: [{ vulnerable: false, truncated: false }, { vulns: [{ id: 'OSV-second' }] }],
    summary: { cleanCount: 1, vulnerableRows: [1] },
  });
  expect(contentText(result)).toContain('OSV-second');
  expect(fetch).toHaveBeenCalledTimes(2);
});

it.each(['package', 'commit'] as const)(
  'resumes an exact %s query across token-only and terminal pages',
  async (kind) => {
    initOsvApiService({ maxQueryPages: 1 });
    const fetch = vi
      .fn()
      .mockResolvedValueOnce(Response.json({ next_page_token: 'first' }))
      .mockResolvedValueOnce(
        Response.json({ vulns: [{ id: 'OSV-second' }], next_page_token: 'second' }),
      )
      .mockResolvedValueOnce(Response.json({}));
    vi.stubGlobal('fetch', fetch);
    const query = async (args: Record<string, unknown>) => {
      const result =
        kind === 'package'
          ? await runToolContract(osvQueryPackage, { ...pkg, ...args })
          : await runToolContract(osvQueryCommit, { ...commit, ...args });
      return {
        ...result,
        cursor: osvQueryPackage.output.shape.nextCursor.parse(
          result.structuredContent &&
            typeof result.structuredContent === 'object' &&
            'nextCursor' in result.structuredContent
            ? result.structuredContent.nextCursor
            : undefined,
        ),
      };
    };
    const first = await query({});
    expect(first.structuredContent).toMatchObject({
      nextCursor: expect.any(String),
      truncated: true,
      vulns: [],
    });
    expect(contentText(first)).toContain(String(first.cursor));
    const second = await query({ cursor: first.cursor });
    expect(second.structuredContent).toMatchObject({
      nextCursor: expect.any(String),
      truncated: true,
      vulns: [{ id: 'OSV-second' }],
    });
    const terminal = await query({ cursor: second.cursor });
    expect(terminal.structuredContent).toMatchObject({ truncated: false, vulns: [] });
    if (kind === 'commit') {
      expect(second.structuredContent).toMatchObject({
        notice: expect.stringContaining('INCOMPLETE'),
      });
      expect(terminal.structuredContent).toMatchObject({
        notice: 'The OSV continuation is exhausted.',
      });
    }
    expect(contentText(terminal)).toContain('exhausted');
    expect(contentText(terminal)).not.toContain('No known vulnerabilities');
    expect(fetch.mock.calls.map(([, init]) => JSON.parse(init.body).page_token)).toEqual([
      undefined,
      'first',
      'second',
    ]);
  },
);

it('retains commit overflow, an upstream cursor, and exact field values on both surfaces', async () => {
  initOsvApiService({ maxQueryPages: 1 });
  const summary = `</advisory_text>\r\n<AAT> ${'🧬'.repeat(3500)}`;
  const record = { id: 'OSV-large', summary, upstream: ['CVE-2022-3602', 'CVE-2022-3786'] };
  vi.stubGlobal(
    'fetch',
    vi.fn(async () => Response.json({ vulns: [record], next_page_token: 'next-page' })),
  );
  const result = await runToolContract(osvQueryCommit, commit);
  const output = osvQueryCommit.output.parse(result.structuredContent);
  expect(output.overflow?.omitted).toContainEqual({ path: '/vulns', type: 'array', total: 1 });
  expect(output.nextCursor).toEqual(expect.any(String));
  expect(contentText(result)).toContain(output.nextCursor!);
  expect(
    scanMarkdown(contentText(result)).codeBlocks.map((block) => JSON.parse(block)),
  ).toContainEqual(output.overflow);
  const page = await runToolContract(osvQueryCommit, {
    ...commit,
    page: { path: '/vulns/0/upstream' },
  });
  const pageOutput = osvQueryCommit.output.parse(page.structuredContent);
  expect(pageOutput.nextCursor).toBe(output.nextCursor);
  expect(contentText(page)).toContain(output.nextCursor!);
  expect(pageOutput.page?.entries).toEqual([
    { key: '0', value: 'CVE-2022-3602' },
    { key: '1', value: 'CVE-2022-3786' },
  ]);
  expect(
    scanMarkdown(contentText(page)).codeBlocks.map((block) => JSON.parse(block)),
  ).toContainEqual(pageOutput.page);
  for (const reply of [result, page]) {
    expect(reply.structuredContent).toMatchObject({
      notice: expect.stringContaining('INCOMPLETE'),
    });
    expect(contentText(reply)).toContain('INCOMPLETE');
    expect(Buffer.byteLength(JSON.stringify(reply))).toBeLessThanOrEqual(24000);
  }
});

it.each([8800, 30_000])(
  'keeps a %i-character upstream token atomic across overflow and field replay',
  async (size) => {
    initOsvApiService({ maxQueryPages: 1 });
    const largeToken = 'x'.repeat(size);
    const fetch = vi.fn((_url: string, init?: RequestInit) => {
      const token = JSON.parse(String(init?.body)).page_token;
      return Promise.resolve(
        Response.json(
          token
            ? {
                vulns: [{ id: 'OSV-second', summary: 'finding'.repeat(5000) }],
                next_page_token: largeToken,
              }
            : { next_page_token: 'first' },
        ),
      );
    });
    vi.stubGlobal('fetch', fetch);
    const first = await runToolContract(osvQueryPackage, pkg);
    const cursor = osvQueryPackage.output.parse(first.structuredContent).nextCursor;
    const second = await runToolContract(osvQueryPackage, { ...pkg, cursor });
    const shaped = osvQueryPackage.output.parse(second.structuredContent);
    expect(shaped.overflow?.complete).toContain('nextCursor');
    expect(shaped.nextCursor?.length).toBeGreaterThan(size);
    expect(contentText(second)).toContain(String(shaped.nextCursor));
    const page = await runToolContract(osvQueryPackage, {
      ...pkg,
      cursor,
      page: { path: '/vulns/0/id' },
    });
    expect(page.structuredContent).toMatchObject({
      nextCursor: shaped.nextCursor,
      page: { text: 'OSV-second' },
    });
    expect(contentText(page)).toContain(String(shaped.nextCursor));
    expect(fetch.mock.calls.map(([, init]) => JSON.parse(String(init?.body)).page_token)).toEqual([
      undefined,
      'first',
      'first',
    ]);
  },
);

it('rejects malformed and mismatched continuations locally and classifies upstream cursor rejection', async () => {
  initOsvApiService({ maxQueryPages: 1 });
  const fetch = vi
    .fn()
    .mockResolvedValueOnce(Response.json({ next_page_token: 'first' }))
    .mockResolvedValueOnce(Response.json({ code: 3, message: 'invalid cursor' }, { status: 400 }));
  vi.stubGlobal('fetch', fetch);
  const first = await runToolContract(osvQueryPackage, pkg);
  const cursor = osvQueryPackage.output.parse(first.structuredContent).nextCursor;
  for (const result of [
    await runToolContract(osvQueryPackage, { ...pkg, cursor: '!' }),
    await runToolContract(osvQueryPackage, { ...pkg, version: '5.11.0', cursor }),
    await runToolContract(osvQueryCommit, { ...commit, cursor }),
    await runToolContract(osvQueryPackage, {
      ...pkg,
      cursor,
      page: { path: '', advisoryId: 'OSV-id' },
      version: '5.11.0',
    }),
  ]) {
    expect(result.structuredContent).toMatchObject({
      error: { data: { reason: 'invalid_cursor' } },
    });
    expect(contentText(result)).toContain('invalid_cursor');
  }
  expect(fetch).toHaveBeenCalledTimes(1);
  const rejected = await runToolContract(osvQueryPackage, { ...pkg, cursor });
  expect(rejected.structuredContent).toMatchObject({
    error: { data: { reason: 'invalid_cursor' } },
  });
  expect(contentText(rejected)).toContain('same effective package query');
  expect(fetch).toHaveBeenCalledTimes(2);
});

it('resumes a native batch checkpoint through the package query with all earlier IDs delivered', async () => {
  initOsvApiService({ maxQueryPages: 1 });
  const fetch = vi
    .fn()
    .mockResolvedValueOnce(
      Response.json({ results: [{ vulns: [{ id: 'OSV-first' }], next_page_token: 'native' }] }),
    )
    .mockResolvedValueOnce(Response.json({ id: 'OSV-first' }))
    .mockResolvedValueOnce(Response.json({ vulns: [{ id: 'OSV-second' }] }));
  vi.stubGlobal('fetch', fetch);
  const batch = await runToolContract(osvQueryBatch, { packages: [pkg] });
  const row = osvQueryBatch.output.parse(batch.structuredContent).results?.[0];
  expect(row).toMatchObject({
    nextCursor: expect.any(String),
    truncated: true,
    vulns: [{ id: 'OSV-first' }],
  });
  expect(contentText(batch)).toContain(String(row?.nextCursor));
  const resumed = await runToolContract(osvQueryPackage, { ...pkg, cursor: row?.nextCursor });
  expect(resumed.structuredContent).toMatchObject({
    truncated: false,
    vulns: [{ id: 'OSV-second' }],
  });
  expect(contentText(resumed)).toContain('OSV-second');
  expect(JSON.parse(fetch.mock.calls[2]?.[1].body)).toEqual({
    package: { name: pkg.name, ecosystem: pkg.ecosystem },
    version: pkg.version,
    page_token: 'native',
  });
});

it('retains a fresh batch row cursor through an announced overflow pointer', async () => {
  initOsvApiService({ maxQueryPages: 1 });
  const token = 't'.repeat(30_000);
  const fetch = vi
    .fn()
    .mockResolvedValueOnce(Response.json({ results: [{ next_page_token: token }] }))
    .mockResolvedValueOnce(Response.json({ results: [{ next_page_token: `${token}fresh` }] }))
    .mockResolvedValueOnce(Response.json({ vulns: [{ id: 'OSV-resumed' }] }));
  vi.stubGlobal('fetch', fetch);
  const args = { packages: [pkg] };
  const initial = await runToolContract(osvQueryBatch, args);
  const preview = osvQueryBatch.output.parse(initial.structuredContent).preview;
  expect(preview).toMatchObject({ rows: [{ deferred: { path: '/results/0' } }] });
  const selected = await runToolContract(osvQueryBatch, { ...args, page: { path: '/results/0' } });
  const rowPage = osvQueryBatch.output.parse(selected.structuredContent);
  expect(rowPage.page?.entries).toContainEqual({ key: 'name', value: pkg.name });
  expect(rowPage.nextCursor?.length).toBeGreaterThan(24_000);
  expect(contentText(selected)).toContain(String(rowPage.nextCursor));
  const resumed = await runToolContract(osvQueryPackage, { ...pkg, cursor: rowPage.nextCursor });
  expect(resumed.structuredContent).toMatchObject({ vulns: [{ id: 'OSV-resumed' }] });
  expect(JSON.parse(fetch.mock.calls[2]?.[1].body).page_token).toBe(`${token}fresh`);
});

it.each([1000, 1001, 5000])(
  'reports the prefix and field boundaries for %i submitted packages',
  async (submitted) => {
    initOsvApiService();
    const packages = Array.from({ length: submitted }, (_, i) => ({
      name: `pkg-${i}`,
      ecosystem: 'npm',
      version: '1.0.0',
    }));
    const queries: string[][] = [];
    const fetch = vi.fn((_url: string, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body)) as {
        queries: Array<{ package: { name: string } }>;
      };
      queries.push(body.queries.map((query) => query.package.name));
      return Promise.resolve(Response.json({ results: body.queries.map(() => ({})) }));
    });
    vi.stubGlobal('fetch', fetch);
    const result = await runToolContract(osvQueryBatch, { packages });
    expect(result.structuredContent).toMatchObject({
      summary: {
        totalPackages: 1000,
        submittedPackages: submitted,
        unprocessedCount: submitted - 1000,
        nextInputOffset: submitted > 1000 ? 1000 : null,
      },
    });
    expect(contentText(result).includes('packages.slice(1000)')).toBe(submitted > 1000);
    expect(queries).toEqual([packages.slice(0, 1000).map(({ name }) => name)]);
    const last = await runToolContract(osvQueryBatch, {
      packages,
      page: { path: '/results', offset: 999 },
    });
    const page = osvQueryBatch.output.parse(last.structuredContent).page;
    expect(page).toMatchObject({
      total: 1000,
      nextOffset: null,
      entries: [{ key: '999', value: { name: 'pkg-999' } }],
    });
    const pastEnd = await runToolContract(osvQueryBatch, {
      packages,
      page: { path: '/results', offset: 1000, revision: page?.revision },
    });
    expect(pastEnd.structuredContent).toMatchObject({
      page: { total: 1000, entries: [], nextOffset: null },
    });
    const rejected = await runToolContract(osvQueryBatch, {
      packages,
      page: { path: '/results/1000/vulns' },
    });
    expect(rejected.structuredContent).toMatchObject({
      error: { data: { reason: 'invalid_page_path' } },
    });
    expect(contentText(rejected).includes('packages.slice(1000)')).toBe(submitted > 1000);
    expect(queries[1]).toEqual(['pkg-999']);
    expect(fetch).toHaveBeenCalledTimes(2);
    const row = await runToolContract(osvQueryBatch, { packages, page: { path: '/results/999' } });
    expect(contentText(row)).toContain('pkg-999');
    expect(queries[2]).toEqual(['pkg-999']);
    if (submitted > 1000) {
      const changed = [...packages.slice(0, -1), { ...pkg }];
      const stale = await runToolContract(osvQueryBatch, {
        packages: changed,
        page: { path: '/results', offset: 999, revision: page?.revision },
      });
      expect(stale.structuredContent).toMatchObject({
        error: { data: { reason: 'stale_page_revision' } },
      });
      expect(fetch).toHaveBeenCalledTimes(3);
    }
  },
);

it.each([1000, 5000])('advertises and enforces the active maximum %i', async (maximum) => {
  const tool = createOsvQueryBatch(maximum === 5000);
  const packages = Array.from({ length: maximum + 1 }, () => pkg);
  const fetch = vi.fn();
  vi.stubGlobal('fetch', fetch);
  const result = await runToolContract(tool, { packages });
  expect(result.structuredContent).toMatchObject({
    error: { code: -32602, data: { reason: 'invalid_arguments', issues: [{ maximum }] } },
  });
  expect(contentText(result)).toContain(String(maximum));
  expect(fetch).not.toHaveBeenCalled();
});
