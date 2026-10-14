/**
 * @fileoverview Native OSV batch orchestration tested at the HTTP boundary.
 * @module tests/services/osv-native-batch.test
 */
import { createMockContext } from '@cyanheads/mcp-ts-core/testing';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { OsvApiService } from '@/services/osv-api/osv-api-service.js';
import { stubOsvApi } from '../helpers/osv-fixtures.js';

const packages = ['a', 'b'].map((name) => ({ name, ecosystem: 'npm', version: '1' }));
const record = {
  id: 'shared',
  aliases: ['CVE-shared'],
  summary: 'Shared advisory',
  affected: [
    {
      package: { name: 'a', ecosystem: 'npm' },
      severity: [{ type: 'Ubuntu', score: 'low' }],
      ranges: [
        {
          type: 'SEMVER' as const,
          events: [{ introduced: '0' }, { fixed: '2' }, { introduced: '3' }, { fixed: '4' }],
        },
      ],
    },
    {
      package: { name: 'b', ecosystem: 'npm' },
      severity: [{ type: 'Ubuntu', score: 'critical' }],
      ranges: [{ type: 'SEMVER' as const, events: [{ introduced: '0' }, { fixed: '5' }] }],
    },
  ],
};

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe('batch characterization', () => {
  it('keeps ordered intervals and package severity independent on shared advisories', async () => {
    stubOsvApi({ query: () => [record] });
    const rows = await new OsvApiService().queryBatch(packages, createMockContext());
    expect(rows.map((row) => row.vulns[0])).toEqual([
      {
        id: 'shared',
        aliases: ['CVE-shared'],
        summary: 'Shared advisory',
        severityLabel: 'LOW',
        fixedVersions: ['2', '4'],
      },
      {
        id: 'shared',
        aliases: ['CVE-shared'],
        summary: 'Shared advisory',
        severityLabel: 'CRITICAL',
        fixedVersions: ['5'],
      },
    ]);
  });
});

describe('native batch', () => {
  it('marks queued fallback rows failed when the operation deadline expires', async () => {
    vi.useFakeTimers();
    const fetch = vi.fn((url: string, init?: RequestInit) => {
      if (new URL(url).pathname === '/v1/querybatch')
        return Promise.resolve(
          Response.json({ code: 3, message: 'invalid query' }, { status: 400 }),
        );
      return new Promise<Response>((_resolve, reject) =>
        init?.signal?.addEventListener('abort', () => reject(init.signal?.reason), { once: true }),
      );
    });
    vi.stubGlobal('fetch', fetch);
    const pending = new OsvApiService({ timeoutMs: 60_000, batchConcurrency: 1 }).queryBatch(
      packages,
      createMockContext(),
    );
    await vi.advanceTimersByTimeAsync(50_000);
    const rows = await pending;
    expect(rows.every((row) => row.error !== null)).toBe(true);
    expect(fetch).toHaveBeenCalledTimes(2);
  });
  it('follows independent token-only pages, removing completed rows and deduplicating repeated IDs', async () => {
    const bodies: unknown[] = [];
    const pages = [
      {
        results: [{ next_page_token: 'a1' }, { vulns: [{ id: 'shared' }], next_page_token: 'b1' }],
      },
      { results: [{ next_page_token: 'a2' }, {}] },
      { results: [{ vulns: [{ id: 'shared' }, { id: 'shared' }] }] },
    ];
    const fetch = vi.fn((url: string, init?: RequestInit) => {
      if (new URL(url).pathname === '/v1/querybatch') {
        bodies.push(JSON.parse(String(init?.body)));
        return Promise.resolve(Response.json(pages.shift()));
      }
      return Promise.resolve(Response.json(record));
    });
    vi.stubGlobal('fetch', fetch);
    const rows = await new OsvApiService().queryBatch(packages, createMockContext());
    expect(rows.map((row) => row.truncated)).toEqual([false, false]);
    expect(rows.map((row) => row.vulns.length)).toEqual([1, 1]);
    expect(bodies).toEqual([
      {
        queries: packages.map(({ name, ecosystem, version }) => ({
          package: { name, ecosystem },
          version,
        })),
      },
      {
        queries: packages.map(({ name, ecosystem, version }, i) => ({
          package: { name, ecosystem },
          version,
          page_token: i ? 'b1' : 'a1',
        })),
      },
      { queries: [{ package: { name: 'a', ecosystem: 'npm' }, version: '1', page_token: 'a2' }] },
    ]);
    expect(fetch).toHaveBeenCalledTimes(4);
  });

  it('caps token-only pages without calling an unfinished row clean', async () => {
    const fetch = vi.fn(() =>
      Promise.resolve(Response.json({ results: [{ next_page_token: 'more' }, {}] })),
    );
    vi.stubGlobal('fetch', fetch);
    const rows = await new OsvApiService({ maxQueryPages: 1 }).queryBatch(
      packages,
      createMockContext(),
    );
    expect(rows[0]).toMatchObject({ vulns: [], truncated: true, error: null });
    expect(rows[1]).toMatchObject({ vulns: [], truncated: false, error: null });
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it('retains original positions after indexed rejection and one resubmission', async () => {
    const fetch = vi
      .fn()
      .mockResolvedValueOnce(
        Response.json(
          { code: 3, message: 'error in query at index 1: invalid ecosystem' },
          { status: 400 },
        ),
      )
      .mockResolvedValueOnce(Response.json({ results: [{ vulns: [{ id: 'shared' }] }, {}] }))
      .mockResolvedValueOnce(Response.json(record));
    vi.stubGlobal('fetch', fetch);
    const rows = await new OsvApiService().queryBatch(
      [...packages, { name: 'clean', ecosystem: 'npm', version: '1' }],
      createMockContext(),
    );
    expect(rows.map((row) => row.name)).toEqual(['a', 'b', 'clean']);
    expect(rows[0]?.vulns[0]?.id).toBe('shared');
    expect(rows[1]?.error).toContain('index 1');
    expect(rows[2]?.error).toBeNull();
    expect(
      JSON.parse(fetch.mock.calls[1]![1].body).queries.map(
        (query: { package: { name: string } }) => query.package.name,
      ),
    ).toEqual(['a', 'clean']);
  });

  it.each(['invalid query', 'error in query at index 999: invalid ecosystem'])(
    'uses per-row recovery for untrustworthy index: %s',
    async (message) => {
      const fetch = vi.fn((url: string, init?: RequestInit) => {
        if (new URL(url).pathname === '/v1/querybatch')
          return Promise.resolve(Response.json({ code: 3, message }, { status: 400 }));
        const query = JSON.parse(String(init?.body));
        return Promise.resolve(
          query.package.name === 'a'
            ? Response.json({ vulns: [record] })
            : Response.json({ code: 3, message: 'Invalid ecosystem.' }, { status: 400 }),
        );
      });
      vi.stubGlobal('fetch', fetch);
      const rows = await new OsvApiService({ batchConcurrency: 1 }).queryBatch(
        packages,
        createMockContext(),
      );
      expect(rows[0]?.vulns[0]?.id).toBe('shared');
      expect(rows[1]?.error).toBe('Invalid ecosystem.');
      expect(fetch).toHaveBeenCalledTimes(3);
    },
  );

  it('bounds repeated rejection and preserves accumulated IDs, token and remaining cap in fallback', async () => {
    const bodies: Array<{ path: string; body: unknown }> = [];
    let native = 0;
    const fetch = vi.fn((url: string, init?: RequestInit) => {
      const path = new URL(url).pathname;
      if (path.startsWith('/v1/vulns/')) return Promise.resolve(Response.json(record));
      bodies.push({ path, body: JSON.parse(String(init?.body)) });
      if (path === '/v1/querybatch') {
        native++;
        if (native === 1)
          return Promise.resolve(
            Response.json({
              results: [
                { vulns: [{ id: 'shared' }], next_page_token: 'a1' },
                { next_page_token: 'b1' },
                { next_page_token: 'c1' },
              ],
            }),
          );
        return Promise.resolve(
          Response.json(
            { code: 3, message: 'error in query at index 1: invalid ecosystem' },
            { status: 400 },
          ),
        );
      }
      return Promise.resolve(Response.json({ next_page_token: 'still-more' }));
    });
    vi.stubGlobal('fetch', fetch);
    const rows = await new OsvApiService({ maxQueryPages: 2 }).queryBatch(
      [...packages, { name: 'c', ecosystem: 'npm', version: '1' }],
      createMockContext(),
    );
    expect(native).toBe(3);
    expect(bodies.filter(({ path }) => path === '/v1/query')).toEqual([
      {
        path: '/v1/query',
        body: { package: { name: 'a', ecosystem: 'npm' }, version: '1', page_token: 'a1' },
      },
      {
        path: '/v1/query',
        body: { package: { name: 'c', ecosystem: 'npm' }, version: '1', page_token: 'c1' },
      },
    ]);
    expect(rows[0]).toMatchObject({ truncated: true, error: null, vulns: [{ id: 'shared' }] });
    expect(rows[1]?.error).toContain('index 1');
    expect(rows[2]).toMatchObject({ truncated: true, error: null, vulns: [] });
  });

  it('isolates a shared detail failure to every dependent row', async () => {
    const fetch = vi.fn((url: string) =>
      Promise.resolve(
        new URL(url).pathname === '/v1/querybatch'
          ? Response.json({
              results: [{ vulns: [{ id: 'gone' }] }, { vulns: [{ id: 'gone' }] }, {}],
            })
          : Response.json({ code: 5, message: 'not found' }, { status: 404 }),
      ),
    );
    vi.stubGlobal('fetch', fetch);
    const rows = await new OsvApiService().queryBatch(
      [...packages, { name: 'clean', ecosystem: 'npm', version: '1' }],
      createMockContext(),
    );
    expect(rows.map((row) => row.error !== null)).toEqual([true, true, false]);
    expect(fetch).toHaveBeenCalledTimes(2);
  });

  it('does not amplify exhausted transient preflight errors into per-package retries', async () => {
    const fetch = vi.fn((_url: string) =>
      Promise.resolve(
        Response.json({ message: 'Unavailable' }, { status: 503, headers: { 'Retry-After': '0' } }),
      ),
    );
    vi.stubGlobal('fetch', fetch);
    const rows = await new OsvApiService().queryBatch(packages, createMockContext());
    expect(rows.every((row) => row.error !== null)).toBe(true);
    expect(fetch).toHaveBeenCalledTimes(3);
    expect(
      fetch.mock.calls.every((call) => new URL(String(call[0])).pathname === '/v1/querybatch'),
    ).toBe(true);
  });

  it('does not retain raw records between calls', async () => {
    stubOsvApi({ query: () => [record] });
    const service = new OsvApiService();
    await service.queryBatch(packages, createMockContext());
    stubOsvApi({ query: () => [{ ...record, summary: 'Changed' }] });
    expect((await service.queryBatch(packages, createMockContext()))[0]?.vulns[0]?.summary).toBe(
      'Changed',
    );
  });
  it('preflights once and GETs a shared advisory once, with no clean-row details', async () => {
    const fetch = vi.fn((url: string) =>
      Promise.resolve(
        Response.json(
          new URL(url).pathname === '/v1/querybatch'
            ? { results: [{ vulns: [{ id: 'shared' }] }, { vulns: [{ id: 'shared' }] }, {}] }
            : record,
        ),
      ),
    );
    vi.stubGlobal('fetch', fetch);
    const rows = await new OsvApiService().queryBatch(
      [...packages, { name: 'clean', ecosystem: 'npm', version: '1' }],
      createMockContext(),
    );
    expect(rows.map((row) => row.error)).toEqual([null, null, null]);
    expect(rows.map((row) => row.vulns.length)).toEqual([1, 1, 0]);
    expect(fetch).toHaveBeenCalledTimes(2);
    expect(new URL(fetch.mock.calls[0]![0]).pathname).toBe('/v1/querybatch');
  });

  it('propagates caller cancellation and stops queued work', async () => {
    const controller = new AbortController();
    const fetch = vi.fn(() => {
      controller.abort();
      return Promise.reject(new DOMException('Cancelled', 'AbortError'));
    });
    vi.stubGlobal('fetch', fetch);
    await expect(
      new OsvApiService({ batchConcurrency: 1 }).queryBatch(
        packages,
        createMockContext({ signal: controller.signal }),
      ),
    ).rejects.toThrow();
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it.each(['page', 'detail', 'fallback'])(
    'propagates cancellation during %s and starts no queued work',
    async (stage) => {
      const controller = new AbortController();
      let calls = 0;
      const fetch = vi.fn((url: string) => {
        calls++;
        if (calls === 1) {
          if (stage === 'fallback')
            return Promise.resolve(
              Response.json({ code: 3, message: 'invalid query' }, { status: 400 }),
            );
          return Promise.resolve(
            Response.json({
              results: packages.map(() =>
                stage === 'page'
                  ? { next_page_token: 'more' }
                  : { vulns: [{ id: 'shared' }, { id: 'queued' }] },
              ),
            }),
          );
        }
        controller.abort();
        return Promise.reject(new DOMException(`cancelled ${url}`, 'AbortError'));
      });
      vi.stubGlobal('fetch', fetch);
      await expect(
        new OsvApiService({ batchConcurrency: 1 }).queryBatch(
          packages,
          createMockContext({ signal: controller.signal }),
        ),
      ).rejects.toThrow();
      expect(fetch).toHaveBeenCalledTimes(2);
    },
  );

  it('returns an empty service batch without upstream work', async () => {
    const fetch = vi.fn();
    vi.stubGlobal('fetch', fetch);
    expect(await new OsvApiService().queryBatch([], createMockContext())).toEqual([]);
    expect(fetch).not.toHaveBeenCalled();
  });

  it.each([{}, { results: [{}] }, { results: [null, {}] }, { results: [{ vulns: [{}] }, {}] }])(
    'rejects malformed or misaligned upstream batch %j without clean rows',
    async (body) => {
      vi.stubGlobal(
        'fetch',
        vi.fn(() => Promise.resolve(Response.json(body))),
      );
      const rows = await new OsvApiService().queryBatch(packages, createMockContext());
      expect(rows.every((row) => row.error !== null)).toBe(true);
    },
  );
});
