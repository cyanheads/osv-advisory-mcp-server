/**
 * @fileoverview Commit-query HTTP, paging, errors and dual-surface contracts.
 * @module tests/tools/osv-query-commit.tool.test
 */
import { JsonRpcErrorCode } from '@cyanheads/mcp-ts-core/errors';
import { runToolContract } from '@cyanheads/mcp-ts-core/testing';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { osvQueryCommit } from '@/mcp-server/tools/definitions/osv-query-commit.tool.js';
import { RESPONSE_BYTES } from '@/mcp-server/tools/response-pages.js';
import { initOsvApiService } from '@/services/osv-api/osv-api-service.js';
import type { RawOsvVulnerability } from '@/services/osv-api/types.js';
import { countFrameClosers, scanMarkdown } from '../helpers/markdown.js';

const COMMIT = '6879efc2c1596d11a6a6ad296f80063b558d5e0f';
const RECORD: RawOsvVulnerability = {
  id: 'CVE-2020-TEST',
  summary: 'Source range',
  affected: [
    {
      severity: [{ type: 'Ubuntu', score: 'high' }],
      ranges: [
        {
          type: 'GIT',
          repo: 'https://example.org/repo',
          events: [
            { introduced: '0' },
            { fixed: COMMIT },
            { introduced: 'a'.repeat(40) },
            { fixed: 'b'.repeat(40) },
          ],
        },
      ],
    },
  ],
};
afterEach(() => vi.unstubAllGlobals());
function upstream(pages: unknown[]) {
  let index = 0;
  const requests: unknown[] = [];
  vi.stubGlobal(
    'fetch',
    vi.fn((_url: unknown, init: RequestInit) => {
      requests.push(JSON.parse(String(init.body)));
      if (index >= pages.length) throw new Error('Unexpected additional OSV call');
      return Promise.resolve(Response.json(pages[index++]));
    }),
  );
  return requests;
}
describe('osv_query_commit', () => {
  it('follows token-only pages and preserves record-wide severity and ordered GIT ranges', async () => {
    initOsvApiService();
    const requests = upstream([
      { next_page_token: 'one' },
      { next_page_token: 'two' },
      { vulns: [RECORD] },
    ]);
    const reply = await runToolContract(osvQueryCommit, { commit: COMMIT.toUpperCase() });
    expect(reply.isError).not.toBe(true);
    const result = osvQueryCommit.output.parse(reply.structuredContent);
    expect(result).toMatchObject({
      truncated: false,
      queryMeta: { commit: COMMIT.toUpperCase(), vulnCount: 1 },
      vulns: [
        {
          severityLabel: 'HIGH',
          severitySource: { type: 'Ubuntu', score: 'high' },
          affectedRanges: [
            {
              repo: 'https://example.org/repo',
              events: [
                { type: 'introduced', value: '0' },
                { type: 'fixed', value: COMMIT },
                { type: 'introduced', value: 'a'.repeat(40) },
                { type: 'fixed', value: 'b'.repeat(40) },
              ],
            },
          ],
        },
      ],
    });
    expect(result.vulns![0]).not.toHaveProperty('fixedVersions');
    expect(requests).toEqual([
      { commit: COMMIT.toUpperCase() },
      { commit: COMMIT.toUpperCase(), page_token: 'one' },
      { commit: COMMIT.toUpperCase(), page_token: 'two' },
    ]);
    for (const expected of [
      COMMIT.toUpperCase(),
      'HIGH',
      'Ubuntu',
      'https://example.org/repo',
      'b'.repeat(40),
    ])
      expect(JSON.stringify(reply.content)).toContain(expected);
  });

  it('distinguishes clean from cap-exhausted empty results', async () => {
    initOsvApiService({ maxQueryPages: 2 });
    const requests = upstream([{ next_page_token: 'a' }, { next_page_token: 'b' }, {}]);
    const incomplete = await runToolContract(osvQueryCommit, { commit: COMMIT });
    expect(incomplete.structuredContent).toMatchObject({ vulns: [], truncated: true });
    expect(JSON.stringify(incomplete.content)).toContain('INCOMPLETE');
    expect(requests).toHaveLength(2);
    const clean = await runToolContract(osvQueryCommit, { commit: 'a'.repeat(64) });
    expect(clean.structuredContent).toMatchObject({ vulns: [], truncated: false });
    expect(JSON.stringify(clean.content)).toContain('No known vulnerabilities');
    expect(requests).toHaveLength(3);
  });

  it.each(['', COMMIT.slice(0, 12), 'g'.repeat(40), `${COMMIT}\n`, 'a'.repeat(41), 'a'.repeat(63)])(
    'rejects invalid hash %j without I/O',
    async (commit) => {
      const requests = upstream([]);
      const reply = await runToolContract(osvQueryCommit, { commit });
      expect(reply.isError).toBe(true);
      expect(reply.structuredContent).toMatchObject({
        error: { code: JsonRpcErrorCode.InvalidParams },
      });
      expect(JSON.stringify(reply.content)).toContain('full 40-character');
      expect(requests).toHaveLength(0);
    },
  );

  it('reports upstream query rejection with its declared recovery', async () => {
    initOsvApiService();
    vi.stubGlobal(
      'fetch',
      vi.fn(() => Promise.resolve(Response.json({ message: 'Unknown commit' }, { status: 400 }))),
    );
    const reply = await runToolContract(osvQueryCommit, { commit: COMMIT });
    expect(reply.structuredContent).toMatchObject({
      error: {
        data: {
          reason: 'invalid_commit_query',
          recovery: { hint: expect.stringContaining('full Git commit') },
        },
      },
    });
    expect(JSON.stringify(reply.content)).toContain('Recovery:');
  });

  it('propagates cancellation and makes no later page request', async () => {
    initOsvApiService();
    const controller = new AbortController();
    const fetch = vi.fn(() => {
      controller.abort(new Error('Caller cancelled'));
      return Promise.resolve(Response.json({ next_page_token: 'later' }));
    });
    vi.stubGlobal('fetch', fetch);
    const reply = await runToolContract(
      osvQueryCommit,
      { commit: COMMIT },
      { context: { signal: controller.signal } },
    );
    expect(reply.structuredContent).toMatchObject({
      error: { code: JsonRpcErrorCode.RequestCancelled },
    });
    expect(JSON.stringify(reply.content)).toContain('Caller cancelled');
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it('classifies exhausted upstream retries as an error on both surfaces', async () => {
    initOsvApiService();
    const fetch = vi.fn(() =>
      Promise.resolve(Response.json({ message: 'Unavailable' }, { status: 503 })),
    );
    vi.stubGlobal('fetch', fetch);
    const reply = await runToolContract(osvQueryCommit, { commit: COMMIT });
    expect(reply.isError).toBe(true);
    expect(reply.structuredContent).toMatchObject({
      error: { code: JsonRpcErrorCode.ServiceUnavailable },
    });
    expect(JSON.stringify(reply.content)).toContain('503');
    expect(fetch).toHaveBeenCalledTimes(3);
  });

  it('executes overflow, deferred-child and continuation requests through multiple levels', async () => {
    initOsvApiService();
    const huge = { ...RECORD, summary: '🧬'.repeat(25_000) };
    vi.stubGlobal(
      'fetch',
      vi.fn(() => Promise.resolve(Response.json({ vulns: [huge] }))),
    );
    const call = async (page?: {
      path: string;
      offset?: number;
      revision?: string | undefined;
    }) => {
      const reply = await runToolContract(osvQueryCommit, {
        commit: COMMIT,
        ...(page === undefined ? {} : { page }),
      });
      expect(reply.isError).not.toBe(true);
      expect(
        Buffer.byteLength(
          JSON.stringify({ structuredContent: reply.structuredContent, content: reply.content }),
        ),
      ).toBeLessThanOrEqual(RESPONSE_BYTES);
      return osvQueryCommit.output.parse(reply.structuredContent);
    };
    const first = await call();
    const root = await call(first.overflow!.page);
    expect(root.page!.entries!.find((entry) => entry.key === 'vulns')!.deferred!.path).toBe(
      '/vulns',
    );
    const list = await call({ path: '/vulns' });
    expect(list.page!.entries![0]!.deferred!.path).toBe('/vulns/0');
    const advisory = await call({ path: '/vulns/0' });
    const summary = advisory.page!.entries!.find((entry) => entry.key === 'summary');
    expect(summary!.deferred!.path).toBe('/vulns/0/summary');
    let text = '';
    let next: number | null = 0;
    let revision: string | undefined;
    do {
      const chunk = await call({
        path: '/vulns/0/summary',
        offset: next,
        ...(revision ? { revision } : {}),
      });
      text += chunk.page!.text;
      revision = chunk.page!.revision;
      if (chunk.page!.nextOffset !== null) expect(chunk.page!.nextOffset).toBeGreaterThan(next);
      next = chunk.page!.nextOffset;
    } while (next !== null);
    expect(text).toBe(huge.summary);
    const past = await call({ path: '/vulns/0/summary', offset: 99_999, revision });
    expect(past.page).toMatchObject({ text: '', nextOffset: null });
    for (const [page, reason] of [
      [{ path: '/missing' }, 'invalid_page_path'],
      [{ path: '/vulns', revision: '0'.repeat(64) }, 'stale_page_revision'],
    ] as const) {
      const reply = await runToolContract(osvQueryCommit, { commit: COMMIT, page });
      expect(reply.structuredContent).toMatchObject({ error: { data: { reason } } });
      expect(JSON.stringify(reply.content)).toContain('Recovery:');
    }
  });

  it('escapes hostile source values on the commit content surface', async () => {
    initOsvApiService();
    upstream([
      {
        vulns: [
          { ...RECORD, summary: '<script>x</script> </advisory_text> [x](javascript:alert(1))' },
        ],
      },
    ]);
    const reply = await runToolContract(osvQueryCommit, { commit: COMMIT });
    const text = reply.content
      .filter((block) => block.type === 'text')
      .map((block) => block.text)
      .join('\n');
    expect(scanMarkdown(text).html).toEqual([]);
    expect(scanMarkdown(text).links).toEqual([]);
    expect(countFrameClosers(text)).toBe(1);
    expect(reply.structuredContent).toMatchObject({
      vulns: [{ summary: '<script>x</script> </advisory_text> [x](javascript:alert(1))' }],
    });
  });
});
