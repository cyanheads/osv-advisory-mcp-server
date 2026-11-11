/**
 * @fileoverview OSV deadline and cancellation across transport stages.
 * @module tests/services/osv-query-deadline.test
 */
import { JsonRpcErrorCode } from '@cyanheads/mcp-ts-core/errors';
import { createMockContext } from '@cyanheads/mcp-ts-core/testing';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { OsvApiService } from '@/services/osv-api/osv-api-service.js';

const query = (service: OsvApiService, signal?: AbortSignal) =>
  service.queryPackage('Kernel', 'Linux', '5.10.0', createMockContext(signal ? { signal } : {}));

function stalledBody(signal: AbortSignal) {
  return new Response(
    new ReadableStream({
      start(controller) {
        signal.addEventListener('abort', () => controller.error(signal.reason), { once: true });
      },
    }),
  );
}

beforeEach(() => vi.useFakeTimers());
afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

it('lets the default request timeout receive a time-sliced OSV page', async () => {
  const fetch = vi.fn(
    (_url: string, init?: RequestInit) =>
      new Promise<Response>((resolve, reject) => {
        const timer = setTimeout(
          () => resolve(Response.json({ next_page_token: 'page-1' })),
          35_000,
        );
        init?.signal?.addEventListener(
          'abort',
          () => {
            clearTimeout(timer);
            reject(init.signal?.reason);
          },
          { once: true },
        );
      }),
  );
  vi.stubGlobal('fetch', fetch);
  const pending = query(new OsvApiService({ maxQueryPages: 1 }));
  await vi.advanceTimersByTimeAsync(35_000);
  await expect(pending).resolves.toMatchObject({ truncated: true, nextCursor: expect.any(String) });
  expect(fetch).toHaveBeenCalledTimes(1);
});

it.each([false, true])('bounds body reads with a completed checkpoint = %s', async (checkpoint) => {
  const fetch = vi.fn((_url: string, init: RequestInit) =>
    Promise.resolve(stalledBody(init.signal!)),
  );
  if (checkpoint)
    fetch.mockResolvedValueOnce(
      Response.json({ vulns: [{ id: 'OSV-first' }], next_page_token: 'page-1' }),
    );
  vi.stubGlobal('fetch', fetch);
  const pending = query(new OsvApiService({ timeoutMs: 60_000 }));
  const assertion = checkpoint
    ? expect(pending).resolves.toMatchObject({
        truncated: true,
        nextCursor: expect.any(String),
        vulns: [{ id: 'OSV-first' }],
      })
    : expect(pending).rejects.toMatchObject({ code: JsonRpcErrorCode.Timeout });
  await vi.advanceTimersByTimeAsync(50_000);
  await assertion;
  expect(fetch).toHaveBeenCalledTimes(checkpoint ? 2 : 1);
  if (checkpoint)
    expect(JSON.parse(String(fetch.mock.calls[1]?.[1].body)).page_token).toBe('page-1');
});

it.each(['body read', 'retry backoff'])(
  'propagates caller cancellation during %s after a usable page',
  async (stage) => {
    const controller = new AbortController();
    const fetch = vi
      .fn<(_url: string, init: RequestInit) => Promise<Response>>()
      .mockResolvedValueOnce(Response.json({ next_page_token: 'page-1' }))
      .mockImplementationOnce((_url, init) =>
        Promise.resolve(
          stage === 'body read'
            ? stalledBody(init.signal!)
            : Response.json({}, { status: 503, headers: { 'Retry-After': '10' } }),
        ),
      );
    vi.stubGlobal('fetch', fetch);
    const pending = query(new OsvApiService({ timeoutMs: 60_000 }), controller.signal);
    const cause = new DOMException('Caller canceled the query', 'AbortError');
    const assertion = expect(pending).rejects.toBe(cause);
    await vi.advanceTimersByTimeAsync(5);
    expect(fetch).toHaveBeenCalledTimes(2);
    controller.abort(cause);
    await assertion;
    await vi.advanceTimersByTimeAsync(50_000);
    expect(fetch).toHaveBeenCalledTimes(2);
  },
);
