/**
 * @fileoverview Native batch wiring through both tool result surfaces.
 * @module tests/tools/osv-native-batch.tool.test
 */
import { JsonRpcErrorCode } from '@cyanheads/mcp-ts-core/errors';
import { runToolContract } from '@cyanheads/mcp-ts-core/testing';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { osvQueryBatch } from '@/mcp-server/tools/definitions/osv-query-batch.tool.js';
import { initOsvApiService } from '@/services/osv-api/osv-api-service.js';
import { contentText } from '../helpers/markdown.js';

const packages = ['a', 'b', 'clean'].map((name) => ({ name, ecosystem: 'npm', version: '1' }));
beforeEach(() => initOsvApiService({ maxQueryPages: 1, batchConcurrency: 1 }));
afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

it('renders capped and failed native rows as incomplete/errors on both surfaces', async () => {
  vi.stubGlobal(
    'fetch',
    vi.fn((url: string) =>
      Promise.resolve(
        new URL(url).pathname === '/v1/querybatch'
          ? Response.json({
              results: [{ next_page_token: 'more' }, { vulns: [{ id: 'missing' }] }, {}],
            })
          : Response.json({ code: 5, message: 'not found' }, { status: 404 }),
      ),
    ),
  );
  const result = await runToolContract(osvQueryBatch, { packages });
  expect(result.isError).not.toBe(true);
  expect(result.structuredContent).toMatchObject({
    results: [
      { truncated: true, error: null },
      { error: expect.stringContaining('missing') },
      { error: null },
    ],
    summary: { totalPackages: 3, cleanCount: 1, truncatedCount: 1, errorCount: 1, totalVulns: 0 },
  });
  const text = contentText(result);
  expect(text).toContain('Incomplete (truncated) Packages');
  expect(text).toContain('NOT confirmed clean');
  expect(text).toContain('## Errors');
  expect(text).toContain('missing');
  expect(text).toContain('`clean` @ `1` (npm) — clean');
});

it('maps cancellation to RequestCancelled on both surfaces', async () => {
  const controller = new AbortController();
  const fetch = vi.fn(() => {
    controller.abort();
    return Promise.reject(new DOMException('cancelled', 'AbortError'));
  });
  vi.stubGlobal('fetch', fetch);
  const result = await runToolContract(
    osvQueryBatch,
    { packages },
    { context: { signal: controller.signal } },
  );
  expect(result.isError).toBe(true);
  expect(result.structuredContent).toMatchObject({
    error: { code: JsonRpcErrorCode.RequestCancelled },
  });
  expect(contentText(result)).toMatch(/aborted|cancel/i);
  expect(fetch).toHaveBeenCalledTimes(1);
});

it('keeps schema-invalid input outside native work with its declared recovery on both surfaces', async () => {
  const fetch = vi.fn();
  vi.stubGlobal('fetch', fetch);
  const result = await runToolContract(osvQueryBatch, {
    packages: [{ name: '', ecosystem: 'npm', version: '1' }],
  });
  expect(result.isError).toBe(true);
  expect(result.structuredContent).toMatchObject({
    error: { code: JsonRpcErrorCode.InvalidParams, data: { reason: 'invalid_arguments' } },
  });
  expect(contentText(result)).toContain('Package name must not be blank');
  expect(fetch).not.toHaveBeenCalled();
});
