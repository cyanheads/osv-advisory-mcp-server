/**
 * @fileoverview Tests for server-config — validation of OSV_REQUEST_TIMEOUT_MS,
 * OSV_BATCH_CONCURRENCY, and OSV_QUERY_MAX_PAGES through parseEnvConfig. Each case
 * re-imports the module so the lazy `_config` cache resets and the freshly-stubbed
 * env is parsed.
 * @module tests/config/server-config.test
 */

import { JsonRpcErrorCode, McpError } from '@cyanheads/mcp-ts-core/errors';
import { afterEach, describe, expect, it, vi } from 'vitest';

/** Stub the server env vars, reset the module cache, then resolve fresh config. */
async function loadConfig(env: {
  timeout?: string;
  concurrency?: string;
  maxPages?: string;
  serveOverCap?: string;
}) {
  vi.stubEnv('OSV_REQUEST_TIMEOUT_MS', env.timeout);
  vi.stubEnv('OSV_BATCH_CONCURRENCY', env.concurrency);
  vi.stubEnv('OSV_QUERY_MAX_PAGES', env.maxPages);
  vi.stubEnv('OSV_BATCH_SERVE_OVER_CAP', env.serveOverCap);
  vi.resetModules();
  const mod = await import('@/config/server-config.js');
  return mod.getServerConfig();
}

describe('getServerConfig', () => {
  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it('applies defaults when the env vars are omitted', async () => {
    const config = await loadConfig({});
    expect(config.requestTimeoutMs).toBe(40000);
    expect(config.batchConcurrency).toBe(10);
    expect(config.maxQueryPages).toBe(10);
    expect(config.batchServeOverCap).toBe(true);
  });

  it('parses valid values', async () => {
    const config = await loadConfig({
      timeout: '5000',
      concurrency: '4',
      maxPages: '3',
      serveOverCap: 'false',
    });
    expect(config.requestTimeoutMs).toBe(5000);
    expect(config.batchConcurrency).toBe(4);
    expect(config.maxQueryPages).toBe(3);
    expect(config.batchServeOverCap).toBe(false);
  });

  it.each(['yes', 'FALSE', '0'])(
    'rejects an invalid batch prefix flag %s',
    async (serveOverCap) => {
      await expect(loadConfig({ serveOverCap })).rejects.toMatchObject({
        code: JsonRpcErrorCode.ConfigurationError,
        message: expect.stringContaining('OSV_BATCH_SERVE_OVER_CAP'),
      });
    },
  );

  describe('OSV_REQUEST_TIMEOUT_MS validation', () => {
    for (const bad of ['abc', '0', '-100']) {
      it(`throws a ConfigurationError naming the var for ${JSON.stringify(bad)}`, async () => {
        const err = await loadConfig({ timeout: bad }).catch((e: unknown) => e);
        expect(err).toBeInstanceOf(McpError);
        expect((err as McpError).code).toBe(JsonRpcErrorCode.ConfigurationError);
        expect((err as McpError).message).toContain('OSV_REQUEST_TIMEOUT_MS');
      });
    }
  });

  describe('OSV_BATCH_CONCURRENCY validation', () => {
    // Non-numeric, zero, negative, and non-integer values are all rejected.
    for (const bad of ['abc', '0', '-1', '2.5']) {
      it(`throws a ConfigurationError naming the var for ${JSON.stringify(bad)}`, async () => {
        const err = await loadConfig({ concurrency: bad }).catch((e: unknown) => e);
        expect(err).toBeInstanceOf(McpError);
        expect((err as McpError).code).toBe(JsonRpcErrorCode.ConfigurationError);
        expect((err as McpError).message).toContain('OSV_BATCH_CONCURRENCY');
      });
    }
  });

  describe('OSV_QUERY_MAX_PAGES validation', () => {
    // Non-numeric, zero, negative, and non-integer values are all rejected.
    for (const bad of ['abc', '0', '-1', '2.5']) {
      it(`throws a ConfigurationError naming the var for ${JSON.stringify(bad)}`, async () => {
        const err = await loadConfig({ maxPages: bad }).catch((e: unknown) => e);
        expect(err).toBeInstanceOf(McpError);
        expect((err as McpError).code).toBe(JsonRpcErrorCode.ConfigurationError);
        expect((err as McpError).message).toContain('OSV_QUERY_MAX_PAGES');
      });
    }
  });
});
