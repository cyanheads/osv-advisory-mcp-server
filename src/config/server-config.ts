/**
 * @fileoverview Server-specific environment configuration for osv-advisory-mcp-server,
 * validated through the framework's `parseEnvConfig` so invalid values fail startup
 * with a `ConfigurationError` that names the offending environment variable rather
 * than silently falling back to a default. Kept separate from the core mcp-ts-core
 * config and lazily parsed (no top-level `process.env` reads) for Workers parity.
 * @module config/server-config
 */

import { z } from '@cyanheads/mcp-ts-core';
import { parseEnvConfig } from '@cyanheads/mcp-ts-core/config';

/** Default OSV.dev HTTP request timeout (ms) when `OSV_REQUEST_TIMEOUT_MS` is unset. */
const DEFAULT_REQUEST_TIMEOUT_MS = 10_000;

/** Default in-flight request cap for `osv_query_batch` when `OSV_BATCH_CONCURRENCY` is unset. */
const DEFAULT_BATCH_CONCURRENCY = 10;

/** Default page-follow cap for `osv_query_package` when `OSV_QUERY_MAX_PAGES` is unset. */
const DEFAULT_MAX_QUERY_PAGES = 10;

/**
 * Server config schema. `z.coerce.number()` turns the always-string env value into
 * a number; `.positive()` rejects `0` and negatives, and a non-numeric value coerces
 * to `NaN` and fails the number check — so typoed config fails loudly instead of
 * being treated as unset.
 */
const ServerConfigSchema = z.object({
  requestTimeoutMs: z.coerce
    .number()
    .positive()
    .default(DEFAULT_REQUEST_TIMEOUT_MS)
    .describe('HTTP request timeout for OSV.dev API calls, in milliseconds. Must be positive.'),
  batchConcurrency: z.coerce
    .number()
    .int()
    .positive()
    .default(DEFAULT_BATCH_CONCURRENCY)
    .describe(
      'Maximum number of concurrent OSV.dev requests issued by osv_query_batch. Must be a positive integer.',
    ),
  maxQueryPages: z.coerce
    .number()
    .int()
    .positive()
    .default(DEFAULT_MAX_QUERY_PAGES)
    .describe(
      'Maximum number of OSV.dev result pages osv_query_package follows before marking a result truncated. Must be a positive integer.',
    ),
});

export type ServerConfig = z.infer<typeof ServerConfigSchema>;

let _config: ServerConfig | undefined;

/**
 * Lazily parse and cache server config from the environment.
 *
 * @throws {McpError} `ConfigurationError` naming `OSV_REQUEST_TIMEOUT_MS`,
 *   `OSV_BATCH_CONCURRENCY`, or `OSV_QUERY_MAX_PAGES` when the corresponding value
 *   is non-numeric, zero, or negative (or non-integer for the integer caps).
 */
export function getServerConfig(): ServerConfig {
  _config ??= parseEnvConfig(ServerConfigSchema, {
    requestTimeoutMs: 'OSV_REQUEST_TIMEOUT_MS',
    batchConcurrency: 'OSV_BATCH_CONCURRENCY',
    maxQueryPages: 'OSV_QUERY_MAX_PAGES',
  });
  return _config;
}
