/**
 * @fileoverview Release-scoped Ubuntu binary-to-source resolution.
 * @module services/osv-api/ubuntu-source-resolution
 */
import { z } from '@cyanheads/mcp-ts-core';
import { JsonRpcErrorCode, McpError, serviceUnavailable } from '@cyanheads/mcp-ts-core/errors';
import type { PackageQuery } from './affected-match.js';

const MAX_NAMES_PER_REQUEST = 1000;
const MappingResponse = z.object({
  results: z.array(z.object({ source_names: z.array(z.string().min(1)).optional() })),
});

/** Normalize the mapping release only. Advisory lookups keep the original Ubuntu ecosystem. */
export function ubuntuMappingRelease(ecosystem: string): string | undefined {
  const release = /^Ubuntu:(?:Pro:)?(\d{2}\.\d{2})(?::LTS)?$/.exec(ecosystem)?.[1];
  return release === undefined ? undefined : `Ubuntu:${release}`;
}

/** A query's ordered, distinct target names and whether resolution was available. */
export type UbuntuSourceResolution = {
  sourceNames: string[];
  sourceResolutionUnavailable?: true;
};

/** Map once per release and distinct name. Experimental mapping failures allow scoped fallback. */
export async function resolveUbuntuSources<T extends PackageQuery>(
  packages: T[],
  post: (body: { ecosystem: string; binary_names: string[] }) => Promise<{
    status: number;
    data: unknown;
  }>,
  signal: AbortSignal,
): Promise<Map<T, UbuntuSourceResolution | McpError>> {
  const groups = new Map<string, Map<string, T[]>>();
  for (const pkg of packages) {
    const release = ubuntuMappingRelease(pkg.ecosystem);
    if (!release) continue;
    let names = groups.get(release);
    if (!names) {
      names = new Map();
      groups.set(release, names);
    }
    const existing = names.get(pkg.name);
    if (existing) existing.push(pkg);
    else names.set(pkg.name, [pkg]);
  }

  const resolutions = new Map<T, UbuntuSourceResolution | McpError>();
  for (const [ecosystem, names] of groups) {
    const entries = [...names];
    for (let offset = 0; offset < entries.length; offset += MAX_NAMES_PER_REQUEST) {
      signal.throwIfAborted();
      const chunk = entries.slice(offset, offset + MAX_NAMES_PER_REQUEST);
      const binary_names = chunk.map(([name]) => name);
      try {
        const { status, data } = await post({ ecosystem, binary_names });
        const parsed = MappingResponse.safeParse(data);
        if (status !== 200 || !parsed.success || parsed.data.results.length !== chunk.length) {
          throw serviceUnavailable('OSV returned an invalid Ubuntu source mapping response.');
        }
        for (const [index, [name, queries]] of chunk.entries()) {
          const mapped = parsed.data.results[index]?.source_names;
          const sourceNames = mapped?.length ? [...new Set(mapped)].sort() : [name];
          for (const query of queries) resolutions.set(query, { sourceNames });
        }
      } catch (error) {
        signal.throwIfAborted();
        if (!(error instanceof McpError)) throw error;
        for (const [name, queries] of chunk) {
          const resolution: UbuntuSourceResolution | McpError =
            error.code === JsonRpcErrorCode.RateLimited
              ? error
              : { sourceNames: [name], sourceResolutionUnavailable: true };
          for (const query of queries) resolutions.set(query, resolution);
        }
      }
    }
  }
  return resolutions;
}
