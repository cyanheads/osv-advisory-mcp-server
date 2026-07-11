/**
 * @fileoverview Tests for osv_query_batch tool.
 * @module tests/tools/osv-query-batch.tool.test
 */

import { createMockContext, getEnrichment } from '@cyanheads/mcp-ts-core/testing';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { osvQueryBatch } from '@/mcp-server/tools/definitions/osv-query-batch.tool.js';
import * as osvApiModule from '@/services/osv-api/osv-api-service.js';

/** Build a minimal batch result row. */
function makeResult(
  name: string,
  ecosystem: string,
  version: string,
  vulns: Array<{
    id: string;
    summary: string;
    aliases: string[];
    severityLabel: string | null;
    fixedVersions: string[];
  }> = [],
  error: string | null = null,
) {
  return { name, ecosystem, version, vulns, error };
}

describe('osvQueryBatch', () => {
  const mockService = { queryBatch: vi.fn() };

  beforeEach(() => {
    vi.spyOn(osvApiModule, 'getOsvApiService').mockReturnValue(
      mockService as unknown as ReturnType<typeof osvApiModule.getOsvApiService>,
    );
    mockService.queryBatch.mockReset();
  });

  it('returns per-package results with summary stats', async () => {
    mockService.queryBatch.mockResolvedValue([
      makeResult('lodash', 'npm', '4.17.1', [
        {
          id: 'GHSA-29mw-wpgm-hmr9',
          summary: 'Prototype Pollution',
          aliases: ['CVE-2020-28500'],
          severityLabel: 'MODERATE',
          fixedVersions: ['4.17.21'],
        },
      ]),
      makeResult('express', 'npm', '4.18.0'),
    ]);

    const ctx = createMockContext();
    const input = osvQueryBatch.input.parse({
      packages: [
        { name: 'lodash', ecosystem: 'npm', version: '4.17.1' },
        { name: 'express', ecosystem: 'npm', version: '4.18.0' },
      ],
    });
    const result = await osvQueryBatch.handler(input, ctx);

    expect(result.results).toHaveLength(2);
    expect(result.results[0]!.vulnerable).toBe(true);
    expect(result.results[0]!.vulnCount).toBe(1);
    expect(result.results[0]!.vulns[0]!.aliases).toEqual(['CVE-2020-28500']);
    expect(result.results[1]!.vulnerable).toBe(false);
    expect(result.summary.totalPackages).toBe(2);
    expect(result.summary.vulnerableCount).toBe(1);
    expect(result.summary.cleanCount).toBe(1);
    expect(result.summary.errorCount).toBe(0);
    expect(result.summary.totalVulns).toBe(1);
    expect(result.summary.worstSeverity).toBe('MODERATE');
  });

  it('accepts an ecosystem absent from the old static allowlist and passes it through', async () => {
    // Ubuntu:22.04:LTS is a valid OSV ecosystem the removed static allowlist rejected.
    // With the preflight gone, OSV is the authority: the package reaches the service.
    mockService.queryBatch.mockResolvedValue([makeResult('curl', 'Ubuntu:22.04:LTS', '7.68.0')]);
    const ctx = createMockContext();
    const input = osvQueryBatch.input.parse({
      packages: [{ name: 'curl', ecosystem: 'Ubuntu:22.04:LTS', version: '7.68.0' }],
    });
    const result = await osvQueryBatch.handler(input, ctx);

    expect(mockService.queryBatch).toHaveBeenCalledTimes(1);
    expect(mockService.queryBatch.mock.calls[0]![0]).toEqual([
      { name: 'curl', ecosystem: 'Ubuntu:22.04:LTS', version: '7.68.0' },
    ]);
    expect(result.results[0]!.error).toBeNull();
    expect(result.results[0]!.vulnerable).toBe(false);
    expect(result.summary.errorCount).toBe(0);
  });

  it('surfaces a genuinely-invalid ecosystem as a per-row error, not a thrown error', async () => {
    // No preflight: OSV's per-package rejection (service maps HTTP 400 to a message) comes
    // back inline, so one bad ecosystem degrades to results[i].error without failing the call.
    mockService.queryBatch.mockResolvedValue([
      makeResult('lodash', 'npm', '4.17.1'),
      makeResult('pkg', 'totally-not-an-ecosystem', '1.0.0', [], 'Invalid ecosystem.'),
    ]);
    const ctx = createMockContext();
    const input = osvQueryBatch.input.parse({
      packages: [
        { name: 'lodash', ecosystem: 'npm', version: '4.17.1' },
        { name: 'pkg', ecosystem: 'totally-not-an-ecosystem', version: '1.0.0' },
      ],
    });
    const result = await osvQueryBatch.handler(input, ctx);

    expect(result.results[1]!.error).toBe('Invalid ecosystem.');
    expect(result.results[1]!.vulnerable).toBe(false);
    expect(result.summary.errorCount).toBe(1);
  });

  it('handles per-package errors without aborting the batch', async () => {
    mockService.queryBatch.mockResolvedValue([
      makeResult('lodash', 'npm', '4.17.1', [], 'Network error'),
      makeResult('express', 'npm', '4.18.0'),
    ]);

    const ctx = createMockContext();
    const input = osvQueryBatch.input.parse({
      packages: [
        { name: 'lodash', ecosystem: 'npm', version: '4.17.1' },
        { name: 'express', ecosystem: 'npm', version: '4.18.0' },
      ],
    });
    const result = await osvQueryBatch.handler(input, ctx);

    expect(result.summary.errorCount).toBe(1);
    expect(result.results[0]!.error).toBe('Network error');
    expect(result.results[0]!.vulnerable).toBe(false);
    expect(result.results[1]!.error).toBeNull();
  });

  it('computes null worstSeverity when all vulns have null severity', async () => {
    mockService.queryBatch.mockResolvedValue([
      makeResult('pkg', 'npm', '1.0.0', [
        { id: 'PYSEC-1', summary: 'Test', aliases: [], severityLabel: null, fixedVersions: [] },
      ]),
    ]);

    const ctx = createMockContext();
    const input = osvQueryBatch.input.parse({
      packages: [{ name: 'pkg', ecosystem: 'npm', version: '1.0.0' }],
    });
    const result = await osvQueryBatch.handler(input, ctx);
    expect(result.summary.worstSeverity).toBeNull();
  });

  it('partial success: mix of vulnerable, clean, and per-package error', async () => {
    // The service returns inline errors for per-package failures (not a throw).
    // This tests the tool-level aggregation of a realistic mixed batch.
    mockService.queryBatch.mockResolvedValue([
      makeResult('lodash', 'npm', '4.17.1', [
        {
          id: 'GHSA-29mw-wpgm-hmr9',
          summary: 'Prototype Pollution',
          aliases: ['CVE-2020-28500'],
          severityLabel: 'HIGH',
          fixedVersions: ['4.17.21'],
        },
      ]),
      makeResult('express', 'npm', '4.18.0'), // clean
      makeResult('requests', 'PyPI', '2.28.0', [], 'Invalid ecosystem.'), // per-package error
    ]);

    const ctx = createMockContext();
    const input = osvQueryBatch.input.parse({
      packages: [
        { name: 'lodash', ecosystem: 'npm', version: '4.17.1' },
        { name: 'express', ecosystem: 'npm', version: '4.18.0' },
        { name: 'requests', ecosystem: 'PyPI', version: '2.28.0' },
      ],
    });
    const result = await osvQueryBatch.handler(input, ctx);

    // Positional results
    expect(result.results[0]!.vulnerable).toBe(true);
    expect(result.results[0]!.error).toBeNull();
    expect(result.results[1]!.vulnerable).toBe(false);
    expect(result.results[1]!.error).toBeNull();
    expect(result.results[2]!.vulnerable).toBe(false);
    expect(result.results[2]!.error).toBeTruthy();

    // Summary aggregation
    expect(result.summary.totalPackages).toBe(3);
    expect(result.summary.vulnerableCount).toBe(1);
    expect(result.summary.cleanCount).toBe(1);
    expect(result.summary.errorCount).toBe(1);
    expect(result.summary.totalVulns).toBe(1);
    expect(result.summary.worstSeverity).toBe('HIGH');
  });

  it('aliases from fan-out are surfaced per-package in batch results', async () => {
    // Key correctness check: the parallel per-package query approach gives full records
    // (including aliases), unlike /v1/querybatch which only returns {id, modified}.
    mockService.queryBatch.mockResolvedValue([
      makeResult('lodash', 'npm', '4.17.1', [
        {
          id: 'GHSA-29mw-wpgm-hmr9',
          summary: 'Prototype Pollution',
          aliases: ['CVE-2020-28500', 'CVE-2020-28501'],
          severityLabel: 'MODERATE',
          fixedVersions: ['4.17.21'],
        },
        {
          id: 'GHSA-jf85-cpcp-j695',
          summary: 'Command Injection',
          aliases: ['CVE-2021-23337'],
          severityLabel: 'HIGH',
          fixedVersions: ['4.17.21'],
        },
      ]),
      makeResult('express', 'npm', '4.18.0'), // no aliases expected
    ]);

    const ctx = createMockContext();
    const input = osvQueryBatch.input.parse({
      packages: [
        { name: 'lodash', ecosystem: 'npm', version: '4.17.1' },
        { name: 'express', ecosystem: 'npm', version: '4.18.0' },
      ],
    });
    const result = await osvQueryBatch.handler(input, ctx);

    const lodashResult = result.results[0]!;
    expect(lodashResult.vulns).toHaveLength(2);
    // First vuln has two CVE aliases
    expect(lodashResult.vulns[0]!.aliases).toContain('CVE-2020-28500');
    expect(lodashResult.vulns[0]!.aliases).toContain('CVE-2020-28501');
    // Second vuln also has an alias
    expect(lodashResult.vulns[1]!.aliases).toContain('CVE-2021-23337');
    // Clean package has no vulns at all
    expect(result.results[1]!.vulns).toHaveLength(0);

    // worstSeverity from two findings
    expect(result.summary.worstSeverity).toBe('HIGH');
    expect(result.summary.totalVulns).toBe(2);
  });

  it('rejects empty packages array at schema parse', () => {
    expect(() => osvQueryBatch.input.parse({ packages: [] })).toThrow();
  });

  it('rejects packages array over 1000 at schema parse', () => {
    const pkgs = Array.from({ length: 1001 }, (_, i) => ({
      name: `pkg${i}`,
      ecosystem: 'npm',
      version: '1.0.0',
    }));
    expect(() => osvQueryBatch.input.parse({ packages: pkgs })).toThrow();
  });

  it('formats batch output with vulnerable packages section', () => {
    const output = {
      results: [
        {
          name: 'lodash',
          ecosystem: 'npm',
          version: '4.17.1',
          vulnerable: true,
          error: null,
          vulnCount: 1,
          vulns: [
            {
              id: 'GHSA-29mw-wpgm-hmr9',
              summary: 'Prototype Pollution',
              aliases: ['CVE-2020-28500'],
              severityLabel: 'MODERATE',
              fixedVersions: ['4.17.21'],
            },
          ],
        },
        {
          name: 'express',
          ecosystem: 'npm',
          version: '4.18.0',
          vulnerable: false,
          error: null,
          vulnCount: 0,
          vulns: [],
        },
      ],
      summary: {
        totalPackages: 2,
        vulnerableCount: 1,
        cleanCount: 1,
        errorCount: 0,
        totalVulns: 1,
        worstSeverity: 'MODERATE',
      },
    };
    const blocks = osvQueryBatch.format!(output);
    const text = (blocks[0] as { text: string }).text;
    expect(text).toContain('MODERATE');
    expect(text).toContain('lodash');
    expect(text).toContain('CVE-2020-28500');
    expect(text).toContain('4.17.21');
    expect(text).toContain('GHSA-29mw-wpgm-hmr9');
    // #11: the per-vuln summary sits in its own untrusted-data boundary block.
    expect(text).toContain('<advisory_summary>Prototype Pollution</advisory_summary>');
  });

  it('renders clean packages in content[] (parity with structuredContent)', () => {
    const output = {
      results: [
        {
          name: 'express',
          ecosystem: 'npm',
          version: '4.18.0',
          vulnerable: false,
          error: null,
          vulnCount: 0,
          vulns: [],
        },
      ],
      summary: {
        totalPackages: 1,
        vulnerableCount: 0,
        cleanCount: 1,
        errorCount: 0,
        totalVulns: 0,
        worstSeverity: null,
      },
    };
    const blocks = osvQueryBatch.format!(output);
    const text = (blocks[0] as { text: string }).text;
    expect(text).toContain('express');
    expect(text).toContain('4.18.0');
    expect(text).toContain('Clean Packages');
  });

  it('renders the input version on error rows (parity with structuredContent)', () => {
    // #5: structuredContent.results[i] carries the input version; content[] must too,
    // so text-only clients can identify the exact failed dependency tuple.
    const output = {
      results: [
        {
          name: 'requests',
          ecosystem: 'pypi',
          version: '2.31.0',
          vulnerable: false,
          error: 'Invalid ecosystem.',
          vulnCount: 0,
          vulns: [],
        },
      ],
      summary: {
        totalPackages: 1,
        vulnerableCount: 0,
        cleanCount: 0,
        errorCount: 1,
        totalVulns: 0,
        worstSeverity: null,
      },
    };
    const blocks = osvQueryBatch.format!(output);
    const text = (blocks[0] as { text: string }).text;
    expect(text).toContain('## Errors');
    expect(text).toContain('requests');
    expect(text).toContain('2.31.0');
    expect(text).toContain('Invalid ecosystem.');
    // The full failed tuple — name @ version (ecosystem) — is on the error line.
    expect(text).toContain('`requests` @ `2.31.0` (pypi): Invalid ecosystem.');
  });

  it('enriches all-clean batches with a notice and summary echo', async () => {
    mockService.queryBatch.mockResolvedValue([
      makeResult('is-number', 'npm', '7.0.0'),
      makeResult('express', 'npm', '4.18.0'),
    ]);
    const ctx = createMockContext();
    const input = osvQueryBatch.input.parse({
      packages: [
        { name: 'is-number', ecosystem: 'npm', version: '7.0.0' },
        { name: 'express', ecosystem: 'npm', version: '4.18.0' },
      ],
    });
    await osvQueryBatch.handler(input, ctx);

    // #9: all-clean edge case gets a machine-readable notice + compact scan echo.
    const enrichment = getEnrichment(ctx);
    expect(enrichment.notice).toBe('All 2 package(s) clean — no known vulnerabilities.');
    expect(enrichment.effectiveQuery).toBe('2 package(s): 0 vulnerable, 2 clean, 0 error(s)');
  });

  it('enriches all-errors batches with a notice and summary echo', async () => {
    mockService.queryBatch.mockResolvedValue([
      makeResult('requests', 'pypi', '2.31.0', [], 'Invalid ecosystem.'),
    ]);
    const ctx = createMockContext();
    const input = osvQueryBatch.input.parse({
      packages: [{ name: 'requests', ecosystem: 'pypi', version: '2.31.0' }],
    });
    await osvQueryBatch.handler(input, ctx);

    // #9: all-errors edge case (errorCount === totalPackages).
    const enrichment = getEnrichment(ctx);
    expect(enrichment.notice).toBe('All 1 package(s) errored — none could be checked.');
    expect(enrichment.effectiveQuery).toBe('1 package(s): 0 vulnerable, 0 clean, 1 error(s)');
  });

  it('does not enrich mixed batches (some vulnerable, some clean)', async () => {
    mockService.queryBatch.mockResolvedValue([
      makeResult('lodash', 'npm', '4.17.1', [
        {
          id: 'GHSA-29mw-wpgm-hmr9',
          summary: 'Prototype Pollution',
          aliases: ['CVE-2020-28500'],
          severityLabel: 'HIGH',
          fixedVersions: ['4.17.21'],
        },
      ]),
      makeResult('express', 'npm', '4.18.0'),
    ]);
    const ctx = createMockContext();
    const input = osvQueryBatch.input.parse({
      packages: [
        { name: 'lodash', ecosystem: 'npm', version: '4.17.1' },
        { name: 'express', ecosystem: 'npm', version: '4.18.0' },
      ],
    });
    await osvQueryBatch.handler(input, ctx);

    const enrichment = getEnrichment(ctx);
    expect(enrichment.notice).toBeUndefined();
    expect(enrichment.effectiveQuery).toBeUndefined();
  });
});
