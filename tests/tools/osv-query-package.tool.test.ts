/**
 * @fileoverview Tests for osv_query_package tool.
 * @module tests/tools/osv-query-package.tool.test
 */

import { createMockContext, getEnrichment } from '@cyanheads/mcp-ts-core/testing';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { osvQueryPackage } from '@/mcp-server/tools/definitions/osv-query-package.tool.js';
import type { OsvVulnerability } from '@/services/osv-api/osv-api-service.js';
import * as osvApiModule from '@/services/osv-api/osv-api-service.js';

const SAMPLE_VULN: OsvVulnerability = {
  id: 'GHSA-29mw-wpgm-hmr9',
  summary: 'Prototype Pollution in lodash',
  details: 'lodash before 4.17.21 allows prototype pollution.',
  aliases: ['CVE-2020-28500'],
  published: '2022-01-06T20:30:46Z',
  modified: '2025-09-29T21:12:31Z',
  severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L' }],
  severityLabel: 'MODERATE',
  affected: [
    {
      packageName: 'lodash',
      ecosystem: 'npm',
      purl: 'pkg:npm/lodash',
      ranges: [
        {
          rangeType: 'SEMVER',
          introduced: '0',
          fixed: '4.17.21',
        },
      ],
    },
  ],
  cweIds: ['CWE-1333'],
  references: [{ type: 'ADVISORY', url: 'https://nvd.nist.gov/vuln/detail/CVE-2020-28500' }],
  schemaVersion: '1.7.3',
  affectedRanges: [
    {
      packageName: 'lodash',
      ecosystem: 'npm',
      rangeType: 'SEMVER',
      introduced: '0',
      fixed: '4.17.21',
    },
  ],
  fixedVersions: ['4.17.21'],
};

const SPARSE_VULN: OsvVulnerability = {
  id: 'PYSEC-2024-1',
  summary: 'Vulnerability in requests',
  details: '',
  aliases: [],
  published: '2024-01-01T00:00:00Z',
  modified: '2024-01-02T00:00:00Z',
  severity: [],
  severityLabel: null,
  affected: [],
  cweIds: [],
  references: [],
  schemaVersion: '1.7.3',
  affectedRanges: [],
  fixedVersions: [],
};

describe('osvQueryPackage', () => {
  const mockService = { queryPackage: vi.fn() };

  beforeEach(() => {
    vi.spyOn(osvApiModule, 'getOsvApiService').mockReturnValue(
      mockService as unknown as ReturnType<typeof osvApiModule.getOsvApiService>,
    );
    mockService.queryPackage.mockReset();
  });

  it('returns vulnerabilities for a known vulnerable package', async () => {
    mockService.queryPackage.mockResolvedValue({
      invalid: false,
      vulns: [SAMPLE_VULN],
      truncated: false,
    });
    const ctx = createMockContext({ errors: osvQueryPackage.errors });
    const input = osvQueryPackage.input.parse({
      name: 'lodash',
      ecosystem: 'npm',
      version: '4.17.1',
    });
    const result = await osvQueryPackage.handler(input, ctx);

    expect(result.vulns).toHaveLength(1);
    expect(result.vulns[0]!.id).toBe('GHSA-29mw-wpgm-hmr9');
    expect(result.vulns[0]!.aliases).toEqual(['CVE-2020-28500']);
    expect(result.vulns[0]!.severityLabel).toBe('MODERATE');
    expect(result.vulns[0]!.fixedVersions).toEqual(['4.17.21']);
    expect(result.queryMeta.vulnCount).toBe(1);
    expect(result.queryMeta.package).toBe('lodash');
  });

  it('returns empty vulns array for a clean package', async () => {
    mockService.queryPackage.mockResolvedValue({ invalid: false, vulns: [], truncated: false });
    const ctx = createMockContext({ errors: osvQueryPackage.errors });
    const input = osvQueryPackage.input.parse({
      name: 'lodash',
      ecosystem: 'npm',
      version: '4.17.21',
    });
    const result = await osvQueryPackage.handler(input, ctx);

    expect(result.vulns).toHaveLength(0);
    expect(result.queryMeta.vulnCount).toBe(0);
  });

  it('throws invalid_ecosystem via ctx.fail with the contract recovery hint on the wire', async () => {
    mockService.queryPackage.mockResolvedValue({ invalid: true, message: 'Invalid ecosystem.' });
    const ctx = createMockContext({ errors: osvQueryPackage.errors });
    const input = osvQueryPackage.input.parse({
      name: 'lodash',
      ecosystem: 'NPM',
      version: '4.17.1',
    });
    // data.reason + data.recovery.hint must reach the wire (hint is mirrored into content[]).
    await expect(osvQueryPackage.handler(input, ctx)).rejects.toMatchObject({
      data: {
        reason: 'invalid_ecosystem',
        recovery: { hint: osvQueryPackage.errors![0]!.recovery },
      },
    });
  });

  it('handles sparse upstream vuln with null severity and empty aliases', async () => {
    mockService.queryPackage.mockResolvedValue({
      invalid: false,
      vulns: [SPARSE_VULN],
      truncated: false,
    });
    const ctx = createMockContext({ errors: osvQueryPackage.errors });
    const input = osvQueryPackage.input.parse({
      name: 'requests',
      ecosystem: 'PyPI',
      version: '2.28.0',
    });
    const result = await osvQueryPackage.handler(input, ctx);

    expect(result.vulns[0]!.severityLabel).toBeNull();
    expect(result.vulns[0]!.aliases).toHaveLength(0);
    expect(result.vulns[0]!.cweIds).toHaveLength(0);
  });

  it('formats vulnerable package output with aliases and fix', () => {
    const output = {
      vulns: [
        {
          id: 'GHSA-29mw-wpgm-hmr9',
          summary: 'Prototype Pollution',
          aliases: ['CVE-2020-28500'],
          severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/...' }],
          severityLabel: 'MODERATE',
          fixedVersions: ['4.17.21'],
          affectedRanges: [],
          cweIds: ['CWE-1333'],
          published: '2022-01-06T20:30:46Z',
          modified: '2025-09-29T21:12:31Z',
        },
      ],
      queryMeta: { package: 'lodash', ecosystem: 'npm', version: '4.17.1', vulnCount: 1 },
    };
    const blocks = osvQueryPackage.format!(output);
    const text = (blocks[0] as { text: string }).text;
    expect(text).toContain('GHSA-29mw-wpgm-hmr9');
    expect(text).toContain('CVE-2020-28500');
    expect(text).toContain('4.17.21');
    expect(text).toContain('MODERATE');
    expect(text).toContain('CWE-1333');
    // #11: upstream summary text is framed behind an untrusted-data boundary.
    expect(text).toContain('<advisory_summary>\nPrototype Pollution\n</advisory_summary>');
  });

  it('formats clean package output with no vulnerabilities message', () => {
    const output = {
      vulns: [],
      queryMeta: { package: 'lodash', ecosystem: 'npm', version: '4.17.21', vulnCount: 0 },
    };
    const blocks = osvQueryPackage.format!(output);
    const text = (blocks[0] as { text: string }).text;
    expect(text).toContain('No known vulnerabilities');
  });

  it('handles empty {} API response (no vulns key) as zero vulnerabilities', async () => {
    // OSV returns {} (not {vulns:[]}) when no results — service normalizes this to []
    mockService.queryPackage.mockResolvedValue({ invalid: false, vulns: [], truncated: false });
    const ctx = createMockContext({ errors: osvQueryPackage.errors });
    const input = osvQueryPackage.input.parse({
      name: 'not-a-real-package',
      ecosystem: 'npm',
      version: '99.99.99',
    });
    const result = await osvQueryPackage.handler(input, ctx);

    expect(result.vulns).toHaveLength(0);
    expect(result.queryMeta.vulnCount).toBe(0);
    expect(result.vulns).toBeInstanceOf(Array);
  });

  it('surfaces lastAffected range when no fix exists', async () => {
    const unfixedVuln: OsvVulnerability = {
      id: 'RUSTSEC-2024-0001',
      summary: 'Memory corruption in unsafe-lib',
      details: 'No fix available.',
      aliases: [],
      published: '2024-01-01T00:00:00Z',
      modified: '2024-01-10T00:00:00Z',
      severity: [],
      severityLabel: null,
      affected: [],
      cweIds: [],
      references: [],
      schemaVersion: '1.7.3',
      affectedRanges: [
        {
          packageName: 'unsafe-lib',
          ecosystem: 'crates.io',
          rangeType: 'SEMVER',
          introduced: '0',
          lastAffected: '1.2.3', // no `fixed` field — no fix exists
        },
      ],
      fixedVersions: [], // empty — no fix
    };

    mockService.queryPackage.mockResolvedValue({
      invalid: false,
      vulns: [unfixedVuln],
      truncated: false,
    });
    const ctx = createMockContext({ errors: osvQueryPackage.errors });
    const input = osvQueryPackage.input.parse({
      name: 'unsafe-lib',
      ecosystem: 'crates.io',
      version: '1.2.0',
    });
    const result = await osvQueryPackage.handler(input, ctx);

    expect(result.vulns[0]!.fixedVersions).toHaveLength(0);
    const range = result.vulns[0]!.affectedRanges[0]!;
    expect(range.lastAffected).toBe('1.2.3');
    expect(range.fixed).toBeUndefined();
  });

  it('formats output with no fix message when fixedVersions is empty', () => {
    const output = {
      vulns: [
        {
          id: 'RUSTSEC-2024-0001',
          summary: 'Memory corruption',
          aliases: [],
          severity: [],
          severityLabel: null,
          fixedVersions: [],
          affectedRanges: [
            {
              packageName: 'unsafe-lib',
              ecosystem: 'crates.io',
              rangeType: 'SEMVER',
              introduced: '0',
              lastAffected: '1.2.3',
            },
          ],
          cweIds: [],
          published: '2024-01-01T00:00:00Z',
          modified: '2024-01-10T00:00:00Z',
        },
      ],
      queryMeta: { package: 'unsafe-lib', ecosystem: 'crates.io', version: '1.2.0', vulnCount: 1 },
    };
    const blocks = osvQueryPackage.format!(output);
    const text = (blocks[0] as { text: string }).text;
    expect(text).toContain('No fix available');
    expect(text).toContain('last_affected: 1.2.3');
  });

  it('omits the summary boundary when a vuln summary is empty', () => {
    const output = {
      vulns: [
        {
          id: 'GHSA-empty-summary',
          summary: '',
          aliases: [],
          severity: [],
          severityLabel: null,
          fixedVersions: [],
          affectedRanges: [],
          cweIds: [],
          published: '2024-01-01T00:00:00Z',
          modified: '2024-01-02T00:00:00Z',
        },
      ],
      queryMeta: { package: 'pkg', ecosystem: 'npm', version: '1.0.0', vulnCount: 1 },
    };
    const blocks = osvQueryPackage.format!(output);
    const text = (blocks[0] as { text: string }).text;
    // #11: empty summary must not emit an empty <advisory_summary></advisory_summary> block.
    expect(text).not.toContain('<advisory_summary>');
    expect(text).not.toContain('**Summary:**');
  });

  it('enriches the clean path with a no-vulns notice and an effective-query echo', async () => {
    mockService.queryPackage.mockResolvedValue({ invalid: false, vulns: [], truncated: false });
    const ctx = createMockContext({ errors: osvQueryPackage.errors });
    const input = osvQueryPackage.input.parse({
      name: 'is-number',
      ecosystem: 'npm',
      version: '7.0.0',
    });
    await osvQueryPackage.handler(input, ctx);

    // #9: machine-readable "is this clean?" + "what did I query?" signals.
    const enrichment = getEnrichment(ctx);
    expect(enrichment.notice).toBe('No known vulnerabilities for is-number@7.0.0 (npm).');
    expect(enrichment.effectiveQuery).toBe('is-number@7.0.0 (npm)');
  });

  it('does not enrich when vulnerabilities are found', async () => {
    mockService.queryPackage.mockResolvedValue({
      invalid: false,
      vulns: [SAMPLE_VULN],
      truncated: false,
    });
    const ctx = createMockContext({ errors: osvQueryPackage.errors });
    const input = osvQueryPackage.input.parse({
      name: 'lodash',
      ecosystem: 'npm',
      version: '4.17.1',
    });
    await osvQueryPackage.handler(input, ctx);

    const enrichment = getEnrichment(ctx);
    expect(enrichment.notice).toBeUndefined();
    expect(enrichment.effectiveQuery).toBeUndefined();
  });

  it('passes through repo, ordered events, and versions on affected ranges (#13)', async () => {
    const vulnWithRichRange: OsvVulnerability = {
      ...SAMPLE_VULN,
      affectedRanges: [
        {
          packageName: 'lodash',
          ecosystem: 'npm',
          rangeType: 'SEMVER',
          introduced: '0',
          fixed: '4.17.21',
          repo: 'https://github.com/lodash/lodash',
          events: [
            { type: 'introduced', value: '0' },
            { type: 'fixed', value: '4.17.21' },
          ],
          versions: ['4.17.19', '4.17.20'],
        },
      ],
    };
    mockService.queryPackage.mockResolvedValue({
      invalid: false,
      vulns: [vulnWithRichRange],
      truncated: false,
    });
    const ctx = createMockContext({ errors: osvQueryPackage.errors });
    const input = osvQueryPackage.input.parse({
      name: 'lodash',
      ecosystem: 'npm',
      version: '4.17.1',
    });
    const result = await osvQueryPackage.handler(input, ctx);

    const range = result.vulns[0]!.affectedRanges[0]!;
    expect(range.repo).toBe('https://github.com/lodash/lodash');
    expect(range.events).toHaveLength(2);
    expect(range.versions).toEqual(['4.17.19', '4.17.20']);

    const blocks = osvQueryPackage.format!(result);
    const text = (blocks[0] as { text: string }).text;
    expect(text).toContain('repo: https://github.com/lodash/lodash');
    expect(text).toContain('events: introduced=0 → fixed=4.17.21');
    expect(text).toContain('versions: 4.17.19, 4.17.20');
  });

  it('discloses truncation instead of a false clean on a paginated empty page (#15)', async () => {
    mockService.queryPackage.mockResolvedValue({ invalid: false, vulns: [], truncated: true });
    const ctx = createMockContext({ errors: osvQueryPackage.errors });
    const input = osvQueryPackage.input.parse({
      name: 'Kernel',
      ecosystem: 'Linux',
      version: '5.10.0',
    });
    const result = await osvQueryPackage.handler(input, ctx);

    expect(result.truncated).toBe(true);
    // The enrichment notice must NOT claim "no known vulnerabilities".
    const enrichment = getEnrichment(ctx);
    expect(enrichment.notice).toContain('INCOMPLETE');
    expect(enrichment.notice).not.toContain('No known vulnerabilities');

    // content[] must not render the false-clean line.
    const blocks = osvQueryPackage.format!(result);
    const text = (blocks[0] as { text: string }).text;
    expect(text).not.toContain('No known vulnerabilities found');
    expect(text).toContain('truncated');
  });

  it('formats a truncated non-empty result with a truncation warning (#15)', () => {
    const output = {
      vulns: [
        {
          id: 'GHSA-x',
          summary: 'x',
          aliases: [],
          severity: [],
          severityLabel: null,
          fixedVersions: [],
          affectedRanges: [],
          cweIds: [],
          published: '2024-01-01T00:00:00Z',
          modified: '2024-01-02T00:00:00Z',
        },
      ],
      truncated: true,
      queryMeta: { package: 'Kernel', ecosystem: 'Linux', version: '5.10.0', vulnCount: 1 },
    };
    const blocks = osvQueryPackage.format!(output);
    const text = (blocks[0] as { text: string }).text;
    expect(text).toContain('Results truncated');
  });

  // #10: blank/whitespace-only identifiers must fail local schema validation before any OSV call.
  describe('input validation (#10): rejects blank and whitespace-only fields', () => {
    it('rejects an empty package name', () => {
      expect(() =>
        osvQueryPackage.input.parse({ name: '', ecosystem: 'npm', version: '4.17.1' }),
      ).toThrow();
    });

    it('rejects a whitespace-only package name', () => {
      expect(() =>
        osvQueryPackage.input.parse({ name: '   ', ecosystem: 'npm', version: '4.17.1' }),
      ).toThrow();
    });

    it('rejects an empty ecosystem', () => {
      expect(() =>
        osvQueryPackage.input.parse({ name: 'lodash', ecosystem: '', version: '4.17.1' }),
      ).toThrow();
    });

    it('rejects a whitespace-only ecosystem', () => {
      expect(() =>
        osvQueryPackage.input.parse({ name: 'lodash', ecosystem: '  ', version: '4.17.1' }),
      ).toThrow();
    });

    it('rejects an empty version', () => {
      expect(() =>
        osvQueryPackage.input.parse({ name: 'lodash', ecosystem: 'npm', version: '' }),
      ).toThrow();
    });

    it('rejects a whitespace-only version', () => {
      expect(() =>
        osvQueryPackage.input.parse({ name: 'lodash', ecosystem: 'npm', version: '\t' }),
      ).toThrow();
    });
  });
});
