/**
 * @fileoverview Tests for OsvApiService — HTTP fetch, normalization, and error handling.
 * @module tests/services/osv-api-service.test
 */

import { createMockContext } from '@cyanheads/mcp-ts-core/testing';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { OsvApiService } from '@/services/osv-api/osv-api-service.js';
import type { RawOsvVulnerability } from '@/services/osv-api/types.js';
import { loadOsvRecord, stubOsvApi } from '../helpers/osv-fixtures.js';

// ---------------------------------------------------------------------------
// Fixture responses
// ---------------------------------------------------------------------------

const QUERY_RESPONSE_WITH_VULN = {
  vulns: [
    {
      id: 'GHSA-29mw-wpgm-hmr9',
      summary: 'Prototype Pollution in lodash',
      details: 'lodash before 4.17.21 allows prototype pollution.',
      aliases: ['CVE-2020-28500'],
      published: '2022-01-06T20:30:46Z',
      modified: '2025-09-29T21:12:31Z',
      schema_version: '1.7.3',
      severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L' }],
      database_specific: {
        severity: 'MODERATE',
        cwe_ids: ['CWE-1333'],
      },
      affected: [
        {
          package: { name: 'lodash', ecosystem: 'npm', purl: 'pkg:npm/lodash' },
          ranges: [
            {
              type: 'SEMVER',
              events: [{ introduced: '0' }, { fixed: '4.17.21' }],
            },
          ],
        },
      ],
      references: [{ type: 'ADVISORY', url: 'https://nvd.nist.gov/vuln/detail/CVE-2020-28500' }],
    },
  ],
};

const EMPTY_QUERY_RESPONSE = {}; // OSV returns {} (not { vulns: [] }) when nothing found

const INVALID_ECOSYSTEM_RESPONSE = { code: 3, message: 'Invalid ecosystem.' };

const VULN_DETAIL_RESPONSE = QUERY_RESPONSE_WITH_VULN.vulns[0]!;

const VULN_NOT_FOUND_RESPONSE = { code: 5, message: 'Bug not found.' };

// ---------------------------------------------------------------------------
// Fetch mock helper
// ---------------------------------------------------------------------------

function jsonResponse(status: number, body: unknown, headers?: Record<string, string>): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', ...headers },
  });
}

function mockFetch(
  responses: Array<{ status: number; body: unknown; headers?: Record<string, string> }>,
) {
  let callIndex = 0;
  return vi.fn().mockImplementation(() => {
    const res = responses[callIndex++];
    if (!res) throw new Error('Unexpected fetch call');
    return Promise.resolve(jsonResponse(res.status, res.body, res.headers));
  });
}

describe('OsvApiService', () => {
  let service: OsvApiService;

  beforeEach(() => {
    service = new OsvApiService({ timeoutMs: 5000 });
    vi.restoreAllMocks();
  });

  describe('queryPackage', () => {
    it('returns normalized vulns for a vulnerable package', async () => {
      vi.stubGlobal('fetch', mockFetch([{ status: 200, body: QUERY_RESPONSE_WITH_VULN }]));
      const ctx = createMockContext();
      const result = await service.queryPackage('lodash', 'npm', '4.17.1', ctx);

      expect(result.invalid).toBe(false);
      if (result.invalid) return;
      expect(result.vulns).toHaveLength(1);
      const vuln = result.vulns[0]!;
      expect(vuln.id).toBe('GHSA-29mw-wpgm-hmr9');
      expect(vuln.aliases).toEqual(['CVE-2020-28500']);
      expect(vuln.severityLabel).toBe('MODERATE');
      expect(vuln.fixedVersions).toEqual(['4.17.21']);
      expect(vuln.cweIds).toEqual(['CWE-1333']);
    });

    it('returns empty vulns array when OSV returns {} (no vulns key)', async () => {
      vi.stubGlobal('fetch', mockFetch([{ status: 200, body: EMPTY_QUERY_RESPONSE }]));
      const ctx = createMockContext();
      const result = await service.queryPackage('lodash', 'npm', '99.99.99', ctx);

      expect(result.invalid).toBe(false);
      if (result.invalid) return;
      expect(result.vulns).toHaveLength(0);
    });

    it('returns invalid: true for HTTP 400 (invalid ecosystem)', async () => {
      const fetch = mockFetch([{ status: 400, body: INVALID_ECOSYSTEM_RESPONSE }]);
      vi.stubGlobal('fetch', fetch);
      const ctx = createMockContext();
      const result = await service.queryPackage('lodash', 'NPM', '4.17.1', ctx);

      expect(result.invalid).toBe(true);
      if (!result.invalid) return;
      expect(result.message).toBe('Invalid ecosystem.');
      expect(fetch).toHaveBeenCalledTimes(1);
    });

    it('extracts affected ranges correctly', async () => {
      vi.stubGlobal('fetch', mockFetch([{ status: 200, body: QUERY_RESPONSE_WITH_VULN }]));
      const ctx = createMockContext();
      const result = await service.queryPackage('lodash', 'npm', '4.17.1', ctx);

      if (result.invalid) return;
      const vuln = result.vulns[0]!;
      expect(vuln.affectedRanges).toHaveLength(1);
      expect(vuln.affectedRanges[0]!.rangeType).toBe('SEMVER');
      expect(vuln.affectedRanges[0]!.introduced).toBe('0');
      expect(vuln.affectedRanges[0]!.fixed).toBe('4.17.21');
    });
  });

  describe('getVulnerability', () => {
    it('returns normalized full record for a known ID', async () => {
      vi.stubGlobal('fetch', mockFetch([{ status: 200, body: VULN_DETAIL_RESPONSE }]));
      const ctx = createMockContext();
      const result = await service.getVulnerability('GHSA-29mw-wpgm-hmr9', ctx);

      expect(result).not.toBeNull();
      expect(result!.id).toBe('GHSA-29mw-wpgm-hmr9');
      expect(result!.aliases).toEqual(['CVE-2020-28500']);
    });

    it('returns null for HTTP 404 (vuln not found)', async () => {
      const fetch = mockFetch([{ status: 404, body: VULN_NOT_FOUND_RESPONSE }]);
      vi.stubGlobal('fetch', fetch);
      const ctx = createMockContext();
      const result = await service.getVulnerability('GHSA-xxxx-xxxx-xxxx', ctx);
      expect(result).toBeNull();
      expect(fetch).toHaveBeenCalledTimes(1);
    });
  });

  describe('framework HTTP handling', () => {
    it('retries transient OSV failures for three total attempts and preserves Retry-After', async () => {
      const fetch = mockFetch([
        { status: 503, body: { error: 'temporary outage' }, headers: { 'Retry-After': '0' } },
        { status: 503, body: { error: 'temporary outage' }, headers: { 'Retry-After': '0' } },
        { status: 503, body: { error: 'temporary outage' }, headers: { 'Retry-After': '0' } },
      ]);
      vi.stubGlobal('fetch', fetch);

      await expect(
        service.queryPackage('lodash', 'npm', '4.17.1', createMockContext()),
      ).rejects.toMatchObject({
        data: expect.objectContaining({ retryAfter: '0', retryAttempts: 3, status: 503 }),
      });
      expect(fetch).toHaveBeenCalledTimes(3);
    });

    it('stops immediately when the caller cancels instead of retrying', async () => {
      const controller = new AbortController();
      controller.abort();
      const fetch = vi
        .fn()
        .mockImplementation(() =>
          Promise.reject(new DOMException('The operation was aborted.', 'AbortError')),
        );
      vi.stubGlobal('fetch', fetch);

      await expect(
        service.queryPackage(
          'lodash',
          'npm',
          '4.17.1',
          createMockContext({ signal: controller.signal }),
        ),
      ).rejects.toThrow();
      expect(fetch).toHaveBeenCalledTimes(1);
    });
  });

  describe('queryBatch', () => {
    it('returns partial-success results across packages', async () => {
      vi.stubGlobal(
        'fetch',
        mockFetch([
          { status: 200, body: QUERY_RESPONSE_WITH_VULN }, // lodash
          { status: 200, body: EMPTY_QUERY_RESPONSE }, // express (clean)
          { status: 400, body: INVALID_ECOSYSTEM_RESPONSE }, // bad ecosystem
        ]),
      );

      const ctx = createMockContext();
      const results = await service.queryBatch(
        [
          { name: 'lodash', ecosystem: 'npm', version: '4.17.1' },
          { name: 'express', ecosystem: 'npm', version: '4.18.0' },
          { name: 'requests', ecosystem: 'NPM', version: '2.0.0' },
        ],
        ctx,
      );

      expect(results).toHaveLength(3);
      expect(results[0]!.vulns).toHaveLength(1);
      expect(results[0]!.error).toBeNull();
      expect(results[1]!.vulns).toHaveLength(0);
      expect(results[1]!.error).toBeNull();
      // Third package got invalid ecosystem error surfaced inline
      expect(results[2]!.vulns).toHaveLength(0);
      expect(results[2]!.error).toBeTruthy();
    });

    it('surfaces CVE aliases in batch brief from full per-package query', async () => {
      // /v1/querybatch returns only {id, modified} — no aliases.
      // The implementation uses parallel /v1/query calls to get full records including aliases.
      // This test verifies aliases flow through queryBatch → toBrief.
      vi.stubGlobal(
        'fetch',
        mockFetch([
          { status: 200, body: QUERY_RESPONSE_WITH_VULN }, // lodash with CVE alias
        ]),
      );

      const ctx = createMockContext();
      const results = await service.queryBatch(
        [{ name: 'lodash', ecosystem: 'npm', version: '4.17.1' }],
        ctx,
      );

      expect(results[0]!.vulns).toHaveLength(1);
      expect(results[0]!.vulns[0]!.aliases).toEqual(['CVE-2020-28500']);
      expect(results[0]!.error).toBeNull();
    });
  });

  describe('queryBatch concurrency', () => {
    /** Build packages p0..p{n-1} for concurrency tests. */
    function makePackages(n: number) {
      return Array.from({ length: n }, (_, i) => ({
        name: `p${i}`,
        ecosystem: 'npm',
        version: '1.0.0',
      }));
    }

    it('preserves positional result mapping under out-of-order completion', async () => {
      const total = 6;
      // Even-indexed packages are vulnerable, odd are clean; higher indices resolve
      // sooner (delay = total - idx) so completion order is the reverse of input order.
      // A positional bug (writing results in completion order) would scramble the parities.
      vi.stubGlobal(
        'fetch',
        vi.fn().mockImplementation((_url: string, init: RequestInit) => {
          const idx = Number((JSON.parse(String(init.body)).package.name as string).slice(1));
          const vulnerable = idx % 2 === 0;
          return new Promise((resolve) =>
            setTimeout(
              () =>
                resolve(
                  jsonResponse(200, vulnerable ? QUERY_RESPONSE_WITH_VULN : EMPTY_QUERY_RESPONSE),
                ),
              total - idx,
            ),
          );
        }),
      );

      const svc = new OsvApiService({ timeoutMs: 5000, batchConcurrency: 2 });
      const ctx = createMockContext();
      const results = await svc.queryBatch(makePackages(total), ctx);

      expect(results).toHaveLength(total);
      results.forEach((r, i) => {
        expect(r.name).toBe(`p${i}`);
        expect(r.error).toBeNull();
        expect(r.vulns.length > 0).toBe(i % 2 === 0);
      });
    });

    it('never exceeds the configured concurrency cap', async () => {
      const cap = 3;
      const total = 12;
      let inFlight = 0;
      let maxInFlight = 0;
      vi.stubGlobal(
        'fetch',
        vi.fn().mockImplementation(() => {
          inFlight++;
          maxInFlight = Math.max(maxInFlight, inFlight);
          return new Promise((resolve) =>
            setTimeout(() => {
              inFlight--;
              resolve(jsonResponse(200, EMPTY_QUERY_RESPONSE));
            }, 5),
          );
        }),
      );

      const svc = new OsvApiService({ timeoutMs: 5000, batchConcurrency: cap });
      const ctx = createMockContext();
      const results = await svc.queryBatch(makePackages(total), ctx);

      expect(results).toHaveLength(total);
      expect(maxInFlight).toBeLessThanOrEqual(cap);
      // More packages than the cap, so the pool saturates exactly at the cap.
      expect(maxInFlight).toBe(cap);
    });

    it('honors a custom concurrency cap (cap of 1 serializes requests)', async () => {
      let inFlight = 0;
      let maxInFlight = 0;
      vi.stubGlobal(
        'fetch',
        vi.fn().mockImplementation(() => {
          inFlight++;
          maxInFlight = Math.max(maxInFlight, inFlight);
          return new Promise((resolve) =>
            setTimeout(() => {
              inFlight--;
              resolve(jsonResponse(200, EMPTY_QUERY_RESPONSE));
            }, 3),
          );
        }),
      );

      const svc = new OsvApiService({ timeoutMs: 5000, batchConcurrency: 1 });
      const ctx = createMockContext();
      const results = await svc.queryBatch(makePackages(5), ctx);

      expect(results).toHaveLength(5);
      expect(maxInFlight).toBe(1);
    });
  });

  describe('normalization', () => {
    it('normalizes lastAffected range event (no fix exists)', async () => {
      const responseWithLastAffected = {
        vulns: [
          {
            id: 'RUSTSEC-2024-0001',
            summary: 'No fix available',
            details: '',
            aliases: [],
            published: '2024-01-01T00:00:00Z',
            modified: '2024-01-10T00:00:00Z',
            schema_version: '1.7.3',
            severity: [],
            affected: [
              {
                package: { name: 'unsafe-lib', ecosystem: 'crates.io' },
                ranges: [
                  {
                    type: 'SEMVER',
                    events: [{ introduced: '0' }, { last_affected: '1.2.3' }],
                  },
                ],
              },
            ],
            references: [],
          },
        ],
      };

      vi.stubGlobal('fetch', mockFetch([{ status: 200, body: responseWithLastAffected }]));
      const ctx = createMockContext();
      const result = await service.queryPackage('unsafe-lib', 'crates.io', '1.2.0', ctx);

      expect(result.invalid).toBe(false);
      if (result.invalid) return;

      const vuln = result.vulns[0]!;
      expect(vuln.fixedVersions).toHaveLength(0); // no fix
      const range = vuln.affectedRanges[0]!;
      expect(range.lastAffected).toBe('1.2.3');
      expect(range.fixed).toBeUndefined();
      expect(range.introduced).toBe('0');
    });

    it('handles sparse upstream vuln with no affected, no severity, no aliases', async () => {
      const sparseResponse = {
        vulns: [
          {
            id: 'PYSEC-2024-999',
            summary: 'Sparse record',
            // No: details, aliases, severity, affected, references, database_specific, schema_version
          },
        ],
      };

      vi.stubGlobal('fetch', mockFetch([{ status: 200, body: sparseResponse }]));
      const ctx = createMockContext();
      const result = await service.queryPackage('some-pkg', 'PyPI', '1.0.0', ctx);

      expect(result.invalid).toBe(false);
      if (result.invalid) return;

      const vuln = result.vulns[0]!;
      expect(vuln.id).toBe('PYSEC-2024-999');
      expect(vuln.aliases).toEqual([]);
      expect(vuln.severity).toEqual([]);
      expect(vuln.severityLabel).toBeNull();
      expect(vuln.affectedRanges).toEqual([]);
      expect(vuln.fixedVersions).toEqual([]);
      expect(vuln.cweIds).toEqual([]);
      expect(vuln.references).toEqual([]);
      expect(vuln.details).toBe('');
      expect(vuln.schemaVersion).toBe('');
    });

    it('surfaces affected entries with no package identity (CVE GIT-range-only records)', async () => {
      // #13: Live CVE records (e.g. CVE-2020-28500) have affected entries with no `package`
      // field — only a GIT range. Normalization must PRESERVE these (empty packageName/
      // ecosystem, the GIT repo, and ordered events) so the only affected source range is
      // not silently lost.
      const cveStyleResponse = {
        vulns: [
          {
            id: 'CVE-2020-28500',
            summary: null, // CVE records often have no summary
            details: 'Lodash versions prior to 4.17.21 are vulnerable.',
            aliases: ['GHSA-29mw-wpgm-hmr9'],
            published: '2021-02-15T11:15:12Z',
            modified: '2026-04-10T04:25:46Z',
            schema_version: '1.7.5',
            severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L' }],
            // No database_specific — CVE record, no GHSA severity label
            affected: [
              {
                // No `package` field — GIT-range-only entry (real CVE shape)
                ranges: [
                  {
                    type: 'GIT',
                    repo: 'https://github.com/lodash/lodash',
                    events: [{ introduced: '0' }, { fixed: 'c6e281b' }],
                  },
                ],
              },
            ],
            references: [],
          },
        ],
      };

      vi.stubGlobal('fetch', mockFetch([{ status: 200, body: cveStyleResponse }]));
      const ctx = createMockContext();
      const result = await service.queryPackage('lodash', 'npm', '4.17.20', ctx);

      expect(result.invalid).toBe(false);
      if (result.invalid) return;

      const vuln = result.vulns[0]!;
      expect(vuln.id).toBe('CVE-2020-28500');
      // The package-less GIT entry is preserved, not dropped.
      expect(vuln.affected).toHaveLength(1);
      const entry = vuln.affected[0]!;
      expect(entry.packageName).toBe('');
      expect(entry.ecosystem).toBe('');
      const range = entry.ranges[0]!;
      expect(range.rangeType).toBe('GIT');
      expect(range.repo).toBe('https://github.com/lodash/lodash');
      // Ordered events preserved, in order.
      expect(range.events).toEqual([
        { type: 'introduced', value: '0' },
        { type: 'fixed', value: 'c6e281b' },
      ]);
      // The flat affectedRanges view surfaces the package-less range too.
      expect(vuln.affectedRanges).toHaveLength(1);
      expect(vuln.affectedRanges[0]!.repo).toBe('https://github.com/lodash/lodash');
      expect(vuln.affectedRanges[0]!.packageName).toBe('');
      // summary is null upstream → normalized to empty string
      expect(vuln.summary).toBe('');
      // No database_specific.severity — the label comes from the CVSS_V3 vector (5.3).
      expect(vuln.severityLabel).toBe('MODERATE');
      expect(vuln.severitySource).toMatchObject({ type: 'CVSS_V3', computedScore: 5.3 });
    });

    it('preserves explicit versions[] and multi-interval ordered events (#13)', async () => {
      const response = {
        vulns: [
          {
            id: 'GHSA-multi-interval',
            summary: 'Advisory with explicit versions and two intervals',
            schema_version: '1.7.3',
            affected: [
              {
                package: { name: 'lodash-rails', ecosystem: 'RubyGems' },
                versions: ['1.0.0', '1.0.1', '1.1.0'],
                ranges: [
                  {
                    type: 'ECOSYSTEM',
                    events: [
                      { introduced: '0' },
                      { fixed: '1.2.0' },
                      { introduced: '2.0.0' },
                      { fixed: '2.1.0' },
                    ],
                  },
                ],
              },
            ],
          },
        ],
      };

      vi.stubGlobal('fetch', mockFetch([{ status: 200, body: response }]));
      const ctx = createMockContext();
      const result = await service.queryPackage('lodash-rails', 'RubyGems', '1.0.0', ctx);
      if (result.invalid) return;

      const entry = result.vulns[0]!.affected[0]!;
      // Explicit affected versions preserved.
      expect(entry.versions).toEqual(['1.0.0', '1.0.1', '1.1.0']);
      // Ordered events preserve BOTH intervals — the scalar view would collapse them.
      expect(entry.ranges[0]!.events).toEqual([
        { type: 'introduced', value: '0' },
        { type: 'fixed', value: '1.2.0' },
        { type: 'introduced', value: '2.0.0' },
        { type: 'fixed', value: '2.1.0' },
      ]);
      // Scalar convenience view keeps the last-value collapse (back-compat, unchanged).
      expect(entry.ranges[0]!.introduced).toBe('2.0.0');
      expect(entry.ranges[0]!.fixed).toBe('2.1.0');
      // Flat range carries versions + ordered events as well.
      expect(result.vulns[0]!.affectedRanges[0]!.versions).toEqual(['1.0.0', '1.0.1', '1.1.0']);
      expect(result.vulns[0]!.affectedRanges[0]!.events).toHaveLength(4);
    });

    it('preserves the withdrawn timestamp when present, omits it otherwise (#14)', async () => {
      const withdrawnResponse = {
        id: 'CVE-2024-0968',
        summary: 'Withdrawn advisory',
        withdrawn: '2024-05-15T05:33:02.244296Z',
        schema_version: '1.7.3',
      };
      vi.stubGlobal('fetch', mockFetch([{ status: 200, body: withdrawnResponse }]));
      let ctx = createMockContext();
      const withdrawn = await service.getVulnerability('CVE-2024-0968', ctx);
      expect(withdrawn!.withdrawn).toBe('2024-05-15T05:33:02.244296Z');

      // An active advisory (no withdrawn field) must not carry the field.
      vi.stubGlobal('fetch', mockFetch([{ status: 200, body: VULN_DETAIL_RESPONSE }]));
      ctx = createMockContext();
      const active = await service.getVulnerability('GHSA-29mw-wpgm-hmr9', ctx);
      expect(active!.withdrawn).toBeUndefined();
    });
  });

  describe('fixedVersions scoped to the queried package (#16)', () => {
    /** Query one saved live record as `name` in `ecosystem`; returns that vuln. */
    async function queryRecord(id: string, name: string, ecosystem: string) {
      stubOsvApi({ query: () => [loadOsvRecord(id)] });
      const result = await service.queryPackage(name, ecosystem, '0', createMockContext());
      if (result.invalid) throw new Error(result.message);
      return result.vulns[0]!;
    }

    it.each(['Ubuntu:22.04:LTS', 'Ubuntu:22.04'])(
      'lists only the xz-utils Ubuntu 22.04 fix of a gzip + xz-utils advisory (%s)',
      async (ecosystem) => {
        const vuln = await queryRecord('UBUNTU-CVE-2022-1271', 'xz-utils', ecosystem);
        expect(vuln.fixedVersions).toEqual(['5.2.5-2ubuntu1']);
      },
    );

    it('lists the fix of every Ubuntu release for a bare Ubuntu query, and no gzip fix', async () => {
      const vuln = await queryRecord('UBUNTU-CVE-2022-1271', 'xz-utils', 'Ubuntu');
      expect(vuln.fixedVersions).toEqual([
        '5.1.1alpha+20120614-2ubuntu2.14.04.1+esm1',
        '5.1.1alpha+20120614-2ubuntu2.16.04.1+esm1',
        '5.2.2-1.3ubuntu0.1',
        '5.2.4-1ubuntu1.1',
        '5.2.5-2ubuntu1',
      ]);
    });

    it('lists every fixed event of a multi-interval range, in record order', async () => {
      const vuln = await queryRecord('PYSEC-2022-190', 'Django', 'PyPI');
      expect(vuln.fixedVersions).toEqual(['4.0.4', '3.2.13', '2.2.28']);
    });

    it('excludes GIT commit fixes but keeps the GIT range in affectedRanges', async () => {
      const vuln = await queryRecord('PYSEC-2022-304', 'Django', 'PyPI');
      expect(vuln.fixedVersions).toEqual(['3.2.16', '4.0.8', '4.1.2']);
      expect(vuln.affectedRanges.map((r) => r.rangeType)).toEqual(['GIT', 'ECOSYSTEM']);
      expect(vuln.affectedRanges[0]!.fixed).toBe('5b6b257fa7ec37ff27965358800c67e2dd11c924');
    });

    it('matches release-suffixed Debian entries from a base Debian query, one release from a suffixed one', async () => {
      expect(
        (await queryRecord('DEBIAN-CVE-2025-31115', 'xz-utils', 'Debian')).fixedVersions,
      ).toEqual(['5.4.1-1', '5.8.1-1']);
      expect(
        (await queryRecord('DEBIAN-CVE-2025-31115', 'xz-utils', 'Debian:12')).fixedVersions,
      ).toEqual(['5.4.1-1']);
    });

    it.each([
      ['GHSA-6757-jp84-gxfx', 'PyYAML', ['5.3.1']],
      ['GHSA-2jv5-9r88-3w3p', 'python_multipart', ['0.0.7']],
    ])('matches PyPI entries by PEP 503 name (%s queried as %s)', async (id, name, fixes) => {
      expect((await queryRecord(id, name, 'PyPI')).fixedVersions).toEqual(fixes);
    });

    it('returns an empty list, with no fallback to other entries, when no entry matches', async () => {
      const vuln = await queryRecord('UBUNTU-CVE-2022-1271', 'xz-utils', 'Alpine:v3.15');
      expect(vuln.fixedVersions).toEqual([]);
    });

    it('keeps every entry and range in affectedRanges, other packages included', async () => {
      const vuln = await queryRecord('UBUNTU-CVE-2022-1271', 'xz-utils', 'Ubuntu:22.04:LTS');
      expect(vuln.affectedRanges).toHaveLength(10);
      expect(vuln.affectedRanges.map((r) => r.packageName)).toEqual(
        Array.from({ length: 5 }, () => ['gzip', 'xz-utils']).flat(),
      );
      expect(vuln.affectedRanges.map((r) => r.fixed)).toContain('1.10-4ubuntu4');
    });

    it('carries the same list into a batch row as queryPackage does for the same tuple', async () => {
      stubOsvApi({ query: () => [loadOsvRecord('UBUNTU-CVE-2022-1271')] });
      const [row] = await service.queryBatch(
        [{ name: 'xz-utils', ecosystem: 'Ubuntu:22.04:LTS', version: '5.2.5-2build2' }],
        createMockContext(),
      );
      expect(row!.vulns[0]!.fixedVersions).toEqual(['5.2.5-2ubuntu1']);
    });

    it('does not attach fixedVersions to a record fetched by ID', async () => {
      stubOsvApi({ vuln: loadOsvRecord('UBUNTU-CVE-2022-1271') });
      const vuln = await service.getVulnerability('UBUNTU-CVE-2022-1271', createMockContext());
      expect(vuln).not.toHaveProperty('fixedVersions');
      expect(vuln!.affected).toHaveLength(10);
    });
  });

  describe('severity passthrough and database_specific labels', () => {
    it('passes record-level severity entries through verbatim, Ubuntu priorities included', async () => {
      const record = loadOsvRecord('UBUNTU-CVE-2024-3094');
      stubOsvApi({ vuln: record });
      const vuln = await service.getVulnerability('UBUNTU-CVE-2024-3094', createMockContext());
      expect(vuln!.severity).toEqual(record.severity);
      expect(vuln!.severity.map((s) => s.type)).toEqual(['CVSS_V3', 'CVSS_V3', 'Ubuntu']);
    });

    it.each([
      ['moderate', 'MODERATE'],
      ['High', 'HIGH'],
      ['CRITICAL', 'CRITICAL'],
      ['low', 'LOW'],
    ])('labels database_specific.severity %s as %s in any case', async (published, label) => {
      stubOsvApi({ vuln: { id: 'X-1', database_specific: { severity: published } } });
      const vuln = await service.getVulnerability('X-1', createMockContext());
      expect(vuln!.severityLabel).toBe(label);
    });
  });

  describe('severity derivation (#17)', () => {
    /** Fetch one record by ID through the real service. */
    async function getRecord(record: RawOsvVulnerability) {
      stubOsvApi({ vuln: record });
      const vuln = await service.getVulnerability(record.id ?? '', createMockContext());
      if (!vuln) throw new Error('expected a record');
      return vuln;
    }

    /** Query one record as `name` in `ecosystem` through the real service. */
    async function queryRecord(record: RawOsvVulnerability, name: string, ecosystem: string) {
      stubOsvApi({ query: () => [record] });
      const result = await service.queryPackage(name, ecosystem, '0', createMockContext());
      if (result.invalid) throw new Error(result.message);
      return result.vulns[0]!;
    }

    /** A synthetic record carrying only record-level severity entries. */
    const withSeverity = (severity: Array<{ type: string; score: string }>) =>
      ({ id: 'X-1', severity }) as RawOsvVulnerability;

    const VECTORS = {
      v3Low: 'CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L', // 3.9
      v3Moderate: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:N/A:L', // 4.0
      v3ModerateTop: 'CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:N/I:L/A:H', // 6.9
      v3High: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:H', // 7.0
      v3HighTop: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:H/A:H', // 8.9
      v3Critical: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:H', // 9.0
      v3Ten: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H', // 10.0
      v3Zero: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N', // 0.0
    };

    it.each([
      ['UBUNTU-CVE-2024-3094', 'CRITICAL', { type: 'Ubuntu', score: 'critical' }],
      [
        'DEBIAN-CVE-2024-3094',
        'CRITICAL',
        { type: 'CVSS_V3', score: VECTORS.v3Ten, computedScore: 10 },
      ],
      [
        'CVE-2025-31115',
        'HIGH',
        {
          type: 'CVSS_V4',
          score: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N',
          computedScore: 8.7,
        },
      ],
      [
        'CVE-2026-34743',
        'LOW',
        {
          type: 'CVSS_V4',
          score: 'CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N/E:U',
          computedScore: 1.7,
        },
      ],
      [
        'HSEC-2023-0001',
        'MODERATE',
        {
          type: 'CVSS_V3',
          score: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H',
          computedScore: 6.5,
        },
      ],
      ['OESA-2023-1092', 'MODERATE', { type: 'database_specific', score: 'Medium' }],
      ['GHSA-29mw-wpgm-hmr9', 'MODERATE', { type: 'database_specific', score: 'MODERATE' }],
      ['UBUNTU-CVE-2025-31115', 'MODERATE', { type: 'Ubuntu', score: 'medium' }],
    ])('labels live record %s %s with its source', async (id, label, source) => {
      const vuln = await getRecord(loadOsvRecord(id));
      expect(vuln.severityLabel).toBe(label);
      expect(vuln.severitySource).toEqual(source);
    });

    it('returns a null label and source for a record with no severity data (PYSEC-2022-190)', async () => {
      const vuln = await getRecord(loadOsvRecord('PYSEC-2022-190'));
      expect(vuln.severityLabel).toBeNull();
      expect(vuln.severitySource).toBeNull();
    });

    it('exposes affected-level severity entries on the affected package (HSEC-2023-0001)', async () => {
      const vuln = await getRecord(loadOsvRecord('HSEC-2023-0001'));
      expect(vuln.severity).toEqual([]);
      expect(vuln.affected[0]!.severity).toEqual([
        { type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H' },
      ]);
    });

    it('omits severity on affected entries that carry none', async () => {
      const vuln = await getRecord(loadOsvRecord('UBUNTU-CVE-2024-3094'));
      for (const entry of vuln.affected) expect(entry).not.toHaveProperty('severity');
    });

    it.each([
      [VECTORS.v3Low, 'LOW', 3.9],
      [VECTORS.v3Moderate, 'MODERATE', 4],
      [VECTORS.v3ModerateTop, 'MODERATE', 6.9],
      [VECTORS.v3High, 'HIGH', 7],
      [VECTORS.v3HighTop, 'HIGH', 8.9],
      [VECTORS.v3Critical, 'CRITICAL', 9],
      [VECTORS.v3Ten, 'CRITICAL', 10],
    ])('bands %s as %s (%s)', async (vector, label, score) => {
      const vuln = await getRecord(withSeverity([{ type: 'CVSS_V3', score: vector }]));
      expect(vuln.severityLabel).toBe(label);
      expect(vuln.severitySource).toEqual({ type: 'CVSS_V3', score: vector, computedScore: score });
    });

    it('scores a CVSS_V3 vector with its temporal metrics, as published', async () => {
      const vector = 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H/E:U/RL:O/RC:C'; // base 9.0
      const vuln = await getRecord(withSeverity([{ type: 'CVSS_V3', score: vector }]));
      expect(vuln.severityLabel).toBe('HIGH');
      expect(vuln.severitySource).toEqual({ type: 'CVSS_V3', score: vector, computedScore: 7.8 });
    });

    it('picks the highest-scoring vector when it is not the first entry', async () => {
      const vuln = await getRecord(
        withSeverity([
          { type: 'CVSS_V3', score: VECTORS.v3Low },
          {
            type: 'CVSS_V4',
            score: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N',
          },
          { type: 'CVSS_V3', score: VECTORS.v3Critical },
        ]),
      );
      expect(vuln.severityLabel).toBe('CRITICAL');
      expect(vuln.severitySource).toEqual({
        type: 'CVSS_V3',
        score: VECTORS.v3Critical,
        computedScore: 9,
      });
    });

    it('skips a malformed vector and scores the rest', async () => {
      const vuln = await getRecord(
        withSeverity([
          { type: 'CVSS_V3', score: 'CVSS:3.1/AV:N' },
          { type: 'CVSS_V3', score: VECTORS.v3High },
        ]),
      );
      expect(vuln.severityLabel).toBe('HIGH');
    });

    it.each([
      [
        'a malformed vector',
        [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:Z' }],
      ],
      ['a CVSS_V2-only record', [{ type: 'CVSS_V2', score: 'AV:N/AC:L/Au:N/C:P/I:P/A:P' }]],
      ['an unknown severity type', [{ type: 'CVSS_V5', score: VECTORS.v3Ten }]],
      ['an all-zero vector', [{ type: 'CVSS_V3', score: VECTORS.v3Zero }]],
      ['an unrecognized Ubuntu priority', [{ type: 'Ubuntu', score: 'untriaged' }]],
      ['an empty severity array', []],
    ])('returns null without an error for %s', async (_case, severity) => {
      const vuln = await getRecord(withSeverity(severity));
      expect(vuln.severityLabel).toBeNull();
      expect(vuln.severitySource).toBeNull();
      expect(vuln.severity).toEqual(severity);
    });

    it.each([
      ['negligible', 'LOW'],
      ['low', 'LOW'],
      ['medium', 'MODERATE'],
      ['high', 'HIGH'],
      ['critical', 'CRITICAL'],
    ])('maps Ubuntu priority %s to %s', async (priority, label) => {
      const vuln = await getRecord(withSeverity([{ type: 'Ubuntu', score: priority }]));
      expect(vuln.severityLabel).toBe(label);
      expect(vuln.severitySource).toEqual({ type: 'Ubuntu', score: priority });
    });

    it('skips an unrecognized Ubuntu priority and falls through to the CVSS score', async () => {
      const vuln = await getRecord(
        withSeverity([
          { type: 'Ubuntu', score: 'untriaged' },
          { type: 'CVSS_V3', score: VECTORS.v3Moderate },
        ]),
      );
      expect(vuln.severityLabel).toBe('MODERATE');
      expect(vuln.severitySource).toMatchObject({ type: 'CVSS_V3' });
    });

    it('ranks an Ubuntu priority above a CVSS score listed before it', async () => {
      const vuln = await getRecord(
        withSeverity([
          { type: 'CVSS_V3', score: VECTORS.v3Ten },
          { type: 'Ubuntu', score: 'low' },
        ]),
      );
      expect(vuln.severityLabel).toBe('LOW');
      expect(vuln.severitySource).toEqual({ type: 'Ubuntu', score: 'low' });
    });

    it('falls through an unrecognized database_specific.severity to the next source', async () => {
      const vuln = await getRecord({
        id: 'X-1',
        database_specific: { severity: 'important' },
        severity: [{ type: 'Ubuntu', score: 'high' }],
      });
      expect(vuln.severityLabel).toBe('HIGH');
      expect(vuln.severitySource).toEqual({ type: 'Ubuntu', score: 'high' });
    });

    it('ignores affected-level severity when record-level severity is present', async () => {
      const vuln = await getRecord({
        id: 'X-1',
        severity: [{ type: 'CVSS_V3', score: VECTORS.v3Low }],
        affected: [
          {
            package: { name: 'a', ecosystem: 'npm' },
            severity: [{ type: 'CVSS_V3', score: VECTORS.v3Ten }],
          },
        ],
      });
      expect(vuln.severityLabel).toBe('LOW');
    });

    describe('affected-level severity scope', () => {
      /** Two packages with different affected-level severity; the queried one is second. */
      const TWO_PACKAGES: RawOsvVulnerability = {
        id: 'X-2',
        affected: [
          {
            package: { name: 'other', ecosystem: 'PyPI' },
            severity: [{ type: 'CVSS_V3', score: VECTORS.v3Ten }],
          },
          {
            package: { name: 'python_multipart', ecosystem: 'PyPI' },
            severity: [
              { type: 'CVSS_V3', score: VECTORS.v3Low },
              { type: 'CVSS_V3', score: VECTORS.v3HighTop },
            ],
          },
          { package: { name: 'unscored', ecosystem: 'PyPI' } },
        ],
      };

      it('derives a query label from the matching entry only, even when it is not the first', async () => {
        const vuln = await queryRecord(TWO_PACKAGES, 'python-multipart', 'PyPI');
        expect(vuln.severityLabel).toBe('HIGH');
        expect(vuln.severitySource).toEqual({
          type: 'CVSS_V3',
          score: VECTORS.v3HighTop,
          computedScore: 8.9,
        });
      });

      it('returns null for a query whose matching entry carries no severity, with no fallback', async () => {
        const vuln = await queryRecord(TWO_PACKAGES, 'unscored', 'PyPI');
        expect(vuln.severityLabel).toBeNull();
        expect(vuln.severitySource).toBeNull();
      });

      it('derives a by-ID label from every affected entry', async () => {
        const vuln = await getRecord(TWO_PACKAGES);
        expect(vuln.severityLabel).toBe('CRITICAL');
        expect(vuln.severitySource).toMatchObject({ score: VECTORS.v3Ten, computedScore: 10 });
        expect(vuln.affected.map((a) => a.severity?.length ?? 0)).toEqual([1, 2, 0]);
      });

      it('labels HSEC-2023-0001 from its affected entry for an aeson query', async () => {
        const vuln = await queryRecord(loadOsvRecord('HSEC-2023-0001'), 'aeson', 'Hackage');
        expect(vuln.severityLabel).toBe('MODERATE');
        expect(vuln.severitySource).toMatchObject({ type: 'CVSS_V3', computedScore: 6.5 });
      });

      it('keeps record-level labels for a package query (openEuler Medium)', async () => {
        const vuln = await queryRecord(
          loadOsvRecord('OESA-2023-1092'),
          'openssl',
          'openEuler:22.03-LTS',
        );
        expect(vuln.severityLabel).toBe('MODERATE');
        expect(vuln.severitySource).toEqual({ type: 'database_specific', score: 'Medium' });
      });

      it('carries the query-scoped label into a batch row', async () => {
        stubOsvApi({ query: () => [TWO_PACKAGES] });
        const [row] = await service.queryBatch(
          [{ name: 'python-multipart', ecosystem: 'PyPI', version: '0' }],
          createMockContext(),
        );
        expect(row!.vulns[0]!.severityLabel).toBe('HIGH');
      });
    });
  });

  describe('pagination (#15)', () => {
    it('follows next_page_token and accumulates vulns until the token disappears', async () => {
      const page1 = { vulns: [{ id: 'V1', schema_version: '1' }], next_page_token: 'tok-1' };
      const page2 = { vulns: [{ id: 'V2', schema_version: '1' }] }; // no token — complete
      vi.stubGlobal(
        'fetch',
        mockFetch([
          { status: 200, body: page1 },
          { status: 200, body: page2 },
        ]),
      );
      const ctx = createMockContext();
      const result = await service.queryPackage('pkg', 'npm', '1.0.0', ctx);
      if (result.invalid) return;
      expect(result.vulns.map((v) => v.id)).toEqual(['V1', 'V2']);
      expect(result.truncated).toBe(false);
    });

    it('sends the page_token in the follow-up request body, omits it on page one', async () => {
      const bodies: string[] = [];
      vi.stubGlobal(
        'fetch',
        vi.fn().mockImplementation((_url: string, init: RequestInit) => {
          bodies.push(String(init.body));
          const call = bodies.length;
          return Promise.resolve(
            jsonResponse(200, call === 1 ? { next_page_token: 'tok-abc' } : {}),
          );
        }),
      );
      const ctx = createMockContext();
      await service.queryPackage('pkg', 'npm', '1.0.0', ctx);
      expect(bodies).toHaveLength(2);
      expect(JSON.parse(bodies[0]!).page_token).toBeUndefined();
      expect(JSON.parse(bodies[1]!).page_token).toBe('tok-abc');
    });

    it('never reports an empty paginated first page as clean — marks it truncated', async () => {
      // OSV returns a bare next_page_token with zero vulns; with the cap reached and a
      // token still pending, the result is truncated (incomplete), NOT a false clean.
      vi.stubGlobal(
        'fetch',
        vi
          .fn()
          .mockImplementation(() =>
            Promise.resolve(jsonResponse(200, { next_page_token: 'always-more' })),
          ),
      );
      const svc = new OsvApiService({ timeoutMs: 5000, maxQueryPages: 1 });
      const ctx = createMockContext();
      const result = await svc.queryPackage('Kernel', 'Linux', '5.10.0', ctx);
      if (result.invalid) return;
      expect(result.vulns).toHaveLength(0);
      expect(result.truncated).toBe(true);
    });

    it('bounds total work at the page cap when OSV keeps returning a token', async () => {
      let calls = 0;
      vi.stubGlobal(
        'fetch',
        vi.fn().mockImplementation(() => {
          calls++;
          return Promise.resolve(jsonResponse(200, { next_page_token: 'more' }));
        }),
      );
      const svc = new OsvApiService({ timeoutMs: 5000, maxQueryPages: 3 });
      const ctx = createMockContext();
      const result = await svc.queryPackage('Kernel', 'Linux', '5.10.0', ctx);
      if (result.invalid) return;
      expect(calls).toBe(3); // cap enforced
      expect(result.truncated).toBe(true);
    });

    it('batch rows inherit truncation from the per-package query', async () => {
      vi.stubGlobal(
        'fetch',
        vi.fn().mockImplementation((_url: string, init: RequestInit) => {
          const name = JSON.parse(String(init.body)).package.name as string;
          // "Kernel" always paginates (never resolves); "express" is clean in one page.
          const body = name === 'Kernel' ? { next_page_token: 'more' } : {};
          return Promise.resolve(jsonResponse(200, body));
        }),
      );
      const svc = new OsvApiService({ timeoutMs: 5000, maxQueryPages: 2, batchConcurrency: 2 });
      const ctx = createMockContext();
      const results = await svc.queryBatch(
        [
          { name: 'Kernel', ecosystem: 'Linux', version: '5.10.0' },
          { name: 'express', ecosystem: 'npm', version: '4.18.0' },
        ],
        ctx,
      );
      expect(results[0]!.truncated).toBe(true);
      expect(results[1]!.truncated).toBe(false);
    });
  });
});
