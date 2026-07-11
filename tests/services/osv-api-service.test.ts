/**
 * @fileoverview Tests for OsvApiService — HTTP fetch, normalization, and error handling.
 * @module tests/services/osv-api-service.test
 */

import { createMockContext } from '@cyanheads/mcp-ts-core/testing';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { OsvApiService } from '@/services/osv-api/osv-api-service.js';

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

function mockFetch(responses: Array<{ status: number; body: unknown }>) {
  let callIndex = 0;
  return vi.fn().mockImplementation(() => {
    const res = responses[callIndex++];
    if (!res) throw new Error('Unexpected fetch call');
    return Promise.resolve({
      ok: res.status >= 200 && res.status < 300,
      status: res.status,
      text: () => Promise.resolve(JSON.stringify(res.body)),
    });
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
      vi.stubGlobal('fetch', mockFetch([{ status: 400, body: INVALID_ECOSYSTEM_RESPONSE }]));
      const ctx = createMockContext();
      const result = await service.queryPackage('lodash', 'NPM', '4.17.1', ctx);

      expect(result.invalid).toBe(true);
      if (!result.invalid) return;
      expect(result.message).toBe('Invalid ecosystem.');
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
      vi.stubGlobal('fetch', mockFetch([{ status: 404, body: VULN_NOT_FOUND_RESPONSE }]));
      const ctx = createMockContext();
      const result = await service.getVulnerability('GHSA-xxxx-xxxx-xxxx', ctx);
      expect(result).toBeNull();
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
                resolve({
                  ok: true,
                  status: 200,
                  text: () =>
                    Promise.resolve(
                      JSON.stringify(vulnerable ? QUERY_RESPONSE_WITH_VULN : EMPTY_QUERY_RESPONSE),
                    ),
                }),
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
              resolve({
                ok: true,
                status: 200,
                text: () => Promise.resolve(JSON.stringify(EMPTY_QUERY_RESPONSE)),
              });
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
              resolve({
                ok: true,
                status: 200,
                text: () => Promise.resolve(JSON.stringify(EMPTY_QUERY_RESPONSE)),
              });
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
      // severityLabel null because no database_specific.severity
      expect(vuln.severityLabel).toBeNull();
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
          return Promise.resolve({
            ok: true,
            status: 200,
            text: () =>
              Promise.resolve(JSON.stringify(call === 1 ? { next_page_token: 'tok-abc' } : {})),
          });
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
        vi.fn().mockImplementation(() =>
          Promise.resolve({
            ok: true,
            status: 200,
            text: () => Promise.resolve(JSON.stringify({ next_page_token: 'always-more' })),
          }),
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
          return Promise.resolve({
            ok: true,
            status: 200,
            text: () => Promise.resolve(JSON.stringify({ next_page_token: 'more' })),
          });
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
          return Promise.resolve({
            ok: true,
            status: 200,
            text: () => Promise.resolve(JSON.stringify(body)),
          });
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
