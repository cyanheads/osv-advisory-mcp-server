/**
 * @fileoverview PURL queries through real normalization, native batches and both output surfaces.
 * @module tests/tools/purl-query.test
 */
import { runToolContract } from '@cyanheads/mcp-ts-core/testing';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { osvQueryBatch, osvQueryPackage } from '@/mcp-server/tools/definitions/index.js';
import { initOsvApiService } from '@/services/osv-api/osv-api-service.js';
import { resolvePackage } from '@/services/osv-api/package-identifier.js';
import { captureOsvQueries, loadOsvRecord } from '../helpers/osv-fixtures.js';

afterEach(() => vi.unstubAllGlobals());
describe('PURL package queries', () => {
  it.each([
    ['pkg:npm/%40angular/core@1.0.0', '@angular/core', 'npm'],
    ['pkg:maven/org.example/lib@1', 'org.example:lib', 'Maven'],
    ['pkg:gradle/org.example/lib@1', 'org.example:lib', 'Maven'],
    ['pkg:golang/github.com/owner/repo@1#sub/child', 'github.com/owner/repo/sub/child', 'Go'],
    ['pkg:deb/debian/curl@7.88.1?distro=bookworm', 'curl', 'Debian:12'],
    ['pkg:deb/debian/curl@7.88.1?distro=12', 'curl', 'Debian:12'],
  ])('maps %s to the OSV coordinate', (purl, name, ecosystem) => {
    expect(resolvePackage({ purl })).toMatchObject({ name, ecosystem, purl });
  });

  it('matches embedded and separate versions to the tuple, forwarding PURL intact', async () => {
    const raw = loadOsvRecord('PYSEC-2022-190');
    const bodies = captureOsvQueries([raw]);
    initOsvApiService();
    const inputs = [
      { name: 'Django', ecosystem: 'PyPI', version: '3.2.12' },
      { purl: 'pkg:pypi/django@3.2.12' },
      { purl: 'pkg:pypi/django', version: '3.2.12' },
    ];
    const replies = [];
    for (const input of inputs) {
      const reply = await runToolContract(osvQueryPackage, input);
      expect(reply.isError).not.toBe(true);
      const result = osvQueryPackage.output.parse(reply.structuredContent);
      expect(result.vulns).toHaveLength(1);
      expect(JSON.stringify(reply.content)).toContain(raw.id);
      replies.push(result);
    }
    expect(replies[1]!.vulns).toEqual(replies[0]!.vulns);
    expect(replies[2]!.vulns).toEqual(replies[0]!.vulns);
    expect(replies[0]!.vulns![0]!.fixedVersions).toEqual(['4.0.4', '3.2.13', '2.2.28']);
    expect(bodies[1]).toEqual({ package: { purl: inputs[1]!.purl } });
    expect(bodies[2]).toEqual({ package: { purl: inputs[2]!.purl }, version: '3.2.12' });
    const page = await runToolContract(osvQueryPackage, {
      ...inputs[1],
      page: { advisoryId: raw.id, path: '/fixedVersions' },
    });
    expect(page.isError).not.toBe(true);
    expect(
      osvQueryPackage.output
        .parse(page.structuredContent)
        .page!.entries!.map((entry) => entry.value),
    ).toEqual(replies[0]!.vulns![0]!.fixedVersions);
    const expected = structuredClone(replies[1]);
    replies[1]!.vulns![0]!.fixedVersions.push('mutated');
    replies[1]!.vulns![0]!.affectedRanges[0]!.events!.push({ type: 'fixed', value: 'mutated' });
    await runToolContract(osvQueryBatch, { packages: [inputs[0]!, { purl: 'broken' }] });
    const repeated = await runToolContract(osvQueryPackage, inputs[1]!);
    expect(repeated.structuredContent).toEqual(expected);
  });

  it('retains advisoryId through fresh multi-page PURL retrieval and scopes child revisions', async () => {
    const raw = { ...loadOsvRecord('PYSEC-2022-190'), summary: '🧬'.repeat(25_000) };
    captureOsvQueries([raw]);
    initOsvApiService();
    const original = { purl: 'pkg:pypi/django@3.2.12' };
    const call = async (page: {
      advisoryId: string;
      path: string;
      offset?: number;
      revision?: string;
    }) => {
      const reply = await runToolContract(osvQueryPackage, { ...original, page });
      expect(reply.isError).not.toBe(true);
      return osvQueryPackage.output.parse(reply.structuredContent).page!;
    };
    const advisory = await call({ advisoryId: raw.id!, path: '' });
    const summary = advisory.entries!.find((entry) => entry.key === 'summary')!.deferred!;
    expect(summary).toMatchObject({ path: '/summary', type: 'string', total: 25_000 });
    const wrongScope = await runToolContract(osvQueryPackage, {
      ...original,
      page: { advisoryId: raw.id, path: summary.path, revision: advisory.revision },
    });
    expect(wrongScope.structuredContent).toMatchObject({
      error: { data: { reason: 'stale_page_revision' } },
    });
    let offset: number | null = 0;
    let revision: string | undefined;
    let text = '';
    let count = 0;
    do {
      const page = await call({
        advisoryId: raw.id!,
        path: summary.path,
        offset,
        ...(revision ? { revision } : {}),
      });
      text += page.text;
      revision = page.revision;
      offset = page.nextOffset;
      count++;
    } while (offset !== null);
    expect(count).toBeGreaterThan(2);
    expect(text).toBe(raw.summary);
    expect(
      await call({ advisoryId: raw.id!, path: summary.path, offset: 25_000, revision: revision! }),
    ).toMatchObject({ text: '', nextOffset: null });
  });

  it.each([
    ['pkg:npm/%40scope/example@1', '@scope/example', 'npm'],
    ['pkg:deb/debian/example@1?arch=source&distro=bookworm', 'example', 'Debian:12'],
  ])('scopes fixes and severity correctly for %s', async (purl, name, ecosystem) => {
    captureOsvQueries([
      {
        id: 'OSV-scoped-example',
        affected: [
          {
            package: { name, ecosystem: 'Other' },
            severity: [{ type: 'Ubuntu', score: 'critical' }],
            ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '0' }, { fixed: '999' }] }],
          },
          {
            package: { name, ecosystem },
            severity: [{ type: 'Ubuntu', score: 'low' }],
            ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '0' }, { fixed: '2' }] }],
          },
        ],
      },
    ]);
    initOsvApiService();
    const purlReply = await runToolContract(osvQueryPackage, { purl });
    const tupleReply = await runToolContract(osvQueryPackage, { name, ecosystem, version: '1' });
    const result = osvQueryPackage.output.parse(purlReply.structuredContent);
    expect(result.vulns).toEqual(osvQueryPackage.output.parse(tupleReply.structuredContent).vulns);
    expect(result.vulns![0]).toMatchObject({
      fixedVersions: ['2'],
      severityLabel: 'LOW',
      severitySource: { score: 'low' },
    });
    expect(JSON.stringify(purlReply.content)).toContain('Fixed in 2');
    expect(JSON.stringify(purlReply.content)).not.toContain('Fixed in 999');
  });

  it.each([
    [{ purl: 'not-a-purl' }, 'invalid_purl'],
    [{ purl: 'pkg:github/owner/repo@1' }, 'unsupported_purl'],
    [{ purl: 'pkg:pypi/jinja2' }, 'invalid_purl_version'],
    [{ purl: 'pkg:pypi/jinja2@1', version: '1' }, 'invalid_purl_version'],
  ])('returns actionable typed validation for %j', async (input, reason) => {
    initOsvApiService();
    const reply = await runToolContract(osvQueryPackage, input);
    expect(reply.isError).toBe(true);
    expect(reply.structuredContent).toMatchObject({
      error: { data: { reason, recovery: { hint: expect.any(String) } } },
    });
    expect(JSON.stringify(reply.content)).toContain('Recovery:');
  });

  it('rejects mixed identifiers before querying', () => {
    expect(
      osvQueryPackage.input.safeParse({
        purl: 'pkg:npm/a@1',
        name: 'a',
        ecosystem: 'npm',
        version: '1',
      }).success,
    ).toBe(false);
  });

  it('preserves stripping unrelated tuple row properties but rejects mixed PURL identifiers', () => {
    const tuple = { name: 'a', ecosystem: 'npm', version: '1' };
    expect(
      osvQueryBatch.input.parse({ packages: [{ ...tuple, extra: 'legacy ignored property' }] })
        .packages,
    ).toEqual([tuple]);
    expect(
      osvQueryBatch.input.safeParse({ packages: [{ ...tuple, purl: 'pkg:npm/a@1' }] }).success,
    ).toBe(false);
  });

  it('reports an upstream PURL rejection distinctly from invalid ecosystem', async () => {
    initOsvApiService();
    vi.stubGlobal(
      'fetch',
      vi.fn(() =>
        Promise.resolve(Response.json({ message: 'Rejected PURL query' }, { status: 400 })),
      ),
    );
    const reply = await runToolContract(osvQueryPackage, { purl: 'pkg:pypi/jinja2@1' });
    expect(reply.structuredContent).toMatchObject({
      error: { data: { reason: 'invalid_purl_query', recovery: { hint: expect.any(String) } } },
    });
    expect(JSON.stringify(reply.content)).toContain('Recovery:');
  });

  it('retains PURL bodies across token-only pages and never treats cap exhaustion as clean', async () => {
    initOsvApiService({ maxQueryPages: 2 });
    const requests: unknown[] = [];
    vi.stubGlobal(
      'fetch',
      vi.fn((_url: unknown, init: RequestInit) => {
        requests.push(JSON.parse(String(init.body)));
        return Promise.resolve(Response.json({ next_page_token: 'next' }));
      }),
    );
    const reply = await runToolContract(osvQueryPackage, { purl: 'pkg:pypi/jinja2@1' });
    expect(reply.structuredContent).toMatchObject({
      truncated: true,
      vulns: [],
      queryMeta: { purl: 'pkg:pypi/jinja2@1', version: '1' },
    });
    expect(JSON.stringify(reply.content)).toContain('INCOMPLETE');
    expect(requests).toEqual([
      { package: { purl: 'pkg:pypi/jinja2@1' } },
      { package: { purl: 'pkg:pypi/jinja2@1' }, page_token: 'next' },
    ]);
  });

  it('keeps clean PURL echoes and empty past-end pages on both surfaces', async () => {
    initOsvApiService();
    captureOsvQueries([]);
    const original = { purl: 'pkg:npm/example@99' };
    const reply = await runToolContract(osvQueryPackage, original);
    expect(reply.structuredContent).toMatchObject({
      truncated: false,
      vulns: [],
      queryMeta: { purl: original.purl },
    });
    expect(JSON.stringify(reply.content)).toContain(original.purl);
    const page = await runToolContract(osvQueryPackage, {
      ...original,
      page: { path: '/vulns', offset: 10 },
    });
    expect(osvQueryPackage.output.parse(page.structuredContent).page).toMatchObject({
      entries: [],
      nextOffset: null,
    });
    expect(JSON.stringify(page.content)).toContain('nextOffset');
  });

  it('isolates malformed PURLs while keeping native batch order and canonical fixes', async () => {
    const raw = loadOsvRecord('PYSEC-2022-190');
    const bodies = captureOsvQueries([raw]);
    initOsvApiService();
    const reply = await runToolContract(osvQueryBatch, {
      packages: [
        { purl: 'broken' },
        { name: 'Django', ecosystem: 'PyPI', version: '3.2.12' },
        { purl: 'pkg:pypi/django@3.2.12' },
      ],
    });
    expect(reply.isError).not.toBe(true);
    const output = osvQueryBatch.output.parse(reply.structuredContent);
    expect(output.summary).toMatchObject({
      totalPackages: 3,
      errorCount: 1,
      vulnerableCount: 2,
      cleanCount: 0,
    });
    expect(output.results![0]).toMatchObject({
      purl: 'broken',
      error: expect.stringContaining('Malformed'),
    });
    expect(output.results![2]).toMatchObject({
      purl: 'pkg:pypi/django@3.2.12',
      name: 'django',
      ecosystem: 'PyPI',
    });
    expect(output.results![2]!.vulns).toEqual(output.results![1]!.vulns);
    expect(output.results![2]!.vulns[0]!.fixedVersions).toEqual(['4.0.4', '3.2.13', '2.2.28']);
    expect(bodies).toHaveLength(2);
    expect(JSON.stringify(reply.content)).toContain('pkg:pypi/django@3.2.12');
    const page = await runToolContract(osvQueryBatch, {
      packages: [
        { purl: 'broken' },
        { name: 'Django', ecosystem: 'PyPI', version: '3.2.12' },
        { purl: 'pkg:pypi/django@3.2.12' },
      ],
      page: { path: '/results/2/vulns/0/fixedVersions' },
    });
    expect(page.isError).not.toBe(true);
    expect(osvQueryBatch.output.parse(page.structuredContent).page!.path).toBe(
      '/results/2/vulns/0/fixedVersions',
    );
    expect(
      osvQueryBatch.output.parse(page.structuredContent).page!.entries!.map((entry) => entry.value),
    ).toEqual(output.results![2]!.vulns[0]!.fixedVersions);
  });
});
