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
    [
      { name: 'openssl', ecosystem: 'Alpine', version: '3.0.8-r0' },
      'alpine_release_required',
      'Alpine:v3.17',
    ],
    [
      { name: 'log4j-core', ecosystem: 'Maven', version: '2.14.1' },
      'invalid_maven_name',
      'groupId:artifactId',
    ],
  ] as const)('surfaces actionable coordinate errors for %j', async (input, reason, hint) => {
    const bodies = captureOsvQueries([]);
    initOsvApiService();
    const reply = await runToolContract(osvQueryPackage, input);
    expect(reply.structuredContent).toMatchObject({
      error: { data: { reason, recovery: { hint: expect.stringContaining(hint) } } },
    });
    expect(JSON.stringify(reply.content)).toContain(hint);
    expect(bodies).toEqual([]);
  });

  it('explains indexed and fallback ecosystem rejections at their original batch rows', async () => {
    const native = vi.fn().mockImplementation(() =>
      Promise.resolve(
        Response.json(
          {
            code: 3,
            message:
              'error in query at index 0: rpc error: code = InvalidArgument desc = invalid ecosystem',
          },
          { status: 400 },
        ),
      ),
    );
    const single = vi.fn((query: { package: { ecosystem: string } }) =>
      Promise.resolve(
        query.package.ecosystem === 'PyPI'
          ? Response.json({})
          : Response.json({ code: 3, message: 'invalid ecosystem' }, { status: 400 }),
      ),
    );
    vi.stubGlobal(
      'fetch',
      vi.fn((url: string, init?: RequestInit) => {
        const body = JSON.parse(String(init?.body));
        return new URL(url).pathname === '/v1/querybatch' ? native(body) : single(body);
      }),
    );
    initOsvApiService();
    const packages = [
      { purl: 'broken' },
      { name: 'a', ecosystem: 'Unlisted-One', version: '1' },
      { name: 'b', ecosystem: 'Unlisted-Two', version: '1' },
      { name: 'c', ecosystem: 'pypi', version: '1' },
    ];
    const batch = await runToolContract(osvQueryBatch, { packages });
    expect(batch.structuredContent).toMatchObject({
      summary: { errorRows: [0, 1, 2], cleanCount: 1 },
      results: [
        { error: expect.stringContaining('Malformed PURL') },
        {
          error:
            'Ecosystem "Unlisted-One" is not recognized by OSV. Call osv_list_ecosystems to see valid ecosystem strings, then retry with the correct value.',
        },
        {
          error:
            'Ecosystem "Unlisted-Two" is not recognized by OSV. Call osv_list_ecosystems to see valid ecosystem strings, then retry with the correct value.',
        },
        { ecosystem: 'PyPI', error: null },
      ],
    });
    expect(JSON.stringify(batch.content)).toContain('Call osv_list_ecosystems');
    expect(native).toHaveBeenCalledTimes(2);
    expect(
      native.mock.calls.map(([body]) =>
        body.queries.map((row: { package: { ecosystem: string } }) => row.package.ecosystem),
      ),
    ).toEqual([
      ['Unlisted-One', 'Unlisted-Two', 'PyPI'],
      ['Unlisted-Two', 'PyPI'],
    ]);
    expect(single).toHaveBeenCalledTimes(2);
  });

  it('uses the Alpine release coordinate across batch continuation and advisory field retrieval', async () => {
    const purl = 'pkg:apk/alpine/openssl?distro=v3.17.3';
    const input = { purl, version: '3.0.8-r0' };
    const query = {
      package: { name: 'openssl', ecosystem: 'Alpine:v3.17' },
      version: input.version,
    };
    const record = {
      id: 'ALPINE-CVE-2023-0464',
      affected: ['Alpine:v3.18', 'Alpine:v3.17'].map((ecosystem, index) => ({
        package: { name: 'openssl', ecosystem },
        ranges: [
          {
            type: 'ECOSYSTEM',
            events: [{ introduced: '0' }, { fixed: index ? '3.0.8-r1' : '3.1.0-r1' }],
          },
        ],
      })),
    };
    const fetchMock = vi.fn((url: string | URL, init?: RequestInit) => {
      const path = new URL(String(url)).pathname;
      if (path === '/v1/querybatch') {
        expect(JSON.parse(String(init?.body))).toEqual({ queries: [query] });
        return Promise.resolve(Response.json({ results: [{ next_page_token: 'next' }] }));
      }
      if (path === '/v1/query') {
        expect(JSON.parse(String(init?.body))).toEqual({ ...query, page_token: 'next' });
        return Promise.resolve(Response.json({ vulns: [record] }));
      }
      expect(path).toBe(`/v1/vulns/${record.id}`);
      return Promise.resolve(Response.json(record));
    });
    vi.stubGlobal('fetch', fetchMock);
    initOsvApiService({ maxQueryPages: 1 });
    const invalid = { purl: 'pkg:apk/alpine/openssl@3.0.8-r0' };
    const batch = await runToolContract(osvQueryBatch, { packages: [invalid, input] });
    const batchValue = osvQueryBatch.output.parse(batch.structuredContent);
    expect(batchValue.summary).toMatchObject({ errorRows: [0], truncatedRows: [1] });
    expect(batchValue.results).toMatchObject([
      { purl: invalid.purl, error: expect.stringContaining('Alpine:v<major>.<minor>') },
      { purl, ecosystem: 'Alpine:v3.17', truncated: true },
    ]);
    expect(JSON.stringify(batch.content)).toContain('Alpine:v3.17');
    const cursor = batchValue.results![1]!.nextCursor!;
    const resumed = await runToolContract(osvQueryPackage, { ...input, cursor });
    expect(resumed.structuredContent).toMatchObject({
      queryMeta: { purl, ecosystem: 'Alpine:v3.17' },
      vulns: [{ fixedVersions: ['3.0.8-r1'] }],
    });
    expect(JSON.stringify(resumed.content)).toContain('Fixed in 3.0.8-r1');
    const field = await runToolContract(osvQueryPackage, {
      ...input,
      cursor,
      page: { advisoryId: record.id, path: '/fixedVersions' },
    });
    expect(field.structuredContent).toMatchObject({ page: { entries: [{ value: '3.0.8-r1' }] } });
    expect(JSON.stringify(field.content)).toContain('3.0.8-r1');
    const stale = await runToolContract(osvQueryPackage, {
      ...input,
      purl: 'pkg:apk/alpine/openssl?distro=v3.18',
      cursor,
    });
    expect(stale.isError).toBe(true);
    expect(fetchMock).toHaveBeenCalledTimes(3);
  });

  it('scopes Composer fixes to the PURL repository while forwarding its wire identity', async () => {
    const purl = 'pkg:composer/guzzlehttp/guzzle?repository_url=https%3A%2F%2Fexample.org%2FRepo';
    const ecosystem = 'Packagist:https://example.org/Repo';
    const input = { purl, version: '7.4.0' };
    const record = {
      id: 'OSV-composer',
      affected: ['Packagist', ecosystem].map((scope, index) => ({
        package: { name: 'guzzlehttp/guzzle', ecosystem: scope },
        ranges: [
          {
            type: 'ECOSYSTEM' as const,
            events: [{ introduced: '0' }, { fixed: index ? '7.4.1' : '8.0.0' }],
          },
        ],
        severity: [{ type: 'Ubuntu', score: index ? 'low' : 'critical' }],
      })),
    };
    const bodies = captureOsvQueries([record]);
    initOsvApiService();
    const single = await runToolContract(osvQueryPackage, input);
    expect(single.structuredContent).toMatchObject({
      queryMeta: { purl, ecosystem, package: 'guzzlehttp/guzzle' },
      vulns: [{ fixedVersions: ['7.4.1'], severityLabel: 'LOW' }],
    });
    expect(JSON.stringify(single.content)).toContain('Fixed in 7.4.1');
    const batch = await runToolContract(osvQueryBatch, { packages: [input] });
    expect(batch.structuredContent).toMatchObject({
      results: [{ purl, ecosystem, vulns: [{ fixedVersions: ['7.4.1'], severityLabel: 'LOW' }] }],
    });
    expect(JSON.stringify(batch.content)).toContain('7.4.1');
    const field = await runToolContract(osvQueryPackage, {
      ...input,
      page: { advisoryId: record.id, path: '/fixedVersions' },
    });
    expect(field.structuredContent).toMatchObject({ page: { entries: [{ value: '7.4.1' }] } });
    expect(bodies).toEqual([
      { package: { purl }, version: '7.4.0' },
      { package: { purl }, version: '7.4.0' },
    ]);
  });
  it.each([
    ['npm', 'npm'],
    ['crates.io', 'cargo'],
  ])(
    'normalizes embedded and separate %s PURL pins through both query tools',
    async (ecosystem, type) => {
      const bodies = captureOsvQueries([]);
      initOsvApiService();
      const embedded = `pkg:${type}/example@%3D1.2.3`;
      const versionless = `pkg:${type}/example`;
      const inputs = [{ purl: embedded }, { purl: versionless, version: '==1.2.3' }];
      for (const input of inputs) {
        const reply = await runToolContract(osvQueryPackage, input);
        expect(reply.structuredContent).toMatchObject({
          queryMeta: { purl: input.purl, ecosystem, version: '1.2.3' },
          vulns: [],
        });
        expect(JSON.stringify(reply.content)).toContain('1.2.3');
      }
      const batch = await runToolContract(osvQueryBatch, { packages: inputs });
      expect(osvQueryBatch.output.parse(batch.structuredContent).results).toMatchObject([
        { purl: embedded, version: '1.2.3', error: null },
        { purl: versionless, version: '1.2.3', error: null },
      ]);
      expect(JSON.stringify(batch.content)).toContain('1.2.3');
      expect(bodies).toEqual([
        { package: { purl: `pkg:${type}/example@1.2.3` } },
        { package: { purl: versionless }, version: '1.2.3' },
        { package: { purl: `pkg:${type}/example@1.2.3` } },
        { package: { purl: versionless }, version: '1.2.3' },
      ]);
    },
  );
  it.each([
    ['NuGet', 'Newtonsoft.Json', 'newtonsoft.json', 'nuget'],
    ['crates.io', 'crossbeam-utils', 'CROSSBEAM_UTILS', 'cargo'],
  ])(
    'preserves registry aliases through tuple, PURL, batch and advisory retrieval for %s',
    async (ecosystem, name, alias, type) => {
      const raw = {
        id: 'OSV-alias',
        affected: [
          {
            package: { name, ecosystem },
            severity: [{ type: 'Ubuntu', score: 'high' }],
            ranges: [
              { type: 'ECOSYSTEM' as const, events: [{ introduced: '0' }, { fixed: '2.0.0' }] },
            ],
          },
        ],
      };
      captureOsvQueries([raw]);
      initOsvApiService();
      const inputs = [
        { name: alias, ecosystem, version: '1.0.0' },
        { purl: `pkg:${type}/${alias}@1.0.0` },
      ];
      for (const input of inputs) {
        const reply = await runToolContract(osvQueryPackage, input);
        expect(reply.structuredContent).toMatchObject({
          queryMeta: { package: alias },
          vulns: [{ fixedVersions: ['2.0.0'], severityLabel: 'HIGH' }],
        });
        expect(JSON.stringify(reply.content)).toContain('Fixed in 2.0.0');
        const page = await runToolContract(osvQueryPackage, {
          ...input,
          page: { advisoryId: raw.id, path: '/fixedVersions' },
        });
        expect(
          osvQueryPackage.output
            .parse(page.structuredContent)
            .page!.entries!.map((entry) => entry.value),
        ).toEqual(['2.0.0']);
        expect(JSON.stringify(page.content)).toContain('2.0.0');
      }
      const batch = await runToolContract(osvQueryBatch, { packages: inputs });
      expect(osvQueryBatch.output.parse(batch.structuredContent).results).toMatchObject([
        { name: alias, vulns: [{ fixedVersions: ['2.0.0'], severityLabel: 'HIGH' }] },
        { vulns: [{ fixedVersions: ['2.0.0'], severityLabel: 'HIGH' }] },
      ]);
      expect(JSON.stringify(batch.content)).toContain('2.0.0');
    },
  );

  it('rejects invalid tuple and encoded PURL versions before fetch with recovery on both surfaces', async () => {
    initOsvApiService();
    const fetchMock = vi.fn(() => Promise.resolve(Response.json({})));
    vi.stubGlobal('fetch', fetchMock);
    for (const input of [
      { name: 'lodash', ecosystem: 'npm', version: '^4.17.20' },
      { purl: 'pkg:npm/lodash@%5E4.17.20' },
    ]) {
      const reply = await runToolContract(osvQueryPackage, input);
      expect(reply.isError).toBe(true);
      expect(reply.structuredContent).toMatchObject({
        error: {
          data: {
            reason: 'invalid_version',
            recovery: { hint: expect.stringContaining('lockfile') },
          },
        },
      });
      expect(JSON.stringify(reply.content)).toContain('lockfile');
    }
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('normalizes exact pins on metadata, tuple and PURL wire requests and isolates rejected batch rows', async () => {
    const bodies = captureOsvQueries([]);
    initOsvApiService();
    const purl = 'pkg:npm/lodash@%3D%3D4.17.20';
    const pinned = await runToolContract(osvQueryPackage, { purl });
    expect(pinned.structuredContent).toMatchObject({
      queryMeta: { purl, version: '4.17.20' },
      vulns: [],
    });
    expect(JSON.stringify(pinned.content)).toContain(purl);
    expect(bodies[0]).toEqual({ package: { purl: 'pkg:npm/lodash@4.17.20' } });
    const tuple = { name: 'lodash', ecosystem: 'npm', version: '^4.17.20' };
    const reply = await runToolContract(osvQueryBatch, {
      packages: [tuple, { ...tuple, version: '=4.17.20' }, { purl }],
    });
    expect(osvQueryBatch.output.parse(reply.structuredContent)).toMatchObject({
      summary: { errorCount: 1, cleanCount: 2 },
      results: [
        { ...tuple, error: expect.stringContaining('lockfile') },
        { name: 'lodash', version: '4.17.20', error: null },
        { purl, version: '4.17.20', error: null },
      ],
    });
    expect(JSON.stringify(reply.content)).toContain('lockfile');
    expect(bodies.slice(1)).toEqual([
      { package: { name: 'lodash', ecosystem: 'npm' }, version: '4.17.20' },
      { package: { purl: 'pkg:npm/lodash@4.17.20' } },
    ]);
  });
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
    ['pkg:npm/%40scope/example@1.0.0', '@scope/example', 'npm'],
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
    const tupleReply = await runToolContract(osvQueryPackage, {
      name,
      ecosystem,
      version: ecosystem === 'npm' ? '1.0.0' : '1',
    });
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
    const original = { purl: 'pkg:npm/example@99.0.0' };
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
