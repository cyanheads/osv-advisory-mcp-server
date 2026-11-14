/**
 * @fileoverview Exact-version resolution and wire identity tests.
 * @module tests/services/package-identifier.test
 */
import { describe, expect, it } from 'vitest';
import { matchesQueriedPackage } from '@/services/osv-api/affected-match.js';
import { packageBody, resolvePackage } from '@/services/osv-api/package-identifier.js';

describe('OSV wire package coordinates', () => {
  it.each([
    { name: 'example', ecosystem: 'Debian', version: '1' },
    { name: 'example', ecosystem: 'Unlisted:Case:Sensitive', version: '1' },
    { name: 'example', ecosystem: 'Alpine:v3.17', version: '1-r0' },
    { name: 'g:a', ecosystem: 'Maven:https://maven.google.com', version: '1' },
  ])('retains the tuple for $ecosystem', ({ name, ecosystem, version }) => {
    expect(packageBody(resolvePackage({ name, ecosystem, version }))).toEqual({
      package: { name, ecosystem },
      version,
    });
  });

  it.each(['pkg:gradle/g/a@1', 'pkg:maven/g/a@1', 'pkg:deb/debian/a@1?distro=bullseye'])(
    'retains the native wire PURL for %s',
    (purl) => expect(packageBody(resolvePackage({ purl }))).toEqual({ package: { purl } }),
  );

  it.each([
    ['pypi', 'PyPI'],
    ['go', 'Go'],
    ['rubygems', 'RubyGems'],
    ['debian:11', 'Debian:11'],
    ['ubuntu:Pro:22.04:LTS', 'Ubuntu:Pro:22.04:LTS'],
  ])('canonicalizes %s', (ecosystem, canonical) => {
    expect(resolvePackage({ name: 'example', ecosystem, version: '1' }).ecosystem).toBe(canonical);
  });

  it('validates versions against the canonical ecosystem', () => {
    expect(() => resolvePackage({ name: 'example', ecosystem: 'pypi', version: '>=1' })).toThrow(
      expect.objectContaining({ data: expect.objectContaining({ reason: 'invalid_version' }) }),
    );
  });

  it.each([
    { purl: 'pkg:apk/alpine/openssl@3.0.8-r0?distro=3.17.3' },
    { purl: 'pkg:apk/alpine/openssl?distro=v3.17', version: '3.0.8-r0' },
  ])('uses an Alpine release tuple for $purl', (input) => {
    const resolved = resolvePackage(input);
    expect(resolved.purl).toBe(input.purl);
    expect(packageBody(resolved)).toEqual({
      package: { name: 'openssl', ecosystem: 'Alpine:v3.17' },
      version: '3.0.8-r0',
    });
  });

  it.each([
    [{ name: 'openssl', ecosystem: 'alpine', version: '3.0.8-r0' }, 'alpine_release_required'],
    [{ purl: 'pkg:apk/alpine/openssl@3.0.8-r0' }, 'alpine_release_required'],
    [{ purl: 'pkg:apk/alpine/openssl@3.0.8-r0?distro=edge' }, 'alpine_release_required'],
    [{ name: 'a', ecosystem: 'Maven', version: '1' }, 'invalid_maven_name'],
    [{ name: 'g/a:b', ecosystem: 'Maven', version: '1' }, 'invalid_maven_name'],
    [{ name: 'g:', ecosystem: 'Maven', version: '1' }, 'invalid_maven_name'],
    [{ purl: 'pkg:maven/a@1' }, 'invalid_purl'],
    [{ purl: 'pkg:gradle/a@1' }, 'invalid_maven_name'],
  ] as const)('rejects incomplete coordinates %j', (input, reason) => {
    expect(() => resolvePackage(input)).toThrow(
      expect.objectContaining({ data: expect.objectContaining({ reason }) }),
    );
  });

  it('normalizes Maven slash coordinates and preserves a repository suffix', () => {
    const ecosystem = 'Maven:https://maven.google.com';
    expect(packageBody(resolvePackage({ name: 'g/a', ecosystem, version: '1' }))).toEqual({
      package: { name: 'g:a', ecosystem },
      version: '1',
    });
  });

  it.each([
    ['pkg:composer/guzzlehttp/guzzle@7.4.0', 'Packagist'],
    [
      'pkg:composer/guzzlehttp/guzzle@7.4.0?repository_url=https%3A%2F%2Fexample.org%2FRepo',
      'Packagist:https://example.org/Repo',
    ],
  ])('derives the Composer matching coordinate and preserves %s on the wire', (purl, ecosystem) => {
    const resolved = resolvePackage({ purl });
    expect(resolved).toMatchObject({ name: 'guzzlehttp/guzzle', ecosystem, purl });
    expect(packageBody(resolved)).toEqual({ package: { purl } });
  });
});

describe('exact installed versions', () => {
  it.each([
    ['npm', '04.17.20'],
    ['npm', '4.17.20-01'],
    ['npm', '4.17.20-alpha.01'],
    ['crates.io', '00.7.0'],
    ['crates.io', '0.7.0-01'],
  ])('retains legacy %s exact version %s', (ecosystem, version) => {
    const input = { name: 'example', ecosystem, version };
    expect(resolvePackage(input)).toEqual(input);
    expect(packageBody(resolvePackage(input))).toEqual({
      package: { name: 'example', ecosystem },
      version,
    });
  });
  it.each([
    ['npm', '^4.17.20'],
    ['npm', '~4.17.20'],
    ['npm', '>=4.17.20'],
    ['npm', '4.17'],
    ['npm', '4.17.x'],
    ['npm', 'not-a-version'],
    ['npm', '1.0.0-..'],
    ['npm', '1.0.0\n'],
    ['crates.io', '1'],
    ['PyPI', '>=3.2.0'],
    ['PyPI', '===3.2.0'],
    ['RubyGems', '~> 6.1.0'],
    ['Maven', '[2.9.0,2.10)'],
    ['Maven', '(,1.0],[1.2,)'],
  ])('rejects %s constraint %s', (ecosystem, version) => {
    expect(() => resolvePackage({ name: 'example', ecosystem, version })).toThrow(
      expect.objectContaining({ data: expect.objectContaining({ reason: 'invalid_version' }) }),
    );
  });
  it.each(['npm', 'crates.io'])('normalizes exact pins for %s', (ecosystem) => {
    for (const version of ['=1.2.3', '==1.2.3']) {
      const resolved = resolvePackage({ name: 'example', ecosystem, version });
      expect(resolved.version).toBe('1.2.3');
      expect(packageBody(resolved)).toEqual({
        package: { name: 'example', ecosystem },
        version: '1.2.3',
      });
    }
  });
  it('normalizes the embedded PURL wire version while retaining the caller PURL', () => {
    const purl = 'pkg:npm/example@%3D%3D1.2.3?arch=source#child';
    const resolved = resolvePackage({ purl });
    expect(resolved).toMatchObject({ purl, version: '1.2.3' });
    expect(packageBody(resolved)).toEqual({
      package: { purl: 'pkg:npm/example@1.2.3?arch=source#child' },
    });
  });
  it.each([
    ['npm', 'v4.17.20'],
    ['npm', '1.0.0-alpha.1+build.42'],
    ['crates.io', '1.0.0-rc.1+build'],
    ['Debian', '1:2.36-9+deb12u4'],
    ['Debian', '1.0~rc1-1'],
    ['FreeBSD', '5.36.0_1,1'],
    ['PyPI', '1.0.post1'],
    ['Maven', '1.0-SNAPSHOT'],
    ['GIT', 'release/~nightly'],
  ])('preserves %s version %s', (ecosystem, version) => {
    const input = {
      name: ecosystem === 'Maven' ? 'example:example' : 'example',
      ecosystem,
      version,
    };
    expect(resolvePackage(input)).toEqual(input);
    expect(packageBody(resolvePackage(input))).toEqual({
      package: { name: input.name, ecosystem },
      version,
    });
  });
});

describe('linear version and name scans', () => {
  it.each(['plain', 'newline-ended', 'interspersed-newlines'])(
    'bounds %s caller text across a 64-fold span',
    (shape) => {
      const measure = (run: () => void) => {
        let best = Number.POSITIVE_INFINITY;
        for (let trial = 0; trial < 3; trial++) {
          const start = process.threadCpuUsage();
          let runs = 0;
          let elapsed = 0;
          do {
            run();
            runs++;
            const cpu = process.threadCpuUsage(start);
            elapsed = cpu.user + cpu.system;
          } while (elapsed < 5_000);
          best = Math.min(best, elapsed / runs);
        }
        return best;
      };
      let baseline = 0;
      for (const size of [5_000, 10_000, 20_000, 40_000, 80_000, 160_000, 320_000]) {
        const text =
          shape === 'plain'
            ? 'A_'.repeat(size / 2)
            : shape === 'newline-ended'
              ? `${'A_'.repeat(size / 2)}\n`
              : 'A_\n'.repeat(Math.floor(size / 3));
        const input = {
          name: text,
          ecosystem: 'npm',
          version: `1.0.0-${text.replaceAll('_', '-')}`,
        };
        const run = () => {
          if (shape === 'plain') resolvePackage(input);
          else {
            try {
              resolvePackage(input);
            } catch (error) {
              if (!(error instanceof Error)) throw error;
            }
          }
          matchesQueriedPackage(
            { name: text, ecosystem: 'crates.io' },
            { name: text, ecosystem: 'crates.io' },
          );
        };
        if (shape === 'plain') expect(resolvePackage(input).version).toBe(input.version);
        else
          expect(() => resolvePackage(input)).toThrow(
            expect.objectContaining({
              data: expect.objectContaining({ reason: 'invalid_version' }),
            }),
          );
        expect(
          matchesQueriedPackage(
            { name: text, ecosystem: 'crates.io' },
            { name: text, ecosystem: 'crates.io' },
          ),
        ).toBe(true);
        const start = process.threadCpuUsage();
        run();
        const cpu = process.threadCpuUsage(start);
        expect(cpu.user + cpu.system).toBeLessThan(50_000);
        const cost = measure(run);
        expect(cost).toBeLessThan(50_000);
        if (size === 5_000) baseline = cost;
        if (size === 320_000) expect(cost / baseline).toBeLessThan(256);
      }
    },
  );
});
