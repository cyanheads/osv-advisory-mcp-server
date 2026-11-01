/**
 * @fileoverview Exact-version resolution and wire identity tests.
 * @module tests/services/package-identifier.test
 */
import { describe, expect, it } from 'vitest';
import { matchesQueriedPackage } from '@/services/osv-api/affected-match.js';
import { packageBody, resolvePackage } from '@/services/osv-api/package-identifier.js';

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
    const input = { name: 'example', ecosystem, version };
    expect(resolvePackage(input)).toEqual(input);
    expect(packageBody(resolvePackage(input))).toEqual({
      package: { name: 'example', ecosystem },
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
