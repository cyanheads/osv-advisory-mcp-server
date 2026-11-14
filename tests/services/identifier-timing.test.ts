/**
 * @fileoverview Adversarial CPU growth checks for caller-sized PURLs and commit hashes.
 * @module tests/services/identifier-timing.test
 */
import { describe, expect, it } from 'vitest';
import { osvQueryCommit } from '@/mcp-server/tools/definitions/osv-query-commit.tool.js';
import { resolvePackage } from '@/services/osv-api/package-identifier.js';

describe('identifier timing', () => {
  it('bounds ecosystem, Maven and Alpine coordinate scans', () => {
    const cases = [
      (size: number) => ({ name: 'a', ecosystem: 'A'.repeat(size), version: '1' }),
      (size: number) => ({ name: `${'a'.repeat(size)}\n:g`, ecosystem: 'Maven', version: '1' }),
      (size: number) => ({ name: 'a\n'.repeat(size / 2), ecosystem: 'Maven', version: '1' }),
      (size: number) => ({ purl: `pkg:apk/alpine/a@1?distro=${'1'.repeat(size)}.1` }),
    ];
    const measure = (run: () => void) => {
      const start = process.threadCpuUsage();
      for (let i = 0; i < 16; i++) run();
      const { user, system } = process.threadCpuUsage(start);
      return (user + system) / 16;
    };
    for (const build of cases) {
      const run = (size: number) => {
        const input = build(size);
        return () => {
          try {
            resolvePackage(input);
          } catch (error) {
            expect(error).toMatchObject({ data: { reason: 'invalid_maven_name' } });
          }
        };
      };
      const base = run(5_000);
      for (const size of [10_000, 20_000, 40_000, 80_000, 160_000, 320_000]) {
        const sample = run(size);
        let leastGrowth = Number.POSITIVE_INFINITY;
        let leastCpu = Number.POSITIVE_INFINITY;
        for (let trial = 0; trial < 5; trial++) {
          const baseline = measure(base);
          const cpu = measure(sample);
          leastGrowth = Math.min(leastGrowth, cpu / baseline);
          leastCpu = Math.min(leastCpu, cpu);
        }
        expect(leastGrowth).toBeLessThan(4 * (size / 5_000));
        expect(leastCpu).toBeLessThan(50_000);
      }
    }
  }, 0);

  it('bounds parser and hash-check CPU across a 64-fold input span', () => {
    const measure = (run: () => void, repetitions: number) => {
      let best = Number.POSITIVE_INFINITY;
      for (let trial = 0; trial < 5; trial++) {
        const start = process.threadCpuUsage();
        for (let i = 0; i < repetitions; i++) run();
        const elapsed = process.threadCpuUsage(start);
        best = Math.min(best, (elapsed.user + elapsed.system) / repetitions);
      }
      return best;
    };
    for (const build of [
      (size: number) => `pkg:pypi/${'a'.repeat(size)}@1`,
      (size: number) => `pkg:golang/example.org/repo@1#${'a/'.repeat(size / 2)}`,
      (size: number) => `pkg:pypi/${'a'.repeat(size)}\n@1`,
      (size: number) => `pkg:pypi/${'a\n'.repeat(size / 2)}@1`,
      (size: number) => `pkg:pypi/a@1?${'q='.repeat(size / 2)}`,
    ]) {
      const run = (size: number) => {
        const input = build(size);
        expect(resolvePackage({ purl: input }).version).toBe('1');
        return () => {
          resolvePackage({ purl: input });
        };
      };
      const base = measure(run(5_000), 32);
      for (const size of [10_000, 20_000, 40_000, 80_000, 160_000, 320_000]) {
        const cpu = measure(run(size), 4);
        expect(cpu).toBeLessThan(500_000);
        expect(cpu / base).toBeLessThan(4 * (size / 5_000));
      }
    }
    for (const build of [
      (size: number) => 'a'.repeat(size),
      (size: number) => `${'a'.repeat(size)}\n`,
      (size: number) => 'a\n'.repeat(size / 2),
    ]) {
      const run = (size: number) => {
        const commit = build(size);
        expect(osvQueryCommit.input.safeParse({ commit }).success).toBe(false);
        return () => {
          osvQueryCommit.input.safeParse({ commit });
        };
      };
      const base = measure(run(5_000), 64);
      for (const size of [10_000, 20_000, 40_000, 80_000, 160_000, 320_000]) {
        const cpu = measure(run(size), 16);
        expect(cpu).toBeLessThan(50_000);
        expect(cpu / base).toBeLessThan(4 * (size / 5_000));
      }
    }
  }, 60000);
});
