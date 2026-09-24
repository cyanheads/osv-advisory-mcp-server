/**
 * @fileoverview Tests for the affected-entry matcher — which OSV `affected[]` entries
 * belong to a queried package, mirroring how OSV.dev indexes entries for /v1/query.
 * @module tests/services/affected-match.test
 */

import { describe, expect, it } from 'vitest';
import { matchesQueriedPackage } from '@/services/osv-api/affected-match.js';

describe('matchesQueriedPackage', () => {
  it('matches an identical name and ecosystem', () => {
    expect(
      matchesQueriedPackage(
        { name: 'lodash', ecosystem: 'npm' },
        { name: 'lodash', ecosystem: 'npm' },
      ),
    ).toBe(true);
  });

  it('rejects another package in the same ecosystem', () => {
    expect(
      matchesQueriedPackage(
        { name: 'gzip', ecosystem: 'Ubuntu:22.04:LTS' },
        { name: 'xz-utils', ecosystem: 'Ubuntu:22.04:LTS' },
      ),
    ).toBe(false);
  });

  it.each([
    ['Debian', 'Debian:12', true],
    ['Debian', 'Debian:13', true],
    ['Debian:12', 'Debian:13', false],
    ['Debian:12', 'Debian', false],
    ['Ubuntu:22.04', 'Ubuntu:22.04:LTS', true],
    ['Ubuntu:22.04:LTS', 'Ubuntu:22.04:LTS', true],
    ['Ubuntu', 'Ubuntu:22.04:LTS', true],
    ['Ubuntu:18.04', 'Ubuntu:Pro:18.04:LTS', true],
    ['Ubuntu:Pro:18.04', 'Ubuntu:Pro:18.04:LTS', false],
    ['Ubuntu:22.04', 'Ubuntu:Pro:14.04:LTS', false],
    ['Alpine', 'Alpine:v3.15', true],
    ['Alpine:v3.16', 'Alpine:v3.15', false],
    ['npm', 'PyPI', false],
  ])('queried ecosystem %s vs entry ecosystem %s → %s', (queried, entry, expected) => {
    expect(
      matchesQueriedPackage({ name: 'pkg', ecosystem: entry }, { name: 'pkg', ecosystem: queried }),
    ).toBe(expected);
  });

  it.each([
    ['PyYAML', 'pyyaml', 'PyPI', true],
    ['python_multipart', 'python-multipart', 'PyPI', true],
    ['Zope.Interface', 'zope-interface', 'PyPI', true],
    ['Django', 'django', 'Echo:PyPI', true],
    ['Lodash', 'lodash', 'npm', false],
    ['newtonsoft.json', 'Newtonsoft.Json', 'NuGet', false],
    ['log4j_core', 'log4j-core', 'Maven', false],
  ])('queried name %s vs entry name %s in %s → %s', (queried, entry, ecosystem, expected) => {
    expect(matchesQueriedPackage({ name: entry, ecosystem }, { name: queried, ecosystem })).toBe(
      expected,
    );
  });

  it('never matches a package-less entry', () => {
    expect(matchesQueriedPackage(undefined, { name: 'lodash', ecosystem: 'npm' })).toBe(false);
    expect(matchesQueriedPackage({}, { name: 'lodash', ecosystem: 'npm' })).toBe(false);
  });
});
