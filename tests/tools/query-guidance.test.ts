/**
 * @fileoverview Regression coverage for caller-visible alias and paging guidance.
 * @module tests/tools/query-guidance.test
 */
import { readFileSync } from 'node:fs';
import { z } from '@cyanheads/mcp-ts-core';
import { describe, expect, it } from 'vitest';
import {
  osvGetVulnerability,
  osvQueryBatch,
  osvQueryPackage,
} from '@/mcp-server/tools/definitions/index.js';

describe('query guidance', () => {
  it('preserves alias chaining to the available NVD capabilities', () => {
    for (const [tool, path] of [
      [osvGetVulnerability, 'properties.aliases.description'],
      [osvQueryPackage, 'properties.vulns.items.properties.aliases.description'],
      [
        osvQueryBatch,
        'properties.results.items.properties.vulns.items.properties.aliases.description',
      ],
    ] as const) {
      expect(z.toJSONSchema(tool.output)).toHaveProperty(
        path,
        expect.stringMatching(/nist-nvd-mcp-server.*CVSS.*CISA KEV/),
      );
    }
  });

  it('never advertises EPSS as an NVD server capability', () => {
    for (const file of [
      'src/index.ts',
      'src/mcp-server/tools/definitions/osv-get-vulnerability.tool.ts',
      'src/mcp-server/tools/definitions/osv-query-package.tool.ts',
      'src/mcp-server/tools/definitions/osv-query-batch.tool.ts',
    ]) {
      expect(readFileSync(file, 'utf8')).not.toContain('EPSS');
    }
  });

  it('gives the complete paging request recipe on every tool', () => {
    for (const tool of [osvGetVulnerability, osvQueryPackage, osvQueryBatch]) {
      expect(tool.description).toContain('page: overflow.page');
      expect(tool.description).toContain('nextOffset');
      expect(tool.description).toContain('without a revision');
      expect(tool.description).toContain('output page');
      expect(tool.description).not.toContain('eligibility criteria');
    }
  });
});
