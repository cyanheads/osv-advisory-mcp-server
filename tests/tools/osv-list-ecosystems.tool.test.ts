/**
 * @fileoverview Tests for osv_list_ecosystems tool.
 * @module tests/tools/osv-list-ecosystems.tool.test
 */

import { createMockContext } from '@cyanheads/mcp-ts-core/testing';
import { describe, expect, it } from 'vitest';
import {
  osvListEcosystems,
  SUPPORTED_ECOSYSTEMS,
} from '@/mcp-server/tools/definitions/osv-list-ecosystems.tool.js';

describe('osvListEcosystems', () => {
  it('returns all supported ecosystems', async () => {
    const ctx = createMockContext();
    const result = await osvListEcosystems.handler({}, ctx);
    expect(result.ecosystems).toHaveLength(SUPPORTED_ECOSYSTEMS.length);
    expect(result.ecosystems).toContain('npm');
    expect(result.ecosystems).toContain('PyPI');
    expect(result.ecosystems).toContain('crates.io');
    expect(result.ecosystems).toContain('Go');
    expect(result.ecosystems).toContain('Maven');
  });

  it('includes the advisory note field', async () => {
    const ctx = createMockContext();
    const result = await osvListEcosystems.handler({}, ctx);
    expect(result.note).toBeTruthy();
    expect(result.note.length).toBeGreaterThan(10);
  });

  it('does not include incorrect ecosystem strings', async () => {
    const ctx = createMockContext();
    const result = await osvListEcosystems.handler({}, ctx);
    // pypi (lowercase) is not valid — the correct value is PyPI
    expect(result.ecosystems).not.toContain('pypi');
    expect(result.ecosystems).not.toContain('NPM');
    // #12: GSD is an OSV vulnerability-ID prefix, not an ecosystem — OSV rejects it.
    expect(result.ecosystems).not.toContain('GSD');
  });

  it('pins the canonical OSV ecosystem set — 49 named + GIT, GSD absent (#12)', async () => {
    const ctx = createMockContext();
    const result = await osvListEcosystems.handler({}, ctx);
    // Drift-catcher: the count is fixed to the OSV schema's ecosystemName enum (49) plus GIT.
    // When OSV adds an ecosystem, update SUPPORTED_ECOSYSTEMS and this number together.
    expect(result.ecosystems).toHaveLength(50);
    // A representative slice of the canonical set — including the ones the stale list omitted.
    for (const eco of [
      'AlmaLinux',
      'Alpaquita',
      'Azure Linux',
      'Ubuntu',
      'FreeBSD',
      'Kubernetes',
      'Red Hat',
      'VSCode',
      'npm',
      'PyPI',
      'crates.io',
      'GIT',
    ]) {
      expect(result.ecosystems).toContain(eco);
    }
    // GSD must never reappear.
    expect(result.ecosystems).not.toContain('GSD');
  });

  it('formats output with ecosystem list', () => {
    const output = {
      ecosystems: ['npm', 'PyPI', 'crates.io'],
      note: 'Test note.',
    };
    const blocks = osvListEcosystems.format!(output);
    const text = (blocks[0] as { text: string }).text;
    expect(text).toContain('npm');
    expect(text).toContain('PyPI');
    expect(text).toContain('crates.io');
    expect(text).toContain('Test note.');
  });
});
