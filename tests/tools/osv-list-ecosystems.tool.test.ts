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

  it('pins the catalog — 51 accepted schema names + GIT, Red Hat Lightwell and GSD absent (#12)', async () => {
    const ctx = createMockContext();
    const result = await osvListEcosystems.handler({}, ctx);
    // Offline guard: the count is the schema's ecosystemName members OSV.dev accepts (51) plus GIT.
    // `bun run check:ecosystems` reports upstream drift; update SUPPORTED_ECOSYSTEMS and this number together.
    expect(result.ecosystems).toHaveLength(52);
    expect(new Set(result.ecosystems).size).toBe(result.ecosystems.length);
    // A representative slice of the catalog — including the entries earlier lists omitted.
    for (const eco of [
      'AlmaLinux',
      'Alpaquita',
      'Azure Linux',
      'Ubuntu',
      'FreeBSD',
      'Homebrew',
      'Kubernetes',
      'Red Hat',
      'VSCode',
      'WordPress',
      'npm',
      'PyPI',
      'crates.io',
      'GIT',
    ]) {
      expect(result.ecosystems).toContain(eco);
    }
    // In the schema but rejected by POST /v1/query — withheld until OSV.dev accepts it.
    expect(result.ecosystems).not.toContain('Red Hat Lightwell');
    // GSD is a vulnerability-ID prefix, not an ecosystem, and must never reappear.
    expect(result.ecosystems).not.toContain('GSD');
  });

  it('states the catalog rule and one verification date in the note and the description', async () => {
    const result = await osvListEcosystems.handler({}, createMockContext());
    const dates = [result.note, osvListEcosystems.description].map(
      (text) => text.match(/\d{4}-\d{2}-\d{2}/g) ?? [],
    );
    expect(dates[0]).toHaveLength(1);
    expect(dates[1]).toEqual(dates[0]);
    for (const text of [result.note, osvListEcosystems.description]) {
      expect(text).toContain('GIT');
      expect(text).toMatch(/accept/i);
    }
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
