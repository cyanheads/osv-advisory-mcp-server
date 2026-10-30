/**
 * @fileoverview Guard dependency runtime files against MCPB documentation pruning.
 * @module tests/scripts/mcpb-runtime.test
 */
import { describe, expect, it } from 'vitest';
import { filterAgentDocEntries } from '../../scripts/clean-mcpb.js';
import { AGENT_DOC_ENTRY } from '../../scripts/lint-packaging.js';

describe('MCPB dependency documentation selectors', () => {
  it('keeps the SDK skill extension runtime in both cleaner and linter', () => {
    const runtime = [
      'node_modules/@modelcontextprotocol/server/dist/ext/skills/index.mjs',
      'node_modules/@modelcontextprotocol/server/dist/ext/skills/index.cjs',
      'node_modules/@modelcontextprotocol/server/dist/ext/skills/index.d.mts',
      'node_modules/parent/node_modules/@modelcontextprotocol/server/dist/ext/skills/index.mjs',
      'skills/osv-advisory-guide/SKILL.md',
    ];
    expect(filterAgentDocEntries(runtime)).toEqual([]);
    expect(runtime.filter((entry) => AGENT_DOC_ENTRY.test(entry))).toEqual([]);
  });

  it('still prunes package-root documentation trees and stray SKILL.md files', () => {
    const docs = [
      'node_modules/@cyanheads/mcp-ts-core/framework-skills/add-tool/SKILL.md',
      'node_modules/example/skills/guide/reference.md',
      'node_modules/parent/node_modules/@scope/example/skills/guide/reference.md',
      'node_modules/example/.claude/settings.json',
      'node_modules/example/.agents/guide.md',
      'node_modules/example/docs/SKILL.md',
    ];
    expect(filterAgentDocEntries(docs)).toEqual(docs);
    expect(docs.filter((entry) => AGENT_DOC_ENTRY.test(entry))).toEqual(docs);
  });
});
