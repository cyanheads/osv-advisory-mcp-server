/**
 * @fileoverview Guard dependency runtime files against MCPB documentation pruning.
 * @module tests/scripts/mcpb-runtime.test
 */
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { createInterface } from 'node:readline';
import { describe, expect, it } from 'vitest';
import manifest from '../../manifest.json' with { type: 'json' };
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

describe('MCPB batch option', () => {
  it.each([
    [manifest.server.mcp_config.env.OSV_BATCH_SERVE_OVER_CAP, 5000],
    ['false', 1000],
  ])('uses bundle option %s to advertise maximum %i through stdio', async (setting, maximum) => {
    expect(manifest.user_config.OSV_BATCH_SERVE_OVER_CAP).toMatchObject({
      type: 'boolean',
      default: true,
      required: false,
    });
    expect(manifest.server.mcp_config.env.OSV_BATCH_SERVE_OVER_CAP).toBe(
      `\${user_config.OSV_BATCH_SERVE_OVER_CAP}`,
    );
    const child = spawn('bun', ['run', 'src/index.ts'], {
      env: {
        ...process.env,
        ...manifest.server.mcp_config.env,
        OSV_BATCH_SERVE_OVER_CAP: setting,
        OTEL_ENABLED: 'false',
      },
      stdio: ['pipe', 'pipe', 'ignore'],
      timeout: 4500,
    });
    const closed = once(child, 'close');
    const lines = createInterface({ input: child.stdout });
    const send = (message: object) =>
      child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', ...message })}\n`);
    try {
      send({
        id: 1,
        method: 'initialize',
        params: {
          protocolVersion: '2025-11-25',
          capabilities: {},
          clientInfo: { name: 'bundle-test', version: '1.0.0' },
        },
      });
      for await (const line of lines) {
        const response = JSON.parse(line);
        if (response.id === 1) {
          expect(response.error).toBeUndefined();
          send({ method: 'notifications/initialized' });
          send({ id: 2, method: 'tools/list' });
        }
        if (response.id === 2) {
          expect(
            Object.fromEntries(
              response.result.tools.map(
                (tool: { name: string; annotations: { openWorldHint: boolean } }) => [
                  tool.name,
                  tool.annotations.openWorldHint,
                ],
              ),
            ),
          ).toEqual({
            osv_list_ecosystems: false,
            osv_query_package: true,
            osv_query_batch: true,
            osv_query_commit: true,
            osv_get_vulnerability: true,
          });
          expect(response.result?.tools).toContainEqual(
            expect.objectContaining({
              name: 'osv_query_batch',
              inputSchema: expect.objectContaining({
                properties: expect.objectContaining({
                  packages: expect.objectContaining({ maxItems: maximum }),
                }),
              }),
            }),
          );
          return;
        }
      }
      throw new Error('The stdio process closed before advertising its tools.');
    } finally {
      lines.close();
      child.kill();
      await closed;
    }
  });
});
