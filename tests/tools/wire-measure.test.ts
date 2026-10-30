/**
 * @fileoverview Compare bounded-response accounting with the framework wire assembler.
 * @module tests/tools/wire-measure.test
 */
import { tool, z } from '@cyanheads/mcp-ts-core';
import { runToolContract } from '@cyanheads/mcp-ts-core/testing';
import { describe, expect, it } from 'vitest';
import { wireMeasure } from '@/mcp-server/tools/response-pages.js';

describe('wireMeasure', () => {
  it.each(['pkg@1.0 (npm)', 'a`b', 'line one\nline two', ''])(
    'matches assembled enrichment bytes for %j',
    async (effectiveQuery) => {
      const enrichment = { notice: 'First line\n\nLast line', effectiveQuery };
      const payload = { preview: { matched: false } };
      const format = () => [{ type: 'text' as const, text: 'Result' }];
      const definition = tool('measure_fixture', {
        description: 'Return a fixture for wire measurement.',
        input: z.object({}),
        output: z.object({
          preview: z
            .object({ matched: z.boolean().describe('Match status.') })
            .describe('Preview.'),
        }),
        enrichment: {
          notice: z.string().describe('Notice.'),
          effectiveQuery: z.string().describe('Query.'),
        },
        handler: async (_input, ctx) => {
          ctx.enrich.notice(enrichment.notice);
          ctx.enrich.echo(enrichment.effectiveQuery);
          return payload;
        },
        format,
      });
      const reply = await runToolContract(definition, {});
      expect(reply.isError).not.toBe(true);
      expect(wireMeasure(format, enrichment)(payload)).toBe(
        Buffer.byteLength(JSON.stringify(reply)),
      );
      expect(reply.structuredContent).toMatchObject(enrichment);
    },
  );
});
