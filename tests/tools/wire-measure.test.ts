/**
 * @fileoverview Compare bounded-response accounting with the framework wire assembler.
 * @module tests/tools/wire-measure.test
 */
import { tool, z } from '@cyanheads/mcp-ts-core';
import { runToolContract } from '@cyanheads/mcp-ts-core/testing';
import { describe, expect, it } from 'vitest';
import { callerCode, renderCallerNotice } from '@/mcp-server/tools/render-escape.js';
import { wireMeasure } from '@/mcp-server/tools/response-pages.js';
import { scanMarkdown } from '../helpers/markdown.js';

describe('wireMeasure', () => {
  it.each([
    '<i>x</i> [next](https://example.test)',
    'a`b',
    'line one\n\nline two\n',
    'one\r\ntwo\rthree',
  ])('matches a literal notice renderer for %j', async (notice) => {
    const enrichment = { notice };
    const payload = { preview: { matched: false } };
    const format = () => [{ type: 'text' as const, text: 'Result' }];
    const definition = tool('literal_notice_fixture', {
      description: 'Return a caller-bearing notice for measurement.',
      input: z.object({}),
      output: z.object({
        preview: z.object({ matched: z.boolean().describe('Match status.') }).describe('Preview.'),
      }),
      enrichment: { notice: z.string().describe('Notice.') },
      enrichmentTrailer: { notice: { render: renderCallerNotice } },
      handler: async (_input, ctx) => {
        ctx.enrich.notice(notice);
        return payload;
      },
      format,
    });
    const reply = await runToolContract(definition, {});
    expect(reply.isError).not.toBe(true);
    expect(wireMeasure(format, enrichment, renderCallerNotice)(payload)).toBe(
      Buffer.byteLength(JSON.stringify(reply)),
    );
    expect(reply.structuredContent).toMatchObject(enrichment);
    expect(
      scanMarkdown(
        reply.content.map((block) => (block.type === 'text' ? block.text : '')).join('\n'),
      ).links,
    ).toEqual([]);
  });

  it.each(['plain', 'a`b', 'one\ntwo', 'one\n\ntwo\n', 'one\r\ntwo\rthree'])(
    'round-trips coordinate code literals and line breaks for %j',
    (value) => {
      const parsed = scanMarkdown(`Coordinate: ${callerCode(value)} end`);
      expect(parsed.literalText).toBe(`Coordinate: ${value.replace(/\r\n?/g, '\n')} end`);
      expect(parsed.links).toEqual([]);
      expect(parsed.html).toEqual([]);
    },
  );
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
