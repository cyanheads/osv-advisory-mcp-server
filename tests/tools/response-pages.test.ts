/**
 * @fileoverview Completeness and size accounting for shared overflow responses.
 * @module tests/tools/response-pages.test
 */
import { describe, expect, it } from 'vitest';
import {
  boundResponse,
  RESPONSE_BYTES,
  RetrievalOutput,
  renderRetrieval,
  wireMeasure,
} from '@/mcp-server/tools/response-pages.js';

const measure = wireMeasure(renderRetrieval);

describe('boundResponse', () => {
  it('returns a fitting response unchanged', () => {
    const full = { id: 'OSV-TEST', details: 'Complete details.' };
    expect(boundResponse(full, measure, { id: full.id })).toBe(full);
  });

  it('retains complete top-level fields and omits source collections without a preview', () => {
    const summary = { totalPackages: 1 };
    const result = boundResponse({ results: ['x'.repeat(30000)], summary }, measure, undefined, {
      summary,
    });
    expect(result.summary).toEqual({ totalPackages: 1 });
    expect(RetrievalOutput.parse(result).overflow).toMatchObject({
      complete: ['summary'],
      omitted: [{ path: '/results', type: 'array', total: 1 }],
      page: { path: '', offset: 0 },
    });
  });

  it('classifies complete preview values without treating helper fields or projections as complete', () => {
    const source = {
      vulns: [{ id: 'OSV-TEST', details: 'x'.repeat(30000) }],
      truncated: false,
      queryMeta: { package: 'example', vulnCount: 1 },
    };
    const preview = {
      vulns: [{ id: 'OSV-TEST' }],
      truncated: false,
      queryMeta: { vulnCount: 1, package: 'example' },
      advisoryListComplete: true,
    };
    const result = RetrievalOutput.parse(boundResponse(source, measure, preview));
    expect(result.preview).toEqual(preview);
    expect(result.overflow).toMatchObject({
      complete: ['truncated', 'queryMeta'],
      omitted: [{ path: '/vulns', type: 'array', total: 1 }],
      page: { path: '', offset: 0 },
    });
    const content = renderRetrieval(result)
      .map((block) => block.text)
      .join('\n');
    expect(content).toContain('"complete":["truncated","queryMeta"]');
    expect(content).toContain('"omitted":[{"path":"/vulns","type":"array","total":1}]');
    expect(measure(result)).toBeLessThanOrEqual(RESPONSE_BYTES);
  });

  it('keeps partial objects and arrays omitted with their original totals', () => {
    const source = { array: [1, 2], object: { a: 1, b: 2 }, details: 'x'.repeat(30000) };
    const result = RetrievalOutput.parse(
      boundResponse(source, measure, { array: [1], object: { a: 1 } }),
    );
    expect(result.overflow).toMatchObject({
      complete: [],
      omitted: [
        { path: '/array', type: 'array', total: 2 },
        { path: '/object', type: 'object', total: 2 },
        { path: '/details', type: 'string', total: 30000 },
      ],
    });
  });

  it('recognizes full advisory preview arrays and nulls without changing retained names', () => {
    const source = {
      id: 'OSV-TEST',
      summary: 'Advisory summary',
      aliases: ['CVE-2026-1234'],
      severityLabel: null,
      details: 'x'.repeat(30000),
    };
    const preview = {
      id: 'OSV-TEST',
      summary: 'Advisory summary',
      aliases: ['CVE-2026-1234'],
      severityLabel: null,
    };
    const result = RetrievalOutput.parse(boundResponse(source, measure, preview));
    expect(result.overflow).toMatchObject({
      complete: ['id', 'summary', 'aliases', 'severityLabel'],
      omitted: [{ path: '/details', type: 'string', total: 30000 }],
    });
    expect(result.preview).toEqual(preview);
  });

  it('restores all preview-only values to omitted when the preview cannot fit', () => {
    const source = { id: 'OSV-TEST', summary: 'x'.repeat(30000), aliases: ['CVE-2026-1234'] };
    const result = RetrievalOutput.parse(boundResponse(source, measure, { ...source }));
    expect(result.preview).toBeUndefined();
    expect(result.overflow).toMatchObject({
      complete: [],
      omitted: [
        { path: '/id', type: 'string', total: 8 },
        { path: '/summary', type: 'string', total: 30000 },
        { path: '/aliases', type: 'array', total: 1 },
      ],
    });
    expect(measure(result)).toBeLessThanOrEqual(RESPONSE_BYTES);
  });

  it('measures completeness metadata with a near-ceiling surviving preview', () => {
    const source = { summary: 'x'.repeat(11500), details: 'y'.repeat(30000) };
    const result = RetrievalOutput.parse(
      boundResponse(source, measure, { summary: source.summary }),
    );
    expect(result.preview).toEqual({ summary: source.summary });
    expect(result.overflow).toMatchObject({
      complete: ['summary'],
      omitted: [{ path: '/details', type: 'string', total: 30000 }],
    });
    expect(measure(result)).toBeLessThanOrEqual(RESPONSE_BYTES);
  });
});
