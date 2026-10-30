/**
 * @fileoverview Bounded dual-surface OSV responses and stateless JSON-Pointer retrieval.
 * @module mcp-server/tools/response-pages
 */
import { createHash } from 'node:crypto';
import { z } from '@cyanheads/mcp-ts-core';
import { validationError } from '@cyanheads/mcp-ts-core/errors';
import { MarkdownBuilder } from '@cyanheads/mcp-ts-core/utils';
import { escapeAdvisoryBlock } from './render-escape.js';

/** Combined UTF-8 ceiling, excluding the transport envelope. */
export const RESPONSE_BYTES = 24000;

/** Same-tool addressed retrieval; paths are bounded before any upstream work. */
export const PageInput = z
  .object({
    path: z
      .string()
      .max(1024)
      .regex(/^(?:\/(?:[^~]|~[01])*)?$/)
      .describe(
        'Field pointer announced by overflow or entries[].deferred.path; empty string selects the root. Keep the same path while following nextOffset.',
      ),
    offset: z
      .number()
      .int()
      .nonnegative()
      .default(0)
      .describe(
        'Start at zero; on later calls set this to the previous page.nextOffset until it is null. Text offsets count Unicode code points.',
      ),
    revision: z
      .string()
      .regex(/^[a-f0-9]{64}$/)
      .optional()
      .describe(
        'Use page.revision only when continuing the same path. Omit on the first call to any deferred child path; restart without it after stale_page_revision.',
      ),
  })
  .strict();

const NodeType = z.enum(['array', 'object', 'string', 'scalar']);
const Deferred = z
  .object({
    path: z.string().describe('Exact child pointer to retrieve separately.'),
    type: NodeType.describe('Child value kind.'),
    total: z.number().describe('Number of child entries or Unicode code points; one for scalars.'),
  })
  .describe('An oversized child; parent offset advances past this descriptor.');

/** Shared optional arms; each present arm is rendered independently. */
export const RetrievalOutput = z.object({
  preview: z
    .record(z.string(), z.unknown())
    .optional()
    .describe('Compact view; overflow identifies omissions. This is not the complete record.'),
  overflow: z
    .object({
      complete: z
        .array(z.string())
        .describe('Complete top-level fields retained in this response.'),
      omitted: z.array(Deferred).describe('Omitted values, all addressable through page.path.'),
      page: PageInput.describe(
        'Repeat the original tool input with page: overflow.page. Later select path, offset: page.nextOffset and revision: page.revision; do not pass the output page object.',
      ),
      notice: z.string().describe('Transmission omission and fresh re-fetch semantics.'),
    })
    .optional()
    .describe('Transmission overflow disclosure; independent of upstream truncation.'),
  page: z
    .object({
      path: z.string().describe('Addressed JSON pointer.'),
      type: NodeType.describe('Addressed value kind.'),
      offset: z.number().describe('Starting entry or code-point offset.'),
      total: z.number().describe('Total entries or Unicode code points.'),
      nextOffset: z
        .number()
        .nullable()
        .describe('Next offset, strictly greater or null when finished.'),
      revision: z
        .string()
        .describe(
          'SHA-256 revision of the addressed normalized node; batch collection uses original input order.',
        ),
      entries: z
        .array(
          z
            .object({
              key: z.string().describe('Object key or original array index.'),
              value: z.unknown().optional().describe('Complete child value, unmodified.'),
              deferred: Deferred.optional().describe(
                'Retrievable child descriptor when its value does not fit.',
              ),
            })
            .describe('One source entry, complete or deferred.'),
        )
        .optional()
        .describe('Source-order entries for arrays, objects and scalars.'),
      text: z.string().optional().describe('Verbatim Unicode code-point slice for strings.'),
      notice: z.string().describe('Fresh re-fetch disclosure; no saved historical snapshot.'),
    })
    .optional()
    .describe('One bounded page of an addressed normalized node.'),
});

export type PageRequest = z.infer<typeof PageInput>;
export type Retrieval = z.infer<typeof RetrievalOutput>;
type Content = Array<{ type: 'text'; text: string }>;
type Measure = (result: Retrieval & Record<string, unknown>) => number;

/** Hash normalized node bytes, without retaining cross-call state. */
export function nodeRevision(value: unknown): string {
  return createHash('sha256').update(JSON.stringify(value)).digest('hex');
}

/** Escape one JSON pointer component. */
export function childPointer(path: string, key: string): string {
  return `${path}/${key.replaceAll('~', '~0').replaceAll('/', '~1')}`;
}

function descriptor(path: string, value: unknown): z.infer<typeof Deferred> {
  const type =
    typeof value === 'string'
      ? 'string'
      : Array.isArray(value)
        ? 'array'
        : value !== null && typeof value === 'object'
          ? 'object'
          : 'scalar';
  const total =
    type === 'string'
      ? Array.from(String(value)).length
      : type === 'array'
        ? (value as unknown[]).length
        : type === 'object'
          ? Object.values(value as object).filter((child) => child !== undefined).length
          : 1;
  return { path, type, total };
}

/** Resolve own normalized properties only; prototype names never select inherited state. */
export function resolvePointer(root: unknown, path: string): unknown {
  let node = root;
  for (const token of path === '' ? [] : path.slice(1).split('/')) {
    const key = token.replaceAll('~1', '/').replaceAll('~0', '~');
    if (
      node === null ||
      typeof node !== 'object' ||
      !Object.hasOwn(node, key) ||
      (node as Record<string, unknown>)[key] === undefined ||
      (Array.isArray(node) && !/^(0|[1-9]\d*)$/.test(key))
    ) {
      const available =
        node !== null && typeof node === 'object'
          ? Object.keys(node)
              .slice(0, 12)
              .map((k) => k.slice(0, 60))
          : [];
      throw validationError('Unknown page path. Select an available parent field.', {
        reason: 'invalid_page_path',
        available,
      });
    }
    node = (node as Record<string, unknown>)[key];
  }
  return node;
}

/** Render all retrieval arms through the finite advisory boundary. */
export function renderRetrieval(result: Retrieval): Content {
  const blocks: Content = [];
  for (const key of ['preview', 'overflow', 'page'] as const) {
    if (key === 'preview' && result.preview && Array.isArray(result.preview.vulns)) {
      const { vulns, ...metadata } = result.preview;
      const rows = vulns.map((value) =>
        value !== null && typeof value === 'object'
          ? JSON.stringify(Object.values(value))
          : JSON.stringify(value),
      );
      blocks.push({
        type: 'text',
        text: `### preview\n<advisory_text>\n${escapeAdvisoryBlock(JSON.stringify(metadata))}\nAdvisories: id | aliases | severityLabel | fixedVersions\n${escapeAdvisoryBlock(rows.join('\n'))}\n</advisory_text>`,
      });
    } else if (result[key] !== undefined)
      blocks.push({
        type: 'text',
        text: `### ${key}\n<advisory_text>\n${escapeAdvisoryBlock(JSON.stringify(result[key]))}\n</advisory_text>`,
      });
  }
  return blocks;
}

/**
 * Mirror this server's framework success assembler, including the clean-path
 * notice/echo trailer. Tool contract tests compare this measurement to assembled results.
 */
export function wireMeasure(
  format: (result: Retrieval & Record<string, unknown>) => unknown[],
  enrichment: { notice?: string; effectiveQuery?: string } = {},
): Measure {
  return (result) => {
    const content = format(result);
    const fields: string[] = [];
    if (enrichment.notice !== undefined)
      fields.push(
        enrichment.notice
          .split(/\r\n|\r|\n/)
          .map((line) => (line === '' ? '>' : `> ${line}`))
          .join('\n'),
      );
    if (enrichment.effectiveQuery !== undefined) {
      const query = enrichment.effectiveQuery;
      const literal =
        query === ''
          ? ''
          : /[\r\n]/.test(query)
            ? `\n${new MarkdownBuilder().codeBlock(query.replace(/\r\n?/g, '\n')).build()}\n`
            : new MarkdownBuilder().inlineCode(query).build();
      fields.push(`Query: ${literal}`);
    }
    if (fields.length) content.push({ type: 'text', text: `\n\n${fields.join('\n\n')}` });
    return Buffer.byteLength(
      JSON.stringify({ structuredContent: { ...result, ...enrichment }, content }),
    );
  };
}

/** Page a normalized node; oversized children defer and still consume one source entry. */
export function pageNode(
  root: unknown,
  request: PageRequest,
  measure: Measure,
  retained: Record<string, unknown> = {},
): Retrieval & Record<string, unknown> {
  const value = resolvePointer(root, request.path);
  return pageValue(value, request, measure, retained);
}

/** Page an already-selected value, allowing batch rows to be fetched on demand. */
export function pageValue(
  value: unknown,
  request: PageRequest,
  measure: Measure,
  retained: Record<string, unknown> = {},
  revision = nodeRevision(value),
): Retrieval & Record<string, unknown> {
  if (request.revision !== undefined && request.revision !== revision)
    throw validationError('The addressed value changed. Restart this node without revision.', {
      reason: 'stale_page_revision',
    });
  const shape = descriptor(request.path, value);
  const page: NonNullable<Retrieval['page']> = {
    ...shape,
    offset: request.offset,
    nextOffset: null,
    revision,
    notice: 'Re-fetched now; this is not a saved historical snapshot.',
  };
  const result = { ...retained, page };
  if (shape.type === 'string') {
    const points = Array.from(String(value));
    let low = 0;
    let high = Math.max(0, points.length - request.offset);
    while (low < high) {
      const count = Math.ceil((low + high) / 2);
      page.text = points.slice(request.offset, request.offset + count).join('');
      page.nextOffset = request.offset + count < shape.total ? request.offset + count : null;
      if (measure(result) <= RESPONSE_BYTES) low = count;
      else high = count - 1;
    }
    page.text = points.slice(request.offset, request.offset + low).join('');
    page.nextOffset = request.offset + low < shape.total ? request.offset + low : null;
    if (low === 0 && request.offset < shape.total)
      throw validationError(
        'The page path leaves no room for one code point. Select a shorter parent path.',
        { reason: 'invalid_page_path' },
      );
    return result;
  }
  const entries =
    shape.type === 'array'
      ? (value as unknown[]).map((v, i) => [String(i), v] as const)
      : shape.type === 'object'
        ? Object.entries(value as object).filter(([, v]) => v !== undefined)
        : [['', value] as const];
  page.total = entries.length;
  let low = 0;
  let high = Math.max(0, entries.length - request.offset);
  const select = (count: number) => {
    page.entries = entries
      .slice(request.offset, request.offset + count)
      .map(([key, value]) => ({ key, value }));
    page.nextOffset = request.offset + count < entries.length ? request.offset + count : null;
  };
  while (low < high) {
    const count = Math.ceil((low + high) / 2);
    select(count);
    if (measure(result) <= RESPONSE_BYTES) low = count;
    else high = count - 1;
  }
  select(low);
  const nextChild = entries.at(request.offset + low);
  if (low > 0 && nextChild) {
    const [key, value] = nextChild;
    const selected = page.entries;
    page.entries = [{ key, value }];
    const oversized = measure(result) > RESPONSE_BYTES;
    page.entries = selected;
    if (oversized && page.entries) {
      page.entries.push({ key, deferred: descriptor(childPointer(request.path, key), value) });
      const previousOffset = page.nextOffset;
      page.nextOffset = request.offset + low + 1 < entries.length ? request.offset + low + 1 : null;
      if (measure(result) > RESPONSE_BYTES) {
        page.entries.pop();
        page.nextOffset = previousOffset;
      }
    }
  }
  if (low === 0 && request.offset < entries.length) {
    const child = entries.at(request.offset);
    if (!child) throw new Error('Normalized page entry disappeared.');
    const [key, value] = child;
    page.entries = [
      {
        key,
        deferred: descriptor(
          shape.type === 'scalar' ? request.path : childPointer(request.path, key),
          value,
        ),
      },
    ];
    page.nextOffset = request.offset + 1 < entries.length ? request.offset + 1 : null;
    if (measure(result) > RESPONSE_BYTES)
      throw validationError(
        'The child path is too long to retrieve. Select a shorter parent path.',
        { reason: 'invalid_page_path' },
      );
  }
  return result;
}

/** Fetch only the next needed batch rows; array keys retain their original input positions. */
export async function pageRows(
  total: number,
  request: PageRequest,
  revision: string,
  fetchRow: (index: number) => Promise<unknown>,
  measure: Measure,
): Promise<Retrieval> {
  if (request.revision !== undefined && request.revision !== revision)
    throw validationError('The batch input order changed. Restart without revision.', {
      reason: 'stale_page_revision',
    });
  const entries: NonNullable<NonNullable<Retrieval['page']>['entries']> = [];
  const page: NonNullable<Retrieval['page']> = {
    path: '/results',
    type: 'array',
    total,
    offset: request.offset,
    nextOffset: null,
    revision,
    entries,
    notice:
      'Fresh row lookups in original input order; no aggregate summary is recomputed or saved.',
  };
  const result = { page };
  for (let index = request.offset; index < total; index++) {
    const value = await fetchRow(index);
    const entry: NonNullable<typeof page.entries>[number] = { key: String(index), value };
    entries.push(entry);
    page.nextOffset = index + 1 < total ? index + 1 : null;
    if (measure(result) > RESPONSE_BYTES) {
      delete entry.value;
      entry.deferred = descriptor(`/results/${index}`, value);
      if (measure(result) > RESPONSE_BYTES) {
        entries.pop();
        page.nextOffset = index;
      }
      break;
    }
  }
  return result;
}

/** Keep fitting output unchanged; otherwise retain only measured fields and a complete outline. */
export function boundResponse<T extends Record<string, unknown>>(
  full: T,
  measure: Measure,
  preview?: Record<string, unknown>,
  retained: Record<string, unknown> = {},
  source: Record<string, unknown> = full,
): T | (Retrieval & Record<string, unknown>) {
  if (measure(full) <= RESPONSE_BYTES) return full;
  const result: Retrieval & Record<string, unknown> = {
    ...retained,
    overflow: {
      complete: Object.keys(retained),
      omitted: Object.entries(source)
        .filter(([key, value]) => value !== undefined && !Object.hasOwn(retained, key))
        .map(([key, value]) => descriptor(childPointer('', key), value)),
      page: { path: '', offset: 0 },
      notice:
        'Output exceeds 24,000 UTF-8 bytes. Omitted values remain retrievable with page; repeat the original tool input. Re-fetches are fresh, not saved snapshots. Upstream truncation is separate.',
    },
  };
  if (preview !== undefined) {
    result.preview = preview;
    if (measure(result) > RESPONSE_BYTES) delete result.preview;
    if (Object.hasOwn(preview, 'vulns') && result.preview === undefined && result.overflow)
      result.overflow.notice +=
        ' The advisory list is incomplete in this reply; retrieve /vulns for its entries.';
  }
  return result;
}
