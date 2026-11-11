/**
 * @fileoverview Bounded full-commit vulnerability queries with record-wide severity.
 * @module mcp-server/tools/definitions/osv-query-commit
 */
import { tool, z } from '@cyanheads/mcp-ts-core';
import { JsonRpcErrorCode } from '@cyanheads/mcp-ts-core/errors';
import { getOsvApiService } from '@/services/osv-api/osv-api-service.js';
import {
  CONTINUATION_EXHAUSTED_NOTICE,
  ContinuationExhausted,
  CursorInput,
  cursorBlock,
  NextCursor,
} from '../continuation-fields.js';
import { escapeAdvisoryBlock } from '../render-escape.js';
import {
  boundResponse,
  PageInput,
  pageNode,
  RetrievalOutput,
  renderRetrieval,
  wireMeasure,
} from '../response-pages.js';
import { VulnOutputSchema } from './osv-query-package.tool.js';

const CommitAdvisory = VulnOutputSchema.omit({ fixedVersions: true }).extend({
  severity: VulnOutputSchema.shape.severity.describe(
    'Record-level severity entries. Empty when severity is available only on affected entries; severitySource identifies the derived label basis.',
  ),
  severityLabel: VulnOutputSchema.shape.severityLabel.describe(
    'Record-wide severity label, using every affected entry when record-level severity is empty. Null when no source yields a label.',
  ),
});
const CommitFullOutput = z.object({
  nextCursor: NextCursor,
  continuationExhausted: ContinuationExhausted,
  vulns: z
    .array(
      CommitAdvisory.describe(
        'One commit-matching advisory, without package-specific fixedVersions.',
      ),
    )
    .describe(
      'Matching advisories. An empty initial result confirms no known vulnerabilities only when truncated is false. An empty terminal resume confirms exhaustion of the continuation.',
    ),
  truncated: z
    .boolean()
    .describe(
      'True when the page cap or operation deadline interrupted OSV matching. Use nextCursor to continue.',
    ),
  queryMeta: z
    .object({
      commit: z.string().describe('Full queried Git commit hash.'),
      vulnCount: z.number().describe('Number of advisories retrieved.'),
    })
    .describe('Effective commit query and retrieved count.'),
});
const CommitOutput = CommitFullOutput.partial().extend(RetrievalOutput.shape);

function renderCommit(result: z.infer<typeof CommitOutput>): Array<{ type: 'text'; text: string }> {
  const retrieval = renderRetrieval(result);
  if (result.nextCursor !== undefined) retrieval.unshift(cursorBlock(result.nextCursor));
  if (result.truncated && result.vulns === undefined)
    retrieval.unshift({ type: 'text', text: 'truncated: true' });
  if (result.continuationExhausted && result.vulns === undefined)
    retrieval.unshift({ type: 'text', text: CONTINUATION_EXHAUSTED_NOTICE });
  if (result.vulns === undefined || result.queryMeta === undefined) return retrieval;
  const { nextCursor: _nextCursor, ...full } = CommitFullOutput.parse(result);
  const notice = full.truncated
    ? 'Results are INCOMPLETE; more OSV pages remain. This is not confirmed clean.'
    : full.vulns.length === 0
      ? full.continuationExhausted
        ? CONTINUATION_EXHAUSTED_NOTICE
        : 'No known vulnerabilities found.'
      : 'Commit-matching advisories:';
  return [
    {
      type: 'text',
      text: `${notice}\n<advisory_text>\n${escapeAdvisoryBlock(JSON.stringify(full, null, 2))}\n</advisory_text>`,
    },
    ...retrieval,
  ];
}
const measureCommit = wireMeasure((value) => renderCommit(CommitOutput.parse(value)));

/** Look up a complete SHA-1 or SHA-256 Git commit without inventing a package identity. */
export const osvQueryCommit = tool('osv_query_commit', {
  description:
    'Query known vulnerabilities for one full Git commit hash (40 hexadecimal SHA-1 or 64 hexadecimal SHA-256 characters, case-insensitive). Abbreviated hashes are rejected. Returns advisory summaries, record-wide severity and GIT ranges with repositories and ordered fix events; use osv_get_vulnerability for full records. No package-specific fixedVersions are inferred. For overflow, repeat the original input with page: overflow.page. Continue the same path with offset: page.nextOffset and revision: page.revision until nextOffset is null. Retrieve entries[].deferred.path separately at offset zero without a revision. Do not pass the output page object as input. Pages are fresh lookups; restart a changed node without a revision. Transmission overflow and upstream truncated are separate; neither confirms clean.',
  annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: false },
  input: z.object({
    commit: z
      .string()
      .regex(
        /^(?:[a-fA-F0-9]{40}|[a-fA-F0-9]{64})$/,
        'Provide a full 40-character SHA-1 or 64-character SHA-256 hexadecimal Git commit; abbreviated hashes are not supported.',
      )
      .describe('Full Git commit hash: 40 SHA-1 or 64 SHA-256 hex characters, case-insensitive.'),
    page: PageInput.optional().describe(
      'Repeat the original commit with page: overflow.page first, then select path, offset: page.nextOffset and revision: page.revision.',
    ),
    cursor: CursorInput,
  }),
  output: CommitOutput,
  errors: [
    {
      reason: 'invalid_cursor',
      code: JsonRpcErrorCode.ValidationError,
      when: 'The cursor is malformed, belongs to another query, or was rejected by OSV.',
      recovery:
        'Use the unchanged nextCursor with the same full commit hash, or omit cursor to start over.',
      thrownBy: 'service',
    },
    {
      reason: 'invalid_commit_query',
      code: JsonRpcErrorCode.ValidationError,
      when: 'OSV rejects the complete commit query.',
      recovery:
        'Check the full Git commit hash and retry; package lookups can use osv_query_package instead.',
    },
    {
      reason: 'invalid_page_path',
      code: JsonRpcErrorCode.ValidationError,
      when: 'The requested field is unknown or cannot fit a bounded page.',
      recovery: 'Use an announced field pointer or its shorter parent and retry.',
      thrownBy: 'service',
    },
    {
      reason: 'stale_page_revision',
      code: JsonRpcErrorCode.ValidationError,
      when: 'The freshly retrieved node changed.',
      recovery: 'Restart the same path at offset zero without a revision.',
      thrownBy: 'service',
    },
  ],
  async handler(input, ctx) {
    const service = getOsvApiService();
    const result =
      input.cursor === undefined
        ? await service.queryCommit(input.commit, ctx)
        : await service.queryCommit(input.commit, ctx, input.cursor);
    if ('invalid' in result) throw ctx.fail('invalid_commit_query', result.message);
    const exhausted = input.cursor !== undefined && !result.truncated && result.vulns.length === 0;
    const retained =
      result.nextCursor === undefined
        ? exhausted
          ? { continuationExhausted: true as const }
          : {}
        : { nextCursor: result.nextCursor, truncated: true };
    const full = {
      ...retained,
      vulns: result.vulns.map((record) => CommitAdvisory.parse(record)),
      truncated: result.truncated,
      queryMeta: { commit: input.commit, vulnCount: result.vulns.length },
    };
    if (input.page) return pageNode(full, input.page, measureCommit, retained);
    return boundResponse(full, measureCommit, undefined, retained);
  },
  format: renderCommit,
});
