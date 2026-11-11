/**
 * @fileoverview Shared schemas and rendering for OSV query continuation.
 * @module mcp-server/tools/continuation-fields
 */
import { z } from '@cyanheads/mcp-ts-core';

/** The cursor resumes upstream matching independently of field retrieval. */
export const CursorInput = z
  .string()
  .optional()
  .describe(
    'Pass nextCursor unchanged with the same effective query. Repeat this input cursor when retrieving fields from a resumed response.',
  );

/** A returned cursor is an atomic copyable value. */
export const NextCursor = z
  .string()
  .optional()
  .describe(
    'Resume the OSV query by passing this value unchanged as cursor with the same identifier.',
  );

/** An empty terminal page on resume describes the remaining suffix only. */
export const ContinuationExhausted = z
  .literal(true)
  .optional()
  .describe('The resumed OSV continuation is exhausted and returned no further advisories.');

/** Message shared by empty terminal package and commit resumes. */
export const CONTINUATION_EXHAUSTED_NOTICE = 'The OSV continuation is exhausted.';

/** Render the server-generated base64url cursor without changing its characters. */
export function cursorBlock(nextCursor: string) {
  return {
    type: 'text' as const,
    text: `**nextCursor** (upstream results are incomplete): \`${nextCursor}\``,
  };
}
