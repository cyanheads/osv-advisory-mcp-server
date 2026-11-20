/**
 * @fileoverview Opaque OSV continuation bound to an effective outbound query.
 * @module services/osv-api/query-cursor
 */
import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';
import { z } from '@cyanheads/mcp-ts-core';
import { validationError } from '@cyanheads/mcp-ts-core/errors';

const CursorEnvelope = z.strictObject({
  version: z.literal(1),
  query: z.string(),
  token: z.string().min(1),
});

const SourceCheckpoint = z.strictObject({
  name: z.string().min(1),
  token: z.string().min(1).nullable().optional(),
});

const SourceEnvelope = z.strictObject({
  version: z.literal(2),
  query: z.string(),
  sourceResolutionUnavailable: z.literal(true).optional(),
  sources: z.array(SourceCheckpoint).min(1),
});

/** Pending sources have no token yet, completed sources carry null. */
export type SourceCheckpoint = z.infer<typeof SourceCheckpoint>;

/** Package continuations distinguish the prior wire token from mapped source state. */
export type PackageContinuation =
  | { version: 1; token: string }
  | Pick<z.infer<typeof SourceEnvelope>, 'version' | 'sources' | 'sourceResolutionUnavailable'>;

/** Report a malformed, mismatched or upstream-rejected continuation. */
export function invalidCursor() {
  return validationError('Invalid OSV continuation cursor.', { reason: 'invalid_cursor' });
}

function queryIdentity(body: object): string {
  return createHash('sha256').update(JSON.stringify(body)).digest('base64url');
}

/** Encode an upstream token without exposing query coordinates in the envelope. */
export function encodeQueryCursor(body: object, token: string): string {
  return Buffer.from(JSON.stringify({ version: 1, query: queryIdentity(body), token })).toString(
    'base64url',
  );
}

/** Validate the envelope and its binding before the cursor reaches OSV. */
export function decodeQueryCursor(body: object, cursor: string): string {
  const parsed = decodePackageCursor(body, cursor);
  if (parsed.version !== 1) throw invalidCursor();
  return parsed.token;
}

/** Bind mapped source progress to the original package query. */
export function encodeSourceCursor(
  body: object,
  sources: SourceCheckpoint[],
  sourceResolutionUnavailable?: true,
): string {
  return Buffer.from(
    JSON.stringify({
      version: 2,
      query: queryIdentity(body),
      sources,
      sourceResolutionUnavailable,
    }),
  ).toString('base64url');
}

/** Decode either a previously issued package cursor or a mapped source cursor. */
export function decodePackageCursor(
  body: object,
  cursor: string,
  legacyUbuntuBody?: object,
): PackageContinuation {
  const bytes = Buffer.from(cursor, 'base64url');
  if (bytes.toString('base64url') !== cursor) throw invalidCursor();
  let value: unknown;
  try {
    value = JSON.parse(bytes.toString('utf8'));
  } catch {
    throw invalidCursor();
  }
  const parsed = z.discriminatedUnion('version', [CursorEnvelope, SourceEnvelope]).safeParse(value);
  if (!parsed.success) throw invalidCursor();
  if (parsed.data.query !== queryIdentity(body)) {
    if (
      parsed.data.version === 1 &&
      legacyUbuntuBody !== undefined &&
      parsed.data.query === queryIdentity(legacyUbuntuBody)
    ) {
      throw validationError('This Ubuntu PURL cursor predates release-scoped lookup.', {
        reason: 'invalid_cursor',
        recovery: {
          hint: 'Omit cursor and repeat the original Ubuntu PURL query to start over with the requested release.',
        },
      });
    }
    throw invalidCursor();
  }
  if (parsed.data.version === 2) {
    const names = new Set(parsed.data.sources.map(({ name }) => name));
    if (
      names.size !== parsed.data.sources.length ||
      parsed.data.sources.every(({ token }) => token === null)
    ) {
      throw invalidCursor();
    }
  }
  return parsed.data;
}
