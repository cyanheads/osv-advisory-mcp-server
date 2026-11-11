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
  const bytes = Buffer.from(cursor, 'base64url');
  if (bytes.toString('base64url') !== cursor) throw invalidCursor();
  let value: unknown;
  try {
    value = JSON.parse(bytes.toString('utf8'));
  } catch {
    throw invalidCursor();
  }
  const parsed = CursorEnvelope.safeParse(value);
  if (!parsed.success || parsed.data.query !== queryIdentity(body)) throw invalidCursor();
  return parsed.data.token;
}
