/**
 * @fileoverview Assertion for a tool call the input schema rejects, as `runToolContract`
 * delivers it: the wire's `-32602` `invalid_arguments` envelope.
 * @module tests/helpers/argument-rejection
 */

import type { runToolContract } from '@cyanheads/mcp-ts-core/testing';
import { expect } from 'vitest';
import { contentText } from './markdown.js';

type ToolResult = Awaited<ReturnType<typeof runToolContract>>;

interface ArgumentError {
  code: number;
  data: {
    issues: Array<{ message: string; path: Array<string | number> }>;
    reason: string;
    recovery: { hint: string };
  };
  message: string;
}

/** Occurrences of `needle` in `haystack`. */
function occurrences(haystack: string, needle: string): number {
  return haystack.split(needle).length - 1;
}

/**
 * Assert `result` is a `-32602` `invalid_arguments` rejection carrying exactly one
 * issue, at `path`, whose message appears once in the error message, the recovery
 * hint, and `content[]`. Returns that message.
 */
export function expectSingleArgumentIssue(
  result: ToolResult,
  path: Array<string | number>,
): string {
  expect(result.isError).toBe(true);
  const { error } = result.structuredContent as { error: ArgumentError };
  expect(error.code).toBe(-32602);
  expect(error.data.reason).toBe('invalid_arguments');
  expect(error.data.issues).toHaveLength(1);
  const [issue] = error.data.issues;
  expect(issue?.path).toEqual(path);
  const message = issue?.message ?? '';
  expect(occurrences(error.message, message)).toBe(1);
  expect(occurrences(error.data.recovery.hint, message)).toBe(1);
  expect(occurrences(contentText(result as Parameters<typeof contentText>[0]), message)).toBe(1);
  return message;
}
