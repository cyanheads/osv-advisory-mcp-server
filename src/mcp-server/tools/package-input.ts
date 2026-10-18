/**
 * @fileoverview Exclusive tuple and PURL package input shapes.
 * @module mcp-server/tools/package-input
 */
import { z } from '@cyanheads/mcp-ts-core';

/** Existing exact tuple fields, including whitespace normalization. */
export const PackageTupleInput = z.object({
  name: z
    .string()
    .trim()
    .regex(/\S/, 'Package name must not be blank — provide the exact package name.')
    .describe('Exact package name in its ecosystem.'),
  ecosystem: z
    .string()
    .trim()
    .regex(/\S/, 'Ecosystem must not be blank — see osv_list_ecosystems.')
    .describe('Case-sensitive ecosystem identifier from osv_list_ecosystems.'),
  version: z
    .string()
    .trim()
    .regex(/\S/, 'Version must not be blank — provide the exact version string.')
    .describe('Exact package version, never a range.'),
});

/** PURL parsing errors are handled per row so invalid batch identifiers remain isolated. */
export const PackagePurlInput = z
  .object({
    purl: z
      .string()
      .trim()
      .describe(
        'Complete Package URL, such as pkg:pypi/jinja2@3.1.4. Supply its version either here or separately, exactly once.',
      ),
    version: z
      .string()
      .trim()
      .regex(/\S/, 'Version must not be blank — provide the exact version string.')
      .optional()
      .describe('Exact version only when the PURL does not embed one.'),
  })
  .strict();
