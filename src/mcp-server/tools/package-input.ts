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
    .describe(
      'Ecosystem identifier from osv_list_ecosystems. Known base names are case-insensitive. Preserve suffix spelling.',
    ),
  version: z
    .string()
    .trim()
    .regex(/\S/, 'Version must not be blank — provide the exact version string.')
    .describe(
      'Exact installed version from the lockfile, never a range. npm/crates.io require three numeric components with optional prerelease/build metadata or leading v; = and == exact pins are normalized.',
    ),
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
      .describe(
        'Exact installed version only when the PURL does not embed one; the same ecosystem-specific version rules apply.',
      ),
  })
  .strict();
