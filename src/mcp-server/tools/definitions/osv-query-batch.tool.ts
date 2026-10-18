/**
 * @fileoverview Tool for batch vulnerability queries across multiple packages via OSV.dev.
 * Uses native positional batch preflight and deduplicated advisory enrichment for CVE aliases.
 * @module mcp-server/tools/definitions/osv-query-batch
 */

import { tool, z } from '@cyanheads/mcp-ts-core';
import {
  JsonRpcErrorCode,
  serviceUnavailable,
  validationError,
} from '@cyanheads/mcp-ts-core/errors';
import { escapeAdvisoryInline } from '@/mcp-server/tools/render-escape.js';
import { getOsvApiService } from '@/services/osv-api/osv-api-service.js';
import { PackagePurlInput, PackageTupleInput } from '../package-input.js';
import {
  boundResponse,
  nodeRevision,
  PageInput,
  pageRows,
  pageValue,
  type Retrieval,
  RetrievalOutput,
  renderRetrieval,
  resolvePointer,
  wireMeasure,
} from '../response-pages.js';

/** Severity ordering for worstSeverity derivation. */
const SEVERITY_RANK: Record<string, number> = {
  LOW: 1,
  MODERATE: 2,
  HIGH: 3,
  CRITICAL: 4,
};

function worstSeverity(labels: Array<string | null | undefined>): string | null {
  let best: string | null = null;
  let bestRank = 0;
  for (const label of labels) {
    if (!label) continue;
    const rank = SEVERITY_RANK[label.toUpperCase()] ?? 0;
    if (rank > bestRank) {
      bestRank = rank;
      best = label;
    }
  }
  return best;
}

const PackageInputSchema = z.union([
  PackageTupleInput.extend({
    purl: PackagePurlInput.shape.purl
      .optional()
      .describe('Use purl instead of the tuple, never together with name or ecosystem.'),
  })
    .superRefine((input, ctx) => {
      if (input.purl !== undefined)
        ctx.addIssue({
          code: 'custom',
          path: ['purl'],
          message: 'Provide purl or name/ecosystem, never both.',
        });
    })
    .describe('Exact package tuple.'),
  PackagePurlInput.describe('PURL alternative with exactly one version source.'),
]);

const BatchVulnSchema = z.object({
  id: z.string().describe('OSV vulnerability ID.'),
  summary: z.string().describe('One-line advisory description.'),
  aliases: z
    .array(z.string().describe('A CVE ID or other alias.'))
    .describe(
      'CVE IDs and other aliases. Accepted by nist-nvd-mcp-server for CVSS scores and CISA KEV status.',
    ),
  severityLabel: z
    .string()
    .nullable()
    .describe(
      'Severity label: "LOW", "MODERATE", "HIGH", "CRITICAL", or null. Same derivation as osv_query_package: database_specific.severity, then an Ubuntu priority, then the highest CVSS v3/v4 score, using this row\'s package-level severity entries when the record has none.',
    ),
  fixedVersions: z
    .array(z.string().describe('A version that fixes the vulnerability for this package.'))
    .describe(
      "Every fixed version the advisory lists for this row's package, in record order — one per affected interval, typically one per release line. Excludes other packages' fixes and GIT commits. Empty when the advisory lists no fix for this package.",
    ),
});

const PerPackageResultSchema = z.object({
  name: z.string().describe('Package name from input.'),
  ecosystem: z.string().describe('Ecosystem from input.'),
  version: z.string().describe('Version from input.'),
  purl: z
    .string()
    .optional()
    .describe(
      'Original PURL when supplied; name, ecosystem and version show its effective coordinate on success.',
    ),
  vulnerable: z.boolean().describe('True if any vulnerabilities were found.'),
  truncated: z
    .boolean()
    .describe(
      'True when OSV paginated beyond the fetch cap for this package — its result may be INCOMPLETE. A truncated row with no vulnerabilities is NOT confirmed clean.',
    ),
  error: z
    .string()
    .nullable()
    .describe('Per-package error message (e.g. invalid ecosystem). Null on success.'),
  vulnCount: z
    .number()
    .describe('Number of vulnerabilities found. 0 when not vulnerable or on error.'),
  vulns: z
    .array(BatchVulnSchema.describe('One vulnerability found for this package.'))
    .describe('Vulnerabilities found. Empty array when clean.'),
});

const BatchFullOutput = z.object({
  results: z
    .array(PerPackageResultSchema.describe('Result for one package.'))
    .describe('Per-package results, positionally matching the input array.'),
  summary: z
    .object({
      totalPackages: z.number().describe('Total packages queried.'),
      vulnerableCount: z.number().describe('Packages with at least one vulnerability.'),
      cleanCount: z
        .number()
        .describe('Packages confirmed clean — no vulnerabilities, no error, and not truncated.'),
      truncatedCount: z
        .number()
        .describe(
          'Packages whose OSV results were truncated (may be incomplete). A truncated package with no findings is NOT counted as clean.',
        ),
      errorCount: z.number().describe('Packages that returned an error (e.g. invalid ecosystem).'),
      totalVulns: z
        .number()
        .describe(
          'Total vulnerability instances across all packages (may double-count shared advisories).',
        ),
      worstSeverity: z
        .string()
        .nullable()
        .describe(
          'Highest severity label seen across all findings, or null if no severity data available.',
        ),
    })
    .describe('Aggregate statistics across the full batch.'),
});
const BatchOutput = BatchFullOutput.partial().extend(RetrievalOutput.shape);

function renderBatch(result: z.infer<typeof BatchOutput>): Array<{ type: 'text'; text: string }> {
  const retrieval = renderRetrieval(result);
  if (result.results === undefined) {
    if (result.summary)
      retrieval.unshift({
        type: 'text',
        text: `## OSV Batch Scan Summary\n${JSON.stringify(result.summary)}`,
      });
    return retrieval;
  }
  const lines: string[] = [];
  const { summary } = BatchFullOutput.parse(result);
  // OSV-sourced strings pass through the render escape; name/ecosystem/version echo caller input.
  const esc = escapeAdvisoryInline;
  for (const pkg of result.results)
    if (pkg.purl !== undefined)
      lines.push(
        `**PURL:** ${esc(pkg.purl)}${pkg.error === null ? ` → ${esc(pkg.name)}@${esc(pkg.version)} (${esc(pkg.ecosystem)})` : ''}`,
      );

  lines.push('## OSV Batch Scan Summary\n');
  lines.push(`| Metric | Value |`);
  lines.push(`|:-------|:------|`);
  lines.push(`| Total packages | ${summary.totalPackages} |`);
  lines.push(`| Vulnerable | ${summary.vulnerableCount} |`);
  lines.push(`| Clean | ${summary.cleanCount} |`);
  lines.push(`| Truncated | ${summary.truncatedCount} |`);
  lines.push(`| Errors | ${summary.errorCount} |`);
  lines.push(`| Total vulns | ${summary.totalVulns} |`);
  lines.push(`| Worst severity | ${summary.worstSeverity ?? 'N/A'} |`);

  const vulnerable = result.results.filter((r) => r.vulnerable);
  if (vulnerable.length > 0) {
    lines.push(`\n## Vulnerable Packages\n`);
    for (const pkg of vulnerable) {
      const trunc = pkg.truncated
        ? ' — ⚠️ truncated (more pages exist; list may be incomplete)'
        : '';
      lines.push(`### \`${pkg.name}\` @ \`${pkg.version}\` (${pkg.ecosystem})${trunc}`);
      lines.push(`**Vulnerabilities: ${pkg.vulnCount}**`);
      for (const vuln of pkg.vulns) {
        const aliases =
          vuln.aliases.length > 0
            ? ` — **${vuln.aliases.map((a) => `\`${esc(a)}\``).join(', ')}**`
            : '';
        const sev = vuln.severityLabel ? ` [${esc(vuln.severityLabel)}]` : '';
        const fix =
          vuln.fixedVersions.length > 0 ? ` → fix: ${vuln.fixedVersions.map(esc).join(', ')}` : '';
        lines.push(`- \`${esc(vuln.id)}\`${sev}${aliases}${fix}`);
        if (vuln.summary) {
          lines.push(`  <advisory_summary>${esc(vuln.summary)}</advisory_summary>`);
        }
      }
      lines.push('');
    }
  }

  const incomplete = result.results.filter((r) => !r.vulnerable && r.error === null && r.truncated);
  if (incomplete.length > 0) {
    lines.push('\n## Incomplete (truncated) Packages\n');
    lines.push(
      'No vulnerabilities were retrieved within the page-fetch cap, but OSV had more pages — NOT confirmed clean.\n',
    );
    for (const pkg of incomplete) {
      lines.push(
        `- \`${pkg.name}\` @ \`${pkg.version}\` (${pkg.ecosystem}) — ⚠️ truncated, results incomplete`,
      );
    }
  }

  const clean = result.results.filter((r) => !r.vulnerable && r.error === null && !r.truncated);
  if (clean.length > 0) {
    lines.push(`\n## Clean Packages\n`);
    for (const pkg of clean) {
      lines.push(`- \`${pkg.name}\` @ \`${pkg.version}\` (${pkg.ecosystem}) — clean`);
    }
  }

  const errors = result.results.filter((r): r is typeof r & { error: string } => r.error !== null);
  if (errors.length > 0) {
    lines.push('\n## Errors\n');
    for (const pkg of errors) {
      lines.push(
        pkg.purl === undefined
          ? `- \`${pkg.name}\` @ \`${pkg.version}\` (${pkg.ecosystem}): ${esc(pkg.error)}`
          : `- ${esc(pkg.purl)}: ${esc(pkg.error)}`,
      );
    }
  }

  return [{ type: 'text', text: lines.join('\n') }, ...retrieval];
}

export const osvQueryBatch = tool('osv_query_batch', {
  description:
    'Query vulnerabilities for multiple packages in one call — the primary tool for dependency audits, ' +
    'SBOM scanning, and lockfile triage. Pass up to 1000 mixed {name, ecosystem, version} tuples and {purl, version?} identifiers, with exactly one embedded or separate version per PURL. ' +
    'Each entry in the response corresponds positionally to the input. ' +
    'Each finding includes CVE aliases for chaining to nist-nvd-mcp-server for CVSS scoring. Large replies retain the complete summary. For overflow, repeat the original packages array with page: overflow.page. Continue the same path with offset: page.nextOffset and revision: page.revision until nextOffset is null. Retrieve each entries[].deferred.path separately at offset zero without a revision. Do not pass the output page object as input. /results/17 selects original input row 17, even when earlier rows failed. Pages are fresh lookups and do not recompute the initial summary; restart a changed node without a revision. Transmission overflow and upstream truncated are separate; neither confirms clean.',
  annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: false },

  input: z.object({
    page: PageInput.optional().describe(
      'Repeat the original packages array with page: overflow.page first. Continue using path, offset: page.nextOffset and revision: page.revision. /results/17/... keeps original row index 17; start deferred children without a revision.',
    ),
    packages: z
      .array(PackageInputSchema.describe('One package to audit.'))
      .min(1)
      .max(1000)
      .describe(
        'Packages to audit. One entry per dependency. Positional: result[i] corresponds to packages[i].',
      ),
  }),

  output: BatchOutput,

  errors: [
    {
      reason: 'invalid_page_path',
      code: JsonRpcErrorCode.ValidationError,
      when: 'The pointer is unknown or cannot fit a bounded page.',
      recovery: 'Use an announced pointer or an available parent field and retry.',
      thrownBy: 'service',
    },
    {
      reason: 'stale_page_revision',
      code: JsonRpcErrorCode.ValidationError,
      when: 'The re-fetched node or input order changed.',
      recovery: 'Restart this node at offset zero without a revision.',
      thrownBy: 'service',
    },
  ],

  enrichment: {
    notice: z
      .string()
      .optional()
      .describe(
        'Present on all-clean or all-errors batches — the aggregate outcome for content-only clients.',
      ),
    effectiveQuery: z
      .string()
      .optional()
      .describe(
        'Compact scan summary (package and outcome counts), echoed on edge-case batches for content-only clients.',
      ),
  },

  async handler(input, ctx) {
    ctx.log.info('OSV batch query', { packageCount: input.packages.length });
    const packages = input.packages.map((pkg) =>
      'name' in pkg ? { name: pkg.name, ecosystem: pkg.ecosystem, version: pkg.version } : pkg,
    );

    const service = getOsvApiService();
    const rowContext = input.page
      ? { ...ctx, signal: AbortSignal.any([ctx.signal, AbortSignal.timeout(50000)]) }
      : ctx;
    const project = (r: Awaited<ReturnType<typeof service.queryBatch>>[number]) => ({
      name: r.name,
      ecosystem: r.ecosystem,
      version: r.version,
      ...(r.purl === undefined ? {} : { purl: r.purl }),
      vulnerable: r.vulns.length > 0,
      truncated: r.truncated,
      error: r.error,
      vulnCount: r.vulns.length,
      vulns: r.vulns,
    });
    const fetchRow = async (index: number) => {
      const pkg = packages[index];
      if (!pkg)
        throw validationError('Unknown original batch row index.', { reason: 'invalid_page_path' });
      const [row] = await service.queryBatch([pkg], rowContext);
      if (!row) throw serviceUnavailable('OSV batch service omitted its requested row.');
      return project(row);
    };
    if (input.page?.path === '/results')
      return pageRows(
        input.packages.length,
        input.page,
        nodeRevision(input.packages),
        fetchRow,
        measureBatch,
      );
    if (input.page?.path.startsWith('/results/')) {
      const match = /^\/results\/(0|[1-9]\d*)(\/.*)?$/.exec(input.page.path);
      const index = match ? Number(match[1]) : -1;
      if (!match || index < 0 || index >= input.packages.length)
        throw validationError('Unknown original batch row index.', { reason: 'invalid_page_path' });
      const row = await fetchRow(index);
      const node = resolvePointer(row, match[2] ?? '');
      return pageValue(node, input.page, measureBatch);
    }
    if (input.page)
      throw validationError(
        'Batch pages select /results or /results/<index>/... only. Make a fresh initial call for aggregate summary.',
        { reason: 'invalid_page_path' },
      );
    const rawResults = await service.queryBatch(packages, ctx);

    // Build typed result rows
    const results = rawResults.map(project);

    // Aggregate stats. A truncated row is never counted as clean — its result may
    // be incomplete, so "clean" requires no vulns, no error, AND not truncated.
    const vulnerableCount = results.filter((r) => r.vulnerable).length;
    const errorCount = results.filter((r) => r.error !== null).length;
    const truncatedCount = results.filter((r) => r.truncated).length;
    const cleanCount = results.filter(
      (r) => !r.vulnerable && r.error === null && !r.truncated,
    ).length;
    const totalVulns = results.reduce((sum, r) => sum + r.vulnCount, 0);
    const allSeverities = results.flatMap((r) => r.vulns.map((v) => v.severityLabel));
    const worst = worstSeverity(allSeverities);

    const summary = {
      totalPackages: results.length,
      vulnerableCount,
      cleanCount,
      truncatedCount,
      errorCount,
      totalVulns,
      worstSeverity: worst,
    };

    ctx.log.info('OSV batch complete', {
      totalPackages: results.length,
      vulnerableCount,
      truncatedCount,
      totalVulns,
    });

    // "All clean" must exclude truncated rows — a truncated batch is not confirmed clean.
    const allClean = vulnerableCount === 0 && errorCount === 0 && truncatedCount === 0;
    const allErrors = errorCount === results.length;
    const enrichment: { notice?: string; effectiveQuery?: string } = {};
    if ((allClean || allErrors) && !input.page) {
      enrichment.notice = allClean
        ? `All ${results.length} package(s) clean — no known vulnerabilities.`
        : `All ${results.length} package(s) errored — none could be checked.`;
      enrichment.effectiveQuery = `${summary.totalPackages} package(s): ${vulnerableCount} vulnerable, ${cleanCount} clean, ${errorCount} error(s)`;
    }

    const full = { results, summary };
    const shaped = boundResponse(full, (value) => measureBatch(value, enrichment), undefined, {
      summary,
    });
    if ('overflow' in shaped && shaped.overflow) {
      shaped.overflow.page.path = '/results';
      const preview = (page: NonNullable<Retrieval['page']>) => ({
        rows: page.entries,
        totalRows: page.total,
        nextOffset: page.nextOffset,
        notice:
          'Initial-scan preview; row keys are original input indices. Remaining rows and deferred values are omitted, never confirmed clean. Retrieve /results for fresh row pages.',
      });
      const previewPage = pageValue(
        results,
        { path: '/results', offset: 0 },
        (value) =>
          measureBatch({
            ...shaped,
            preview: preview(RetrievalOutput.shape.page.unwrap().parse(value.page)),
          }),
        {},
        nodeRevision(input.packages),
      );
      shaped.preview = preview(RetrievalOutput.shape.page.unwrap().parse(previewPage.page));
    }
    if (!('overflow' in shaped)) {
      if (enrichment.notice !== undefined) ctx.enrich.notice(enrichment.notice);
      if (enrichment.effectiveQuery !== undefined) ctx.enrich.echo(enrichment.effectiveQuery);
    }
    return shaped;
  },

  format: renderBatch,
});

const measureBatch: (
  value: Retrieval & Record<string, unknown>,
  enrichment?: { notice?: string; effectiveQuery?: string },
) => number = (value, enrichment) =>
  wireMeasure((v) => renderBatch(BatchOutput.parse(v)), enrichment)(value);
