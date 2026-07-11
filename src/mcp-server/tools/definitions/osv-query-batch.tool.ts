/**
 * @fileoverview Tool for batch vulnerability queries across multiple packages via OSV.dev.
 * Uses parallel per-package POST /v1/query for full records including CVE aliases.
 * @module mcp-server/tools/definitions/osv-query-batch
 */

import { tool, z } from '@cyanheads/mcp-ts-core';
import { getOsvApiService } from '@/services/osv-api/osv-api-service.js';

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

const PackageInputSchema = z.object({
  name: z.string().describe('Package name as it appears in the ecosystem.'),
  ecosystem: z
    .string()
    .describe(
      'Ecosystem identifier. Case-sensitive exact match. Use osv_list_ecosystems to validate.',
    ),
  version: z.string().describe('Exact version string to check.'),
});

const BatchVulnSchema = z.object({
  id: z.string().describe('OSV vulnerability ID.'),
  summary: z.string().describe('One-line advisory description.'),
  aliases: z
    .array(z.string().describe('A CVE ID or other alias.'))
    .describe(
      'CVE IDs and other aliases. Accepted by nist-nvd-mcp-server for CVSS/KEV/EPSS context.',
    ),
  severityLabel: z
    .string()
    .nullable()
    .describe('Severity label: "LOW", "MODERATE", "HIGH", "CRITICAL", or null.'),
  fixedVersions: z
    .array(z.string().describe('A first-safe version string.'))
    .describe('First safe version(s) to upgrade to. Empty if no fix exists.'),
});

const PerPackageResultSchema = z.object({
  name: z.string().describe('Package name from input.'),
  ecosystem: z.string().describe('Ecosystem from input.'),
  version: z.string().describe('Version from input.'),
  vulnerable: z.boolean().describe('True if any vulnerabilities were found.'),
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

export const osvQueryBatch = tool('osv_query_batch', {
  description:
    'Query vulnerabilities for multiple packages in one call — the primary tool for dependency audits, ' +
    'SBOM scanning, and lockfile triage. Pass an array of {name, ecosystem, version} tuples (up to 1000). ' +
    'Each entry in the response corresponds positionally to the input. ' +
    'Each finding includes CVE aliases for chaining to nist-nvd-mcp-server for CVSS scoring.',
  annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: false },

  input: z.object({
    packages: z
      .array(PackageInputSchema.describe('One package to audit.'))
      .min(1)
      .max(1000)
      .describe(
        'Packages to audit. One entry per dependency. Positional: result[i] corresponds to packages[i].',
      ),
  }),

  output: z.object({
    results: z
      .array(PerPackageResultSchema.describe('Result for one package.'))
      .describe('Per-package results, positionally matching the input array.'),
    summary: z
      .object({
        totalPackages: z.number().describe('Total packages queried.'),
        vulnerableCount: z.number().describe('Packages with at least one vulnerability.'),
        cleanCount: z.number().describe('Packages with no vulnerabilities.'),
        errorCount: z
          .number()
          .describe('Packages that returned an error (e.g. invalid ecosystem).'),
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
  }),

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

    const service = getOsvApiService();
    const rawResults = await service.queryBatch(input.packages, ctx);

    // Build typed result rows
    const results = rawResults.map((r) => ({
      name: r.name,
      ecosystem: r.ecosystem,
      version: r.version,
      vulnerable: r.vulns.length > 0,
      error: r.error,
      vulnCount: r.vulns.length,
      vulns: r.vulns,
    }));

    // Aggregate stats
    const vulnerableCount = results.filter((r) => r.vulnerable).length;
    const errorCount = results.filter((r) => r.error !== null).length;
    const cleanCount = results.filter((r) => !r.vulnerable && r.error === null).length;
    const totalVulns = results.reduce((sum, r) => sum + r.vulnCount, 0);
    const allSeverities = results.flatMap((r) => r.vulns.map((v) => v.severityLabel));
    const worst = worstSeverity(allSeverities);

    const summary = {
      totalPackages: results.length,
      vulnerableCount,
      cleanCount,
      errorCount,
      totalVulns,
      worstSeverity: worst,
    };

    ctx.log.info('OSV batch complete', {
      totalPackages: results.length,
      vulnerableCount,
      totalVulns,
    });

    const allClean = vulnerableCount === 0 && errorCount === 0;
    const allErrors = errorCount === results.length;
    if (allClean || allErrors) {
      ctx.enrich.notice(
        allClean
          ? `All ${results.length} package(s) clean — no known vulnerabilities.`
          : `All ${results.length} package(s) errored — none could be checked.`,
      );
      ctx.enrich.echo(
        `${summary.totalPackages} package(s): ${vulnerableCount} vulnerable, ${cleanCount} clean, ${errorCount} error(s)`,
      );
    }

    return { results, summary };
  },

  format: (result) => {
    const lines: string[] = [];
    const { summary } = result;

    lines.push('## OSV Batch Scan Summary\n');
    lines.push(`| Metric | Value |`);
    lines.push(`|:-------|:------|`);
    lines.push(`| Total packages | ${summary.totalPackages} |`);
    lines.push(`| Vulnerable | ${summary.vulnerableCount} |`);
    lines.push(`| Clean | ${summary.cleanCount} |`);
    lines.push(`| Errors | ${summary.errorCount} |`);
    lines.push(`| Total vulns | ${summary.totalVulns} |`);
    lines.push(`| Worst severity | ${summary.worstSeverity ?? 'N/A'} |`);

    const vulnerable = result.results.filter((r) => r.vulnerable);
    if (vulnerable.length > 0) {
      lines.push(`\n## Vulnerable Packages\n`);
      for (const pkg of vulnerable) {
        lines.push(`### \`${pkg.name}\` @ \`${pkg.version}\` (${pkg.ecosystem})`);
        lines.push(`**Vulnerabilities: ${pkg.vulnCount}**`);
        for (const vuln of pkg.vulns) {
          const aliases =
            vuln.aliases.length > 0
              ? ` — **${vuln.aliases.map((a) => `\`${a}\``).join(', ')}**`
              : '';
          const sev = vuln.severityLabel ? ` [${vuln.severityLabel}]` : '';
          const fix =
            vuln.fixedVersions.length > 0 ? ` → fix: ${vuln.fixedVersions.join(', ')}` : '';
          lines.push(`- \`${vuln.id}\`${sev}${aliases}${fix}`);
          if (vuln.summary) {
            lines.push(`  <advisory_summary>${vuln.summary}</advisory_summary>`);
          }
        }
        lines.push('');
      }
    }

    const clean = result.results.filter((r) => !r.vulnerable && r.error === null);
    if (clean.length > 0) {
      lines.push(`\n## Clean Packages\n`);
      for (const pkg of clean) {
        lines.push(`- \`${pkg.name}\` @ \`${pkg.version}\` (${pkg.ecosystem}) — clean`);
      }
    }

    const errors = result.results.filter((r) => r.error !== null);
    if (errors.length > 0) {
      lines.push('\n## Errors\n');
      for (const pkg of errors) {
        lines.push(`- \`${pkg.name}\` @ \`${pkg.version}\` (${pkg.ecosystem}): ${pkg.error}`);
      }
    }

    return [{ type: 'text', text: lines.join('\n') }];
  },
});
