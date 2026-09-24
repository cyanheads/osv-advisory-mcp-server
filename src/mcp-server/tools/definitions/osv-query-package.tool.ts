/**
 * @fileoverview Tool for querying vulnerabilities for a single package version via OSV.dev.
 * @module mcp-server/tools/definitions/osv-query-package
 */

import { tool, z } from '@cyanheads/mcp-ts-core';
import { JsonRpcErrorCode } from '@cyanheads/mcp-ts-core/errors';
import { escapeAdvisoryInline } from '@/mcp-server/tools/render-escape.js';
import { getOsvApiService } from '@/services/osv-api/osv-api-service.js';

const RangeEventSchema = z.object({
  type: z
    .string()
    .describe('Event boundary type: "introduced", "fixed", "last_affected", or "limit".'),
  value: z.string().describe('Version string or commit identifier at this boundary.'),
});

const AffectedRangeSchema = z.object({
  packageName: z
    .string()
    .describe(
      'Affected package name (may differ from queried name for umbrella advisories). Empty for source-only advisory ranges.',
    ),
  ecosystem: z
    .string()
    .describe('Affected package ecosystem. Empty for source-only advisory ranges.'),
  rangeType: z.string().describe('"SEMVER", "ECOSYSTEM", or "GIT".'),
  repo: z
    .string()
    .optional()
    .describe('Source repository URL for GIT ranges. Absent on version ranges.'),
  introduced: z
    .string()
    .optional()
    .describe('First affected version (convenience view — see events[]).'),
  fixed: z
    .string()
    .optional()
    .describe(
      'The last "fixed" event of this range (convenience view — a multi-interval range carries several; see events[]).',
    ),
  lastAffected: z
    .string()
    .optional()
    .describe(
      'Last affected version. Present when no fix exists (convenience view — see events[]).',
    ),
  events: z
    .array(RangeEventSchema.describe('One ordered range event.'))
    .optional()
    .describe(
      'Ordered event boundaries for this range — the loss-free view preserving multiple introduced/fixed pairs the scalar fields collapse.',
    ),
  versions: z
    .array(z.string().describe('An explicitly-listed affected version.'))
    .optional()
    .describe(
      'Explicit affected versions listed on this package entry. Absent or empty when affected versions are expressed only as ranges.',
    ),
});

const SeverityEntrySchema = z.object({
  type: z.string().describe('Severity type: "CVSS_V3", "CVSS_V4", "CVSS_V2", or "Ubuntu".'),
  score: z
    .string()
    .describe(
      'CVSS vector string (e.g. "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L"), or the Ubuntu priority (e.g. "medium") for type "Ubuntu".',
    ),
});

const SeveritySourceSchema = z
  .object({
    type: z
      .enum(['database_specific', 'Ubuntu', 'CVSS_V3', 'CVSS_V4'])
      .describe(
        'Source kind: the database_specific.severity label, an Ubuntu priority, or a CVSS vector.',
      ),
    score: z
      .string()
      .describe(
        'The published value the label came from: the database_specific.severity text, the Ubuntu priority, or the CVSS vector.',
      ),
    computedScore: z
      .number()
      .optional()
      .describe(
        'CVSS score computed from the vector as published: a CVSS 4.0 vector over every metric group it carries (threat and environmental included), a CVSS 3.x vector with its temporal metrics. Present only for CVSS sources.',
      ),
  })
  .nullable()
  .describe('The severity entry severityLabel was derived from. Null exactly when the label is.');

const VulnOutputSchema = z.object({
  id: z
    .string()
    .describe(
      'OSV vulnerability ID (e.g. "GHSA-29mw-wpgm-hmr9", "PYSEC-2024-1"). Pass to osv_get_vulnerability to retrieve the full advisory record.',
    ),
  summary: z.string().describe('One-line vulnerability description.'),
  aliases: z
    .array(z.string().describe('A CVE ID or other alias.'))
    .describe(
      'Alternative IDs — typically CVE IDs (e.g. ["CVE-2020-28500"]). ' +
        'Accepted by nist-nvd-mcp-server for CVSS scores, EPSS, and CISA KEV status.',
    ),
  severity: z
    .array(SeverityEntrySchema.describe('One record-level severity entry.'))
    .describe(
      'Record-level severity entries (CVSS vectors, Ubuntu priorities). Empty for advisories not yet scored and for advisories that score each affected package separately — severitySource then carries the queried package entry used.',
    ),
  severityLabel: z
    .string()
    .nullable()
    .describe(
      'Severity label ("LOW", "MODERATE", "HIGH", "CRITICAL") from the first source that yields one: database_specific.severity, an Ubuntu priority, then the highest CVSS v3/v4 score (0.1–3.9 LOW, 4.0–6.9 MODERATE, 7.0–8.9 HIGH, 9.0–10.0 CRITICAL). Uses the queried package\'s affected-level severity entries when the record-level list is empty. Null when no source yields a label.',
    ),
  severitySource: SeveritySourceSchema,
  fixedVersions: z
    .array(z.string().describe('A version that fixes the vulnerability for the queried package.'))
    .describe(
      "Every fixed version the advisory lists for the queried package, in record order. A multi-interval range contributes one per interval (typically one per release line); affectedRanges shows which interval each one closes. Excludes other packages' fixes and GIT commits. Empty when the advisory lists no fix for this package.",
    ),
  affectedRanges: z
    .array(AffectedRangeSchema.describe('One affected version range.'))
    .describe('Version ranges affected by this vulnerability.'),
  cweIds: z
    .array(z.string().describe('A CWE ID string.'))
    .describe(
      'CWE weakness IDs (e.g. ["CWE-79", "CWE-94"]). Populated on GHSA-sourced records; empty otherwise.',
    ),
  published: z.string().describe('ISO 8601 timestamp when the advisory was published.'),
  modified: z.string().describe('ISO 8601 timestamp of last modification.'),
});

export const osvQueryPackage = tool('osv_query_package', {
  description:
    'Query known vulnerabilities for a single package version across any supported ecosystem. ' +
    'Returns all matching OSV advisories with severity (CVSS vectors), CVE aliases, affected version ranges, ' +
    'and the fixed versions listed for the queried package. ' +
    'Use osv_list_ecosystems to validate the ecosystem string before querying — ecosystem strings are ' +
    'case-sensitive exact matches and an invalid value returns an error, not empty results.',
  annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: false },

  input: z.object({
    name: z
      .string()
      .trim()
      .regex(/\S/, 'Package name must not be blank — provide the exact package name.')
      .describe(
        'Package name as it appears in the ecosystem (e.g. "express", "requests", "serde"). Case-sensitive.',
      ),
    ecosystem: z
      .string()
      .trim()
      .regex(
        /\S/,
        'Ecosystem must not be blank — provide a valid ecosystem identifier (see osv_list_ecosystems).',
      )
      .describe(
        'Ecosystem identifier. Must be an exact match (case-sensitive). Use osv_list_ecosystems to see valid values. Examples: "npm", "PyPI", "crates.io", "Go", "Maven", "NuGet".',
      ),
    version: z
      .string()
      .trim()
      .regex(/\S/, 'Version must not be blank — provide the exact version string to check.')
      .describe(
        'Package version to check (e.g. "4.17.1", "3.1.4", "1.0.0"). Must be an exact version string, not a range.',
      ),
  }),

  output: z.object({
    vulns: z
      .array(VulnOutputSchema.describe('One vulnerability record.'))
      .describe(
        'Vulnerabilities matching this package version. An empty array means no known vulnerabilities ONLY when truncated is false.',
      ),
    truncated: z
      .boolean()
      .describe(
        'True when OSV returned more result pages than the fetch cap could follow — the vulnerability list may be INCOMPLETE. A truncated empty list is NOT a clean result; raise OSV_QUERY_MAX_PAGES or narrow the query.',
      ),
    queryMeta: z
      .object({
        package: z.string().describe('Queried package name.'),
        ecosystem: z.string().describe('Queried ecosystem.'),
        version: z.string().describe('Queried version.'),
        vulnCount: z.number().describe('Number of vulnerabilities found.'),
      })
      .describe('Query parameters as submitted.'),
  }),

  enrichment: {
    notice: z
      .string()
      .optional()
      .describe(
        'Present on the clean path — confirms no known vulnerabilities for the queried package.',
      ),
    effectiveQuery: z
      .string()
      .optional()
      .describe(
        'The package@version (ecosystem) tuple as queried, echoed for content-only clients.',
      ),
  },

  errors: [
    {
      reason: 'invalid_ecosystem',
      code: JsonRpcErrorCode.ValidationError,
      when: 'The ecosystem string is not recognized by OSV. Ecosystem names are case-sensitive exact matches.',
      recovery:
        'Call osv_list_ecosystems to see valid ecosystem strings, then retry with the correct value.',
    },
  ],

  async handler(input, ctx) {
    ctx.log.info('OSV query', {
      name: input.name,
      ecosystem: input.ecosystem,
      version: input.version,
    });
    const service = getOsvApiService();
    const result = await service.queryPackage(input.name, input.ecosystem, input.version, ctx);

    if (result.invalid) {
      throw ctx.fail(
        'invalid_ecosystem',
        `Ecosystem "${input.ecosystem}" is not recognized by OSV.`,
        { ...ctx.recoveryFor('invalid_ecosystem') },
      );
    }

    ctx.log.info('OSV query complete', {
      vulnCount: result.vulns.length,
      truncated: result.truncated,
    });

    if (result.vulns.length === 0) {
      // A truncated empty page is NOT a clean result — never emit the false-clean notice.
      ctx.enrich.notice(
        result.truncated
          ? `Results for ${input.name}@${input.version} (${input.ecosystem}) are INCOMPLETE — OSV paginated beyond the fetch cap before any page fully resolved. This is NOT a clean result; raise OSV_QUERY_MAX_PAGES or narrow the query.`
          : `No known vulnerabilities for ${input.name}@${input.version} (${input.ecosystem}).`,
      );
      ctx.enrich.echo(`${input.name}@${input.version} (${input.ecosystem})`);
    }

    return {
      vulns: result.vulns.map((v) => ({
        id: v.id,
        summary: v.summary,
        aliases: v.aliases,
        severity: v.severity,
        severityLabel: v.severityLabel,
        severitySource: v.severitySource,
        fixedVersions: v.fixedVersions,
        affectedRanges: v.affectedRanges,
        cweIds: v.cweIds,
        published: v.published,
        modified: v.modified,
      })),
      truncated: result.truncated,
      queryMeta: {
        package: input.name,
        ecosystem: input.ecosystem,
        version: input.version,
        vulnCount: result.vulns.length,
      },
    };
  },

  format: (result) => {
    const lines: string[] = [];
    const { queryMeta } = result;
    lines.push(
      `**Package:** \`${queryMeta.package}\` @ \`${queryMeta.version}\` (${queryMeta.ecosystem}) — ${queryMeta.vulnCount} vuln(s)\n`,
    );

    if (result.vulns.length === 0) {
      lines.push(
        result.truncated
          ? '⚠️ **Results truncated** — OSV returned additional pages beyond the fetch cap. This is NOT a confirmed clean result; more vulnerabilities may exist. Raise OSV_QUERY_MAX_PAGES or narrow the query.'
          : '✅ No known vulnerabilities found.',
      );
      return [{ type: 'text', text: lines.join('\n') }];
    }

    lines.push(`**Vulnerabilities found: ${result.vulns.length}**\n`);
    if (result.truncated) {
      lines.push(
        '⚠️ **Results truncated** — more advisory pages exist beyond the fetch cap; this list may be incomplete.\n',
      );
    }

    // Every OSV-sourced string passes through the render escape; queryMeta echoes caller input.
    const esc = escapeAdvisoryInline;
    const list = (values: string[]) => values.map(esc).join(', ');
    for (const vuln of result.vulns) {
      lines.push(`## ${esc(vuln.id)}`);
      if (vuln.aliases.length > 0) {
        lines.push(`**Aliases:** ${vuln.aliases.map((a) => `\`${esc(a)}\``).join(', ')}`);
      }
      const source = vuln.severitySource;
      const basis = source
        ? ` (from ${esc(source.type)} \`${esc(source.score)}\`${source.computedScore !== undefined ? `, computed score ${source.computedScore}` : ''})`
        : '';
      lines.push(`**Severity:** ${esc(vuln.severityLabel ?? 'N/A')}${basis}`);
      for (const s of vuln.severity) {
        lines.push(`- ${esc(s.type)}: \`${esc(s.score)}\``);
      }
      if (vuln.summary) {
        lines.push(`**Summary:**\n<advisory_summary>\n${esc(vuln.summary)}\n</advisory_summary>`);
      }
      lines.push(
        vuln.fixedVersions.length > 0
          ? `**Fix:** Fixed in ${list(vuln.fixedVersions)}`
          : '**Fix:** No fixed version listed for this package — see affected ranges.',
      );
      if (vuln.affectedRanges.length > 0) {
        lines.push('**Affected ranges:**');
        for (const r of vuln.affectedRanges) {
          const intro = r.introduced !== undefined ? `introduced: ${esc(r.introduced)}` : '';
          const fix = r.fixed !== undefined ? `fixed: ${esc(r.fixed)}` : '';
          const last = r.lastAffected !== undefined ? `last_affected: ${esc(r.lastAffected)}` : '';
          const scalar = [intro, fix, last].filter(Boolean).join(', ');
          const repoStr = r.repo ? ` repo: ${esc(r.repo)}` : '';
          const pkgLabel = r.packageName
            ? `\`${esc(r.packageName)}\` (${esc(r.ecosystem)})`
            : '_source range_';
          lines.push(`- ${pkgLabel} [${esc(r.rangeType)}]${repoStr}: ${scalar || 'no events'}`);
          if (r.events && r.events.length > 0) {
            lines.push(
              `  - events: ${r.events.map((e) => `${esc(e.type)}=${esc(e.value)}`).join(' → ')}`,
            );
          }
          if (r.versions && r.versions.length > 0) {
            lines.push(`  - versions: ${list(r.versions)}`);
          }
        }
      }
      if (vuln.cweIds.length > 0) {
        lines.push(`**CWE:** ${list(vuln.cweIds)}`);
      }
      lines.push(`**Published:** ${esc(vuln.published)} | **Modified:** ${esc(vuln.modified)}`);
      lines.push('');
    }

    return [{ type: 'text', text: lines.join('\n') }];
  },
});
