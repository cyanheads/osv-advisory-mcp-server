# osv-advisory-mcp-server - Directory Structure

Generated on: 2026-09-24 17:03:36

```text
osv-advisory-mcp-server/
├── .claude-plugin/
│   └── plugin.json
├── .codex-plugin/
│   ├── mcp.json
│   └── plugin.json
├── .github/
│   ├── ISSUE_TEMPLATE/
│   │   ├── bug_report.yml
│   │   ├── config.yml
│   │   └── feature_request.yml
│   ├── workflows/
│   │   └── codeql.yml
│   ├── CODE_OF_CONDUCT.md
│   ├── CONTRIBUTING.md
│   ├── FUNDING.yml
│   └── SECURITY.md
├── .vscode/
│   ├── extensions.json
│   └── settings.json
├── changelog/
│   ├── 0.1.x/
│   └── template.md
├── docs/
│   ├── design.md
│   └── idea.md
├── framework-skills/
│   ├── add-app-tool/
│   │   └── SKILL.md
│   ├── add-prompt/
│   │   └── SKILL.md
│   ├── add-resource/
│   │   └── SKILL.md
│   ├── add-service/
│   │   └── SKILL.md
│   ├── add-test/
│   │   └── SKILL.md
│   ├── add-tool/
│   │   └── SKILL.md
│   ├── api-auth/
│   │   └── SKILL.md
│   ├── api-canvas/
│   │   └── SKILL.md
│   ├── api-config/
│   │   └── SKILL.md
│   ├── api-context/
│   │   └── SKILL.md
│   ├── api-errors/
│   │   └── SKILL.md
│   ├── api-linter/
│   │   └── SKILL.md
│   ├── api-mirror/
│   │   └── SKILL.md
│   ├── api-services/
│   │   ├── references/
│   │   │   ├── graph.md
│   │   │   ├── llm.md
│   │   │   └── speech.md
│   │   └── SKILL.md
│   ├── api-telemetry/
│   │   └── SKILL.md
│   ├── api-testing/
│   │   └── SKILL.md
│   ├── api-utils/
│   │   ├── references/
│   │   │   ├── formatting.md
│   │   │   ├── parsing.md
│   │   │   └── security.md
│   │   └── SKILL.md
│   ├── api-workers/
│   │   └── SKILL.md
│   ├── code-simplifier/
│   │   └── SKILL.md
│   ├── design-mcp-server/
│   │   └── SKILL.md
│   ├── field-test/
│   │   └── SKILL.md
│   ├── git-wrapup/
│   │   └── SKILL.md
│   ├── maintenance/
│   │   └── SKILL.md
│   ├── orchestrations/
│   │   ├── workflows/
│   │   │   ├── field-test-fix.md
│   │   │   ├── fix-wrapup-release.md
│   │   │   ├── greenfield-build.md
│   │   │   └── maintenance-release.md
│   │   └── SKILL.md
│   ├── polish-docs-meta/
│   │   ├── references/
│   │   │   ├── agent-protocol.md
│   │   │   ├── package-meta.md
│   │   │   ├── readme.md
│   │   │   └── server-json.md
│   │   └── SKILL.md
│   ├── release-and-publish/
│   │   └── SKILL.md
│   ├── release-pr-review/
│   │   └── SKILL.md
│   ├── report-issue-framework/
│   │   └── SKILL.md
│   ├── report-issue-local/
│   │   └── SKILL.md
│   ├── security-pass/
│   │   └── SKILL.md
│   ├── setup/
│   │   └── SKILL.md
│   ├── techniques/
│   │   ├── references/
│   │   │   └── outline-on-overflow.md
│   │   └── SKILL.md
│   └── tool-defs-analysis/
│       └── SKILL.md
├── scripts/
│   ├── build-changelog.ts
│   ├── build.ts
│   ├── check-dependency-specifiers.ts
│   ├── check-docs-sync.ts
│   ├── check-ecosystems.ts
│   ├── check-framework-antipatterns.ts
│   ├── check-skill-versions.ts
│   ├── check-skills-sync.ts
│   ├── clean-mcpb.ts
│   ├── clean.ts
│   ├── devcheck.ts
│   ├── lint-mcp.ts
│   ├── lint-packaging.ts
│   ├── list-skills.ts
│   ├── release-github.ts
│   └── tree.ts
├── src/
│   ├── config/
│   │   └── server-config.ts
│   ├── mcp-server/
│   │   ├── prompts/
│   │   │   └── definitions/
│   │   ├── resources/
│   │   │   └── definitions/
│   │   └── tools/
│   │       ├── definitions/
│   │       │   ├── index.ts
│   │       │   ├── osv-get-vulnerability.tool.ts
│   │       │   ├── osv-list-ecosystems.tool.ts
│   │       │   ├── osv-query-batch.tool.ts
│   │       │   └── osv-query-package.tool.ts
│   │       └── render-escape.ts
│   ├── services/
│   │   └── osv-api/
│   │       ├── affected-match.ts
│   │       ├── osv-api-service.ts
│   │       ├── severity.ts
│   │       └── types.ts
│   └── index.ts
├── tests/
│   ├── config/
│   │   └── server-config.test.ts
│   ├── fixtures/
│   │   └── osv/
│   │       ├── CVE-2025-31115.json
│   │       ├── CVE-2026-34743.json
│   │       ├── DEBIAN-CVE-2024-3094.json
│   │       ├── DEBIAN-CVE-2025-31115.json
│   │       ├── GHSA-29mw-wpgm-hmr9.json
│   │       ├── GHSA-2jv5-9r88-3w3p.json
│   │       ├── GHSA-6757-jp84-gxfx.json
│   │       ├── GHSA-rp9w-3fw7-7cwq.json
│   │       ├── HSEC-2023-0001.json
│   │       ├── OESA-2023-1092.json
│   │       ├── PYSEC-2022-190.json
│   │       ├── PYSEC-2022-304.json
│   │       ├── UBUNTU-CVE-2022-1271.json
│   │       ├── UBUNTU-CVE-2024-3094.json
│   │       └── UBUNTU-CVE-2025-31115.json
│   ├── helpers/
│   │   ├── argument-rejection.ts
│   │   ├── markdown.ts
│   │   └── osv-fixtures.ts
│   ├── prompts/
│   ├── resources/
│   ├── scripts/
│   │   └── check-ecosystems.test.ts
│   ├── services/
│   │   ├── affected-match.test.ts
│   │   └── osv-api-service.test.ts
│   └── tools/
│       ├── __snapshots__/
│       │   ├── osv-get-vulnerability.tool.test.ts.snap
│       │   ├── osv-query-batch.tool.test.ts.snap
│       │   └── osv-query-package.tool.test.ts.snap
│       ├── osv-get-vulnerability.tool.test.ts
│       ├── osv-list-ecosystems.tool.test.ts
│       ├── osv-query-batch.tool.test.ts
│       ├── osv-query-package.tool.test.ts
│       └── render-escape.test.ts
├── .dockerignore
├── .env.example
├── .gitattributes
├── .gitignore
├── .mcpbignore
├── AGENTS.md
├── biome.json
├── bun.lock
├── bunfig.toml
├── CHANGELOG.md
├── CITATION.cff
├── CLAUDE.md
├── devcheck.config.json
├── Dockerfile
├── LICENSE
├── manifest.json
├── package.json
├── README.md
├── server.json
├── tsconfig.build.json
├── tsconfig.json
└── vitest.config.ts
```

_Note: This tree excludes files and directories matched by .gitignore and default patterns._
