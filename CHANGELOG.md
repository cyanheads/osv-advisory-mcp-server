# Changelog

All notable changes to this project. Each entry links to its full per-version file in [changelog/](changelog/).

## [0.1.6](changelog/0.1.x/0.1.6.md) — 2026-06-20

Adopt mcp-ts-core ^0.10.9; vendored devcheck scripts gain the dependency-specifier guard and plugin-manifest packaging checks; codex-plugin longDescription filled

## [0.1.5](changelog/0.1.x/0.1.5.md) — 2026-06-12 · ⚠️ Breaking

Adopt mcp-ts-core ^0.10.6; invalid_ecosystem now returns ValidationError (-32007); Docker healthcheck + bundle cleaner

## [0.1.4](changelog/0.1.x/0.1.4.md) — 2026-06-04 · ⚠️ Breaking

BREAKING: rename osv_query → osv_query_package; callers must update tool name

## [0.1.3](changelog/0.1.x/0.1.3.md) — 2026-06-02

Adopt @cyanheads/mcp-ts-core 0.9.21 — HTTP log context fix, secret-stripping, and retry improvements

## [0.1.2](changelog/0.1.x/0.1.2.md) — 2026-05-31

Remove DataCanvas integration from osv_query_batch — canvas_id input/output and services/canvas accessor deleted

## [0.1.1](changelog/0.1.x/0.1.1.md) — 2026-05-30

Public hosted endpoint at https://osv-advisory.caseyjhand.com/mcp.

## [0.1.0](changelog/0.1.x/0.1.0.md) — 2026-05-30

Initial release — keyless OSV.dev vulnerability queries across 26 ecosystems with NVD bridging via CVE aliases.
