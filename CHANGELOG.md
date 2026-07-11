# Changelog

All notable changes to this project. Each entry links to its full per-version file in [changelog/](changelog/).

## [0.1.11](changelog/0.1.x/0.1.11.md) — 2026-07-11

osv_get_vulnerability and osv_query_package no longer drop package-less GIT ranges or collapse multi-interval events; osv_get_vulnerability exposes withdrawn-advisory status; osv_query_package now follows OSV pagination and discloses truncation instead of returning false-clean results

## [0.1.10](changelog/0.1.x/0.1.10.md) — 2026-07-11 · 🛡️ Security

osv_query_package and osv_query_batch gain enrichment (empty-case notice + effective-query echo); batch error rows include the queried version; advisory summaries are framed behind <advisory_summary> boundaries as untrusted-data hardening; adopts @cyanheads/mcp-ts-core ^0.10.14

## [0.1.9](changelog/0.1.x/0.1.9.md) — 2026-06-30

server.json advertises OSV_BATCH_CONCURRENCY (default 10) in both packages' environmentVariables, matching OSV_REQUEST_TIMEOUT_MS — MCP Registry discovery parity for the batch-concurrency knob added in 0.1.8

## [0.1.8](changelog/0.1.x/0.1.8.md) — 2026-06-30

osv_query_batch drains per-package queries through a bounded worker pool (default 10, configurable via OSV_BATCH_CONCURRENCY) instead of up to 1000 concurrent requests; OSV_REQUEST_TIMEOUT_MS and the new cap are validated at startup; adopts @cyanheads/mcp-ts-core ^0.10.10

## [0.1.7](changelog/0.1.x/0.1.7.md) — 2026-06-30

osv_query_batch no longer rejects valid OSV ecosystems (static preflight removed); declared recovery hints now reach tool errors; content[] renders clean packages and all advisory references; stale osv_query tool-text references corrected

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
