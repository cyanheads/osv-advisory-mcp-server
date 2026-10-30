---
name: osv-advisory-guide
description: Use osv_* tools to audit resolved dependencies or Git commits, retrieve oversized advisory results, and choose package-scoped remediation without mistaking incomplete coverage for a clean scan.
license: Apache-2.0
metadata:
  author: "cyanheads"
  version: "1.0"
---

## Scope

Use OSV for known vulnerabilities in exact resolved package versions or full Git commits. It is a public, keyless database lookup, not a source-code security review or proof that a dependency is safe. Resolve dependency ranges from a lockfile before auditing them.

## Identifiers

Take advisory IDs from `osv_query_package`, `osv_query_batch`, or `osv_query_commit` results and pass them to `osv_get_vulnerability`. CVE aliases identify the same reported vulnerability in another database; they are not extra findings to count.

Page paths and revisions come from the response being retrieved. Batch row indexes refer to the original input order, including failed rows.

## Gates

1. Before reporting an audit complete, account for every input row. Check row errors and upstream `truncated` flags; an errored or truncated row cannot establish a clean result. Cancellation is a failed call, not a completed scan.
2. Before drawing conclusions from an oversized reply, retrieve the omitted fields needed for the decision. A preview is incomplete. Transmission overflow and upstream truncation are independent: retrieving all transmitted pages does not recover upstream pages beyond the configured fetch cap.
3. Before recommending a fixed version, identify the affected interval and release line that contains the queried version. `fixedVersions` includes fixes for multiple intervals, in advisory order; it is not a sorted upgrade recommendation. Inspect ordered range events when the release line matters.
4. Keep package-scoped remediation attached to the original package query. A full advisory covers every affected package, and its severity may differ from the queried package's severity. A missing severity label is unknown, not low severity.

## Core chain

Audit resolved dependencies with `osv_query_batch`, then fetch full advisory records only where the remediation decision needs more detail. Keep the original row identity when relating an advisory to a dependency. For a single dependency use `osv_query_package`; retain that query when retrieving package-scoped fixes and severity.

## Workflows

**Retrieve an oversized result.** Repeat the original tool input with the announced `overflow.page`. Continue the same path using the returned next offset and revision until the next offset is null. Retrieve each deferred child separately from offset zero without the parent's revision. Reuse the announced advisory ID for package advisory pages. Do not pass an output page object back as a request. A stale revision requires restarting that node without a revision; pages are fresh lookups, not a historical snapshot.

**Inspect source revisions.** Use `osv_query_commit` for a full Git commit. Read GIT repositories and ordered events for source-level boundaries; a commit query has no package identity and supplies no package-specific fixed-version list. Switch to an exact package-version query when the task becomes choosing a dependency release.
