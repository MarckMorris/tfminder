# Changelog

## 0.2.0

Deeper use of pyrrho and strayform, so tfminder is one control loop instead of three tools.

- **Declared scope.** `review_plan(scope=[...])` / `--scope`: the agent states which addresses it means to
  change; pyrrho's RD007 flags anything else in the plan, and tfminder denies it by default
  (`deny_out_of_scope`). `require_scope: true` makes the declaration mandatory.
- **Signed review attestations.** Every review writes a pyrrho attestation (HMAC-signed when
  `TFMINDER_ATTEST_KEY` is set). Approve and apply refuse if it was modified or its signature fails.
- **Convergence check.** After apply, tfminder plans again and records whether the infrastructure converged
  (`verify_after_apply`, on by default). Non-convergent applies are flagged in the request and the audit log.
- **Baselines.** Per-workspace `baseline:` using pyrrho's format; `tfminder baseline <id>` writes one from a
  request. Accepted findings stay visible; stale entries are reported.
- **SARIF + GitHub Action.** `tfminder check --sarif` and `uses: MarckMorris/tfminder@v0` with PR comment,
  job summary and code-scanning upload.
- **Windows fix.** Terraform providers failed with "Plugin did not respond" when an MCP client started
  tfminder with a stripped environment; the runner now restores SYSTEMROOT, TEMP and friends.

## 0.1.1

- Fix GC005 false positive: Terraform marks known list elements as `false` in `after_unknown`. Found by running
  against a real plan of `examples/gcp-lab`, which is now a test fixture.

## 0.1.0

- Initial release: MCP server + CLI, risk review (pyrrho + gcp-guard), policy gate, human approval,
  sha256-pinned plans, hash-chained audit log, drift scan through strayform.
