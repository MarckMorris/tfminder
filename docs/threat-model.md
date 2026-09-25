# Threat model

## What tfminder protects against

| Risk | Control |
|---|---|
| Agent applies a change nobody looked at | No apply without a human approval of that request |
| Agent approves its own change | No approve tool over MCP; the CLI refuses to approve without a terminal and asks for a typed code |
| Agent swaps the plan after approval | Apply uses the stored plan file only if its SHA-256 matches the reviewed one |
| Approved plan applied days later on a changed world | Approvals expire (`approval_ttl_minutes`); Terraform rejects saved plans once state has moved |
| Obviously dangerous change slips through review fatigue | `block_at`, `max_destroy`, `protected` and `deny_types` deny outright; approval cannot override a deny |
| Nobody can say who did what | Every review, approval, rejection and apply is written to a hash-chained audit log with the actor |
| Resources created around Terraform | `drift_scan` (strayform) reports ClickOps and ghosts |

| Agent forges an approval by editing `.tfminder/` | Approvals are HMAC-signed with `TFMINDER_APPROVAL_KEY`, which only the human's terminal has. Apply refuses unsigned or altered approvals. The worker will not start without the key |
| Agent runs code through `review_plan` itself | `terraform plan` executes `data "external"` programs and provider binaries. tfminder refuses to plan configurations with `data "external"` or provisioners (`allow_external_programs: false`) and, with `allowed_providers`, any provider not on the list |
| Agent weakens policy or baselines on disk | The worker loads `.tfminder.yaml` and baselines once, when a person starts it; later edits have no effect until a person restarts it |
| Path tricks through request ids | Ids must match the exact generated shape (no `..`, no `C:` drive-relative names) |
| Agent impersonates a human in the audit log | Jobs are always recorded as `agent:...`, and job arguments are allow-listed per operation |

## What it does not protect against

- **An agent with a shell and credentials.** If the agent can run `terraform apply`, `gcloud`, or
  `tfminder approve` in a pseudo-terminal, tfminder is advice, not a boundary. Give the agent tfminder's
  MCP tools and nothing that reaches the cloud directly. With Claude Code, deny `Bash(terraform:*)`,
  `Bash(tofu:*)`, `Bash(gcloud:*)` and `Bash(tfminder approve:*)` in settings.
- **Setups without the approval key.** With `executor: local` and no `TFMINDER_APPROVAL_KEY`, approvals are a
  field in a file. That is only safe if the agent cannot write to `.tfminder/`. Use `executor: worker` with
  the key for any real environment.
- **The static scan is not a sandbox.** It reads configuration text and modules already downloaded. A
  provider that is itself malicious still runs during plan: pin providers with `allowed_providers` and a
  committed `.terraform.lock.hcl`.
- **Credentials in the agent's host.** With the default `executor: local` the MCP server process runs
  Terraform and needs cloud credentials. Use `executor: worker` so only `tfminder worker`, started by a
  person, holds them.
- **Over-privileged credentials.** tfminder runs Terraform with whatever credentials are in its
  environment. Use a plan-only identity for `tier: plan`; give apply rights only to the identity that runs
  `tfminder serve` at `tier: apply`, ideally short-lived (Workload Identity Federation, impersonation).
- **Someone rewriting the whole audit log.** The chain detects edits, deletions and reordering, but a
  writer with full access can rebuild it. Export entries or the head hash (`tfminder audit head`) to a
  location the agent cannot write, such as a GCS bucket with a retention policy.
- **Secrets in plan files.** `.tfminder/` contains binary plans and plan JSON, which can include
  sensitive values in clear text. tfminder writes a `.gitignore` there; keep the directory out of
  anything shared.
- **Rules it does not have.** A clean review means the configured analyzers found nothing, not that the
  change is safe. Keep `approval_at` low for production.
