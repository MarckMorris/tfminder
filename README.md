# tfminder

[![CI](https://github.com/MarckMorris/tfminder/actions/workflows/ci.yml/badge.svg)](https://github.com/MarckMorris/tfminder/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-green.svg)](LICENSE)

**Let AI agents run Terraform without handing them the keys.**

tfminder sits between an agent (Claude, Cursor, Copilot, anything that speaks
[MCP](https://modelcontextprotocol.io)) and your infrastructure. The agent can
plan. It can ask. It cannot approve itself, cannot apply a plan nobody
reviewed, and cannot quietly apply something different from what was reviewed.

```
agent ──MCP──> review_plan ──> risk review + policy ──> allow / needs approval / deny
                                                              │
human ── tfminder approve <id> (terminal, typed confirmation) ┘
                                                              │
agent ──MCP──> apply_approved ──> applies the exact reviewed plan file (sha256-pinned)
                                                              │
everything ──> hash-chained audit log  ◄──────────────────────┘
```

Works with plain Terraform or OpenTofu, local or `gs://` state. No HCP account,
no SaaS, no agent-side credentials beyond what `terraform plan` already needs.

---

## Why

Terraform MCP servers make agents good at *writing* infrastructure code. The
hard part is the next step: letting the agent run it. The options today are
either read-only (safe, not very useful) or a flag that turns on writes with
nothing in between. Commercial platforms solve it inside their own control
plane. tfminder is that middle layer as a small open-source tool you run next
to your code.

## What an agent sees

A risky change, straight from the included example
([`examples/plans/gcp-risky.json`](examples/plans/gcp-risky.json)):

```
$ tfminder check examples/plans/gcp-risky.json
changes  create 2  update 2  delete 0  replace 0
  update                           google_compute_firewall.allow_ssh
  create                           google_storage_bucket_iam_member.reports_public
  update                           google_sql_database_instance.orders
  create                           google_pubsub_topic.events

CRITICAL GC001  Resource made public through IAM
         google_storage_bucket_iam_member.reports_public
         Grants roles/storage.objectViewer to allUsers: anyone on the internet.
CRITICAL GC006  Administrative or data port opened to the internet
         google_compute_firewall.allow_ssh
         Ingress from 0.0.0.0/0 now reaches 22/SSH
HIGH     RD004  Deletion protection removed
         google_sql_database_instance.orders
         deletion_protection goes from true to false. ...

decision DENY
```

Over MCP the agent gets the same data as JSON, plus a request id. A denied plan
cannot be submitted, approved or applied. The agent has to change the code.

A normal change, run for real against OpenTofu (`examples/local-lab`):

```
$ tfminder plan stack -j "ship api and worker"
request  20260925-163444-fbd46a   status: reviewed
changes  create 2  update 0  delete 0  replace 0
decision APPROVAL

$ tfminder approve 20260925-163444-fbd46a
Type fbd46a to approve applying this exact plan: fbd46a
approved 20260925-163444-fbd46a; valid until 2026-09-25T17:34:44+00:00

$ tfminder apply 20260925-163444-fbd46a
Apply complete! Resources: 2 added, 0 changed, 0 destroyed.

$ tfminder plan stack --destroy
decision DENY
  - plan destroys or replaces 2 resource(s); policy allows 1

$ tfminder audit verify
ok: 5 entries, chain intact, head a735bd68fe4c...
```

## How it decides

1. **Real plan.** `terraform plan -out` then `terraform show -json`. No parsing of HCL, no guessing.
2. **Risk review** with [pyrrho](https://github.com/MarckMorris/pyrrho)'s engine, which compares the
   planned state with the *prior* state, so a change is only blamed for what it changes. tfminder adds a
   `gcp-guard` analyzer for Google Cloud (below).
3. **Policy** from `.tfminder.yaml`, per environment and per workspace:

| Setting | Effect |
|---|---|
| `block_at` | Findings at or above this severity: **deny** |
| `approval_at` | Findings at or above this severity: a human must approve |
| `max_destroy` | More deletes + replacements than this: **deny** |
| `protected` | Address globs that may never be deleted or replaced |
| `deny_types` | Resource types an agent may never touch (e.g. `google_project_iam_policy`) |
| `approval_on_destroy` | Any delete/replace needs a human |
| `auto_apply` | Clean plans skip the human (off by default) |
| `approval_ttl_minutes` | Approvals expire |

4. **Apply** only if: a human approved it, the approval has not expired, the plan file's SHA-256 matches
   the one reviewed, and Terraform itself accepts the saved plan (it rejects stale plans if state moved).

## Google Cloud rules (`gcp-guard`)

| Rule | Severity | Catches |
|---|---|---|
| GC001 | critical | `allUsers` / `allAuthenticatedUsers` added to any `google_*_iam_member/binding/policy` |
| GC002 | high | `roles/owner` or `roles/editor` granted |
| GC003 | high | Escalation roles granted (token creator, SA user, IAM admin...) |
| GC004 | high | Authoritative `*_iam_policy` written (can remove every other binding) |
| GC005 | medium | Firewall ranges/ports unknown until apply |
| GC006 | critical | SSH, RDP, databases, etcd, kubelet... opened to `0.0.0.0/0` |
| GC007 | medium | Any other non-web port opened to the internet |
| GC009 | medium | Long-lived service account key created |
| GC010 | critical | BigQuery, Spanner, Bigtable, disks, KMS keys, Redis, Filestore, AlloyDB... destroyed or replaced |
| GC011 | high | GKE cluster, secret, log sink, VPC, DNS zone destroyed |
| GC012 | high | `deletion_protection` turned off (GKE, BigQuery, Spanner, instances...) |
| GC013–16 | high/medium | Bucket public access prevention removed, `force_destroy`, versioning off, retention removed |
| GC017–18 | critical/high | Cloud SQL open to `0.0.0.0/0`, backups disabled |
| GC019–20 | high | GKE private endpoint turned off, master authorized networks removed |

Cloud SQL and bucket destruction and Cloud SQL deletion protection come from pyrrho (`RD001`, `RD002`,
`RD004`). They are not duplicated here. pyrrho's AWS rules run too.

## MCP tools, by tier

| Tier | Tools |
|---|---|
| `read` | `list_workspaces`, `list_requests`, `get_request`, `drift_scan` |
| `plan` | + `review_plan`, `submit_for_approval` |
| `apply` | + `apply_approved` |

There is no approve or reject tool at any tier.

`drift_scan` uses [strayform](https://github.com/MarckMorris/strayform) to compare live GCP (Cloud Asset
Inventory) with state: resources created by hand, resources in state that no longer exist, IaC coverage,
and ready-to-paste `import {}` blocks. That closes the loop: tfminder watches what goes in through
Terraform, strayform finds what went in around it.

## Quick start

```bash
# pyrrho and strayform are not on PyPI yet, so install them first
pip install "git+https://github.com/MarckMorris/pyrrho@v0.2.1" "git+https://github.com/MarckMorris/strayform"
pip install "tfminder[drift] @ git+https://github.com/MarckMorris/tfminder"

cd your-infra-repo
tfminder init                 # writes .tfminder.yaml, one workspace per directory with .tf files
tfminder mcp-config           # prints the snippet for your MCP client
```

Claude Desktop / Claude Code (`claude mcp add` or the JSON config):

```json
{
  "mcpServers": {
    "tfminder": {
      "command": "tfminder",
      "args": ["serve"],
      "env": { "TFMINDER_CONFIG": "/path/to/repo/.tfminder.yaml", "TFMINDER_AGENT": "claude" }
    }
  }
}
```

Then ask the agent for a change. Review and approve in your terminal:

```bash
tfminder requests            # what is waiting
tfminder show <id>           # changes, findings, the agent's justification
tfminder approve <id>        # or: tfminder reject <id> -r "reason"
```

### In CI, without an agent

`tfminder check plan.json --workspace prod --format markdown` evaluates a plan JSON and exits `1` on deny
(`--strict` also exits `3` when approval is needed). See
[`examples/tfminder-pr-check.yml`](examples/tfminder-pr-check.yml) for a pull request check that
comments the verdict.

### Try it

- `examples/local-lab`: no cloud account needed. Uses the built-in `terraform_data` resource.
- `examples/gcp-lab`: a VPC, a firewall rule, a bucket and a topic. Pennies to run. Destroy it through
  tfminder when you are done.

## Security model

Read [docs/threat-model.md](docs/threat-model.md) before exposing `tier: apply`. The short version:
tfminder is a boundary only if the agent's **only** way to reach Terraform is tfminder. An agent with a
shell and your cloud credentials can run `terraform apply` itself.

## What is verified, and what is not

- **Verified:** unit tests for every rule and policy path; end to end against a real OpenTofu 1.10 binary
  (plan → approve → apply, stale plan refused, tampered plan file refused, destroy limits); the MCP server
  tested over stdio with the official client on both `mcp` 1.x and 2.x. CI runs the same suite against
  Terraform and OpenTofu.
- **Not yet verified:** the `gcp-guard` rules were written against the documented plan JSON format and
  provider schema, not captured from live `terraform plan` output against Google Cloud. The drift scan
  inherits strayform's status: it has not been run against a real project yet. Both are next.
- The audit log is tamper-evident, not tamper-proof. Ship it somewhere the agent cannot write.

## Development

```bash
pip install "git+https://github.com/MarckMorris/pyrrho@v0.2.1" "git+https://github.com/MarckMorris/strayform"
pip install -e ".[dev,drift]"
ruff check . && pytest        # e2e tests run when terraform or tofu is on PATH
```

## License

Apache-2.0
