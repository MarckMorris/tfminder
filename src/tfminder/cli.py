"""tfminder command line: the human side of the approval loop, plus CI checks."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from pathlib import Path
from typing import Any, Sequence

from pyrrho import baseline as pyrrho_baseline
from pyrrho import sarif as pyrrho_sarif
from pyrrho.plan import PlanFormatError
from pyrrho.plan import load as load_plan

from . import __version__
from .audit import human_identity
from .config import Config, ConfigError, Policy, load
from .engine import Decision, evaluate
from .service import Service, ServiceError

SAMPLE = """\
# tfminder configuration. Docs: https://github.com/MarckMorris/tfminder
version: 1

# What an AI agent may do through the MCP server: read | plan | apply
tier: plan

# local: the MCP server runs terraform (needs cloud credentials)
# worker: `tfminder worker`, started by a person, runs it; the agent's process holds no credentials
executor: local

# terraform or tofu (auto-detected when omitted)
# binary: terraform

policy:
  block_at: critical        # findings at or above this: denied, no human can override through tfminder
  approval_at: low          # findings at or above this: a human must approve
  approval_on_destroy: true
  auto_apply: false         # true: clean plans (no findings, no destroys) skip the human
  approval_ttl_minutes: 60
  require_scope: false      # true: the agent must declare which addresses it means to change
  deny_out_of_scope: true   # a plan that touches more than the declared scope is denied
  verify_after_apply: true  # re-plan after apply and record whether it converged
  deny_types:
    - google_project_iam_policy
    - google_organization_iam_policy

environments:
  production:
    max_destroy: 0
    approval_at: info
    protected:
      - "google_sql_database_instance.*"
      - "google_storage_bucket.*"

workspaces:
{workspaces}
"""


def _print(data: Any) -> None:
    print(json.dumps(data, indent=2, default=str))


def _config(args: argparse.Namespace) -> Config:
    return load(Path(args.config) if args.config else None)


SEV_COLOR = {"critical": "\033[1;31m", "high": "\033[31m", "medium": "\033[33m", "low": "\033[36m", "info": ""}
DEC_COLOR = {"deny": "\033[1;31m", "approval": "\033[33m", "allow": "\033[32m", "noop": "\033[2m"}


def _c(text: str, code: str) -> str:
    if not code or not sys.stdout.isatty() or os.environ.get("NO_COLOR"):
        return text
    return f"{code}{text}\033[0m"


def render(detail: dict[str, Any]) -> str:
    lines = []
    head = detail.get("id", "")
    status = detail.get("status")
    lines.append(f"request  {head}" + (f"   status: {status}" if status else ""))
    if detail.get("workspace"):
        env = f" ({detail['environment']})" if detail.get("environment") else ""
        lines.append(f"workspace {detail['workspace']}{env}")
    counts = detail.get("counts") or {}
    if counts:
        lines.append("changes  " + "  ".join(f"{k} {v}" for k, v in counts.items()))
    for ch in detail.get("changes", [])[:50]:
        lines.append(f"  {ch['action']:<32} {ch['address']}")
    findings = detail.get("findings") or []
    if findings:
        lines.append("")
    for f in findings:
        sev = f["severity"]
        tag = "  (accepted by baseline)" if f.get("suppressed") else ""
        lines.append(_c(f"{sev.upper():<8} {f['rule_id']}  {f['title']}{tag}", SEV_COLOR.get(sev, "")))
        lines.append(f"         {f['resource']}")
        lines.append(f"         {f['detail']}")
    lines.append("")
    dec = detail.get("decision", "")
    lines.append(_c(f"decision {dec.upper()}", DEC_COLOR.get(dec, "")))
    for r in detail.get("reasons", []):
        lines.append(f"  - {r}")
    if detail.get("justification"):
        lines.append(f"justification: {detail['justification']}")
    if detail.get("approved_by"):
        lines.append(f"approved by {detail['approved_by']} at {detail['approved_at']} (expires {detail['expires_at']})")
    if detail.get("scope"):
        lines.append("scope    " + ", ".join(detail["scope"]))
    if detail.get("suppressed"):
        lines.append(f"baseline {len(detail['suppressed'])} finding(s) accepted by baseline")
    if detail.get("stale_baseline"):
        lines.append(f"baseline {len(detail['stale_baseline'])} stale entr(ies) no longer match anything; prune them")
    if detail.get("converged") is True:
        lines.append(_c("converged: a plan after apply shows no changes", DEC_COLOR["allow"]))
    elif detail.get("converged") is False:
        lines.append(_c("NOT CONVERGED: changes remain after apply", DEC_COLOR["deny"]))
        for r in detail.get("post_apply_changes", [])[:20]:
            lines.append(f"  - {r}")
    if detail.get("error"):
        lines.append("error:\n" + detail["error"])
    return "\n".join(lines)


def to_markdown(ev: dict[str, Any]) -> str:
    icon = {"deny": "⛔", "approval": "🟡", "allow": "✅", "noop": "➖"}[ev["decision"]]
    out = [f"## {icon} tfminder: {ev['decision'].upper()}", ""]
    c = ev["counts"]
    out.append(f"**Changes:** {c['create']} create, {c['update']} update, {c['delete']} delete, "
               f"{c['replace']} replace")
    out.append("")
    if ev["reasons"]:
        out.append("**Why**")
        out.extend(f"- {r}" for r in ev["reasons"])
        out.append("")
    if ev["findings"]:
        out.append("| Severity | Rule | Resource | Finding |")
        out.append("|---|---|---|---|")
        for f in ev["findings"]:
            detail = f["detail"].replace("|", "\\|")
            out.append(f"| {f['severity']} | {f['rule_id']} | `{f['resource']}` | {f['title']}: {detail} |")
    return "\n".join(out) + "\n"


# -- commands -----------------------------------------------------------------

def cmd_init(args: argparse.Namespace) -> int:
    target = Path(".tfminder.yaml")
    if target.exists() and not args.force:
        print(".tfminder.yaml already exists (use --force to overwrite)", file=sys.stderr)
        return 1
    dirs = sorted({p.parent for p in Path(".").rglob("*.tf") if ".terraform" not in p.parts})
    if not dirs:
        dirs = [Path(".")]
    entries = []
    for d in dirs:
        name = "root" if str(d) == "." else str(d).replace(os.sep, "-")
        entries.append(f"  - name: {name}\n    path: {d.as_posix()}\n    environment: \"\"")
    target.write_text(SAMPLE.format(workspaces="\n".join(entries)), encoding="utf-8")
    print(f"wrote {target} with {len(entries)} workspace(s); review the policy before exposing it to an agent")
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    """Evaluate an existing plan JSON (CI mode): no terraform run, no state written."""
    policy = Policy()
    if args.workspace or args.config or Path(".tfminder.yaml").exists():
        cfg = _config(args)
        name = args.workspace or next(iter(cfg.workspaces))
        policy = cfg.workspace(name).policy
    try:
        plan = load_plan(args.plan)
    except PlanFormatError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    suppressed: set[str] = set()
    if args.baseline:
        try:
            suppressed = pyrrho_baseline.load(args.baseline)
        except pyrrho_baseline.BaselineError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
    result = evaluate(plan, policy, scope=args.scope, baseline=suppressed)
    ev = result.to_dict()
    if args.sarif:
        Path(args.sarif).write_text(pyrrho_sarif.dumps(result.report, location=args.sarif_location),
                                    encoding="utf-8")
    if args.format == "json":
        _print(ev)
    elif args.format == "markdown":
        print(to_markdown(ev), end="")
    else:
        print(render(ev))
    if ev["decision"] == Decision.DENY.value:
        return 1
    if args.strict and ev["decision"] == Decision.APPROVAL.value:
        return 3
    return 0


def cmd_plan(args: argparse.Namespace) -> int:
    svc = Service(_config(args))
    detail = svc.review(args.workspace, f"human:{human_identity()}", args.justification or "", args.destroy,
                        args.scope)
    _print(detail) if args.json else print(render(detail))
    return 1 if detail["decision"] == "deny" else 0


def cmd_requests(args: argparse.Namespace) -> int:
    svc = Service(_config(args))
    reqs = svc.store.all()
    if not args.all:
        reqs = [r for r in reqs if r.status in ("pending", "approved", "reviewed")]
    if args.json:
        _print([r.to_dict() for r in reqs])
        return 0
    if not reqs:
        print("no open requests" if not args.all else "no requests")
        return 0
    for r in reqs:
        print(f"{r.id}  {r.status:<9} {r.decision:<8} {r.workspace:<16} worst={r.worst_severity or '-':<8} "
              f"{r.created_by}")
    return 0


def cmd_show(args: argparse.Namespace) -> int:
    svc = Service(_config(args))
    detail = svc.details(args.id)
    _print(detail) if args.json else print(render(detail))
    return 0


def cmd_approve(args: argparse.Namespace) -> int:
    svc = Service(_config(args))
    req = svc.get(args.id)
    interactive = sys.stdin.isatty()
    if not interactive and os.environ.get("TFMINDER_NONINTERACTIVE_APPROVAL") != "1":
        print("refusing to approve without a terminal. Approval is a human decision; for CI approvals "
              "(for example a protected GitHub environment) set TFMINDER_NONINTERACTIVE_APPROVAL=1.",
              file=sys.stderr)
        return 1
    print(render(svc.details(args.id)))
    if interactive and not args.yes:
        code = req.id[-6:]
        answer = input(f"\nType {code} to approve applying this exact plan: ").strip()
        if answer != code:
            print("not approved")
            return 1
    req = svc.approve(args.id, f"human:{human_identity()}")
    print(f"approved {req.id}; valid until {req.expires_at}")
    return 0


def cmd_reject(args: argparse.Namespace) -> int:
    svc = Service(_config(args))
    req = svc.reject(args.id, f"human:{human_identity()}", args.reason)
    print(f"rejected {req.id}")
    return 0


def cmd_apply(args: argparse.Namespace) -> int:
    svc = Service(_config(args))
    result = svc.apply(args.id, f"human:{human_identity()}")
    print(result["output"])
    print(f"applied {args.id}")
    return 0


def cmd_audit(args: argparse.Namespace) -> int:
    svc = Service(_config(args))
    if args.action == "verify":
        res = svc.audit.verify()
        if res.ok:
            print(f"ok: {res.entries} entries, chain intact, head {res.head}")
            return 0
        print(f"TAMPERED: {res.error} (after {res.entries} valid entries)", file=sys.stderr)
        return 1
    if args.action == "head":
        print(svc.audit.verify().head)
        return 0
    for e in svc.audit.entries()[-args.n:]:
        print(f"{e['ts']}  {e['event']:<16} {e['actor']:<28} {e['request_id']}")
    return 0


def cmd_drift(args: argparse.Namespace) -> int:
    svc = Service(_config(args))
    out = svc.drift(args.workspace, f"human:{human_identity()}")
    if args.imports and out["import_blocks"]:
        Path(args.imports).write_text(out["import_blocks"], encoding="utf-8")
    blocks = out.pop("import_blocks")
    _print(out)
    if args.imports and blocks:
        print(f"wrote import blocks to {args.imports}", file=sys.stderr)
    return 2 if (out["unmanaged"] or out["ghosts"]) and args.fail_on_drift else 0


def cmd_baseline(args: argparse.Namespace) -> int:
    svc = Service(_config(args))
    doc = svc.baseline_from(args.id, args.note or "")
    if args.output:
        Path(args.output).write_text(doc + "\n", encoding="utf-8")
        print(f"wrote {args.output}; point a workspace's 'baseline:' at it to accept these findings")
    else:
        print(doc)
    return 0


def cmd_worker(args: argparse.Namespace) -> int:
    from .worker import run_worker

    svc = Service(_config(args))
    try:
        run_worker(svc, once=args.once)
    except KeyboardInterrupt:
        print("worker stopped")
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    from .server import serve

    serve(_config(args))
    return 0


def cmd_mcp_config(args: argparse.Namespace) -> int:
    cfg = _config(args)
    exe = shutil.which("tfminder") or "tfminder"
    _print({"mcpServers": {"tfminder": {
        "command": exe, "args": ["serve"],
        "env": {"TFMINDER_CONFIG": str(cfg.root / ".tfminder.yaml"), "TFMINDER_AGENT": "claude"},
    }}})
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="tfminder", description="Supervise AI agents that run Terraform.")
    p.add_argument("--version", action="version", version=f"tfminder {__version__}")
    p.add_argument("--config", help="path to .tfminder.yaml (default: search upwards, or $TFMINDER_CONFIG)")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("init", help="write a starter .tfminder.yaml")
    s.add_argument("--force", action="store_true")
    s.set_defaults(fn=cmd_init)

    s = sub.add_parser("check", help="evaluate a plan JSON against policy (CI; runs nothing)")
    s.add_argument("plan")
    s.add_argument("--workspace", help="use this workspace's policy")
    s.add_argument("--format", choices=("text", "json", "markdown"), default="text")
    s.add_argument("--strict", action="store_true", help="exit 3 when approval is required")
    s.add_argument("--scope", action="append", help="address glob this change is meant to touch (repeatable)")
    s.add_argument("--baseline", help="pyrrho baseline file of accepted findings")
    s.add_argument("--sarif", help="also write SARIF 2.1.0 here (GitHub code scanning)")
    s.add_argument("--sarif-location", help="repository path to anchor SARIF alerts to (e.g. infra/main.tf)")
    s.set_defaults(fn=cmd_check)

    s = sub.add_parser("plan", help="run terraform plan in a workspace and create a request")
    s.add_argument("workspace")
    s.add_argument("--justification", "-j")
    s.add_argument("--destroy", action="store_true")
    s.add_argument("--scope", action="append", help="address glob this change is meant to touch (repeatable)")
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_plan)

    s = sub.add_parser("requests", help="list open requests")
    s.add_argument("--all", action="store_true")
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_requests)

    s = sub.add_parser("show", help="show a request")
    s.add_argument("id")
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_show)

    s = sub.add_parser("approve", help="approve a pending request (human only)")
    s.add_argument("id")
    s.add_argument("--yes", action="store_true", help="skip the typed confirmation")
    s.set_defaults(fn=cmd_approve)

    s = sub.add_parser("reject", help="reject a request")
    s.add_argument("id")
    s.add_argument("--reason", "-r", required=True)
    s.set_defaults(fn=cmd_reject)

    s = sub.add_parser("apply", help="apply an approved request")
    s.add_argument("id")
    s.set_defaults(fn=cmd_apply)

    s = sub.add_parser("audit", help="inspect or verify the audit log")
    s.add_argument("action", choices=("log", "verify", "head"), nargs="?", default="log")
    s.add_argument("-n", type=int, default=30)
    s.set_defaults(fn=cmd_audit)

    s = sub.add_parser("drift", help="find ClickOps and ghosts in GCP (needs tfminder[drift])")
    s.add_argument("workspace")
    s.add_argument("--imports", help="write import {} blocks to this file")
    s.add_argument("--fail-on-drift", action="store_true")
    s.set_defaults(fn=cmd_drift)

    s = sub.add_parser("baseline", help="write a pyrrho baseline accepting a request's findings")
    s.add_argument("id")
    s.add_argument("--output", "-o")
    s.add_argument("--note")
    s.set_defaults(fn=cmd_baseline)

    s = sub.add_parser("worker", help="execute plans/applies queued by the MCP server (executor: worker)")
    s.add_argument("--once", action="store_true", help="process the queue once and exit")
    s.set_defaults(fn=cmd_worker)

    s = sub.add_parser("serve", help="run the MCP server on stdio")
    s.set_defaults(fn=cmd_serve)

    s = sub.add_parser("mcp-config", help="print the MCP client config snippet")
    s.set_defaults(fn=cmd_mcp_config)
    return p


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.fn(args)
    except (ConfigError, ServiceError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130
