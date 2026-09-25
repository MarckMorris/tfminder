"""The operations both the MCP server and the CLI call.

Status flow of a request:

    review ─┬─> noop
            ├─> denied                       (policy says no; nothing can apply it)
            └─> reviewed ─ request_apply ─┬─> pending ─ approve (human) ─> approved ─ apply ─> applied | failed
                                          │           └ reject (human) ─> rejected
                                          └─> approved (auto_apply and a clean plan)

Only the binary plan that was reviewed can ever be applied, and only while its
SHA-256 still matches the one recorded at review time.
"""

from __future__ import annotations

import json
import os
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from pyrrho.plan import Plan

from .audit import AuditLog
from .config import Config, Workspace
from .engine import Decision, evaluate
from .runner import Runner, RunnerError
from .store import Request, Store, StoreError, now, sha256_file


class ServiceError(RuntimeError):
    pass


class Service:
    def __init__(self, config: Config, runner: Runner | None = None):
        self.config = config
        self.runner = runner or Runner(config.binary, config.command_timeout)
        self.store = Store(config.data_dir)
        self.audit = AuditLog(config.data_dir / "audit.jsonl")
        config.data_dir.mkdir(parents=True, exist_ok=True)
        gitignore = config.data_dir / ".gitignore"
        if not gitignore.exists():
            # Plan files can contain secrets in clear text. Never commit them.
            gitignore.write_text("*\n", encoding="utf-8")

    # -- helpers --------------------------------------------------------------

    @contextmanager
    def _lock(self, ws: Workspace) -> Iterator[None]:
        lock = self.config.data_dir / f"{ws.name}.lock"
        try:
            fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError:
            raise ServiceError(f"workspace {ws.name!r} is busy (another plan or apply is running; "
                               f"remove {lock} if that process died)") from None
        try:
            os.write(fd, str(os.getpid()).encode())
            os.close(fd)
            yield
        finally:
            lock.unlink(missing_ok=True)

    def get(self, request_id: str) -> Request:
        try:
            return self.store.load(request_id)
        except StoreError as exc:
            raise ServiceError(str(exc)) from None

    def details(self, request_id: str) -> dict[str, Any]:
        req = self.get(request_id)
        evaluation = self.store.path(req.id) / "evaluation.json"
        out = req.to_dict()
        if evaluation.exists():
            data = json.loads(evaluation.read_text(encoding="utf-8"))
            out["findings"] = data.get("findings", [])
            out["changes"] = data.get("changes", [])
        return out

    # -- operations -------------------------------------------------------------

    def review(self, workspace: str, actor: str, justification: str = "", destroy: bool = False) -> dict[str, Any]:
        ws = self.config.workspace(workspace)
        with self._lock(ws):
            request_id = self.store.new_id()
            rdir = self.store.create_dir(request_id)
            planfile = self.store.planfile(request_id)
            try:
                if not (ws.path / ".terraform").exists():
                    self.runner.init(ws.path)
                result = self.runner.plan(ws.path, planfile, ws.var_files, destroy=destroy)
                plan_json = self.runner.show_json(ws.path, planfile)
            except RunnerError as exc:
                self.audit.append("plan_failed", actor, request_id, workspace=ws.name, error=str(exc))
                raise ServiceError(f"{exc}\n{exc.output}") from None
            self.store.plan_json(request_id).write_text(plan_json, encoding="utf-8")
            digest = sha256_file(planfile)
            plan = Plan.from_json(json.loads(plan_json), path=str(self.store.plan_json(request_id)), digest=digest)
            ev = evaluate(plan, ws.policy)
            (rdir / "evaluation.json").write_text(json.dumps(ev.to_dict(), indent=2), encoding="utf-8")
            status = {"noop": "noop", "deny": "denied"}.get(ev.decision.value, "reviewed")
            req = Request(
                id=request_id, workspace=ws.name, environment=ws.environment, status=status,
                decision=ev.decision.value, reasons=ev.reasons, plan_sha256=digest,
                created_at=now().isoformat(), created_by=actor, justification=justification,
                counts=ev.counts, worst_severity=ev.report.worst.value if ev.report.worst else None,
            )
            self.store.save(req)
            self.audit.append("reviewed", actor, request_id, workspace=ws.name, decision=req.decision,
                              plan_sha256=digest, counts=ev.counts, worst=req.worst_severity,
                              plan_exit=result.code, destroy=destroy)
        out = self.details(request_id)
        return out

    def request_apply(self, request_id: str, actor: str, justification: str) -> Request:
        req = self.get(request_id)
        if req.status != "reviewed":
            raise ServiceError(f"{req.id} is {req.status}; only a reviewed plan can be submitted")
        if not justification.strip():
            raise ServiceError("a justification is required")
        ws = self.config.workspace(req.workspace)
        req.justification = justification.strip()
        if req.decision == Decision.ALLOW.value and ws.policy.auto_apply:
            req.status = "approved"
            req.approved_by = "policy:auto_apply"
            req.approved_at = now().isoformat()
            req.expires_at = self.store.expiry(ws.policy.approval_ttl_minutes)
        else:
            req.status = "pending"
        self.store.save(req)
        self.audit.append("apply_requested", actor, req.id, justification=req.justification, status=req.status)
        return req

    def approve(self, request_id: str, actor: str) -> Request:
        req = self.get(request_id)
        if req.status not in ("pending", "reviewed"):
            raise ServiceError(f"{req.id} is {req.status}; only a reviewed or pending request can be approved")
        if req.decision == Decision.DENY.value:
            raise ServiceError(f"{req.id} was denied by policy and cannot be approved")
        self.store.verify_plan(req)
        ws = self.config.workspace(req.workspace)
        req.status = "approved"
        req.approved_by = actor
        req.approved_at = now().isoformat()
        req.expires_at = self.store.expiry(ws.policy.approval_ttl_minutes)
        self.store.save(req)
        self.audit.append("approved", actor, req.id, plan_sha256=req.plan_sha256, expires_at=req.expires_at)
        return req

    def reject(self, request_id: str, actor: str, reason: str) -> Request:
        req = self.get(request_id)
        if req.status not in ("pending", "approved", "reviewed"):
            raise ServiceError(f"{req.id} is {req.status}; nothing to reject")
        req.status = "rejected"
        req.rejected_by = actor
        req.reject_reason = reason
        self.store.save(req)
        self.audit.append("rejected", actor, req.id, reason=reason)
        return req

    def apply(self, request_id: str, actor: str) -> dict[str, Any]:
        req = self.get(request_id)
        if req.status != "approved":
            raise ServiceError(f"{req.id} is {req.status}; it must be approved by a human before apply")
        if req.approval_expired:
            raise ServiceError(f"{req.id}: approval expired at {req.expires_at}; review the plan again")
        try:
            self.store.verify_plan(req)
        except StoreError as exc:
            self.audit.append("apply_refused", actor, req.id, error=str(exc))
            raise ServiceError(str(exc)) from None
        ws = self.config.workspace(req.workspace)
        with self._lock(ws):
            req.status = "applying"
            self.store.save(req)
            self.audit.append("apply_started", actor, req.id, plan_sha256=req.plan_sha256)
            try:
                result = self.runner.apply(ws.path, self.store.planfile(req.id))
            except RunnerError as exc:
                req.status = "failed"
                req.error = f"{exc}\n{exc.output}"[-4000:]
                self.store.save(req)
                self.audit.append("apply_failed", actor, req.id, error=str(exc))
                raise ServiceError(req.error) from None
            req.status = "applied"
            req.applied_at = now().isoformat()
            self.store.save(req)
            self.audit.append("applied", actor, req.id, plan_sha256=req.plan_sha256)
        return {"request": req.to_dict(), "output": result.output}

    def drift(self, workspace: str, actor: str) -> dict[str, Any]:
        ws = self.config.workspace(workspace)
        if not ws.state or not ws.scope:
            raise ServiceError(f"workspace {ws.name!r} needs 'state' and 'scope' in .tfminder.yaml for drift scans")
        try:
            from strayform.diff import compare
            from strayform.imports import render_import_blocks
            from strayform.inventory import search
            from strayform.report import to_dict
            from strayform.rules import load_rules
            from strayform.state import load_managed
        except ImportError:
            raise ServiceError("drift scans need strayform: pip install 'tfminder[drift]'") from None
        scopes = [s if s.startswith(("projects/", "folders/", "organizations/")) else f"projects/{s}"
                  for s in ws.scope]
        managed = load_managed(ws.state)
        live = search(scopes)
        projects = {s.split("/", 1)[1] for s in scopes if s.startswith("projects/")}
        rules_file = self.config.root / ".strayform.yaml"
        rep = compare(live, managed, load_rules(str(rules_file)), projects or None)
        out = to_dict(rep)
        out["import_blocks"] = render_import_blocks(rep.unmanaged) if rep.unmanaged else ""
        self.audit.append("drift_scanned", actor, workspace=ws.name, summary=out["summary"])
        return out

    def workspaces(self) -> list[dict[str, Any]]:
        out = []
        for ws in self.config.workspaces.values():
            p = ws.policy
            out.append({
                "name": ws.name,
                "path": str(ws.path.relative_to(self.config.root)) if ws.path != self.config.root else ".",
                "environment": ws.environment,
                "drift_configured": bool(ws.state and ws.scope),
                "policy": {
                    "block_at": p.block_at.value, "approval_at": p.approval_at.value,
                    "max_destroy": p.max_destroy, "approval_on_destroy": p.approval_on_destroy,
                    "protected": list(p.protected), "deny_types": list(p.deny_types),
                    "auto_apply": p.auto_apply, "approval_ttl_minutes": p.approval_ttl_minutes,
                },
            })
        return out


def relative(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)
