"""Change requests on disk: one directory per reviewed plan.

.tfminder/requests/<id>/
    request.json   metadata, status, decision, approvals
    tfplan         the binary plan that was reviewed; the only thing that can be applied
    plan.json      terraform show -json of that plan
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

STATUSES = ("reviewed", "pending", "approved", "rejected", "applying", "applied", "failed", "denied", "noop")


def now() -> datetime:
    return datetime.now(timezone.utc)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


@dataclass
class Request:
    id: str
    workspace: str
    environment: str
    status: str
    decision: str
    reasons: list[str]
    plan_sha256: str
    created_at: str
    created_by: str
    justification: str = ""
    counts: dict[str, int] = field(default_factory=dict)
    worst_severity: str | None = None
    approved_by: str = ""
    approved_at: str = ""
    expires_at: str = ""
    rejected_by: str = ""
    reject_reason: str = ""
    applied_at: str = ""
    error: str = ""
    scope: list[str] = field(default_factory=list)
    attestation_sha256: str = ""
    attestation_signed: bool = False
    converged: bool | None = None
    post_apply_changes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @property
    def approval_expired(self) -> bool:
        return bool(self.expires_at) and now() > datetime.fromisoformat(self.expires_at)


class StoreError(RuntimeError):
    pass


class Store:
    def __init__(self, data_dir: Path):
        self.dir = data_dir / "requests"

    def new_id(self) -> str:
        return now().strftime("%Y%m%d-%H%M%S-") + secrets.token_hex(3)

    def path(self, request_id: str) -> Path:
        if not request_id or "/" in request_id or "\\" in request_id or request_id.startswith("."):
            raise StoreError(f"invalid request id {request_id!r}")
        return self.dir / request_id

    def planfile(self, request_id: str) -> Path:
        return self.path(request_id) / "tfplan"

    def plan_json(self, request_id: str) -> Path:
        return self.path(request_id) / "plan.json"

    def create_dir(self, request_id: str) -> Path:
        p = self.path(request_id)
        p.mkdir(parents=True, exist_ok=False)
        return p

    def save(self, req: Request) -> None:
        target = self.path(req.id) / "request.json"
        tmp = target.with_suffix(".tmp")
        tmp.write_text(json.dumps(req.to_dict(), indent=2), encoding="utf-8")
        os.replace(tmp, target)

    def load(self, request_id: str) -> Request:
        target = self.path(request_id) / "request.json"
        if not target.exists():
            raise StoreError(f"no such request: {request_id}")
        data = json.loads(target.read_text(encoding="utf-8"))
        known = set(Request.__dataclass_fields__)
        return Request(**{k: v for k, v in data.items() if k in known})

    def all(self) -> list[Request]:
        if not self.dir.exists():
            return []
        out = []
        for d in sorted(self.dir.iterdir(), reverse=True):
            if (d / "request.json").exists():
                out.append(self.load(d.name))
        return out

    def verify_plan(self, req: Request) -> None:
        planfile = self.planfile(req.id)
        if not planfile.exists():
            raise StoreError(f"{req.id}: plan file is missing")
        actual = sha256_file(planfile)
        if actual != req.plan_sha256:
            raise StoreError(f"{req.id}: plan file changed after review (sha256 {actual[:12]} != {req.plan_sha256[:12]})")

    @staticmethod
    def expiry(minutes: int) -> str:
        return (now() + timedelta(minutes=minutes)).isoformat()
