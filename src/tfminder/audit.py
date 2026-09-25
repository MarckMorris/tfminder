"""Append-only, hash-chained audit log (JSON Lines).

Each entry carries the SHA-256 of the previous entry, so editing, deleting or
reordering any line breaks every hash after it. ``verify`` walks the chain.

This is tamper-evident, not tamper-proof: someone who can rewrite the whole
file can rebuild the chain. Ship the log (or just the head hash printed by
``tfminder audit head``) somewhere the agent cannot write, such as Cloud
Logging or a GCS bucket with a retention policy, to close that gap.
"""

from __future__ import annotations

import getpass
import hashlib
import json
import os
import socket
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

GENESIS = "0" * 64


def _digest(entry: dict[str, Any]) -> str:
    body = {k: v for k, v in entry.items() if k != "hash"}
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def human_identity() -> str:
    user = os.environ.get("TFMINDER_USER") or getpass.getuser()
    return f"{user}@{socket.gethostname()}"


@dataclass
class VerifyResult:
    ok: bool
    entries: int
    head: str
    error: str = ""


class AuditLog:
    def __init__(self, path: Path):
        self.path = path

    def _last_hash(self) -> str:
        if not self.path.exists():
            return GENESIS
        last = ""
        with self.path.open("rb") as fh:
            for line in fh:
                if line.strip():
                    last = line
        return json.loads(last)["hash"] if last else GENESIS

    def append(self, event: str, actor: str, request_id: str = "", **data: Any) -> dict[str, Any]:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "event": event,
            "actor": actor,
            "request_id": request_id,
            "data": data,
            "prev": self._last_hash(),
        }
        entry["hash"] = _digest(entry)
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, sort_keys=True) + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        return entry

    def entries(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        return [json.loads(line) for line in self.path.read_text(encoding="utf-8").splitlines() if line.strip()]

    def verify(self) -> VerifyResult:
        prev = GENESIS
        count = 0
        if not self.path.exists():
            return VerifyResult(True, 0, GENESIS)
        for n, line in enumerate(self.path.read_text(encoding="utf-8").splitlines(), start=1):
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                return VerifyResult(False, count, prev, f"line {n}: not valid JSON")
            if entry.get("prev") != prev:
                return VerifyResult(False, count, prev, f"line {n}: chain broken (prev hash does not match)")
            if _digest(entry) != entry.get("hash"):
                return VerifyResult(False, count, prev, f"line {n}: entry was modified (hash mismatch)")
            prev = entry["hash"]
            count += 1
        return VerifyResult(True, count, prev)
