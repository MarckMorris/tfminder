"""Split execution: the MCP server queues work, a worker the human runs executes it.

With ``executor: worker`` in .tfminder.yaml the process the agent's client starts never runs
Terraform and never needs cloud credentials. It writes a job file and waits. ``tfminder worker``,
started by a person in their own terminal with their own credentials, picks the job up, runs it
through the same Service (policy, attestation, approval checks all still apply) and writes the result.

Why it exists:
- the agent host holds no cloud credentials at all, not even inside the tfminder process it spawned;
- some MCP hosts run servers in sandboxes where Terraform's provider plugins cannot start
  (seen on Windows with the Microsoft Store build of Claude Desktop: the provider's loopback mTLS
  handshake fails). The worker runs in a normal terminal, so that does not apply.

Jobs are files under .tfminder/jobs/. A worker claims one by renaming it, so two workers never run
the same job. Only two operations exist, review and apply, and both go through Service, which is
where every rule is enforced. Writing a job file by hand gains nothing a tool call would not.
"""

from __future__ import annotations

import json
import os
import secrets
import time
import traceback
from pathlib import Path
from typing import Any, Callable

OPERATIONS = ("review", "apply", "drift", "submit")
ALLOWED_KWARGS = {
    "review": {"workspace", "justification", "destroy", "scope"},
    "apply": {"request_id"},
    "drift": {"workspace"},
    "submit": {"request_id", "justification"},
}
POLL_SECONDS = 0.5


class WorkerError(RuntimeError):
    pass


class JobQueue:
    def __init__(self, data_dir: Path):
        self.dir = data_dir / "jobs"

    def _job(self, job_id: str) -> Path:
        return self.dir / f"{job_id}.job.json"

    def _result(self, job_id: str) -> Path:
        return self.dir / f"{job_id}.result.json"

    def submit(self, op: str, kwargs: dict[str, Any], actor: str) -> str:
        if op not in OPERATIONS:
            raise WorkerError(f"unknown operation {op!r}")
        self.dir.mkdir(parents=True, exist_ok=True)
        job_id = time.strftime("%Y%m%d-%H%M%S-") + secrets.token_hex(4)
        tmp = self.dir / f".{job_id}.tmp"
        tmp.write_text(json.dumps({"id": job_id, "op": op, "kwargs": kwargs, "actor": actor,
                                   "submitted_at": time.time()}), encoding="utf-8")
        os.replace(tmp, self._job(job_id))
        return job_id

    def wait(self, job_id: str, timeout: float) -> Any:
        deadline = time.monotonic() + timeout
        result = self._result(job_id)
        while time.monotonic() < deadline:
            if result.exists():
                data = json.loads(result.read_text(encoding="utf-8"))
                if data.get("ok"):
                    return data["value"]
                raise WorkerError(data.get("error", "worker failed"))
            time.sleep(POLL_SECONDS)
        claimed = any(self.dir.glob(f"{job_id}.running.*"))
        if claimed:
            raise WorkerError(f"job {job_id} is still running; check it later with get_request / list_requests")
        self._job(job_id).unlink(missing_ok=True)
        raise WorkerError("no tfminder worker picked up the job. A person has to start one in a terminal "
                          "with cloud credentials: `tfminder worker`")

    def claim(self) -> tuple[Path, dict[str, Any]] | None:
        if not self.dir.exists():
            return None
        for job in sorted(self.dir.glob("*.job.json")):
            running = job.with_name(job.name.replace(".job.json", f".running.{os.getpid()}"))
            try:
                os.replace(job, running)  # atomic: exactly one worker wins
            except FileNotFoundError:
                continue
            try:
                return running, json.loads(running.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                running.unlink(missing_ok=True)
        return None

    def finish(self, running: Path, job_id: str, ok: bool, value: Any = None, error: str = "") -> None:
        tmp = self.dir / f".{job_id}.result.tmp"
        tmp.write_text(json.dumps({"ok": ok, "value": value, "error": error}, default=str), encoding="utf-8")
        os.replace(tmp, self._result(job_id))
        running.unlink(missing_ok=True)


def _agent(actor: Any) -> str:
    """Jobs come from the agent side, so whatever they claim, they are recorded as an agent."""
    name = str(actor or "agent:unknown")
    return name if name.startswith("agent:") else f"agent:{name}"


def run_worker(service: Any, once: bool = False, log: Callable[[str], None] = print,
               max_age: float = 3600, insecure: bool = False) -> int:
    """Execute queued jobs until interrupted. Returns the number of jobs handled."""
    from .service import APPROVAL_KEY_ENV, ServiceError, approval_key

    if not approval_key() and not insecure:
        raise WorkerError(f"{APPROVAL_KEY_ENV} is not set. The worker only applies approvals signed with it, "
                          "so set it here and in the terminal you approve from (never where the agent runs).")

    queue = JobQueue(service.config.data_dir)
    handled = 0
    log(f"tfminder worker: watching {queue.dir} (Ctrl+C to stop)")
    while True:
        claimed = queue.claim()
        if claimed is None:
            if once:
                return handled
            time.sleep(POLL_SECONDS)
            continue
        running, job = claimed
        job_id, op, actor = job.get("id", running.stem), job.get("op"), _agent(job.get("actor"))
        kwargs = job.get("kwargs") if isinstance(job.get("kwargs"), dict) else {}
        if op not in OPERATIONS or set(kwargs) - ALLOWED_KWARGS[op]:
            queue.finish(running, job_id, False, error=f"rejected job: unsupported operation or arguments ({op})")
            continue
        if time.time() - float(job.get("submitted_at", 0)) > max_age:
            queue.finish(running, job_id, False, error="job expired before a worker picked it up")
            continue
        log(f"{time.strftime('%H:%M:%S')}  {op:<6} {kwargs.get('workspace') or kwargs.get('request_id')}"
            f"  ({actor})")
        try:
            if op == "review":
                value = service.review(actor=actor, **kwargs)
            elif op == "apply":
                value = service.apply(kwargs["request_id"], actor)
            elif op == "drift":
                value = service.drift(kwargs["workspace"], actor)
            elif op == "submit":
                value = service.request_apply(kwargs["request_id"], actor, kwargs.get("justification", "")).to_dict()
            else:
                raise ServiceError(f"unknown operation {op!r}")
            queue.finish(running, job_id, True, value)
            status = value.get("decision") or value.get("request", {}).get("status") or "ok"
            log(f"          done: {status}")
        except ServiceError as exc:
            queue.finish(running, job_id, False, error=str(exc))
            log(f"          refused: {str(exc).splitlines()[0]}")
        except Exception as exc:  # keep the worker alive; report the failure to the agent
            queue.finish(running, job_id, False, error=f"worker crashed: {exc}")
            log(traceback.format_exc())
        handled += 1
