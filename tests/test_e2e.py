"""End to end against a real terraform/tofu binary. Uses only the built-in
terraform_data resource, so no provider download and no cloud account."""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path

import pytest
from conftest import requires_tf, tf_binary

from tfminder.config import load
from tfminder.service import Service, ServiceError

pytestmark = requires_tf

MAIN_TF = """
variable "items" {
  type    = list(string)
  default = ["a", "b"]
}
resource "terraform_data" "item" {
  for_each = toset(var.items)
  input    = each.key
}
"""


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    (tmp_path / "stack").mkdir()
    (tmp_path / "stack" / "main.tf").write_text(MAIN_TF)
    (tmp_path / ".tfminder.yaml").write_text(f"""
tier: apply
binary: {tf_binary()}
policy: {{approval_at: low, max_destroy: 1, approval_ttl_minutes: 5}}
workspaces:
  - {{name: stack, path: stack}}
""")
    return tmp_path


def svc(repo: Path) -> Service:
    return Service(load(repo / ".tfminder.yaml"))


def test_full_loop(repo):
    s = svc(repo)
    detail = s.review("stack", "agent:test", "add items")
    assert detail["decision"] == "approval" and detail["counts"]["create"] == 2

    with pytest.raises(ServiceError, match="must be approved"):
        s.apply(detail["id"], "agent:test")

    s.request_apply(detail["id"], "agent:test", "needed for the demo")
    s.approve(detail["id"], "human:tester")
    out = s.apply(detail["id"], "agent:test")
    assert out["request"]["status"] == "applied"
    assert (repo / "stack" / "terraform.tfstate").exists()

    again = s.review("stack", "agent:test")
    assert again["decision"] == "noop"
    assert s.audit.verify().ok


def test_tampered_plan_file_is_refused(repo):
    s = svc(repo)
    detail = s.review("stack", "agent:test")
    s.request_apply(detail["id"], "agent:test", "x")
    s.approve(detail["id"], "human:tester")
    with s.store.planfile(detail["id"]).open("ab") as fh:
        fh.write(b"\0")
    with pytest.raises(ServiceError, match="changed after review"):
        s.apply(detail["id"], "agent:test")


def test_stale_plan_is_refused_by_terraform(repo):
    s = svc(repo)
    first = s.review("stack", "agent:test")
    second = s.review("stack", "agent:test")
    for d in (first, second):
        s.request_apply(d["id"], "agent:test", "x")
        s.approve(d["id"], "human:tester")
    s.apply(first["id"], "agent:test")
    with pytest.raises(ServiceError):
        s.apply(second["id"], "agent:test")  # state moved: terraform rejects the stale plan
    assert s.get(second["id"]).status == "failed"


def test_destroy_limit_denies(repo):
    s = svc(repo)
    d = s.review("stack", "agent:test")
    s.request_apply(d["id"], "agent:test", "x")
    s.approve(d["id"], "human:tester")
    s.apply(d["id"], "agent:test")
    denied = s.review("stack", "agent:test", destroy=True)
    assert denied["decision"] == "deny" and denied["status"] == "denied"
    with pytest.raises(ServiceError):
        s.request_apply(denied["id"], "agent:test", "please")


def test_mcp_over_stdio(repo):
    """Talk to `tfminder serve` exactly the way Claude or Cursor would."""
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    async def run() -> None:
        params = StdioServerParameters(
            command=sys.executable, args=["-m", "tfminder", "serve"],
            env={**os.environ, "TFMINDER_CONFIG": str(repo / ".tfminder.yaml"), "TFMINDER_AGENT": "pytest"},
        )
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                tools = {t.name for t in (await session.list_tools()).tools}
                assert "apply_approved" in tools and "review_plan" in tools
                assert not {"approve", "approve_request", "reject"} & tools

                res = await session.call_tool("review_plan", {"workspace": "stack"})
                detail = json.loads(res.content[0].text)
                assert detail["decision"] == "approval"

                try:  # mcp 1.x returns an error result, mcp 2.x raises
                    res = await session.call_tool("apply_approved", {"request_id": detail["id"]})
                    failed = bool(getattr(res, "is_error", None) or getattr(res, "isError", None))
                    text = res.content[0].text
                except Exception as exc:
                    failed, text = True, str(exc)
                assert failed and "must be approved" in text

    asyncio.run(run())
    log = (repo / ".tfminder" / "audit.jsonl").read_text()
    assert '"actor": "agent:pytest"' in log


def test_tiers_limit_tools(repo):
    from tfminder.server import build

    cfg_path = repo / ".tfminder.yaml"
    for tier, expect_apply, expect_plan in (("read", False, False), ("plan", False, True), ("apply", True, True)):
        cfg_path.write_text(cfg_path.read_text().replace("tier: apply", f"tier: {tier}")
                            .replace("tier: read", f"tier: {tier}").replace("tier: plan", f"tier: {tier}"))
        names = {t.name for t in asyncio.run(build(load(cfg_path)).list_tools())}
        assert ("apply_approved" in names) is expect_apply
        assert ("review_plan" in names) is expect_plan


# -- v0.2 ---------------------------------------------------------------------------------------------

def _approved(s, **kw):
    d = s.review("stack", "agent:test", **kw)
    s.request_apply(d["id"], "agent:test", "x")
    s.approve(d["id"], "human:tester")
    return d


def test_apply_records_convergence(repo):
    s = svc(repo)
    d = _approved(s)
    s.apply(d["id"], "agent:test")
    req = s.get(d["id"])
    assert req.converged is True and req.post_apply_changes == []
    assert '"event": "converged"' in (repo / ".tfminder" / "audit.jsonl").read_text()


def test_tampered_attestation_is_refused(repo):
    s = svc(repo)
    d = s.review("stack", "agent:test")
    s.request_apply(d["id"], "agent:test", "x")
    att = s.store.path(d["id"]) / "attestation.json"
    att.write_text(att.read_text().replace('"verdict": "warn"', '"verdict": "pass"'))
    with pytest.raises(ServiceError, match="attestation"):
        s.approve(d["id"], "human:tester")


def test_signed_attestation_needs_the_key(repo, monkeypatch):
    monkeypatch.setenv("TFMINDER_ATTEST_KEY", "k1")
    s = svc(repo)
    d = _approved(s)
    assert s.get(d["id"]).attestation_signed
    monkeypatch.setenv("TFMINDER_ATTEST_KEY", "another-key")
    with pytest.raises(ServiceError, match="signature"):
        s.apply(d["id"], "agent:test")


def test_scope_through_the_service(repo):
    s = svc(repo)
    ok = s.review("stack", "agent:test", scope=["terraform_data.item*"])
    assert ok["decision"] == "approval" and ok["scope"] == ["terraform_data.item*"]
    bad = s.review("stack", "agent:test", scope=['terraform_data.item["a"]'])
    assert bad["decision"] == "deny" and bad["status"] == "denied"


def test_baseline_roundtrip(repo):
    s = svc(repo)
    d = s.review("stack", "agent:test")
    doc = json.loads(s.baseline_from(d["id"]))
    assert doc["format"] == "pyrrho-baseline/v1"


# -- executor: worker -------------------------------------------------------------------------------

def _mcp_session(repo, fn):
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    async def run():
        params = StdioServerParameters(
            command=sys.executable, args=["-m", "tfminder", "serve"],
            env={**os.environ, "TFMINDER_CONFIG": str(repo / ".tfminder.yaml"), "TFMINDER_AGENT": "pytest"},
        )
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                return await fn(session)

    return asyncio.run(run())


async def _call(session, tool, args):
    try:
        res = await session.call_tool(tool, args)
        failed = bool(getattr(res, "is_error", None) or getattr(res, "isError", None))
        return failed, res.content[0].text
    except Exception as exc:  # mcp 2.x raises on tool errors
        return True, str(exc)


def test_worker_executes_what_the_mcp_server_queues(repo):
    import threading

    from tfminder.worker import run_worker

    cfg = repo / ".tfminder.yaml"
    cfg.write_text(cfg.read_text().replace("tier: apply", "tier: apply\nexecutor: worker\nworker_wait_seconds: 120"))
    worker_svc = Service(load(cfg))
    threading.Thread(target=run_worker, args=(worker_svc,), kwargs={"log": lambda m: None}, daemon=True).start()

    async def flow(session):
        failed, text = await _call(session, "review_plan", {"workspace": "stack", "scope": ["terraform_data.*"]})
        assert not failed, text
        detail = json.loads(text)
        assert detail["decision"] == "approval"
        worker_svc.request_apply(detail["id"], "agent:pytest", "demo")
        worker_svc.approve(detail["id"], "human:tester")
        failed, text = await _call(session, "apply_approved", {"request_id": detail["id"]})
        assert not failed, text
        return detail["id"]

    request_id = _mcp_session(repo, flow)
    req = worker_svc.get(request_id)
    assert req.status == "applied" and req.converged is True and req.created_by == "agent:pytest"


def test_no_worker_gives_a_clear_error(repo):
    cfg = repo / ".tfminder.yaml"
    cfg.write_text(cfg.read_text().replace("tier: apply", "tier: apply\nexecutor: worker\nworker_wait_seconds: 2"))

    async def flow(session):
        return await _call(session, "review_plan", {"workspace": "stack"})

    failed, text = _mcp_session(repo, flow)
    assert failed and "tfminder worker" in text
    assert not list((repo / ".tfminder" / "jobs").glob("*.job.json"))  # abandoned job cleaned up
