"""Unit tests for the fixes from the pre-release security review."""

import json

import pytest

from tfminder.guard import check_providers, scan_config
from tfminder.store import Store, StoreError
from tfminder.worker import JobQueue, WorkerError, run_worker


def write(root, name, text):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def test_scan_finds_external_and_provisioners(tmp_path):
    write(tmp_path, "a.tf", 'data "external" "x" { program = ["id"] }')
    write(tmp_path, "b.tf", 'resource "null_resource" "n" {\n provisioner "local-exec" { command = "id" }\n}')
    write(tmp_path, ".terraform/modules/m/c.tf", 'data  "external" "y" {}')
    kinds = sorted((f.kind, f.file.replace("\\", "/")) for f in scan_config(tmp_path, allow_external_programs=False))
    assert kinds == [
        ("external-program", ".terraform/modules/m/c.tf"),
        ("external-program", "a.tf"),
        ("provisioner", "b.tf"),
    ]
    assert scan_config(tmp_path, allow_external_programs=True) == []


def test_scan_ignores_comments_and_provider_caches(tmp_path):
    write(tmp_path, "a.tf", '# data "external" "x" {}\n/* provisioner "local-exec" {} */\n// data "external"\n')
    write(tmp_path, ".terraform/providers/x/y.tf", 'data "external" "z" {}')
    assert scan_config(tmp_path, allow_external_programs=False) == []


def test_scan_reads_tf_json(tmp_path):
    write(tmp_path, "main.tf.json", json.dumps({"data": {"external": {"x": {"program": ["id"]}}}}))
    assert [f.kind for f in scan_config(tmp_path, False)] == ["external-program"]


def test_provider_allowlist(tmp_path):
    (tmp_path / ".terraform/providers/registry.terraform.io/hashicorp/google").mkdir(parents=True)
    (tmp_path / ".terraform/providers/registry.terraform.io/evil/stealer").mkdir(parents=True)
    bad = check_providers(tmp_path, ("hashicorp/*",))
    assert [b.detail.split()[0] for b in bad] == ["registry.terraform.io/evil/stealer"]
    assert check_providers(tmp_path, ()) == []


@pytest.mark.parametrize("bad", ["C:evil", "..\\x", "../x", "", "20260101-000000-abc", "x" * 30, None])
def test_request_ids_are_strict(tmp_path, bad):
    with pytest.raises(StoreError):
        Store(tmp_path).path(bad)


def test_request_id_shape_accepted(tmp_path):
    assert Store(tmp_path).path("20260925-233417-9247d6").name == "20260925-233417-9247d6"


class FakeService:
    def __init__(self, data_dir):
        self.config = type("C", (), {"data_dir": data_dir})()
        self.calls = []

    def review(self, actor, **kwargs):
        self.calls.append(("review", actor, kwargs))
        return {"decision": "approval"}


def test_worker_records_jobs_as_agent_and_rejects_extra_args(tmp_path, monkeypatch):
    monkeypatch.setenv("TFMINDER_APPROVAL_KEY", "k")
    q = JobQueue(tmp_path)
    ok = q.submit("review", {"workspace": "lab"}, "human:marck")  # a job claiming to be a human
    bad = q.submit("review", {"workspace": "lab", "actor": "human:marck"}, "agent:x")
    svc = FakeService(tmp_path)
    run_worker(svc, once=True, log=lambda m: None)
    assert svc.calls == [("review", "agent:human:marck", {"workspace": "lab"})]
    assert q.wait(ok, 1) == {"decision": "approval"}
    with pytest.raises(WorkerError, match="rejected job"):
        q.wait(bad, 1)


def test_baseline_is_snapshotted_at_start(tmp_path):
    from tfminder.config import load
    from tfminder.service import Service

    (tmp_path / "infra").mkdir()
    base = tmp_path / "baseline.json"
    base.write_text(json.dumps({"format": "pyrrho-baseline/v1", "entries": []}))
    (tmp_path / ".tfminder.yaml").write_text("workspaces: [{name: a, path: infra, baseline: baseline.json}]\n")
    svc = Service(load(tmp_path / ".tfminder.yaml"))
    base.write_text(json.dumps({"format": "pyrrho-baseline/v1", "entries": [{"fingerprint": "silenced"}]}))
    assert svc._baseline(svc.config.workspace("a")) == set()  # the later edit is ignored
