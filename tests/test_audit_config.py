import json

import pytest

from tfminder.audit import AuditLog
from tfminder.config import ConfigError, load


def test_chain_verifies_and_detects_edits(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    for i in range(5):
        log.append("reviewed", "agent:test", f"r{i}", n=i)
    assert log.verify().ok and log.verify().entries == 5

    lines = log.path.read_text().splitlines()
    entry = json.loads(lines[2])
    entry["actor"] = "human:someone-else"
    lines[2] = json.dumps(entry, sort_keys=True)
    log.path.write_text("\n".join(lines) + "\n")
    res = log.verify()
    assert not res.ok and "line 3" in res.error


def test_chain_detects_deleted_line(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    for i in range(3):
        log.append("e", "a", str(i))
    lines = log.path.read_text().splitlines()
    log.path.write_text("\n".join([lines[0], lines[2]]) + "\n")
    assert not log.verify().ok


def write_cfg(tmp_path, text):
    (tmp_path / "infra").mkdir(exist_ok=True)
    p = tmp_path / ".tfminder.yaml"
    p.write_text(text)
    return p


def test_config_merges_environment_and_workspace_policy(tmp_path):
    p = write_cfg(tmp_path, """
tier: apply
binary: tofu
policy: {approval_at: medium, auto_apply: true}
environments:
  production: {max_destroy: 0, approval_at: info}
workspaces:
  - {name: prod, path: infra, environment: production, policy: {protected: ["google_sql_*"]}}
  - {name: dev, path: infra}
""")
    cfg = load(p)
    prod, dev = cfg.workspace("prod").policy, cfg.workspace("dev").policy
    assert prod.max_destroy == 0 and prod.approval_at.value == "info" and prod.protected == ("google_sql_*",)
    assert prod.auto_apply is True
    assert dev.max_destroy is None and dev.approval_at.value == "medium"
    assert cfg.allows("apply") and cfg.binary == "tofu"


@pytest.mark.parametrize("body,msg", [
    ("tier: root\nworkspaces: [{name: a, path: infra}]", "tier"),
    ("workspaces: [{name: a, path: nope}]", "not found"),
    ("workspaces: [{name: a, path: ../}]", "inside"),
    ("policy: {block_at: low, approval_at: high}\nworkspaces: [{name: a, path: infra}]", "approval_at"),
    ("policy: {typo: 1}\nworkspaces: [{name: a, path: infra}]", "unknown policy"),
])
def test_config_errors(tmp_path, body, msg):
    with pytest.raises(ConfigError, match=msg):
        load(write_cfg(tmp_path, body))


def test_windows_env_is_restored(monkeypatch):
    from tfminder import runner

    env = {"PATH": "x", "SystemRoot": "D:\\Win"}
    runner._fill_windows_env(env)
    assert env["SystemRoot"] == "D:\\Win" and "SYSTEMROOT" not in env  # existing value kept, any case
    for key in ("WINDIR", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "TEMP", "TMP"):
        assert env[key]


def test_check_writes_sarif(tmp_path):
    from pathlib import Path

    from tfminder.cli import main

    plan = Path(__file__).parent.parent / "examples" / "plans" / "gcp-risky.json"
    out = tmp_path / "r.sarif"
    code = main(["check", str(plan), "--sarif", str(out), "--format", "json"])
    doc = json.loads(out.read_text())
    assert code == 1  # denied
    assert doc["version"] == "2.1.0"
    rules = {r["ruleId"] for r in doc["runs"][0]["results"]}
    assert {"GC001", "GC006"} <= rules

