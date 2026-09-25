from __future__ import annotations

import json
import shutil
from typing import Any

import pytest
from pyrrho.plan import Plan


def change(address: str, actions: list[str], before: Any = None, after: Any = None,
           after_unknown: dict | None = None) -> dict[str, Any]:
    rtype, name = address.split(".")[-2:]
    return {
        "address": address, "mode": "managed", "type": rtype, "name": name,
        "provider_name": "registry.terraform.io/hashicorp/google",
        "change": {"actions": actions, "before": before, "after": after, "after_unknown": after_unknown or {},
                   "before_sensitive": {}, "after_sensitive": {}},
    }


def make_plan(*changes: dict[str, Any]) -> Plan:
    doc = {"format_version": "1.2", "terraform_version": "1.9.8", "resource_changes": list(changes)}
    return Plan.from_json(json.loads(json.dumps(doc)), path="test", digest="0" * 64)


def tf_binary() -> str | None:
    return shutil.which("terraform") or shutil.which("tofu")


requires_tf = pytest.mark.skipif(tf_binary() is None, reason="terraform or tofu not installed")
