"""Checks that run before `terraform plan`, because a plan is not side-effect free.

Terraform executes code while planning: a `data "external"` block runs an arbitrary program, and
every provider binary runs with the credentials of whoever runs the plan. An agent that can edit
.tf files could use `review_plan` itself, before any human approval, to run a command or
exfiltrate credentials. These checks refuse to plan such configurations unless policy allows it.

The scan is static and deliberately simple: it reads every .tf / .tf.json file in the workspace,
including modules Terraform already downloaded into .terraform/modules. It cannot see modules that
have not been downloaded yet; tfminder only runs `init` for a workspace that was never initialised.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from fnmatch import fnmatchcase
from pathlib import Path

EXTERNAL_DATA = re.compile(r'data\s+"external"')
EXTERNAL_DATA_JSON = re.compile(r'"data"\s*:\s*\{[^{}]*"external"\s*:', re.S)
PROVISIONER = re.compile(r'provisioner\s+"(local-exec|remote-exec|file)"')
PROVISIONER_JSON = re.compile(r'"provisioner"\s*:.*?"(local-exec|remote-exec|file)"', re.S)
BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.S)
LINE_COMMENT = re.compile(r"(?m)(#|//).*$")


@dataclass
class GuardFinding:
    kind: str
    file: str
    detail: str

    def __str__(self) -> str:
        return f"{self.kind}: {self.detail} ({self.file})"


def _config_files(root: Path) -> list[Path]:
    files = []
    for path in root.rglob("*"):
        if path.suffix not in (".tf", ".json") or not path.is_file():
            continue
        if path.suffix == ".json" and not path.name.endswith(".tf.json"):
            continue
        parts = path.relative_to(root).parts
        if ".terraform" in parts and "modules" not in parts:
            continue  # provider binaries and caches, not configuration
        if ".tfminder" in parts:
            continue
        files.append(path)
    return sorted(files)


def scan_config(root: Path, allow_external_programs: bool) -> list[GuardFinding]:
    if allow_external_programs:
        return []
    found: list[GuardFinding] = []
    for path in _config_files(root):
        rel = str(path.relative_to(root))
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if path.name.endswith(".tf.json"):
            if EXTERNAL_DATA_JSON.search(text):
                found.append(GuardFinding("external-program", rel, 'data "external" runs a program during plan'))
            for m in PROVISIONER_JSON.finditer(text):
                found.append(GuardFinding("provisioner", rel, f'provisioner "{m.group(1)}" runs commands on apply'))
            continue
        code = LINE_COMMENT.sub("", BLOCK_COMMENT.sub("", text))
        if EXTERNAL_DATA.search(code):
            found.append(GuardFinding("external-program", rel, 'data "external" runs a program during plan'))
        for m in PROVISIONER.finditer(code):
            found.append(GuardFinding("provisioner", rel, f'provisioner "{m.group(1)}" runs commands on apply'))
    return found


def installed_providers(root: Path) -> list[str]:
    """Providers Terraform installed for this workspace, as host/namespace/type."""
    base = root / ".terraform" / "providers"
    if not base.is_dir():
        return []
    out = set()
    for type_dir in base.glob("*/*/*"):
        if type_dir.is_dir():
            out.add("/".join(type_dir.relative_to(base).parts))
    return sorted(out)


def check_providers(root: Path, allowed: tuple[str, ...]) -> list[GuardFinding]:
    if not allowed:
        return []
    bad = []
    for provider in installed_providers(root):
        short = provider.split("/", 1)[1] if provider.count("/") == 2 else provider
        if not any(fnmatchcase(provider, p) or fnmatchcase(short, p) for p in allowed):
            bad.append(GuardFinding("provider", ".terraform/providers", f"{provider} is not in allowed_providers"))
    return bad
