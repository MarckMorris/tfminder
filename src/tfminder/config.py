"""Load and validate .tfminder.yaml.

The file lives at the root of the repository that holds your Terraform code.
Everything tfminder writes (requests, plan files, the audit log) goes into a
``.tfminder/`` directory next to it.
"""

from __future__ import annotations

import os
import shutil
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

import yaml
from pyrrho.core import Severity

CONFIG_NAMES = (".tfminder.yaml", ".tfminder.yml")
TIERS = ("read", "plan", "apply")


class ConfigError(ValueError):
    pass


@dataclass(frozen=True)
class Policy:
    """Rules that turn a reviewed plan into allow / approval / deny."""

    block_at: Severity = Severity.CRITICAL  # a finding at or above this is denied outright
    approval_at: Severity = Severity.LOW  # a finding at or above this needs a human
    max_destroy: int | None = None  # deletes + replacements allowed; None = no limit
    approval_on_destroy: bool = True  # any delete/replace needs a human
    protected: tuple[str, ...] = ()  # address globs that may never be deleted or replaced
    deny_types: tuple[str, ...] = ()  # resource types an agent may never touch
    auto_apply: bool = False  # clean plans (no findings, no destroys) skip the human
    approval_ttl_minutes: int = 60

    def merged(self, raw: dict[str, Any]) -> "Policy":
        return _policy_from(raw, base=self)


@dataclass(frozen=True)
class Workspace:
    name: str
    path: Path
    environment: str = ""
    policy: Policy = field(default_factory=Policy)
    state: tuple[str, ...] = ()  # strayform sources: files, dirs or gs:// URIs
    scope: tuple[str, ...] = ()  # strayform scopes: project IDs, folders/N, organizations/N
    var_files: tuple[str, ...] = ()


@dataclass(frozen=True)
class Config:
    root: Path
    tier: str
    binary: str
    workspaces: dict[str, Workspace]
    command_timeout: int = 1800

    @property
    def data_dir(self) -> Path:
        return self.root / ".tfminder"

    def workspace(self, name: str) -> Workspace:
        try:
            return self.workspaces[name]
        except KeyError:
            known = ", ".join(sorted(self.workspaces)) or "(none)"
            raise ConfigError(f"unknown workspace {name!r}; configured: {known}") from None

    def allows(self, tier: str) -> bool:
        return TIERS.index(self.tier) >= TIERS.index(tier)


def _severity(value: Any, key: str) -> Severity:
    try:
        return Severity.parse(str(value))
    except ValueError as exc:
        raise ConfigError(f"policy.{key}: {exc}") from None


def _strings(value: Any, key: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ConfigError(f"{key} must be a string or a list of strings")
    return tuple(value)


def _policy_from(raw: dict[str, Any] | None, base: Policy) -> Policy:
    raw = raw or {}
    if not isinstance(raw, dict):
        raise ConfigError("policy must be a mapping")
    known = {f for f in Policy.__dataclass_fields__}
    unknown = set(raw) - known
    if unknown:
        raise ConfigError(f"unknown policy keys: {', '.join(sorted(unknown))}")
    changes: dict[str, Any] = {}
    for key, value in raw.items():
        if key in ("block_at", "approval_at"):
            changes[key] = _severity(value, key)
        elif key in ("protected", "deny_types"):
            changes[key] = _strings(value, f"policy.{key}")
        elif key == "max_destroy":
            if value is not None and (not isinstance(value, int) or value < 0):
                raise ConfigError("policy.max_destroy must be a non-negative integer or null")
            changes[key] = value
        elif key == "approval_ttl_minutes":
            if not isinstance(value, int) or value <= 0:
                raise ConfigError("policy.approval_ttl_minutes must be a positive integer")
            changes[key] = value
        else:
            if not isinstance(value, bool):
                raise ConfigError(f"policy.{key} must be true or false")
            changes[key] = value
    policy = replace(base, **changes)
    if policy.approval_at.rank > policy.block_at.rank:
        raise ConfigError("policy.approval_at cannot be more severe than policy.block_at")
    return policy


def _find_binary(requested: str | None) -> str:
    if requested:
        return requested
    for candidate in ("terraform", "tofu"):
        if shutil.which(candidate):
            return candidate
    return "terraform"


def find_config(start: Path | None = None) -> Path:
    env = os.environ.get("TFMINDER_CONFIG")
    if env:
        return Path(env).resolve()
    here = (start or Path.cwd()).resolve()
    for directory in (here, *here.parents):
        for name in CONFIG_NAMES:
            candidate = directory / name
            if candidate.is_file():
                return candidate
    raise ConfigError("no .tfminder.yaml found in this directory or any parent (set TFMINDER_CONFIG to point at one)")


def load(path: Path | None = None) -> Config:
    path = path.resolve() if path else find_config()
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except FileNotFoundError:
        raise ConfigError(f"config file not found: {path}") from None
    except yaml.YAMLError as exc:
        raise ConfigError(f"{path}: invalid YAML: {exc}") from None
    if not isinstance(data, dict):
        raise ConfigError(f"{path}: top level must be a mapping")
    if data.get("version", 1) != 1:
        raise ConfigError(f"{path}: unsupported config version {data.get('version')!r}")

    root = path.parent
    tier = str(data.get("tier", "plan"))
    if tier not in TIERS:
        raise ConfigError(f"tier must be one of {', '.join(TIERS)}")

    default_policy = _policy_from(data.get("policy"), Policy())
    env_policies: dict[str, Any] = data.get("environments") or {}
    if not isinstance(env_policies, dict):
        raise ConfigError("environments must be a mapping of name -> policy overrides")

    workspaces: dict[str, Workspace] = {}
    raw_ws = data.get("workspaces") or []
    if not isinstance(raw_ws, list) or not raw_ws:
        raise ConfigError("workspaces must be a non-empty list")
    for item in raw_ws:
        if not isinstance(item, dict) or "name" not in item or "path" not in item:
            raise ConfigError("each workspace needs at least 'name' and 'path'")
        name = str(item["name"])
        if name in workspaces:
            raise ConfigError(f"duplicate workspace {name!r}")
        ws_path = (root / str(item["path"])).resolve()
        if not ws_path.is_dir():
            raise ConfigError(f"workspace {name!r}: directory not found: {ws_path}")
        if root.resolve() not in (ws_path, *ws_path.parents):
            raise ConfigError(f"workspace {name!r}: path must be inside {root}")
        env = str(item.get("environment", ""))
        policy = default_policy
        if env and env in env_policies:
            policy = policy.merged(env_policies[env] or {})
        if item.get("policy"):
            policy = policy.merged(item["policy"])
        state = tuple(s if s.startswith("gs://") else str((root / s).resolve())
                      for s in _strings(item.get("state"), f"workspaces[{name}].state"))
        workspaces[name] = Workspace(
            name=name,
            path=ws_path,
            environment=env,
            policy=policy,
            state=state,
            scope=_strings(item.get("scope"), f"workspaces[{name}].scope"),
            var_files=_strings(item.get("var_files"), f"workspaces[{name}].var_files"),
        )

    timeout = data.get("command_timeout", 1800)
    if not isinstance(timeout, int) or timeout <= 0:
        raise ConfigError("command_timeout must be a positive integer (seconds)")
    return Config(root=root, tier=tier, binary=_find_binary(data.get("binary")), workspaces=workspaces,
                  command_timeout=timeout)
