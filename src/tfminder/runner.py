"""Run terraform / tofu as a subprocess. No shell, no interactive prompts."""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

MAX_OUTPUT = 20_000


def _fill_windows_env(env: dict[str, str]) -> None:
    """Restore the variables Windows programs need when a parent stripped them.

    MCP clients often start servers with a minimal environment, and Go binaries such as
    Terraform and its providers need SYSTEMROOT and friends to use the network on Windows.
    Values that are already set are left alone. Note: this does not help when the MCP host
    runs servers in a sandbox that breaks Terraform's provider plugins (the Microsoft Store
    build of Claude Desktop); use ``executor: worker`` there.
    """
    home = os.path.expanduser("~")
    upper = {k.upper(): k for k in env}

    def default(name: str, value: str) -> None:
        if name.upper() not in upper and value:
            env[name] = value

    windir = os.environ.get("SystemRoot") or os.environ.get("WINDIR") or r"C:\Windows"
    default("SYSTEMROOT", windir)
    default("WINDIR", windir)
    default("USERPROFILE", home)
    default("HOMEDRIVE", os.path.splitdrive(home)[0])
    default("HOMEPATH", os.path.splitdrive(home)[1])
    default("APPDATA", os.path.join(home, "AppData", "Roaming"))
    default("LOCALAPPDATA", os.path.join(home, "AppData", "Local"))
    tmp = tempfile.gettempdir()
    default("TEMP", tmp)
    default("TMP", tmp)
    default("PROGRAMDATA", r"C:\ProgramData")
    default("COMSPEC", os.path.join(windir, "System32", "cmd.exe"))


class RunnerError(RuntimeError):
    def __init__(self, message: str, output: str = ""):
        super().__init__(message)
        self.output = output


@dataclass
class Result:
    code: int
    output: str


def _tail(text: str) -> str:
    return text if len(text) <= MAX_OUTPUT else "...(truncated)...\n" + text[-MAX_OUTPUT:]


class Runner:
    def __init__(self, binary: str, timeout: int = 1800):
        self.binary = binary
        self.timeout = timeout

    def _env(self) -> dict[str, str]:
        env = dict(os.environ)
        if os.name == "nt":
            _fill_windows_env(env)
        env["TF_IN_AUTOMATION"] = "1"
        env["TF_INPUT"] = "0"
        env.setdefault("CHECKPOINT_DISABLE", "1")
        return env

    def run(self, args: list[str], cwd: Path, ok: tuple[int, ...] = (0,)) -> Result:
        exe = shutil.which(self.binary)
        if not exe:
            raise RunnerError(f"{self.binary!r} not found on PATH (set 'binary' in .tfminder.yaml)")
        try:
            proc = subprocess.run(
                [exe, *args], cwd=str(cwd), env=self._env(), capture_output=True, text=True, timeout=self.timeout,
            )
        except subprocess.TimeoutExpired as exc:
            raise RunnerError(f"{self.binary} {args[0]} timed out after {self.timeout}s") from exc
        output = _tail((proc.stdout or "") + (proc.stderr or ""))
        if proc.returncode not in ok:
            raise RunnerError(f"{self.binary} {args[0]} failed with exit code {proc.returncode}", output)
        return Result(proc.returncode, output)

    def version(self) -> str:
        return self.run(["version"], Path.cwd()).output.splitlines()[0]

    def init(self, cwd: Path) -> Result:
        return self.run(["init", "-input=false", "-no-color"], cwd)

    def plan(self, cwd: Path, planfile: Path, var_files: tuple[str, ...] = (), destroy: bool = False) -> Result:
        args = ["plan", "-input=false", "-no-color", "-lock-timeout=60s", "-detailed-exitcode", f"-out={planfile}"]
        args += [f"-var-file={v}" for v in var_files]
        if destroy:
            args.append("-destroy")
        return self.run(args, cwd, ok=(0, 2))

    def show_json(self, cwd: Path, planfile: Path) -> str:
        exe = shutil.which(self.binary)
        if not exe:
            raise RunnerError(f"{self.binary!r} not found on PATH")
        proc = subprocess.run([exe, "show", "-json", str(planfile)], cwd=str(cwd), env=self._env(),
                              capture_output=True, text=True, timeout=self.timeout)
        if proc.returncode != 0:
            raise RunnerError(f"{self.binary} show failed with exit code {proc.returncode}", _tail(proc.stderr))
        return proc.stdout

    def apply(self, cwd: Path, planfile: Path) -> Result:
        # Applying a saved plan never prompts, and Terraform refuses it if state moved since the plan.
        return self.run(["apply", "-input=false", "-no-color", "-lock-timeout=60s", str(planfile)], cwd)
