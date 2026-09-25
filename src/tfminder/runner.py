"""Run terraform / tofu as a subprocess. No shell, no interactive prompts."""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

MAX_OUTPUT = 20_000


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
