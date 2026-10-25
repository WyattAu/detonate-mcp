"""Docker runner: the single I/O boundary of detonate-mcp.

Everything else (core.py) is pure. This module executes the argv built
by core.build_docker_argv, enforces the server-side timeout, and shapes
the structured result. Kept as one small class so tests can substitute
it wholesale.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path

from . import core


@dataclass
class RunResult:
    exit_code: int | None
    stdout: str
    stderr: str
    timed_out: bool
    duration_s: float

    def to_dict(self, max_bytes: int = core.MAX_OUTPUT_BYTES) -> dict:
        return {
            "exit_code": self.exit_code,
            "timed_out": self.timed_out,
            "duration_s": round(self.duration_s, 2),
            "stdout": core.cap_output(self.stdout, max_bytes),
            "stderr": core.cap_output(self.stderr, max_bytes // 2),
        }


class DockerRunner:
    """Executes RunSpec argv lists against the real Docker daemon."""

    def run(self, spec: core.RunSpec) -> RunResult:
        import time

        argv = core.build_docker_argv(spec)
        t0 = time.monotonic()
        try:
            proc = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                timeout=spec.timeout_s,
                errors="replace",
            )
        except subprocess.TimeoutExpired as e:
            return RunResult(
                exit_code=None,
                stdout=(e.stdout or "").decode(errors="replace")
                if isinstance(e.stdout, bytes)
                else (e.stdout or ""),
                stderr=f"timed out after {spec.timeout_s}s",
                timed_out=True,
                duration_s=round(time.monotonic() - t0, 2),
            )
        return RunResult(
            exit_code=proc.returncode,
            stdout=proc.stdout,
            stderr=proc.stderr,
            timed_out=False,
            duration_s=round(time.monotonic() - t0, 2),
        )
