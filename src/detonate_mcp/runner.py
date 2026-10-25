"""Docker runner: the single I/O boundary of detonate-mcp."""

from __future__ import annotations

import subprocess
import time
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

    def to_dict(self) -> dict:
        return {
            "exit_code": self.exit_code,
            "timed_out": self.timed_out,
            "duration_s": round(self.duration_s, 2),
            "stdout": core.cap_output(self.stdout),
            "stderr": core.cap_output(self.stderr, core.MAX_OUTPUT_BYTES // 2),
        }


class DockerRunner:
    def run(self, spec: core.RunSpec) -> RunResult:
        argv = core.build_docker_argv(spec)
        t0 = time.monotonic()
        try:
            proc = subprocess.run(
                argv, capture_output=True, text=True, timeout=spec.timeout_s, errors="replace"
            )
        except subprocess.TimeoutExpired as e:
            out = (
                e.stdout.decode(errors="replace")
                if isinstance(e.stdout, bytes)
                else (e.stdout or "")
            )
            return RunResult(
                None,
                out,
                f"timed out after {spec.timeout_s}s",
                True,
                round(time.monotonic() - t0, 2),
            )
        return RunResult(
            proc.returncode, proc.stdout, proc.stderr, False, round(time.monotonic() - t0, 2)
        )
