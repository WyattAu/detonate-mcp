"""detonate-mcp — MCP server exposing the hardened detonation container.

Three tools, deliberately few:

  detonate_run      run a sample from the allowlisted root; structured result
  detonate_profile  the containment profile + threat-model honesty
  detonate_evidence list past evidence directories

The server enforces the safety profile server-side. Tool arguments can
choose the sample and the timeout — nothing else.
"""

from __future__ import annotations

import os
import shutil
from datetime import datetime, timezone
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from . import core
from .runner import DockerRunner

SAMPLES_ROOT = Path(os.environ.get(
    "DETONATE_SAMPLES_ROOT", str(Path.home() / "dev" / "sandbox")
)).resolve()

runner = DockerRunner()


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")


@mcp.tool()
def detonate_run(sample: str, args: list[str] | None = None,
                 timeout_s: int = core.DEFAULT_TIMEOUT_S) -> dict:
    """Detonate a sample in the hardened container."""
    timeout = max(1, min(int(timeout_s), core.MAX_TIMEOUT_S))
    sp = core.resolve_sample(SAMPLES_ROOT, sample)
    evidence = core.evidence_dir_for(SAMPLES_ROOT, _stamp())
    evidence.mkdir(parents=True, exist_ok=True)
    shutil.copy2(sp, evidence / "sample")
    (evidence / "sample").chmod(0o755)
    spec = core.RunSpec(sample_host_path=evidence / "sample",
                        sample_args=tuple(args or []), timeout_s=timeout,
                        evidence_dir=evidence)
    result = runner.run(spec)
    return {**result.to_dict(), "sample": sample, "evidence_dir": str(evidence)}


@mcp.tool()
def detonate_profile() -> dict:
    """The exact containment profile and threat-model boundary."""
    return {"image": core.CONTAINER_IMAGE, "flags": core.CONTAINER_FLAGS,
            "user": core.CONTAINER_USER, "timeout_max_s": core.MAX_TIMEOUT_S,
            "threat_model": core.THREAT_MODEL}


@mcp.tool()
def detonate_evidence_list() -> list[dict]:
    """List past evidence directories (newest first)."""
    base = core.evidence_dir_for(SAMPLES_ROOT, "").parent
    if not base.is_dir():
        return []
    return [{"dir": str(d), "sample": (d / "sample").name}
            for d in sorted(base.iterdir(), reverse=True)
            if d.is_dir() and (d / "sample").exists()]


def main() -> None:
    mcp.run(transport="stdio")
