"""detonate-mcp — MCP server exposing the hardened detonation container.

Three tools, deliberately few:

  detonate_run      run a sample from the allowlisted root; structured result
  detonate_profile  the containment profile + threat-model honesty
  detonate_evidence list past evidence directories

The server enforces the safety profile server-side. Tool arguments can
choose the sample and the timeout — nothing else. There is no argument
that weakens the container, because a "just this once with network"
parameter is the failure mode this server exists to prevent.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from . import core
from .runner import DockerRunner

mcp = FastMCP(
    "detonate-mcp",
    instructions=(
        "Run unknown binaries in a maximum-hardening container (no network, "
        "read-only root, cap-drop ALL, non-root, resource-capped). Samples "
        "must live under the allowlisted samples root. The containment "
        "profile is fixed server-side and cannot be weakened by arguments. "
        "The container shares the host kernel: for kernel-exploit-grade "
        "samples use a disposable VM instead."
    ),
)

SAMPLES_ROOT = Path(
    os.environ.get("DETONATE_SAMPLES_ROOT", str(Path.home() / "dev" / "sandbox"))
).resolve()

runner = DockerRunner()


def _now_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")


@mcp.tool()
def detonate_run(
    sample: str,
    args: list[str] | None = None,
    timeout_s: int = core.DEFAULT_TIMEOUT_S,
) -> dict:
    """Detonate a sample in the hardened container.

    Args:
        sample: relative path under the samples root (~/dev/sandbox).
        args: arguments passed to the sample inside the container.
        timeout_s: server-side kill switch (clamped to 600s).

    Returns:
        Structured result: exit_code, timed_out, duration_s, capped
        stdout/stderr, and the evidence directory path.
    """
    timeout = max(1, min(int(timeout_s), core.MAX_TIMEOUT_S))
    sample_path = core.resolve_sample(SAMPLES_ROOT, sample)
    stamp = f"{_now_stamp()}-{sample_path.name}"
    evidence = core.evidence_dir_for(SAMPLES_ROOT, stamp)
    evidence.mkdir(parents=True, exist_ok=True)

    # Copy the sample into the evidence dir: the container reads it from
    # the mounted evidence volume, and the copy doubles as the retained
    # artifact (the original under the samples root is never executed).
    import shutil

    retained = evidence / "sample"
    shutil.copy2(sample_path, retained)
    retained.chmod(0o755)

    spec = core.RunSpec(
        sample_host_path=retained,
        sample_args=tuple(args or []),
        timeout_s=timeout,
        evidence_dir=evidence,
    )
    result = runner.run(spec)
    return {
        **result.to_dict(),
        "sample": sample,
        "evidence_dir": str(evidence),
        "containment": "no-network, read-only-root, cap-drop ALL, non-root, "
        "resource-capped; shares the host kernel",
    }


@mcp.tool()
def detonate_profile() -> dict:
    """The exact containment profile and threat-model boundary.

    Call this before the first detonation in a session so any risk
    statement quotes the real boundary.
    """
    return {
        "image": core.CONTAINER_IMAGE,
        "flags": core.CONTAINER_FLAGS,
        "user": core.CONTAINER_USER,
        "timeout_max_s": core.MAX_TIMEOUT_S,
        "threat_model": core.THREAT_MODEL,
    }


@mcp.tool()
def detonate_evidence_list() -> list[dict]:
    """List past detonation evidence directories (newest first)."""
    base = core.evidence_dir_for(SAMPLES_ROOT, "")
    base = base.parent
    if not base.is_dir():
        return []
    out = []
    for d in sorted(base.iterdir(), reverse=True):
        if d.is_dir() and (d / "sample").exists():
            out.append({"dir": str(d), "sample": (d / "sample").name})
    return out


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
