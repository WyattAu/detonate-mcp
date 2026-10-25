"""Pure core: the containment profile, argv construction, and validation.

NO I/O in this module by design — everything here is deterministically
testable. The docker invocation lives in runner.py; the MCP tools in
server.py. The split exists because the SAFETY properties (allowlist
enforcement, fixed containment flags, argv construction without a
shell) are the load-bearing code, and load-bearing code must be
testable without Docker.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

# ---------------------------------------------------------------------------
# The containment profile — CONSTANTS, not parameters.
#
# A caller can choose WHICH sample to run and FOR HOW LONG. Nothing else.
# Every hardening flag is fixed here so no MCP tool call can weaken the
# profile (an agent asking for "just this once with network" is the
# failure mode this design exists to prevent).
# ---------------------------------------------------------------------------

CONTAINER_IMAGE = "debian:stable-slim"
CONTAINER_USER = "1000:1000"
SAMPLE_IN_CONTAINER = "/tmp/sample"
EVIDENCE_MOUNT = "/evidence"
DEFAULT_TIMEOUT_S = 120
MAX_TIMEOUT_S = 600
MAX_OUTPUT_BYTES = 200_000

CONTAINER_FLAGS: list[str] = [
    "--network", "none",
    "--read-only",
    "--tmpfs", "/tmp:rw,exec,size=64m,uid=1000",
    "--cap-drop", "ALL",
    "--security-opt", "no-new-privileges",
    "--user", CONTAINER_USER,
    "--cpus", "1",
    "--memory", "512m",
    "--pids-limit", "64",
]

THREAT_MODEL = {
    "defends_against": [
        "network callback and exfiltration (network: none)",
        "filesystem persistence (read-only root, ephemeral container)",
        "privilege escalation (cap-drop ALL, no-new-privileges, non-root)",
        "resource exhaustion (CPU/memory/PID caps, server-side timeout)",
    ],
    "does_not_defend_against": [
        "kernel exploits (docker shares the host kernel — use a disposable "
        "VM for kernel-exploit-grade samples)",
        "hypervisor-grade malware",
        "firmware persistence",
    ],
}


@dataclass(frozen=True)
class RunSpec:
    sample_host_path: Path
    sample_args: tuple[str, ...]
    timeout_s: int
    evidence_dir: Path


def resolve_sample(samples_root: Path, sample_name: str) -> Path:
    if sample_name.startswith("/") or Path(sample_name).is_absolute():
        raise ValueError("sample must be a relative path under the samples root")
    root = samples_root.resolve()
    candidate = (root / sample_name).resolve()
    if candidate != root and root not in candidate.parents:
        raise ValueError(f"sample escapes the samples root: {sample_name}")
    if not candidate.is_file():
        raise ValueError(f"sample not found: {candidate}")
    return candidate


def build_docker_argv(spec: RunSpec) -> list[str]:
    argv = ["docker", "run", "--rm", "-i"]
    argv += CONTAINER_FLAGS
    argv += ["-v", f"{spec.evidence_dir}:{EVIDENCE_MOUNT}"]
    argv += [CONTAINER_IMAGE]
    import shlex
    body = (
        f"cp {EVIDENCE_MOUNT}/sample {SAMPLE_IN_CONTAINER} && "
        f"chmod +x {SAMPLE_IN_CONTAINER} && "
        f"{SAMPLE_IN_CONTAINER}" +
        ("" if not spec.sample_args else " " + " ".join(shlex.quote(a) for a in spec.sample_args))
    )
    argv += ["/bin/sh", "-c", body]
    return argv


def cap_output(text: str, max_bytes: int = MAX_OUTPUT_BYTES) -> str:
    if len(text.encode("utf-8", errors="replace")) <= max_bytes:
        return text
    cut = text[: max_bytes // 2]
    tail = text[-(max_bytes // 2):]
    return f"{cut}\n...[truncated {len(text)} bytes total]...\n{tail}"


def evidence_dir_for(samples_root: Path, stamp: str) -> Path:
    return samples_root / ".detonate" / stamp
