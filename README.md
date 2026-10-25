# detonate-mcp

MCP server: run unknown binaries in a maximum-hardening container.
The safety profile is enforced server-side and cannot be parameterized
away by tool arguments.

## What it does

| Tool | Question answered | Key constraint |
|------|-------------------|----------------|
| `detonate_run` | Does this binary do anything visible in a no-network sandbox? | fixed containment: no network, read-only root, cap-drop ALL, non-root |
| `detonate_profile` | What EXACTLY is the containment boundary? | returns the flag list + threat-model, including what it does NOT defend against |
| `detonate_evidence_list` | What past detonations exist? | timestamps, evidence paths |

## Why MCP (and not just bash)

The estate's pentest toolkit runs nmap/sqlmap/etc via shell — those are
one-shot CLIs. This server is different because it needs to hold STATE:
the allowlisted samples root, the evidence directory chain, the
containment profile. An MCP server with typed tools makes that state
explicit and testable.

## Threat model honesty

The container defends against: network callback, filesystem persistence,
privilege escalation, resource exhaustion.

It does NOT defend against: kernel exploits (docker shares the host
kernel). For kernel-exploit-grade samples, detonate in a disposable VM.

The tmpfs is the ONE exec-allowed mount — the sample must run, and that
is the single deliberate exception to the read-only root.

## Architecture

```
detonate-mcp/
├── src/detonate_mcp/
│   ├── __init__.py
│   ├── core.py         pure: profile constants, RunSpec, argv builder
│   ├── runner.py       DockerRunner: subprocess.run, timeout enforcement
│   ├── server.py       FastMCP tools (thin — delegate to core+runner)
│   ├── jsonc.py        JSONC comment stripping for config parsing
│   ├── config.py       opencode.jsonc declaration probe
│   ├── backend.py      backend resolution probe
│   ├── credential.py   credential entitlement probe
│   ├── handshake.py    MCP initialize handshake probe
│   ├── testing.py      FakeRunner/CtxBuilder test doubles
│   └── util.py         shared helpers (truncate, etc)
├── tests/
└── pyproject.toml
```

## Usage

```sh
uv run pytest                    # 18 tests
uv run python -m detonate_mcp.server   # starts the stdio MCP server
```
