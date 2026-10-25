"""Safety-critical unit tests for the pure core logic."""

from pathlib import Path

import pytest

from detonate_mcp import core


@pytest.fixture
def root(tmp_path):
    r = tmp_path / "sandbox"
    r.mkdir()
    return r


class TestResolveSample:
    def test_resolves_inside_root(self, root):
        (root / "sample").write_bytes(b"MZ")
        got = core.resolve_sample(root, "sample")
        assert got == root.resolve() / "sample"

    def test_subdirectory_stays_inside(self, root):
        sub = root / "nested"
        sub.mkdir()
        (sub / "s").write_bytes(b"x")
        got = core.resolve_sample(root, "nested/s")
        assert got == root.resolve() / "nested" / "s"

    def test_absolute_path_rejected(self, root):
        with pytest.raises(ValueError, match="relative"):
            core.resolve_sample(root, "/etc/passwd")

    def test_traversal_rejected(self, root):
        with pytest.raises(ValueError, match="escapes"):
            core.resolve_sample(root, "../secrets/api.key")

    def test_symlink_escape_rejected(self, root, tmp_path):
        target = tmp_path / "outside"
        target.write_bytes(b"x")
        (root / "link").symlink_to(target)
        with pytest.raises(ValueError, match="escapes"):
            core.resolve_sample(root, "link")

    def test_missing_file_rejected(self, root):
        with pytest.raises(ValueError, match="not found"):
            core.resolve_sample(root, "ghost")


class TestContainmentFlags:
    def test_no_network(self):
        assert "--network" in core.CONTAINER_FLAGS
        assert "none" in core.CONTAINER_FLAGS

    def test_read_only(self):
        assert "--read-only" in core.CONTAINER_FLAGS

    def test_all_caps_dropped(self):
        i = core.CONTAINER_FLAGS.index("--cap-drop")
        assert core.CONTAINER_FLAGS[i + 1] == "ALL"

    def test_no_new_privs(self):
        assert "no-new-privileges" in core.CONTAINER_FLAGS

    def test_non_root(self):
        i = core.CONTAINER_FLAGS.index("--user")
        assert not core.CONTAINER_FLAGS[i + 1].startswith("0:")

    def test_resource_caps(self):
        f = core.CONTAINER_FLAGS
        assert "--cpus" in f and "--memory" in f and "--pids-limit" in f

    def test_exec_tmpfs(self):
        i = core.CONTAINER_FLAGS.index("--tmpfs")
        assert "exec" in core.CONTAINER_FLAGS[i + 1]


class TestThreatModel:
    def test_kernel_boundary_named(self):
        assert any("kernel" in x for x in core.THREAT_MODEL["does_not_defend_against"])

    def test_network_defended(self):
        assert any("network" in x.lower() for x in core.THREAT_MODEL["defends_against"])
