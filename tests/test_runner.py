"""Tests for DockerRunner via a fake subprocess."""

from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from detonate_mcp.runner import DockerRunner
from detonate_mcp import core


@pytest.fixture
def runner():
    return DockerRunner()


@pytest.fixture
def spec():
    return core.RunSpec(
        sample_host_path=Path("/evidence/sample"),
        sample_args=(),
        timeout_s=30,
        evidence_dir=Path("/evidence"),
    )


def _fake_proc(returncode=0, stdout="", stderr=""):
    p = MagicMock()
    p.returncode = returncode
    p.stdout = stdout
    p.stderr = stderr
    return p


class TestDockerRunner:
    @patch("subprocess.run")
    def test_zero_exit_is_success(self, mock_run, runner, spec):
        mock_run.return_value = _fake_proc(0, "output text", "")
        result = runner.run(spec)
        assert result.exit_code == 0
        assert result.stdout == "output text"

    @patch("subprocess.run")
    def test_nonzero_exit_captured(self, mock_run, runner, spec):
        mock_run.return_value = _fake_proc(1, "", "something bad")
        result = runner.run(spec)
        assert result.exit_code == 1
        assert "bad" in result.stderr

    @patch("subprocess.run")
    def test_spawn_failure_raises_probe_error(self, mock_run, runner, spec):
        mock_run.side_effect = FileNotFoundError("docker not found")
        with pytest.raises(FileNotFoundError):
            runner.run(spec)
