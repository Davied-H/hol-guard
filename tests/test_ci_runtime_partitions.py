"""Both runtime partitions must execute with unchanged checked-test settings."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.skipif(os.name == "nt", reason="The Linux workspace CI job runs Bash")
@pytest.mark.parametrize("check", ["test-core", "test-command", "test-runtime-1", "test-runtime-2"])
def test_runtime_matrix_runs_complete_hash_partitions_without_changing_other_packages(tmp_path: Path, check: str):
    workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8"))
    job = workflow["jobs"]["native-workspace"]
    assert job["strategy"]["matrix"]["check"] == [
        "clippy",
        "test-core",
        "test-command",
        "test-runtime-1",
        "test-runtime-2",
    ]
    step = next(s for s in job["steps"] if s.get("name") == "Validate the locked Rust workspace")
    assert "continue-on-error" not in job and "continue-on-error" not in step
    bash = shutil.which("bash")
    assert bash
    binaries = tmp_path / "bin"
    binaries.mkdir()
    python = binaries / "python3"
    python.write_text(f'#!{bash}\nprintf "%s\\n" "${{TEST_BIN}}"\n', encoding="utf-8")
    cargo = binaries / "cargo"
    cargo.write_text(f'#!{bash}\nprintf "%s\\n" "$@" > "$COMMAND_LOG"\n', encoding="utf-8")
    python.chmod(0o700)
    cargo.chmod(0o700)
    result = subprocess.run(
        [bash, "-euo", "pipefail", "-c", step["run"]],
        cwd=tmp_path,
        env={
            **os.environ,
            "CARGO_CHECK": check,
            "TEST_BIN": str(binaries),
            "COMMAND_LOG": str(tmp_path / "command.json"),
            "PATH": f"{binaries}{os.pathsep}{os.environ.get('PATH', '')}",
        },
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr
    args = (tmp_path / "command.json").read_text().splitlines()
    expected = ["nextest", "run", "--manifest-path", "rust/Cargo.toml", "--locked", "--all-targets"]
    if check == "test-core":
        expected += ["--workspace", "--exclude", "guard-command", "--exclude", "hol-guard-runtime"]
    else:
        expected += ["--package", "guard-command" if check == "test-command" else "hol-guard-runtime"]
    expected += ["--profile", "ci"]
    if check.startswith("test-runtime-"):
        expected += ["--partition", f"hash:{check[-1]}/2"]
    expected += ["--test-threads", "4", "--retries", "0", "--no-fail-fast"]
    assert args == expected, json.dumps(args)
