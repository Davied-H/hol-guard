"""Profile experiments must be opt-in and enforce the real native size budget."""

from pathlib import Path

import yaml


def test_lto_experiment_cannot_replace_normal_determinism_or_publish_binaries() -> None:
    root = Path(__file__).resolve().parents[1]
    workflow = yaml.safe_load((root / ".github/workflows/release-native-determinism.yml").read_text())
    assert workflow[True]["workflow_dispatch"]["inputs"]["profile_benchmark"]["default"] is False
    assert workflow["permissions"] == {"contents": "read"}
    assert workflow["jobs"]["compare"]["if"] == "inputs.profile_benchmark != true"
    benchmark = workflow["jobs"]["profile-benchmark"]
    assert benchmark["if"] == "inputs.profile_benchmark == true"
    assert benchmark["strategy"]["matrix"] == {"lto": ["fat", "thin"]}
    assert benchmark["strategy"]["fail-fast"] is False
    assert benchmark["env"]["CARGO_PROFILE_RELEASE_CODEGEN_UNITS"] == "1"
    assert benchmark["steps"][0]["with"]["ref"] == "${{ inputs.source_sha || github.sha }}"
    size = next(step for step in benchmark["steps"] if step.get("name") == "Enforce the existing native size budget")
    assert "check_wheel_size.py --native-dir rust/target/release --platform manylinux_2_17_x86_64" in size["run"]
    assert "if" not in size and "continue-on-error" not in size
    check = next(step for step in benchmark["steps"] if step.get("name") == "Check the measured runtime")
    assert "self-test --json" in check["run"]
    assert "if" not in check and "continue-on-error" not in check
    upload = next(step for step in benchmark["steps"] if step.get("uses", "").startswith("actions/upload-artifact@"))
    assert upload["with"]["path"] == "native-profile-benchmark.json"
