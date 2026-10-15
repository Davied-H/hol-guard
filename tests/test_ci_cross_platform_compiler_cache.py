"""The macOS runtime build must reuse content-addressed objects."""

from __future__ import annotations

from tests.support.ci_workflow import composite_action_steps, load_ci_workflow, step_index


def test_runtime_builds_run_after_the_compiler_cache_is_routed() -> None:
    steps = composite_action_steps("ci-job-macos-native-runtime")
    routed = step_index(steps, "Route the runtime build through the compiler cache")
    assert step_index(steps, "Install content-addressed compiler cache") < routed
    assert routed < step_index(steps, "Build the macOS native runtime")
    script = steps[routed]["run"]
    assert "RUSTC_WRAPPER=sccache" in script
    assert "SCCACHE_GHA_VERSION=cross-platform-runtime" in script


def test_only_main_pushes_write_the_cross_platform_compiler_cache() -> None:
    steps = composite_action_steps("ci-job-macos-native-runtime")
    step = steps[step_index(steps, "Route the runtime build through the compiler cache")]
    assert step["env"]["SCCACHE_MODE"] == (
        "${{ (github.event_name == 'push' && github.ref == 'refs/heads/main') && 'READ_WRITE' || 'READ_ONLY' }}"
    )
    assert "SCCACHE_GHA_RW_MODE=${SCCACHE_MODE}" in step["run"]


def test_fast_runtime_profile_is_confined_to_functional_ci_artifacts() -> None:
    workflow = load_ci_workflow()
    assert "CARGO_PROFILE_RELEASE_OPT_LEVEL" not in workflow["env"]
    for name in ("macos-native-runtime", "windows-native-runtime"):
        job = workflow["jobs"][name]
        assert job["timeout-minutes"] == 5
        assert job["env"]["CARGO_PROFILE_RELEASE_OPT_LEVEL"] == "1"
    for name in ("native-release-size", "native-command-evaluators"):
        assert "CARGO_PROFILE_RELEASE_OPT_LEVEL" not in workflow["jobs"][name].get("env", {})
    assert "macos-native-runtime" in workflow["jobs"]["required"]["needs"]
    assert "windows-native-runtime" in workflow["jobs"]["required"]["needs"]
