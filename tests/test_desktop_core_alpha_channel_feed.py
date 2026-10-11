"""Alpha channel contract for the Desktop Core macOS sidecar feed; stable behaviour stays the default."""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
import subprocess
import urllib.error
from pathlib import Path
from types import ModuleType

import pytest
import yaml

from scripts.release import wait_for_core_publication as wait_module
from scripts.release.ready_core_releases import ready_tags
from scripts.release.verify_desktop_core_attestation import DesktopAttestationError, verify

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "desktop-core-alpha-feed.yml"
FEED = ROOT / "scripts" / "release" / "desktop_core_alpha_feed.py"
DISCOVER = ROOT / "scripts" / "release" / "discover_core_release.sh"
AUTHORIZE = ROOT / "scripts" / "release" / "authorize_macos_core_source.sh"
REPOSITORY = "hashgraph-online/hol-guard"
ALPHA = "3.4.0a2"
ALPHA_TAG = f"alpha/v{ALPHA}"
SOURCE = "a" * 40
NEWER = "b" * 40
PLATFORM = "macosx_.*_arm64"


def _feed() -> ModuleType:
    spec = importlib.util.spec_from_file_location("desktop_core_alpha_feed_alpha", FEED)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _workflow() -> dict:
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))


def _cli(*args: str, cwd: Path = ROOT) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["python3", "-I", str(FEED), *args], cwd=cwd, capture_output=True, text=True, check=False)


# --- dispatch contract -----------------------------------------------------------------


def test_dispatch_exposes_a_stable_default_channel_beside_the_existing_inputs() -> None:
    inputs = _workflow()[True]["workflow_dispatch"]["inputs"]
    assert set(inputs) == {"core_version", "release_channel", "publication_run_id", "publication_source_sha"}
    assert inputs["release_channel"]["type"] == "choice"
    assert inputs["release_channel"]["options"] == ["stable", "alpha"]
    assert inputs["release_channel"]["default"] == "stable"


def test_scheduled_and_push_runs_cannot_select_the_alpha_channel() -> None:
    config = _workflow()
    triggers = config[True]
    assert "schedule" in triggers
    job = config["jobs"]["publish-macos-arm64"]
    # `inputs` is empty outside workflow_dispatch, so every other trigger resolves to stable.
    assert job["env"]["RELEASE_CHANNEL"] == "${{ inputs.release_channel || 'stable' }}"
    steps = {step.get("name"): step for step in job["steps"]}
    release = steps["Discover newest published stable Core release, or the exact requested alpha prerelease"]
    assert release["env"]["CORE_RELEASE_CHANNEL"] == "${{ inputs.release_channel || 'stable' }}"
    validate = steps["Validate release channel request"]
    assert validate["env"]["EVENT_NAME"] == "${{ github.event_name }}"


def test_alpha_queues_separately_from_the_stable_feed() -> None:
    concurrency = _workflow()["jobs"]["publish-macos-arm64"]["concurrency"]
    assert concurrency["group"] == (
        "desktop-core-${{ inputs.release_channel == 'alpha' && 'alpha' || 'stable' }}-feed-macos-arm64"
    )
    assert concurrency["cancel-in-progress"] is False
    assert concurrency["queue"] == "max"


def test_coordinator_dispatch_arguments_are_accepted_by_the_workflow_inputs() -> None:
    dispatched = {"core_version", "release_channel", "publication_run_id", "publication_source_sha"}
    assert dispatched == set(_workflow()[True]["workflow_dispatch"]["inputs"])


def test_alpha_upload_rechecks_the_prerelease_and_never_creates_or_edits_it() -> None:
    job = _workflow()["jobs"]["publish-macos-arm64"]
    names = [step.get("name") for step in job["steps"]]
    gate = names.index("Require alpha prerelease and tag to still be published")
    upload = names.index("Publish immutable Core assets")
    assert gate < upload
    step = job["steps"][gate]
    assert "env.RELEASE_CHANNEL == 'alpha'" in step["if"]
    assert "require-prerelease" in step["run"]
    commands = "\n".join(item.get("run", "") for item in job["steps"])
    assert "gh release create" not in commands
    assert "gh release edit" not in commands
    assert "--clobber" not in commands


def test_alpha_steps_pass_the_channel_to_manifest_attestation_and_registry_checks() -> None:
    commands = "\n".join(step.get("run", "") for step in _workflow()["jobs"]["publish-macos-arm64"]["steps"])
    assert commands.count('--channel "$RELEASE_CHANNEL"') >= 6
    assert "validate-request" in commands


# --- request validation ----------------------------------------------------------------


@pytest.mark.parametrize("version", ["3.0.0a1", "3.4.0a2", "3.10.25a12", "3.0.1a9"])
def test_alpha_request_accepts_exact_alpha_versions(version: str) -> None:
    _feed().validate_request("alpha", "workflow_dispatch", version, "123", SOURCE)


@pytest.mark.parametrize(
    "version",
    [
        "",
        "3.4.0",
        "3.4.0a0",
        "3.4.0a01",
        "3.04.0a1",
        "3.4.00a1",
        "4.0.0a1",
        "2.9.0a1",
        "3.4.0a1.dev1",
        "3.4.0b1",
        "3.4.0-alpha.1",
        "v3.4.0a1",
        "alpha/v3.4.0a1",
        " 3.4.0a1",
        "3.4.0a1\n",
        "3.4a1",
    ],
)
def test_alpha_request_rejects_anything_but_an_exact_alpha_version(version: str) -> None:
    with pytest.raises(SystemExit, match="alpha"):
        _feed().validate_request("alpha", "workflow_dispatch", version, "123", SOURCE)


@pytest.mark.parametrize("event", ["schedule", "push", "pull_request", "workflow_run", ""])
def test_alpha_is_explicit_dispatch_only(event: str) -> None:
    with pytest.raises(SystemExit, match="explicit dispatch"):
        _feed().validate_request("alpha", event, ALPHA, "123", SOURCE)


@pytest.mark.parametrize("run_id", ["", "0", "abc", "012", "12 3"])
def test_alpha_requires_the_publication_run_id(run_id: str) -> None:
    with pytest.raises(SystemExit, match="publication run id"):
        _feed().validate_request("alpha", "workflow_dispatch", ALPHA, run_id, SOURCE)


@pytest.mark.parametrize("sha", ["", "a" * 39, "A" * 40, "g" * 40, "a" * 41, "refs/heads/main"])
def test_alpha_requires_the_full_alpha_source_commit(sha: str) -> None:
    with pytest.raises(SystemExit, match="source commit"):
        _feed().validate_request("alpha", "workflow_dispatch", ALPHA, "123", sha)


@pytest.mark.parametrize("event", ["schedule", "push", "workflow_dispatch", "pull_request"])
@pytest.mark.parametrize("version", ["", "1.2.3", ALPHA])
def test_stable_request_is_never_gated_by_alpha_rules(event: str, version: str) -> None:
    _feed().validate_request("stable", event, version, "", "")


def test_unknown_channel_is_rejected() -> None:
    with pytest.raises(SystemExit, match="Unsupported"):
        _feed().validate_request("beta", "workflow_dispatch", ALPHA, "123", SOURCE)


def test_validate_request_command_matches_the_workflow_call() -> None:
    ok = _cli(
        "validate-request",
        "--channel",
        "alpha",
        "--event-name",
        "workflow_dispatch",
        "--version",
        ALPHA,
        "--publication-run-id",
        "123",
        "--publication-source-sha",
        SOURCE,
    )
    assert ok.returncode == 0, ok.stderr
    scheduled = _cli("validate-request", "--channel", "alpha", "--event-name", "schedule", "--version", ALPHA)
    assert scheduled.returncode != 0
    stable = _cli("validate-request", "--channel", "stable", "--event-name", "schedule")
    assert stable.returncode == 0, stable.stderr


# --- discovery -------------------------------------------------------------------------


def _discover(tmp_path: Path, tags: list[str], version: str, channel: str) -> subprocess.CompletedProcess[str]:
    tags_file = tmp_path / "tags.txt"
    tags_file.write_text("".join(f"{tag}\n" for tag in tags), encoding="utf-8")
    args = ["discover-release", "--tags", str(tags_file), "--channel", channel]
    if version:
        args += ["--version", version]
    return _cli(*args)


def test_alpha_discovery_emits_the_alpha_tag_on_main(tmp_path: Path) -> None:
    result = _discover(tmp_path, [ALPHA_TAG, "alpha/v3.4.0a1"], ALPHA, "alpha")
    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == [
        "available=true",
        f"version={ALPHA}",
        f"tag={ALPHA_TAG}",
        "train=3.4",
        "branch=main",
    ]


def test_alpha_discovery_never_crawls_for_a_version(tmp_path: Path) -> None:
    result = _discover(tmp_path, [ALPHA_TAG, "alpha/v3.4.0a1"], "", "alpha")
    assert result.returncode != 0
    assert "exact alpha version" in result.stderr


def test_alpha_discovery_ignores_stable_tags_and_other_alphas(tmp_path: Path) -> None:
    result = _discover(tmp_path, ["v3.4.0", "alpha/v3.4.0a1"], ALPHA, "alpha")
    assert result.returncode != 0
    assert "not an eligible published prerelease" in result.stderr


def test_stable_discovery_is_unchanged_and_skips_alpha_tags(tmp_path: Path) -> None:
    result = _discover(tmp_path, ["v3.4.0", ALPHA_TAG, "v3.3.9"], "", "stable")
    assert result.returncode == 0, result.stderr
    assert "tag=v3.4.0" in result.stdout
    assert "branch=" in result.stdout
    assert ALPHA not in result.stdout


def test_stable_is_the_default_channel(tmp_path: Path) -> None:
    tags_file = tmp_path / "tags.txt"
    tags_file.write_text("v3.4.0\n" + ALPHA_TAG + "\n", encoding="utf-8")
    result = _cli("discover-release", "--tags", str(tags_file))
    assert result.returncode == 0, result.stderr
    assert "tag=v3.4.0" in result.stdout


def _inventory(path: Path, *items: tuple[str, list[str]]) -> Path:
    path.write_text(
        "".join(json.dumps({"tag": tag, "assets": assets}) + "\n" for tag, assets in items), encoding="utf-8"
    )
    return path


def _assets(version: str) -> list[str]:
    return [f"hol-guard-v{version}.intoto.jsonl", f"hol_guard-{version}-py3-none-macosx_11_0_arm64.whl"]


def test_ready_tags_selects_only_complete_alpha_releases_for_the_alpha_channel(tmp_path: Path) -> None:
    inventory = _inventory(
        tmp_path / "inventory.jsonl",
        (ALPHA_TAG, _assets(ALPHA)),
        ("alpha/v3.4.0a1", _assets("3.4.0a1")[:1]),
        ("v3.4.0", _assets("3.4.0")),
        ("alpha/v4.0.0a1", _assets("4.0.0a1")),
    )
    assert ready_tags(inventory, PLATFORM, "alpha") == [ALPHA_TAG]
    assert ready_tags(inventory, PLATFORM) == ["v3.4.0"]
    assert ready_tags(inventory, PLATFORM, "stable") == ["v3.4.0"]


# --- prerelease requirement --------------------------------------------------------------


def _release_json(tmp_path: Path, **overrides: object) -> Path:
    release = {"tagName": ALPHA_TAG, "isDraft": False, "isPrerelease": True, **overrides}
    path = tmp_path / "release.json"
    path.write_text(json.dumps(release), encoding="utf-8")
    return path


def test_published_prerelease_is_accepted(tmp_path: Path) -> None:
    _feed().require_prerelease(_release_json(tmp_path), ALPHA_TAG)
    assert (
        _cli("require-prerelease", "--release-json", str(_release_json(tmp_path)), "--tag", ALPHA_TAG).returncode == 0
    )


@pytest.mark.parametrize(
    "overrides",
    [
        {"isPrerelease": False},
        {"isDraft": True},
        {"isDraft": True, "isPrerelease": False},
        {"tagName": "alpha/v3.4.0a1"},
        {"isPrerelease": None},
        {"isDraft": None},
        {"isPrerelease": "true"},
    ],
)
def test_converted_draft_or_mismatched_release_fails_without_side_effects(
    tmp_path: Path, overrides: dict[str, object]
) -> None:
    path = _release_json(tmp_path, **overrides)
    with pytest.raises(SystemExit):
        _feed().require_prerelease(path, ALPHA_TAG)
    assert _cli("require-prerelease", "--release-json", str(path), "--tag", ALPHA_TAG).returncode != 0


@pytest.mark.parametrize("content", [None, "", "not json", "[]", "null"])
def test_retracted_release_fails_cleanly(tmp_path: Path, content: str | None) -> None:
    path = tmp_path / "release.json"
    if content is not None:
        path.write_text(content, encoding="utf-8")
    with pytest.raises(SystemExit, match=r"retracted|unavailable"):
        _feed().require_prerelease(path, ALPHA_TAG)


# --- release resolution through the shell helper ------------------------------------------


def _gh_stub(tmp_path: Path, *, release: dict[str, object] | None) -> dict[str, str]:
    stubs = tmp_path / "bin"
    stubs.mkdir()
    fixture = tmp_path / "release.json"
    if release is not None:
        fixture.write_text(json.dumps(release), encoding="utf-8")
    gh = stubs / "gh"
    gh.write_text(
        "#!/bin/bash\n"
        "set -euo pipefail\n"
        'args=("$@")\n'
        "path=''; filter=''\n"
        "for ((i = 0; i < ${#args[@]}; i++)); do\n"
        '  case "${args[i]}" in\n'
        '    --jq) filter="${args[i + 1]}"; i=$((i + 1)) ;;\n'
        '    repos/*) path="${args[i]}" ;;\n'
        "  esac\n"
        "done\n"
        'echo "$path" >> "$RUNNER_TEMP/gh-requests.txt"\n'
        'case "$path" in\n'
        "  repos/example/core/releases/tags/alpha/v*) ;;\n"
        "  *) exit 2 ;;\n"
        "esac\n"
        "test -f \"$FIXTURE\" || { echo 'HTTP 404: Not Found' >&2; exit 1; }\n"
        'jq -c "$filter" "$FIXTURE"\n',
        encoding="utf-8",
    )
    gh.chmod(0o755)
    return {
        **os.environ,
        "PATH": f"{stubs}{os.pathsep}{os.environ['PATH']}",
        "RUNNER_TEMP": str(tmp_path),
        "FIXTURE": str(fixture),
        "GITHUB_REPOSITORY": "example/core",
        "CORE_RELEASE_CHANNEL": "alpha",
        "REQUESTED_CORE_VERSION": ALPHA,
    }


def _alpha_release(*, prerelease: bool = True, draft: bool = False, ready: bool = True) -> dict[str, object]:
    assets = [{"name": name, "state": "uploaded"} for name in _assets(ALPHA)] if ready else []
    return {"tag_name": ALPHA_TAG, "prerelease": prerelease, "draft": draft, "assets": assets}


def _run_discover(env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", str(DISCOVER), PLATFORM], cwd=ROOT, env=env, capture_output=True, text=True, check=False
    )


def test_alpha_discovery_reads_exactly_the_one_alpha_release(tmp_path: Path) -> None:
    result = _run_discover(_gh_stub(tmp_path, release=_alpha_release()))
    assert result.returncode == 0, result.stderr
    assert f"version={ALPHA}\ntag={ALPHA_TAG}\n" in result.stdout
    assert "branch=main" in result.stdout
    assert (tmp_path / "gh-requests.txt").read_text(encoding="utf-8").split() == [
        f"repos/example/core/releases/tags/{ALPHA_TAG}"
    ]


@pytest.mark.parametrize("state", [{"prerelease": False}, {"draft": True}])
def test_alpha_discovery_requires_a_published_prerelease(tmp_path: Path, state: dict[str, bool]) -> None:
    result = _run_discover(_gh_stub(tmp_path, release=_alpha_release(**state)))
    assert result.returncode != 0
    assert "available=true" not in result.stdout


def test_alpha_discovery_without_the_wheel_and_provenance_assets_is_not_available(tmp_path: Path) -> None:
    result = _run_discover(_gh_stub(tmp_path, release=_alpha_release(ready=False)))
    assert result.returncode != 0
    assert "available=true" not in result.stdout


def test_retracted_alpha_release_fails_cleanly_without_recreating_it(tmp_path: Path) -> None:
    result = _run_discover(_gh_stub(tmp_path, release=None))
    assert result.returncode != 0
    assert "retracted" in result.stderr
    assert "Nothing was created" in result.stderr
    assert "available=true" not in result.stdout
    # The only request is the single read; nothing writes a release.
    assert (tmp_path / "gh-requests.txt").read_text(encoding="utf-8").split() == [
        f"repos/example/core/releases/tags/{ALPHA_TAG}"
    ]


@pytest.mark.parametrize("version", ["", "3.4.0", "3.4.0a0", "4.0.0a1", "3.4.0a1-dev"])
def test_alpha_discovery_shell_rejects_non_alpha_versions(tmp_path: Path, version: str) -> None:
    env = _gh_stub(tmp_path, release=_alpha_release())
    env["REQUESTED_CORE_VERSION"] = version
    result = _run_discover(env)
    assert result.returncode != 0
    assert "alpha version" in result.stderr
    assert not (tmp_path / "gh-requests.txt").exists()


def test_unknown_channel_is_rejected_by_the_discovery_shell(tmp_path: Path) -> None:
    env = _gh_stub(tmp_path, release=_alpha_release())
    env["CORE_RELEASE_CHANNEL"] = "beta"
    result = _run_discover(env)
    assert result.returncode != 0
    assert "Unsupported Core release channel" in result.stderr


# --- manifest channel --------------------------------------------------------------------


def _manifest_kwargs() -> dict[str, str]:
    return {
        "version": ALPHA,
        "source_commit": SOURCE,
        "source_tag": ALPHA_TAG,
        "target": "aarch64-apple-darwin",
        "minimum_desktop_version": "0.1.0-beta.0",
    }


def _binary(tmp_path: Path) -> Path:
    binary = tmp_path / f"hol-guard-core-{ALPHA}-aarch64-apple-darwin"
    binary.write_bytes(b"\xcf\xfa\xed\xfe" + b"core")
    return binary


def test_alpha_manifest_declares_the_alpha_channel(tmp_path: Path) -> None:
    feed = _feed()
    binary = _binary(tmp_path)
    manifest = tmp_path / "manifest.json"
    feed.create_manifest(binary, manifest, channel="alpha", **_manifest_kwargs())
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    assert payload["channel"] == "alpha"
    assert payload["sourceTag"] == ALPHA_TAG
    assert payload["version"] == ALPHA
    feed.validate_manifest(binary, manifest, channel="alpha", **_manifest_kwargs())
    # A manifest minted for one channel is never accepted as the other.
    with pytest.raises(SystemExit):
        feed.validate_manifest(binary, manifest, **_manifest_kwargs())


def test_stable_manifest_default_is_unchanged(tmp_path: Path) -> None:
    feed = _feed()
    binary = _binary(tmp_path)
    manifest = tmp_path / "manifest.json"
    kwargs = {**_manifest_kwargs(), "version": "3.4.0", "source_tag": "v3.4.0"}
    feed.create_manifest(binary, manifest, **kwargs)
    assert json.loads(manifest.read_text(encoding="utf-8"))["channel"] == "stable"
    with pytest.raises(SystemExit):
        feed.validate_manifest(binary, manifest, channel="alpha", **kwargs)


def test_manifest_command_line_emits_the_alpha_channel(tmp_path: Path) -> None:
    binary = _binary(tmp_path)
    manifest = tmp_path / "manifest.json"
    common = [
        "--base",
        str(binary),
        "--manifest",
        str(manifest),
        "--version",
        ALPHA,
        "--source-commit",
        SOURCE,
        "--source-tag",
        ALPHA_TAG,
        "--target",
        "aarch64-apple-darwin",
        "--minimum-desktop-version",
        "0.1.0-beta.0",
    ]
    assert _cli("create-manifest", *common, "--channel", "alpha").returncode == 0
    assert json.loads(manifest.read_text(encoding="utf-8"))["channel"] == "alpha"
    assert _cli("validate-manifest", *common, "--channel", "alpha").returncode == 0
    assert _cli("validate-manifest", *common).returncode != 0


def test_unknown_manifest_channel_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(SystemExit, match="Unsupported"):
        _feed().create_manifest(_binary(tmp_path), tmp_path / "m.json", channel="beta", **_manifest_kwargs())


def test_attestation_verifier_rejects_an_unknown_channel(tmp_path: Path) -> None:
    binary = _binary(tmp_path)
    for name in ("m.json", "k.json"):
        (tmp_path / name).write_text("{}", encoding="utf-8")
    with pytest.raises(DesktopAttestationError, match="channel"):
        verify(
            binary=binary,
            manifest=tmp_path / "m.json",
            marker=tmp_path / "k.json",
            version=ALPHA,
            source_commit=SOURCE,
            source_tag=ALPHA_TAG,
            target="aarch64-apple-darwin",
            expected_team_id="ABCDEF1234",
            channel="beta",
        )


# --- publication verification ------------------------------------------------------------


def _publication_api(
    monkeypatch: pytest.MonkeyPatch,
    *,
    run: dict[str, object],
    jobs: list[str],
    comparison: dict[str, object] | None = None,
) -> list[list[str]]:
    calls: list[list[str]] = []

    def api(command: list[str], **kwargs: object) -> str:
        calls.append(command)
        endpoint = next(part for part in command if part.startswith("repos/"))
        if "/compare/" in endpoint:
            assert comparison is not None, "compare must not be called"
            return json.dumps(comparison)
        if "/attempts/1/jobs" in endpoint:
            return "\n".join(jobs)
        return json.dumps(run)

    monkeypatch.setattr(subprocess, "check_output", api)
    return calls


def _run(**overrides: object) -> dict[str, object]:
    return {
        "path": ".github/workflows/publish.yml",
        "event": "workflow_dispatch",
        "head_branch": "main",
        "head_sha": SOURCE,
        "conclusion": None,
        **overrides,
    }


def _ancestor(base: str = SOURCE) -> dict[str, object]:
    return {"status": "ahead", "base_commit": {"sha": base}, "merge_base_commit": {"sha": base}}


def test_alpha_publication_waits_for_the_alpha_pypi_job(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _publication_api(monkeypatch, run=_run(), jobs=["success"])
    assert wait_module.publication_ready(REPOSITORY, "123", SOURCE, "alpha") is True
    jobs_call = next(call for call in calls if any("attempts/1/jobs" in part for part in call))
    assert 'select(.name == "Publish alpha to PyPI")' in jobs_call[-1]
    assert not any("compare" in part for call in calls for part in call)


def test_alpha_publication_is_pending_until_the_job_concludes(monkeypatch: pytest.MonkeyPatch) -> None:
    _publication_api(monkeypatch, run=_run(), jobs=["null"])
    assert wait_module.publication_ready(REPOSITORY, "123", SOURCE, "alpha") is False


@pytest.mark.parametrize("conclusion", ["failure", "cancelled", "skipped"])
def test_failed_or_skipped_alpha_publication_withholds_assets(monkeypatch: pytest.MonkeyPatch, conclusion: str) -> None:
    _publication_api(monkeypatch, run=_run(), jobs=[conclusion])
    with pytest.raises(ValueError, match="alpha registry publication failed"):
        wait_module.publication_ready(REPOSITORY, "123", SOURCE, "alpha")


def test_alpha_publication_without_the_alpha_job_never_falls_back_to_the_whole_run(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _publication_api(monkeypatch, run=_run(conclusion="success"), jobs=[])
    assert wait_module.publication_ready(REPOSITORY, "123", SOURCE, "alpha") is False


def test_alpha_run_may_be_newer_than_the_alpha_source_when_the_source_is_an_ancestor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = _publication_api(monkeypatch, run=_run(head_sha=NEWER), jobs=["success"], comparison=_ancestor())
    assert wait_module.publication_ready(REPOSITORY, "123", SOURCE, "alpha") is True
    assert any(f"repos/{REPOSITORY}/compare/{SOURCE}...{NEWER}" in part for call in calls for part in call)


@pytest.mark.parametrize(
    "comparison",
    [
        {"status": "diverged", "base_commit": {"sha": SOURCE}, "merge_base_commit": {"sha": "c" * 40}},
        {"status": "behind", "base_commit": {"sha": SOURCE}, "merge_base_commit": {"sha": NEWER}},
        {"status": "ahead", "base_commit": {"sha": "c" * 40}, "merge_base_commit": {"sha": SOURCE}},
        {"status": "ahead", "base_commit": {"sha": SOURCE}, "merge_base_commit": {"sha": "c" * 40}},
    ],
)
def test_alpha_source_that_is_not_an_ancestor_of_the_run_is_rejected(
    monkeypatch: pytest.MonkeyPatch, comparison: dict[str, object]
) -> None:
    _publication_api(monkeypatch, run=_run(head_sha=NEWER), jobs=["success"], comparison=comparison)
    with pytest.raises(ValueError, match="alpha publication run is not an authorized"):
        wait_module.publication_ready(REPOSITORY, "123", SOURCE, "alpha")


@pytest.mark.parametrize(
    "run",
    [
        _run(head_branch="release/3.0"),
        _run(head_branch="feature"),
        _run(event="push"),
        _run(event="schedule"),
        _run(path=".github/workflows/other.yml"),
    ],
)
def test_alpha_publication_must_be_a_main_dispatch_of_publish_yml(
    monkeypatch: pytest.MonkeyPatch, run: dict[str, object]
) -> None:
    _publication_api(monkeypatch, run=run, jobs=["success"], comparison=_ancestor())
    with pytest.raises(ValueError, match=r"not the authorized|not an authorized"):
        wait_module.publication_ready(REPOSITORY, "123", SOURCE, "alpha")


def test_stable_publication_still_requires_the_exact_source_sha(monkeypatch: pytest.MonkeyPatch) -> None:
    _publication_api(monkeypatch, run=_run(head_sha=NEWER), jobs=["success"], comparison=_ancestor())
    with pytest.raises(ValueError, match="not the authorized release dispatch"):
        wait_module.publication_ready(REPOSITORY, "123", SOURCE)
    _publication_api(monkeypatch, run=_run(), jobs=["success"])
    assert wait_module.publication_ready(REPOSITORY, "123", SOURCE) is True


def test_stable_publication_still_reads_the_main_release_job(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _publication_api(monkeypatch, run=_run(), jobs=["success"])
    assert wait_module.publication_ready(REPOSITORY, "123", SOURCE, "stable") is True
    jobs_call = next(call for call in calls if any("attempts/1/jobs" in part for part in call))
    assert "Publish main release to PyPI" in jobs_call[-1]


def test_unknown_publication_channel_is_rejected() -> None:
    with pytest.raises(ValueError, match="channel"):
        wait_module.publication_ready(REPOSITORY, "123", SOURCE, "beta")


def _registry(monkeypatch: pytest.MonkeyPatch, wheel: Path, *, version: str, digest: str | None = None) -> str:
    filename = f"hol_guard-{ALPHA}-py3-none-macosx_11_0_arm64.whl"
    metadata = {
        "info": {"version": version},
        "urls": [
            {
                "filename": filename,
                "digests": {"sha256": digest or hashlib.sha256(wheel.read_bytes()).hexdigest()},
            }
        ],
    }
    requested: list[str] = []

    def urlopen(url: str, **kwargs: object) -> io.BytesIO:
        requested.append(url)
        return io.BytesIO(json.dumps(metadata).encode())

    monkeypatch.setattr("urllib.request.urlopen", urlopen)
    assert wait_module.registry_ready(ALPHA, wheel, filename, "alpha") is True
    return requested[0]


def test_alpha_registry_check_reads_the_alpha_version_and_matches_the_wheel(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    wheel = tmp_path / "attested-macos-arm64.whl"
    wheel.write_bytes(b"attested alpha wheel")
    assert _registry(monkeypatch, wheel, version=ALPHA) == f"https://pypi.org/pypi/hol-guard/{ALPHA}/json"


def test_alpha_registry_mismatch_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    wheel = tmp_path / "attested-macos-arm64.whl"
    wheel.write_bytes(b"attested alpha wheel")
    with pytest.raises(ValueError, match="mismatch"):
        _registry(monkeypatch, wheel, version="3.4.0a1")
    with pytest.raises(ValueError, match="mismatch"):
        _registry(monkeypatch, wheel, version=ALPHA, digest="0" * 64)


@pytest.mark.parametrize("version", ["3.4.0", "3.4.0a0", "v3.4.0a2", "4.0.0a1", "3.4.0a2.post1"])
def test_alpha_registry_check_rejects_non_alpha_versions(tmp_path: Path, version: str) -> None:
    with pytest.raises(ValueError, match="invalid alpha version"):
        wait_module.registry_ready(version, tmp_path / "wheel", None, "alpha")


def test_stable_registry_check_rejects_alpha_versions(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="invalid stable version"):
        wait_module.registry_ready(ALPHA, tmp_path / "wheel")


def test_alpha_wait_requires_the_publishing_run_identity(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("PUBLICATION_RUN_ID", raising=False)
    monkeypatch.setattr(wait_module.time, "sleep", lambda *args: None)
    with pytest.raises(ValueError, match="alpha publication requires the publishing run identity"):
        wait_module.wait(ALPHA, tmp_path / "wheel", timeout=1, channel="alpha")


def test_alpha_wait_passes_the_channel_through(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    for key, value in {
        "PUBLICATION_RUN_ID": "123",
        "PUBLICATION_SOURCE_SHA": SOURCE,
        "GITHUB_REPOSITORY": REPOSITORY,
    }.items():
        monkeypatch.setenv(key, value)
    seen: list[tuple[object, ...]] = []

    def ready(*args: object) -> bool:
        seen.append(args)
        return True

    monkeypatch.setattr(wait_module, "publication_ready", ready)
    monkeypatch.setattr(wait_module, "registry_ready", lambda *args: bool(seen.append(args) or True))
    wait_module.wait(ALPHA, tmp_path / "wheel", timeout=1, channel="alpha")
    assert seen[0] == (REPOSITORY, "123", SOURCE, "alpha")
    assert seen[1][-1] == "alpha"


def test_alpha_wait_retries_transient_registry_errors(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    for key, value in {
        "PUBLICATION_RUN_ID": "123",
        "PUBLICATION_SOURCE_SHA": SOURCE,
        "GITHUB_REPOSITORY": REPOSITORY,
    }.items():
        monkeypatch.setenv(key, value)
    attempts: list[int] = []

    def ready(*args: object) -> bool:
        attempts.append(1)
        if len(attempts) == 1:
            raise urllib.error.URLError("temporary")
        return True

    monkeypatch.setattr(wait_module, "publication_ready", ready)
    monkeypatch.setattr(wait_module, "registry_ready", lambda *args: True)
    monkeypatch.setattr(wait_module.time, "sleep", lambda *args: None)
    wait_module.wait(ALPHA, tmp_path / "wheel", timeout=1, channel="alpha")
    assert len(attempts) == 2


# --- source authorization ----------------------------------------------------------------


def _authorize(tmp_path: Path, **overrides: str) -> subprocess.CompletedProcess[str]:
    env = {
        "PATH": os.environ["PATH"],
        "RELEASE_BRANCH": "main",
        "CORE_TAG": ALPHA_TAG,
        "CORE_VERSION": ALPHA,
        "GITHUB_REPOSITORY": REPOSITORY,
        "GITHUB_OUTPUT": str(tmp_path / "out"),
        "RUNNER_TEMP": str(tmp_path),
        "RELEASE_CHANNEL": "alpha",
        "PUBLICATION_SOURCE_SHA": SOURCE,
        **overrides,
    }
    env = {key: value for key, value in env.items() if value != "<unset>"}
    return subprocess.run(["bash", str(AUTHORIZE)], cwd=ROOT, env=env, capture_output=True, text=True, check=False)


@pytest.mark.parametrize(
    "overrides",
    [
        {"RELEASE_BRANCH": "release/3.0"},
        {"CORE_TAG": "v3.4.0"},
        {"CORE_TAG": "alpha/v3.4.0a1"},
        {"PUBLICATION_SOURCE_SHA": ""},
        {"PUBLICATION_SOURCE_SHA": "A" * 40},
        {"PUBLICATION_SOURCE_SHA": "<unset>"},
        {"RELEASE_CHANNEL": "beta"},
    ],
)
def test_alpha_source_authorization_rejects_unbound_inputs_before_any_network_access(
    tmp_path: Path, overrides: dict[str, str]
) -> None:
    result = _authorize(tmp_path, **overrides)
    assert result.returncode != 0
    assert not (tmp_path / "core-trust.git").exists()
    assert not (tmp_path / "out").exists()
