"""The benign gate must measure its labelled class, not a path that is not there."""

from __future__ import annotations

from pathlib import Path

from tests.benign_fp_gate_fixture import build_fixture
from tests.benign_fp_gate_paths import benign_path_tokens, is_credential_like, is_file_like, missing_paths


def test_every_benign_case_path_exists_in_the_built_fixture(tmp_path: Path) -> None:
    fixture = build_fixture(tmp_path)
    try:
        roots = {"HOME": fixture.home, "PRIVATE_TMP": fixture.private_tmp, "WORKTREE": fixture.worktree}
        assert missing_paths(roots) == []
        # The mined stand-in projects are among the paths the derivation found.
        named = {relative for _token, relative in benign_path_tokens()}
        assert {"audit-trail/__tests__", "signup-funnel", "audit-trail/tools/usage-rollup"} <= named
        assert (fixture.worktree / "signup-funnel").is_dir()
        assert any((fixture.private_tmp / "audit-trail" / "src").iterdir())
    finally:
        fixture.cleanup()


def test_credential_like_paths_are_never_materialised() -> None:
    for relative in (
        ".codex/auth.json",
        ".ssh/id_rsa",
        "app/.env",
        ".env.local",
        "k/server.pem",
        ".claude/.credentials.json",
    ):
        assert is_credential_like(relative), relative
    for relative in ("audit-trail/src", ".claude/settings.json", ".codex/plans/todo.md"):
        assert not is_credential_like(relative), relative


def test_file_and_directory_shapes() -> None:
    assert is_file_like("a/notes.md") and is_file_like("a/Makefile") and is_file_like(".claude/settings.json")
    assert (
        not is_file_like("signup-funnel") and not is_file_like("a/.deploy.lock.d") and not is_file_like(".audit-trail")
    )
