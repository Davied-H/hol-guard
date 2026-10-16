"""Guard edits `~/.codex/config.toml`; it does not get to rewrite it.

A Windows tester reported that installing Guard reflowed their whole Codex
config. Codex users write that file by hand, so the comments and the ordering
they put there have to survive every Guard write.
"""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.adapters import codex as adapter
from codex_plugin_scanner.guard.codex_config import dump_toml, read_toml_payload

from .test_codex_publication_preparation import _context

_HAND_WRITTEN = """\
# Which model Codex talks to. Keep this at the top.
model = "fixture"
model_reasoning_effort = 'medium'   # single quotes on purpose

# Everything below is mine.
[mcp_servers.fixture]
command = "node"
args = ["fixture.js"]        # trailing comment
env = { FIXTURE = "1" }

[tui]
# A comment with no key after it.
"""


def test_an_edit_keeps_the_comments_and_the_spelling_around_it() -> None:
    payload = {"model": "fixture", "model_reasoning_effort": "medium", "approval_policy": "never"}
    rendered = dump_toml(payload, original=_HAND_WRITTEN)

    assert "# Which model Codex talks to. Keep this at the top." in rendered
    assert "model_reasoning_effort = 'medium'   # single quotes on purpose" in rendered
    assert 'approval_policy = "never"' in rendered


def test_the_rendered_file_still_means_exactly_the_payload() -> None:
    payload: dict[str, object] = {
        "model": "replacement",
        "mcp_servers": {"fixture": {"command": "node", "args": ["fixture.js", "--guard"]}},
    }
    rendered = dump_toml(payload, original=_HAND_WRITTEN)

    import tomllib

    assert tomllib.loads(rendered) == payload
    assert "# Everything below is mine." in rendered


def test_a_file_guard_cannot_parse_falls_back_to_the_plain_renderer() -> None:
    payload = {"model": "fixture"}

    assert dump_toml(payload, original="model = = =\n") == dump_toml(payload)
    assert dump_toml(payload, original=b"\xff\xfe not utf-8") == dump_toml(payload)


def test_install_and_uninstall_leave_a_hand_written_config_recognizable(tmp_path: Path, monkeypatch) -> None:
    context = _context(tmp_path, monkeypatch)
    harness = adapter.CodexHarnessAdapter()
    config_path = harness._target_config_path(context)
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(_HAND_WRITTEN, encoding="utf-8")

    harness.install(context)
    installed = config_path.read_text(encoding="utf-8")
    assert "# Which model Codex talks to. Keep this at the top." in installed
    assert "# Everything below is mine." in installed
    assert "model_reasoning_effort = 'medium'   # single quotes on purpose" in installed
    assert read_toml_payload(config_path)["hooks"]

    harness.uninstall(context)
    removed = config_path.read_text(encoding="utf-8")
    assert "# Which model Codex talks to. Keep this at the top." in removed
    assert "# Everything below is mine." in removed
    assert read_toml_payload(config_path).get("mcp_servers", {}).get("fixture", {}).get("command") == "node"
