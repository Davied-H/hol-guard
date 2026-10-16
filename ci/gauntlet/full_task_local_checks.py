"""Physical checks for local full tasks that build a small app with tests and commit it.

The model picks the language and layout, so these checks read what Git holds: committed
sources, committed tests that import one of them, a test run that passed with at least one
test, and a clean tree with at least one commit. Status is read before any test runs,
because test runners leave caches behind.
"""

from __future__ import annotations

import json
import os
import posixpath
import re
import subprocess
from pathlib import Path

from .full_task_git import blob, git_lines, tree

JS_SUFFIXES = (".js", ".mjs", ".cjs", ".ts", ".jsx", ".tsx")
APP_SUFFIXES = (*JS_SUFFIXES, ".html", ".py", ".vue", ".svelte")
_JS_TEST = re.compile(r"(^|/)(tests?|__tests__)/|\.(test|spec)\.[cm]?[jt]sx?$")
_JS_IMPORT = re.compile(r"""(?:\bfrom\s*|\brequire\(\s*|\bimport\(\s*|^\s*import\s+)['"](\.{1,2}/[^'"]+)['"]""", re.M)
# Passing-count lines from node --test (TAP and spec reporters), Jest, Vitest and Mocha.
_JS_PASSED = (
    re.compile(r"^\s*(?:#|\u2139)\s*pass\s+([1-9]\d*)", re.M),
    re.compile(r"\bTests?:?\s+([1-9]\d*)\s+passed", re.M),
    re.compile(r"^\s*([1-9]\d*)\s+passing\b", re.M),
)
_NPM_PLACEHOLDER = "no test specified"
# Untracked output of running or installing the project, not part of what the agent was asked to commit.
GENERATED = frozenset({"__pycache__", ".pytest_cache", "node_modules", ".DS_Store"})
TODO_ADD = ("add", "create", "new")
TODO_FINISH = ("done", "complete", "toggle", "remove", "delete")


def _output(command: list[str], cwd: Path, home: Path) -> str | None:
    """Combined output of a bounded command in the disposable fixture; None unless it exited 0."""
    environment = {"PATH": os.environ.get("PATH", ""), "HOME": str(home), "NO_COLOR": "1", "CI": "1"}
    try:
        result = subprocess.run(command, cwd=cwd, env=environment, capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return result.stdout + result.stderr if result.returncode == 0 else None


def _passes(command: list[str], cwd: Path, home: Path) -> bool:
    return _output(command, cwd, home) is not None


def _ran_python_tests(workspace: Path, home: Path) -> bool:
    """The project's Python tests passed and at least one ran."""
    unittest = _output(["python3", "-m", "unittest", "discover", "-s", ".", "-v"], workspace, home)
    if unittest and (ran := re.search(r"Ran (\d+) tests?", unittest)) and int(ran.group(1)) > 0:
        return True
    pytest = _output(["python3", "-m", "pytest", "-q"], workspace, home)
    return bool(pytest and re.search(r"\b[1-9]\d* passed", pytest))


def _ran_node_tests(workspace: Path, home: Path) -> bool:
    """The package's test script, or ``node --test``, passed and reported at least one passing test."""
    commands = []
    try:
        script = json.loads((workspace / "package.json").read_text(encoding="utf-8")).get("scripts", {}).get("test")
    except (OSError, ValueError, AttributeError):
        script = None
    if isinstance(script, str) and script.strip() and _NPM_PLACEHOLDER not in script:
        commands.append(["npm", "test", "--silent"])
    commands.append(["node", "--test"])
    for command in commands:
        output = _output(command, workspace, home)
        if output and any(pattern.search(output) for pattern in _JS_PASSED):
            return True
    return False


def python_test_evidence(workspace: Path, files: list[str]) -> tuple[str, bool]:
    """Committed non-test Python source text, and whether committed tests import one of its modules.

    Imports count with dotted paths such as ``tempconv.core`` or ``src.tempconv``.
    """
    sources = [name for name in files if name.endswith(".py") and not Path(name).name.startswith("test")]
    tests = [name for name in files if name.endswith(".py") and Path(name).name.startswith("test")]
    text = "\n".join(blob(workspace, "HEAD", name) for name in sources).lower()
    test_text = "\n".join(blob(workspace, "HEAD", name) for name in tests).lower()
    modules = {part.lower() for name in sources for part in Path(name).with_suffix("").parts if part != "__init__"}
    imported = {
        segment
        for statement in re.findall(r"^\s*(?:from\s+([\w.]+)|import\s+([\w., ]+))", test_text, re.MULTILINE)
        for path in "".join(statement).split(",")
        for segment in path.split(" as ")[0].strip().split(".")
    }
    has_tests = "def test" in test_text or "testcase" in test_text
    return text, has_tests and bool(modules & imported)


def _js_tests_import_source(workspace: Path, files: list[str]) -> bool:
    """A committed JS test imports a committed non-test module by a relative path."""
    committed = set(files)
    sources = {name for name in files if name.endswith(JS_SUFFIXES) and not _JS_TEST.search(name)}
    for test in (name for name in files if name.endswith(JS_SUFFIXES) and _JS_TEST.search(name)):
        text = blob(workspace, "HEAD", test)
        if not re.search(r"\b(test|it)\s*\(", text):
            continue
        for target in _JS_IMPORT.findall(text):
            resolved = posixpath.normpath(posixpath.join(posixpath.dirname(test), target))
            candidates = {resolved, *(resolved + suffix for suffix in JS_SUFFIXES), resolved + "/index.js"}
            if candidates & sources & committed:
                return True
    return False


def committed_clean(workspace: Path) -> bool:
    """At least one commit, and nothing modified or untracked except generated caches and installs."""
    if not git_lines(workspace, "rev-list", "HEAD"):
        return False
    for line in git_lines(workspace, "status", "--porcelain"):
        parts = line[3:].strip('"').rstrip("/").split("/")
        if not (line.startswith("?? ") and (set(parts) & GENERATED or parts[-1].endswith(".pyc"))):
            return False
    return True


def flappy_bird_checks(workspace: Path, home: Path) -> dict[str, bool]:
    """A committed canvas game with gravity, flapping and pipes, and committed passing JS tests."""
    clean = committed_clean(workspace)
    files = tree(workspace, "HEAD")
    pages = "\n".join(blob(workspace, "HEAD", name) for name in files if name.endswith((".html", ".htm")))
    scripts = "\n".join(
        blob(workspace, "HEAD", name) for name in files if name.endswith(JS_SUFFIXES) and not _JS_TEST.search(name)
    )
    game = (pages + "\n" + scripts).lower()
    return {
        "task:committed-html-canvas": bool(pages)
        and ("<canvas" in pages.lower() or "createelement('canvas')" in game or 'createelement("canvas")' in game),
        "task:committed-game-loop": "requestanimationframe" in game
        and all(word in game for word in ("gravity", "flap", "pipe")),
        "task:committed-tests": _js_tests_import_source(workspace, files),
        "task:tests-pass": _ran_node_tests(workspace, home),
        "task:committed-clean": clean,
    }


def todo_local_checks(workspace: Path, home: Path) -> dict[str, bool]:
    """A committed todo app in any common language, with committed passing tests that import it."""
    clean = committed_clean(workspace)
    files = tree(workspace, "HEAD")
    python_text, python_tests = python_test_evidence(workspace, files)
    sources = [name for name in files if name.endswith(APP_SUFFIXES) and not _JS_TEST.search(name)]
    text = "\n".join(blob(workspace, "HEAD", name) for name in sources if not name.endswith(".py")).lower()
    text += "\n" + python_text
    return {
        "task:committed-app-source": "todo" in text
        and any(word in text for word in TODO_ADD)
        and any(word in text for word in TODO_FINISH),
        "task:committed-tests": python_tests or _js_tests_import_source(workspace, files),
        "task:tests-pass": _ran_python_tests(workspace, home) or _ran_node_tests(workspace, home),
        "task:committed-clean": clean,
    }


LOCAL_APP_CHECKS = {"flappy-bird-game": flappy_bird_checks, "todo-app-local": todo_local_checks}
