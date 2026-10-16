"""Materialise the fixture paths that benign gate cases name.

The mined cases name project directories (scrubbed to stand-in names) that the
hand-built fixture never grew. Instead of listing them one by one, derive them
from the cases: every ``${HOME}``, ``${PRIVATE_TMP}`` and ``${WORKTREE}`` path in
a case that expects ``allow`` is created, so a listing or a search has something
to read and the case measures its labelled class rather than a missing path.
"""

from __future__ import annotations

import json
import posixpath
import re
from collections.abc import Iterator
from pathlib import Path

CASES_PATH = Path(__file__).parent / "fixtures" / "benign_false_positive_gate.json"
ROOT_TOKENS = ("HOME", "PRIVATE_TMP", "WORKTREE")
# A path ends at whitespace, a quote, a shell operator or a glob character.
_PATH_TOKEN = re.compile(r"\$\{(" + "|".join(ROOT_TOKENS) + r")\}((?:/(?:[^\s'\"`;&|<>()*?$\[\]{}\\]|\$(?![{(]))+)*)")
_CREDENTIAL_NAME = re.compile(
    r"(^\.env(\..*)?$|^id_|\.pem$|\.key$|\.p12$|\.pfx$|credential|secret|token|^auth\.json$|^\.netrc$|^\.npmrc$)",
    re.IGNORECASE,
)
_KNOWN_FILES = frozenset({"Makefile", "Dockerfile", "LICENSE", "README", "Procfile", "Gemfile", "Justfile"})
_CODE_PARENTS = frozenset({"src", "lib", "scripts", "tools", "__tests__", "tests", "workers"})


def _strings(value: object) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _strings(item)


def is_credential_like(relative: str) -> bool:
    return any(_CREDENTIAL_NAME.search(part) for part in relative.split("/") if part)


def is_file_like(relative: str) -> bool:
    name = posixpath.basename(relative)
    if name in _KNOWN_FILES or (name.endswith("rc") and name.startswith(".")):
        return True
    if "bin" in relative.split("/")[:-1]:
        return True
    # `.deploy.lock.d` is a lock directory; a bare dotfile such as `.audit-trail` is a directory.
    stem = name.lstrip(".")
    return bool(posixpath.splitext(stem)[1]) and not name.endswith(".d")


def benign_path_tokens(document: dict[str, object] | None = None) -> set[tuple[str, str]]:
    """``(root token, relative path)`` pairs named by cases that expect ``allow``."""
    cases = (document or json.loads(CASES_PATH.read_text(encoding="utf-8")))["cases"]
    found: set[tuple[str, str]] = set()
    for case in cases:
        if case.get("expect") != "allow":
            continue
        for text in _strings(case.get("tool_input", {})):
            for match in _PATH_TOKEN.finditer(text):
                relative = posixpath.normpath("/" + match.group(2).strip("/")).strip("/")
                partial = text[match.end() : match.end() + 1] in {"*", "?", "[", "{", "."}
                if partial:
                    # A glob or brace continues the last name, so only its parent is a real path.
                    relative = posixpath.dirname(relative)
                if relative and ".git" not in relative.split("/"):
                    found.add((match.group(1), relative))
    return found


def materialise(roots: dict[str, Path], document: dict[str, object] | None = None) -> list[tuple[str, str]]:
    """Create each benign path under its root. Returns the credential-like paths left alone."""
    skipped: list[tuple[str, str]] = []
    directories: list[Path] = []
    for token, relative in sorted(benign_path_tokens(document)):
        if is_credential_like(relative):
            skipped.append((token, relative))
            continue
        target = roots[token] / relative
        if target.exists():
            continue
        if any(parent.is_file() for parent in target.parents if roots[token] in parent.parents):
            continue
        if is_file_like(relative):
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(f"# {target.name}\nSynthetic placeholder content.\n", encoding="utf-8")
        else:
            target.mkdir(parents=True, exist_ok=True)
            directories.append(target)
    for directory in directories:
        if any(directory.iterdir()):
            continue
        if directory.name.endswith(".d"):
            (directory / "pid").write_text("4242\n", encoding="utf-8")
        elif directory.name in _CODE_PARENTS:
            (directory / "index.ts").write_text("export const placeholder = 1;\n", encoding="utf-8")
        else:
            (directory / "README.md").write_text(
                f"# {directory.name}\nSynthetic placeholder notes.\n", encoding="utf-8"
            )
    return skipped


def missing_paths(roots: dict[str, Path], document: dict[str, object] | None = None) -> list[str]:
    """Benign, non-credential paths the built fixture does not contain."""
    return sorted(
        f"${{{token}}}/{relative}"
        for token, relative in benign_path_tokens(document)
        if not is_credential_like(relative) and not (roots[token] / relative).exists()
    )
