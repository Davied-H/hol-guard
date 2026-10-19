"""Every path a benign case reads has to be in the gate fixture.

The catalogue names its paths through tokens (``${HOME}``, ``${ORG_WT}``,
``${PRIVATE_TMP}``), and the tokens resolve whether or not anything is there.
A case whose path is missing still runs and can still pass, but it measures
*Guard was asked about a path that is not there* rather than the shape the
case was written for, and a screen that canonicalises its target cannot tell
those two apart. Mined cases are scrubbed of private names before they are
added, so this is the easy mistake to make: the rename lands in the catalogue
and nothing creates the renamed directory.

So a benign case must either find its paths in the fixture or say here that it
creates them. Cases that write, copy into, link at, redirect into, ``mkdir``,
``git init`` or ``git worktree add`` a path are naming where the result goes,
and a few probe deliberately for something that is not there.
"""

from __future__ import annotations

import json
import re
import shutil
import tempfile
from pathlib import Path

from tests.benign_fp_gate_fixture import build_fixture

_CATALOGUE = Path(__file__).parent / "fixtures" / "benign_false_positive_gate.json"
_TOKEN_PATH = re.compile(r"\$\{[A-Z_]+\}[A-Za-z0-9_./@+-]*")

# The path named is where the command puts its result, so it is absent until
# the command runs: a new file or directory, a copy's or a link's destination,
# a redirect target, a fresh repository, a worktree checkout.
_CREATES_ITS_TARGET = frozenset(
    {
        "git-worktree-add-existing-branch",
        "git-worktree-add-existing-branch-tail",
        "git-worktree-add-new-branch-from-local-main",
        "gauntlet-worktree-add-temp-root-leaf",
        "queue-cp-r-sibling-node-modules",
        "queue-diff-sibling-to-tmp-patch",
        "queue-gh-api-logs-redirect-absolute-wc",
        "queue-git-init-scratch",
        "queue-ln-s-sibling-node-modules",
        "queue-mkdir-home-deliverables",
        "queue-touch-probe-rm",
        "queue-worktree-add-org-sibling",
        "queue-worktree-add-parent-pipe-tail",
        "queue-write-org-parent-dot-probe",
        "queue-write-sibling-repo-dot-scratch",
        "queue-write-sibling-worktree-dot-tmp-json",
        "queue-write-sibling-worktree-scratch",
        "session-git-fetch-then-worktree-add",
        "session-git-init-scratch-add-all-commit",
        "session-git-init-scratch-commit-chain",
        "session-git-init-temp-root-leaf",
        "session-git-worktree-add-c-grandparent-sibling",
        "session-git-worktree-add-c-grandparent-tail",
        "session-git-worktree-add-tmp-sibling",
        "session-mkdir-copy-preserved-globs-into-workspace",
        "session-mkdir-copy-scratch-file-into-workspace",
        "session-worktree-add-temp-root-leaf-from-tmp-repo",
        "session-worktree-add-temp-root-leaf-log",
        "tmp-write-new-file",
        "write-dollar-route-file",
        "write-dynamic-route-new-subtree",
    }
)

# The absence is the shape under test: a probe for a file that is not there,
# or a list of roots where one is missing.
_PROBES_FOR_ABSENCE = frozenset(
    {
        "gauntlet-ls-missing-git-leaf-plain-dir",
        "observed-ls-lockfile-probe-mixed",
        "queue-grep-head-wc-absent-tmp-trace",
        "session-grep-roots-one-missing-tmp-sibling",
    }
)


def _referenced(tool_input: dict[str, object]) -> list[str]:
    """Token paths the case names, minus the ones it globs."""
    blob = json.dumps(tool_input)
    named = []
    for match in _TOKEN_PATH.finditer(blob):
        tail = blob[match.end() : match.end() + 1]
        # A glob names a pattern, not a path, so nothing has to match it.
        if tail in {"*", "?", "["}:
            continue
        named.append(match.group())
    return named


def test_every_benign_case_finds_the_paths_it_reads() -> None:
    catalogue = json.loads(_CATALOGUE.read_text())
    root = Path(tempfile.mkdtemp(prefix="gate-fixture-paths-"))
    try:
        fixture = build_fixture(root)
        tokens = fixture.tokens()
        missing: list[str] = []
        for case in catalogue["cases"] + catalogue.get("mcp_cases", []):
            if case.get("expect") != "allow":
                continue
            if case["id"] in _CREATES_ITS_TARGET or case["id"] in _PROBES_FOR_ABSENCE:
                continue
            for reference in _referenced(case.get("tool_input", {})):
                token = reference[: reference.index("}") + 1]
                if token not in tokens:
                    continue
                resolved = Path(reference.replace(token, tokens[token]).rstrip("/"))
                if not resolved.exists() and not resolved.is_symlink():
                    missing.append(f"{case['id']}: {reference}")
    finally:
        try:
            fixture.cleanup()
        except NameError:
            pass
        shutil.rmtree(root, ignore_errors=True)
    assert not missing, (
        "benign cases name paths the fixture does not build, so they measure a "
        "missing path rather than the shape they were written for. Build the "
        "path in tests/benign_fp_gate_fixture.py, or, if the case creates it or "
        "probes for its absence, name the case in this test:\n  "
        + "\n  ".join(missing)
    )
