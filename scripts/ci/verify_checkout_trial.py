"""Verify that measured checkout strategies retain their complete source contracts."""

import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path.cwd()
SHA = os.environ["SOURCE_SHA"]
HEAD = "30194771ec728d5a94e50b1cc91ae653787049d1"
BASE = "51c1d7e70ba30ecee269931ec80de8e17f23cbeb"


def git(root, *args):
    return subprocess.check_output(["git", "-C", str(root), *args], timeout=90)


def scalar(root, *args):
    return git(root, *args).decode().strip()


def object_closure(root):
    return hashlib.sha256(b"\n".join(sorted(git(root, "rev-list", "--objects", "HEAD").splitlines()))).hexdigest()


control, planner, analysis = [ROOT / name for name in ("control", "planner", "analysis")]
for checkout in (control, planner, analysis):
    assert scalar(checkout, "rev-parse", "HEAD") == SHA
    assert git(checkout, "ls-tree", "-r", "HEAD") == git(control, "ls-tree", "-r", "HEAD")
    assert scalar(checkout, "rev-list", "--parents", "-n", "1", "HEAD").split() == [SHA, BASE, HEAD]
    subprocess.run(["git", "-C", str(checkout), "diff", "--exit-code"], check=True, timeout=30)
assert scalar(planner, "rev-parse", "--is-shallow-repository") == "true"
assert scalar(planner, "rev-list", "--count", "HEAD") == "3"

plans = []
for checkout in (control, planner):
    with tempfile.TemporaryDirectory() as temporary:
        trusted = Path(temporary)
        for name in (
            "scripts/__init__.py",
            "scripts/ci/__init__.py",
            "scripts/ci/plan_changes.py",
            "scripts/ci/pr_merge_base.py",
        ):
            source = git(checkout, "show", f"{BASE}:{name}")
            assert source == git(control, "show", f"{BASE}:{name}")
            path = trusted / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(source)
        output = trusted / "plan.json"
        subprocess.run(
            [
                sys.executable,
                str(trusted / "scripts/ci/plan_changes.py"),
                "--root",
                str(checkout),
                "--base",
                BASE,
                "--head",
                HEAD,
                "--output",
                str(output),
            ],
            check=True,
            timeout=90,
        )
        plans.append(json.loads(output.read_text()))
assert plans[0] == plans[1]
assert plans[0]["data_only"] is False

closure = object_closure(control)
for checkout in (control, analysis):
    assert scalar(checkout, "rev-parse", "--is-shallow-repository") == "false"
    assert scalar(checkout, "merge-base", "HEAD", "origin/main") == BASE
    assert object_closure(checkout) == closure
    for name in ("src/codex_plugin_scanner/__init__.py", "rust/crates/guard-runtime/src/main.rs"):
        assert git(checkout, "blame", "--porcelain", "HEAD", "--", name) == git(
            control, "blame", "--porcelain", "HEAD", "--", name
        )
assert scalar(analysis, "tag") == ""

sizes = {}
for checkout in (control, planner, analysis):
    statistics = dict(line.split(": ", 1) for line in scalar(checkout, "count-objects", "-v").splitlines())
    sizes[checkout.name] = {key: int(statistics[key]) for key in ("in-pack", "size-pack")}
print(
    json.dumps(
        {
            "source": SHA,
            "head": HEAD,
            "base": BASE,
            "same_object_closure": closure,
            "same_trusted_plan": True,
            "same_source_snapshot": True,
            "same_representative_blame": True,
            "sizes": sizes,
        },
        sort_keys=True,
    )
)
