"""Record parity vectors for the routine git, setup and developer recognizers.

Usage: ``sfrs_routines_cases.py FIXTURE_DIR`` with ``HOL_GUARD_NATIVE=force``,
``HOL_GUARD_NATIVE_BINARY`` and ``HOL_GUARD_HOME`` set. A directory tree is built
below a fresh root; each case calls a Python function with the git, trust and
PATH services replaced by deterministic stand-ins driven by a scenario dict that
is stored in the case. The Rust port rebuilds the tree, replays the cases with a
host reading the same scenario and compares exactly. Paths carry ``{ROOT}``.
This script depends on the Python implementation and is retired with it.
"""

from __future__ import annotations

import gzip
import itertools
import json
import os
import subprocess
import sys
import tempfile
from collections.abc import Callable
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import sfrs_routines_texts as tx
from sfrs_index_cases import (
    _stand_in_pathspecs,
    _stand_in_show,
)
from sfrs_routines_texts import variant

from codex_plugin_scanner.guard.runtime import git_index_inspection as idx
from codex_plugin_scanner.guard.runtime import github_shell_capabilities as gh_shell
from codex_plugin_scanner.guard.runtime import routine_setup_commands as rsc
from codex_plugin_scanner.guard.runtime.secret_file_request_services import (
    developer_inspection as di,
)
from codex_plugin_scanner.guard.runtime.secret_file_request_services import (
    developer_routines as dr,
)
from codex_plugin_scanner.guard.runtime.secret_file_request_services import (
    git_routines as grt,
)
from codex_plugin_scanner.guard.runtime.secret_file_request_services import (
    tool_action_requests as tar,
)
from codex_plugin_scanner.guard.runtime.secret_file_request_services.shell_tokenization import _split_shell_parts

TOKEN = "{ROOT}"
ROOT = ""
SAFE_STATUS = {"--short", "-s", "-sb", "-b", "--branch", "--porcelain", "--porcelain=v1", "--ignored"}

TREE = {
    "dirs": [
        "home/proj/.git/hooks",
        "home/proj/src/nested",
        "home/proj2/.git/hooks",
        "home/proj3/.git",
        "home/unsafe-cfg/.git",
        "home/CascadeProjects/work/src",
        "home/other",
        "home/ws/.git",
        "home/ws_marker_pkg",
        "home/ws_nomarker",
        "home/ws_existing/node_modules",
        "home/dep/node_modules",
        "home/dep2/node_modules",
        "home/dep4",
        "home/dep5/node_modules",
        "home/ws_dangling",
        "mh0/.codex/memories",
        "mh_dirlink",
        "mh_dirlink_real/memories",
        "mh_filelink/.codex/memories",
        "mh_big/.codex/memories",
        "mh_isdir/.codex/memories/MEMORY.md",
        "mh_none/.codex/memories",
        "mh_empty",
        "elsewhere",
    ],
    "files": {
        "home/proj/src/a.txt": "alpha\n",
        "home/proj/package.json": "{}",
        "home/proj3/f": "x",
        "home/ws/package.json": "{}",
        "home/ws_marker_pkg/pyproject.toml": "",
        "home/ws_existing/package.json": "{}",
        "home/dep/package.json": "{}",
        "home/dep/node_modules/x": "x",
        "home/dep2/node_modules/x": "x",
        "home/dep4/node_modules": "file",
        "home/dep4/package.json": "{}",
        "home/dep5/node_modules/y": "y",
        "home/ws_existing/node_modules/z": "z",
        "mh0/.codex/memories/MEMORY.md": "memory\n",
        "mh_filelink/real.md": "memory\n",
        "mh_dirlink_real/memories/MEMORY.md": "memory\n",
        "mh_big/.codex/memories/MEMORY.md": {"repeat": "x", "count": 4 * 1024 * 1024 + 1},
        "home/proj2/.git/hooks/post-checkout": "#!/bin/sh\n",
        "home/proj/.git/hooks/post-checkout": "#!/bin/sh\n",
        "home/proj/src/hook": "#!/bin/sh\n",
        "elsewhere/out.txt": "out\n",
    },
    "exec": ["home/proj/.git/hooks/post-checkout", "home/proj/src/hook"],
    "links": {
        "mh_dirlink/.codex": "../mh_dirlink_real",
        "mh_filelink/.codex/memories/MEMORY.md": "../../real.md",
        "home/dep3": "dep",
        "home/ws_link": "ws",
        "home/proj/link": "src",
        "home/ws_dangling/node_modules": "../nowhere",
    },
}


def _deep(value: object, old: str, new: str) -> object:
    if isinstance(value, str):
        return value.replace(old, new)
    if isinstance(value, list):
        return [_deep(item, old, new) for item in value]
    if isinstance(value, dict):
        return {key: _deep(item, old, new) for key, item in value.items()}
    return value


def tok(value: object) -> object:
    return _deep(value, ROOT, TOKEN)


def bind(value: object) -> object:
    return _deep(value, TOKEN, ROOT)


def _probe(sc: dict, argv: list[str]):
    key = " ".join(argv)
    if key in sc["probes"]:
        return sc["probes"][key]
    if argv[:3] == ["rev-parse", "--verify", "--quiet"]:
        ref = argv[3][: -len("^{commit}")] if argv[3].endswith("^{commit}") else argv[3]
        known = ref[11:] in sc["branches"] if ref.startswith("refs/heads/") else ref in sc["refs"]
        return [0, sc["sha"] + "\n", ""] if known else [1, "", ""]
    if argv[:3] == ["show-ref", "--verify", "--quiet"]:
        if sc["branch_probe"] == "fail":
            return None
        known = argv[3].removeprefix("refs/heads/") in sc["branches"]
        if known:
            return [0, "", ""]
        return [1, "", "warn" if sc["branch_probe"] == "noise" else ""]
    if argv[:3] == ["config", "--null", "--get-regexp"]:
        return [sc["config_regexp"][0], sc["config_regexp"][1], ""]
    if argv[:3] == ["config", "--null", "--get-all"]:
        found = sc["pager_cfg"].get(argv[3], [1, ""])
        return [found[0], found[1], ""]
    if argv[:2] == ["rev-parse", "--git-path"]:
        return [sc["hook"][0], sc["hook"][1] + "\n", ""]
    if argv[:2] == ["rev-parse", "--absolute-git-dir"]:
        return [sc["git_dir"][0], sc["git_dir"][1] + "\n", ""]
    return [128, "", "fatal"]


@contextmanager
def patched(raw_sc: dict):
    sc = bind(raw_sc)

    def fake_run(argv, **_kw):
        out = _probe(sc, list(argv)[1:])
        if out is None:
            raise OSError("unavailable")
        return SimpleNamespace(returncode=out[0], stdout=out[1], stderr=out[2])

    fake_subprocess = SimpleNamespace(run=fake_run, SubprocessError=subprocess.SubprocessError)
    fake_shutil = SimpleNamespace(which=lambda name, **_kw: sc["which"].get(name))
    git_binary = lambda *_a, **_k: Path("/usr/bin/git") if sc["git_binary"] else None  # noqa: E731
    standalone = lambda context, *, home_dir=None: (  # noqa: E731
        context.complete
        and any("standalone-ok" in t for s in context.segments for t in s.tokens)
        and (home_dir is not None or not any("home-ok" in t for s in context.segments for t in s.tokens))
    )
    patches = [
        (grt, "subprocess", fake_subprocess),
        (grt, "shutil", fake_shutil),
        (rsc, "subprocess", fake_subprocess),
        (grt, "git_binary_path_is_trusted", lambda p, *, cwd: sc["trusted"].get(p.name, False)),
        (grt, "git_config_routing_environment_is_clean", lambda: sc["env_clean"]),
        (grt, "trusted_git_binary_for_cwd", git_binary),
        (rsc, "trusted_git_binary_for_cwd", git_binary),
        (dr, "trusted_git_binary_for_cwd", git_binary),
        (rsc, "git_worktree_add_has_execution_free_config", lambda *_a, **_k: sc["wt_config"]),
        (rsc, "_trusted_path_command", lambda c, *, cwd: Path("/usr/bin/" + c) if sc["trusted"].get(c) else None),
        (grt, "is_safe_standalone_git_object_existence_query", lambda text, *, cwd: "objexist" in text),
        (grt, "canonical_home_git_c_path", lambda text: "/h" if "homec" in text else None),
        (grt, "is_low_risk_standalone_git_routine", standalone),
        (idx, "is_low_risk_standalone_git_routine", standalone),
        (idx, "_cached_diff_pathspecs_allowed", _stand_in_pathspecs),
        (
            idx,
            "is_low_risk_git_inspection_segment",
            lambda s, *, home_dir=None: not any("unsafe-seg" in t for t in s.tokens),
        ),
        (dr, "is_low_risk_git_inspection_segment", lambda s: not any("unsafe-seg" in t for t in s.tokens)),
        (idx, "_git_show_has_execution_free_config", _stand_in_show),
        (
            tar,
            "git_status_args_are_read_only",
            lambda a: bool(a) and a[0] == "status" and all(x in SAFE_STATUS for x in a[1:]),
        ),
        (
            tar,
            "git_status_has_execution_free_config",
            lambda cwd, *, git_binary=None: sc["status_cfg"] and "unsafe-cfg" not in str(cwd),
        ),
        (di, "is_low_risk_compound_git_inspection", lambda _context: False),
        (di, "is_low_risk_git_inspection_segment", lambda s: not any("unsafe-seg" in t for t in s.tokens)),
        (
            dr,
            "_git_status_has_execution_free_config",
            lambda cwd, *, git_binary=None: sc["status_cfg"] and "unsafe-cfg" not in str(cwd),
        ),
        (gh_shell, "classify_github_cli", _gh_stand_in()),
    ]
    saved = []
    for module, name, value in patches:
        if value is None:
            continue
        saved.append((module, name, getattr(module, name)))
        setattr(module, name, value)
    keys = ("RIPGREP_CONFIG_PATH", "GIT_PAGER", "PAGER")
    before = {key: os.environ.get(key) for key in keys}
    for key in keys:
        os.environ.pop(key, None)
    os.environ.update(sc["env"])
    try:
        yield
    finally:
        for module, name, value in reversed(saved):
            setattr(module, name, value)
        for key, value in before.items():
            os.environ.pop(key, None)
            if value is not None:
                os.environ[key] = value


def _gh_stand_in():
    from sfrs_graph_cases import _stand_in

    return _stand_in


def _p(value):
    return None if value is None else Path(bind(value))


CASES: list[dict] = []
STATS: dict[str, list[int]] = {}


def _wire(value: object) -> object:
    if isinstance(value, (list, tuple)):
        return [_wire(item) for item in value]
    if isinstance(value, Path):
        return str(value)
    return value


def emit(fn: str, args: list, sc: dict, call: Callable[..., object]) -> None:
    """Record one case; a Python exception skips it (the port fails closed)."""

    stat = STATS.setdefault(fn, [0, 0])
    with patched(sc):
        try:
            result = call(*bind(args))
        except Exception:
            stat[1] += 1
            return
    if fn == "cli_metadata_command" and (result or str(args[0]).split()[:1] == ["git"]):
        stat[1] += 1  # host-trust dependent (real git binary); not portable
        return
    stat[0] += 1
    CASES.append({"fn": fn, "args": [*args, sc], "result": tok(_wire(result))})


def expand(text: str, home: str = "") -> str:
    return text.replace("{P}", tx.P).replace("{HOME}", home)


def _git_cases() -> None:
    plain = variant()
    for text, cwd, home in ((t, c, h) for t in tx.STANDALONE_TEXTS for c in tx.GIT_CWDS for h in (None, tx.H)):
        emit(
            "git_standalone_routine",
            [text, cwd, home],
            plain,
            lambda t, c, h: grt._looks_like_safe_standalone_git_routine(t, cwd=_p(c), home_dir=_p(h)),
        )
    for sc in tx.STATUS_SCS:
        for text, cwd in itertools.product((expand(t) for t in tx.STATUS_TEXTS), tx.GIT_CWDS):
            emit(
                "git_status_command",
                [text, cwd],
                sc,
                lambda t, c: grt._looks_like_safe_git_status_command(t, _split_shell_parts(t), cwd=_p(c)),
            )
    for sc in tx.GIT_BRANCH_SCS:
        for text, cwd in itertools.product((expand(t) for t in tx.SWITCH_TEXTS), tx.GIT_CWDS[:2] + tx.GIT_CWDS[4:]):
            emit(
                "git_branch_switch_command",
                [text, cwd],
                sc,
                lambda t, c: grt._looks_like_safe_git_branch_switch_command(t, _split_shell_parts(t), cwd=_p(c)),
            )
        for args, cwd in itertools.product(tx.SWITCH_ARGS, tx.GIT_CWDS[:5]):
            emit(
                "git_local_branch_switch_is_safe",
                [args, cwd],
                sc,
                lambda a, c: grt._git_local_branch_switch_is_safe(a, cwd=_p(c)),
            )
    for sc in (variant(), variant(trusted={"git-lfs": False}), variant(which={"git-lfs": None})):
        for output, cwd in itertools.product(tx.CONFIG_OUTPUTS, tx.GIT_CWDS[:2]):
            emit(
                "git_checkout_config_safe",
                [output, cwd],
                sc,
                lambda o, c: grt._git_checkout_execution_config_is_safe(o, cwd=_p(c)),
            )
    invocations = [
        ["status"],
        ["STATUS"],
        ["-C", "src", "status"],
        ["-C", ".", "log"],
        ["-C", "..", "status"],
        ["-C", "missing", "status"],
        ["-C", "~", "status"],
        ["-C", "src"],
        ["-C"],
        ["-c", "x", "status"],
        ["--no-pager", "log"],
        [""],
        ["-C", "src/a.txt", "status"],
        ["-C", tx.P + "/src", "log"],
        ["-C", "link", "ls-files"],
        ["-C", "/tmp", "status"],
        ["\u00df"],
        ["\u0130"],
        ["-C", "src", "-C"],
        ["-C", "", "status"],
        ["-Csrc", "status"],
        ["-C", "src/nested/../..", "log"],
        [],
        ["-C", "{ROOT}/home/other", "status"],
    ]
    for args, cwd in itertools.product(invocations, tx.GIT_CWDS):
        if cwd is not None:
            emit(
                "read_only_git_invocation", [args, cwd], plain, lambda a, c: grt._read_only_git_invocation(a, cwd=_p(c))
            )
    for sc, cwd, binary in itertools.product(tx.LOG_SCS, tx.GIT_CWDS[:5], (None, "/usr/bin/git")):
        emit(
            "git_log_config",
            [cwd, binary],
            sc,
            lambda c, b: grt._git_log_has_execution_free_config(_p(c), git_binary=_p(b)),
        )


def _setup_cases() -> None:
    texts = tx.worktree_texts()
    fixed = texts[:-60] if False else texts
    base = texts[-60:]
    for index, text in enumerate(fixed):
        emit(
            "git_worktree_add",
            [text, tx.WT_CWDS[1], tx.H],
            variant(),
            lambda t, c, h: rsc.is_safe_git_worktree_add(t, cwd=_p(c), home_dir=_p(h)),
        )
        if index % 7 == 0:
            for sc in tx.WT_SCS[1:]:
                emit(
                    "git_worktree_add",
                    [text, tx.WT_CWDS[1], tx.H],
                    sc,
                    lambda t, c, h: rsc.is_safe_git_worktree_add(t, cwd=_p(c), home_dir=_p(h)),
                )
    for text, cwd, home in itertools.product(base, tx.WT_CWDS, tx.WT_HOMES):
        emit(
            "git_worktree_add",
            [text, cwd, home],
            variant(),
            lambda t, c, h: rsc.is_safe_git_worktree_add(t, cwd=_p(c), home_dir=_p(h)),
        )
    for text, sc in itertools.product(base, tx.WT_SCS):
        emit(
            "git_worktree_add",
            [text, tx.WT_CWDS[1], tx.H],
            sc,
            lambda t, c, h: rsc.is_safe_git_worktree_add(t, cwd=_p(c), home_dir=_p(h)),
        )
    for text, home, cwd, sc in itertools.product(tx.RG_TEXTS, tx.RG_HOMES, (None, tx.H), tx.RG_SCS):
        emit(
            "memory_registry_search",
            [text.replace("{HOME}", home), cwd, home],
            sc,
            lambda t, c, h: rsc.is_safe_codex_memory_registry_search(t, cwd=_p(c), home_dir=_p(h)),
        )
    for value in [
        "",
        "x",
        "-x",
        "~",
        "~/x",
        "~//x",
        "~x",
        "~root",
        "a b",
        "a;b",
        "a/b",
        "a/../b",
        "\u00e9",
        "a+b",
        "a.b",
        "~/",
        "/",
        "x\n",
        "$x",
        "a*b",
        "~/a~b",
    ]:
        emit("safe_path_operand", [value], variant(), lambda v: rsc._safe_path_operand(v))
    for kind, value in itertools.product(
        ("branch", "ref"),
        [
            "main",
            "feat/x",
            "a..b",
            "a@{x}",
            "a//b",
            "a/",
            "a.",
            "x.lock",
            "a/.lock",
            "a/./b",
            "a/../b",
            "",
            "/a",
            "-a",
            "A",
            "origin/main",
            "origin/",
            "abc1234",
            "ABC1234",
            "abcdef",
            "a" * 40,
            "a" * 41,
            "a" * 128,
            "a" * 129,
            "origin/a/b.c",
            "origin/.x",
            "x y",
            "\u00e9",
            "a.lock.b",
            "a/b.lock/c",
        ],
    ):
        emit(
            "safe_git_name",
            [kind, value],
            variant(),
            lambda k, v: rsc._safe_git_name(v, rsc._BRANCH if k == "branch" else rsc._REF),
        )
    for text in (
        tx.worktree_texts()[:40]
        + tx.RG_TEXTS
        + [
            "a | b",
            "a || b",
            "a && b",
            "a & b",
            "a ; b",
            "a < b",
            "a > b",
            "a 2>&1",
            "a >>x",
            "a 1>x",
            "a <&0",
            "a>b",
            "a '|' b",
            "a \\| b",
            "a 2>",
            "a >&",
            "a \x00 b",
            "a\rb",
            "a `b`",
            "a $(b)",
            "a 'b",
        ]
    ):
        emit("literal_tokens", [text], variant(), lambda t: rsc._literal_tokens(t))
    for value, cwd, home in itertools.product(
        ["~/x", "x", "/abs/x", "~", "~x", "", ".", "..", "~/", "a/../b"],
        (tx.P, "{ROOT}/elsewhere"),
        (tx.H, "{ROOT}/mh0"),
    ):
        emit(
            "expand_path",
            [value, cwd, home],
            variant(),
            lambda v, c, h: str(rsc._expand_path(v, cwd=Path(c), home_dir=Path(h))),
        )
        emit(
            "absolute_destination",
            [value, cwd, home],
            variant(),
            lambda v, c, h: rsc._absolute_destination(v, cwd=Path(c), home_dir=Path(h)),
        )
    for dest, home in itertools.product(
        [
            "{ROOT}/home/CascadeProjects/work/x",
            "{ROOT}/home/CascadeProjects/x",
            "{ROOT}/home/CascadeProjects/work/src/x",
            "/tmp/x",
            "/tmp/a/b",
            "/tmp",
            "/x",
            "{ROOT}/home/other/x",
            "{ROOT}/home/CascadeProjects",
            "/tmp/../x",
            "{ROOT}/home/CascadeProjects/work/missing/x",
            "{ROOT}/home/proj/link/x",
            "{ROOT}/home/proj/src/a.txt/x",
        ],
        (tx.H, "{ROOT}/mh0"),
    ):
        emit(
            "safe_worktree_parent",
            [dest, home],
            variant(),
            lambda d, h: rsc._safe_worktree_parent(Path(d), home_dir=Path(h)),
        )
    for path, home in itertools.product(
        [
            "{ROOT}/mh0/.codex/memories/MEMORY.md",
            "{ROOT}/mh_dirlink/.codex/memories/MEMORY.md",
            "{ROOT}/mh_filelink/.codex/memories/MEMORY.md",
            "{ROOT}/mh_none/.codex/memories/MEMORY.md",
            "{ROOT}/elsewhere/out.txt",
            "{ROOT}/mh0",
            "{ROOT}/mh0/.codex",
            "{ROOT}/home/proj/link/a.txt",
        ],
        (
            "{ROOT}/mh0",
            "{ROOT}/mh_dirlink",
            "{ROOT}/mh_filelink",
            "{ROOT}/mh_none",
            "{ROOT}/home/proj",
            "{ROOT}/missing",
        ),
    ):
        emit(
            "path_has_symlink_below_home",
            [path, home],
            variant(),
            lambda p, h: rsc._path_has_symlink_below_home(Path(p), home_dir=Path(h)),
        )
    for sc, ref, cwd in itertools.product(tx.WT_SCS, tx.WT_REFS, (tx.P,)):
        emit("git_ref_exists", [cwd, ref], sc, lambda c, r: rsc._git_ref_exists(Path("/usr/bin/git"), Path(c), r))
    for sc, branch in itertools.product(tx.WT_SCS, ["main", "dev", "feature/x", "taken", "new", ""]):
        emit(
            "git_branch_exists",
            [tx.P, branch],
            sc,
            lambda c, b: rsc._git_branch_exists(Path("/usr/bin/git"), Path(c), b),
        )


def _developer_cases() -> None:
    for text, cwd in itertools.product((expand(t) for t in tx.K8S_TEXTS), tx.GIT_CWDS):
        emit(
            "kubernetes_inventory_command",
            [text, cwd],
            variant(),
            lambda t, c: dr._looks_like_safe_kubernetes_inventory_command(t, _split_shell_parts(t), cwd=_p(c)),
        )
    for text, cwd, sc in itertools.product((expand(t) for t in tx.COMPOUND_TEXTS), (None, tx.P, tx.H), tx.COMPOUND_SCS):
        emit(
            "compound_developer_inspection",
            [text, cwd, tx.H],
            sc,
            lambda t, c, h: dr._looks_like_safe_compound_developer_inspection(t, cwd=_p(c), home_dir=_p(h)),
        )
    for text, cwd in itertools.product(tx.CLI_TEXTS, (None, tx.P, "{ROOT}/home/missing")):
        emit(
            "cli_metadata_command",
            [text, cwd],
            variant(),
            lambda t, c: dr._looks_like_safe_cli_metadata_command(t, _split_shell_parts(t), cwd=_p(c)),
        )
    for text, cwd in itertools.product(tx.DEP_TEXTS, tx.DEP_CWDS):
        emit(
            "dependency_symlink_context",
            [text, cwd, tx.H],
            variant(),
            lambda t, c, h: _context(dr._safe_dependency_symlink_execution_context(t, cwd=_p(c), home_dir=_p(h))),
        )


def _context(context):
    if context is None:
        return None
    return {
        "complete": context.complete,
        "segments": len(context.segments),
        "command_text": context.command_text,
        "workspace_root": None if context.workspace_root is None else str(context.workspace_root),
    }


def main() -> None:
    global ROOT
    out_dir = Path(sys.argv[1])
    os.environ["PATH"] = "/usr/bin:/bin"
    with tempfile.TemporaryDirectory() as raw:
        ROOT = str(Path(raw).resolve())
        base = Path(ROOT)
        for name in TREE["dirs"]:
            (base / name).mkdir(parents=True, exist_ok=True)
        for name, spec in TREE["files"].items():
            (base / name).parent.mkdir(parents=True, exist_ok=True)
            (base / name).write_text(spec if isinstance(spec, str) else spec["repeat"] * spec["count"])
        for name in TREE["exec"]:
            (base / name).chmod(0o755)
        for name, target in TREE["links"].items():
            (base / name).parent.mkdir(parents=True, exist_ok=True)
            (base / name).symlink_to(target)
        os.environ["HOME"] = str(base / "home")
        os.chdir(base / "home" / "proj")
        _git_cases()
        _setup_cases()
        _developer_cases()
    document = {"tree": TREE, "cases": CASES}
    out_dir.mkdir(parents=True, exist_ok=True)
    with gzip.GzipFile(out_dir / "routines.json.gz", "wb", mtime=0) as handle:
        handle.write(json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode())
    for fn, (ok, skipped) in sorted(STATS.items()):
        print(f"{fn}: {ok} recorded, {skipped} skipped")
    print(f"{len(CASES)} cases")


if __name__ == "__main__":
    main()
