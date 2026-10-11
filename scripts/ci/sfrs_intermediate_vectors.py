"""Record parity vectors for the pure-text helpers behind the SFRS classifier.

Usage: ``sfrs_intermediate_vectors.py FIXTURE_DIR``. The command corpus is every
shell-looking string found in the recorded entry-point vectors. Each helper is run
by the Python implementation and its output is stored beside its input, so the
Rust port can be checked helper by helper instead of only through the entry
points. This script depends on the Python implementation and is retired with it.
"""

from __future__ import annotations

import ast
import gzip
import json
import os
import sys
from pathlib import Path

from codex_plugin_scanner.guard.runtime import (
    github_shell_bindings as gh_bindings,
)
from codex_plugin_scanner.guard.runtime import (
    github_shell_capabilities as runtime_gh_capabilities,
)
from codex_plugin_scanner.guard.runtime.github_capability_contract import github_assessment
from codex_plugin_scanner.guard.runtime import (
    github_shell_control_flow as gh_control_flow,
)
from codex_plugin_scanner.guard.runtime import (
    github_shell_redirections as gh_redirections,
)
from codex_plugin_scanner.guard.runtime.secret_file_request_services import (
    local_read_operands,
    read_only_filters,
    docker_requests,
    github_shell_capabilities as github_services,
    request_artifacts,
    shell_quote_tokens,
    shell_static_safety,
    shell_tokenization,
)

MAX_TEXTS = 6000
HOST_MARKERS = ("michaelkantor", "runner2-port", "hol-guard/.venv", "/home/runner", "/var/folders", "~/.codex")


GITHUB_EXTRAS = (
    "gh pr view 1",
    "gh pr view $(echo 1)",
    "gh pr view `echo 1`",
    "gh pr view \"$(echo 1)\"",
    "gh pr view '$(echo 1)'",
    "gh pr view ${NUMBER}",
    "gh pr view \"$NUMBER\"",
    "gh pr view $((1+2))",
    "gh pr view <(echo 1)",
    "gh api repos/o/r/pulls/1 | jq .title",
    "gh api repos/o/r/pulls/1 | jq -r '.[] | .title' | sort -u",
    "gh api repos/o/r/pulls/1 | sort -nr | uniq -c",
    "gh api repos/o/r/pulls/1 | head -n 3 | grep x",
    "gh api repos/o/r/pulls/1 | python3 -c 'import json,sys; print(json.load(sys.stdin))'",
    "gh api repos/o/r/pulls/1 | tee out.txt",
    "gh api repos/o/r/pulls/1 > out.json",
    "GH_TOKEN=x gh pr view 1",
    "GH_HOST=ghe.example gh pr view 1",
    "GH_HOST=github.com gh pr view 1",
    "GH_REPO=o/r gh pr view 1",
    "GH_REPO=../r gh pr view 1",
    "export GH_TOKEN=abc; gh pr view 1",
    "export GH_HOST=ghe.example && gh pr view 1",
    "GH_HOST=ghe.example; export GH_HOST; gh pr view 1",
    "FOO=1; gh pr view 1",
    "export FOO=$BAR; gh pr view 1",
    "env GH_TOKEN=x gh pr view 1",
    "env -S 'GH_TOKEN=x gh pr view 1'",
    "env --split-string='gh pr view 1'",
    "env -i gh pr view 1",
    "env -u GH_TOKEN gh pr view 1",
    "bash -c 'gh pr view 1'",
    "sh -lc \"GH_TOKEN=x gh pr view 1\"",
    "zsh -c 'export GH_HOST=x; gh pr view 1'",
    "bash -c \"gh pr view $(echo 1)\"",
    "command -v gh",
    "command -V gh",
    "command -p gh",
    "command -- gh pr view 1",
    "type gh",
    "which gh",
    "alias gh=echo",
    "function gh { echo; }",
    "gh() { echo; }; gh pr view 1",
    "echo ok | gh pr comment 1 --body-file -",
    "gh pr view 1 --json title | jq .title",
    "gh pr view 1 2>&1 | jq .",
    "gh pr view 1 1>&2",
    "unset GH_TOKEN; gh pr view 1",
    "readonly GH_HOST=ghe.example; gh pr view 1",
    "declare -x GH_REPO=o/r; gh pr view 1",
    "GH_ENTERPRISE_TOKEN= gh pr view 1",
    "gh pr view 1; echo $(cat /etc/passwd)",
    "echo $(echo $(echo hi))",
    "echo \"a $(echo \\\") b\"",
    "echo $(unterminated",
    "echo `unterminated",
    "echo $(echo ')' )",
    "echo 'a' \"b\" $(c) `d`",
    "gh pr merge 1 --squash",
    "gh pr merge 1 && echo done",
    "true && gh pr merge 1",
    "false && gh pr merge 1",
    "false || gh pr merge 1",
    "true || gh pr merge 1",
    "if true; then gh pr merge 1; fi",
    "if false; then gh pr merge 1; fi",
    "if false; then echo a; else gh pr merge 1; fi",
    "if true; then echo a; else gh pr merge 1; fi",
    "if foo; then gh pr merge 1; elif true; then gh repo delete x; fi",
    "for n in 1 2; do gh pr merge $n; done",
    "while true; do gh pr view 1; done",
    "case $x in a) gh pr merge 1;; b) echo hi;; esac",
    "case $x in a) gh repo delete x ;& b) echo hi ;;& esac",
    "( gh pr merge 1 )",
    "{ gh pr merge 1; }",
    "! gh pr view 1",
    "coproc gh pr view 1",
    "GH=gh; $GH pr merge 1",
    "GH=$(command -v gh); $GH pr merge 1",
    "GH=\"$(which gh)\"; ${GH} repo delete x",
    "g=/usr/bin/gh; \"$g\" pr view 1",
    "g=gh.exe; $g pr view 1",
    "g=C:\\\\bin\\\\gh.exe; $g pr view 1",
    "cmd='gh pr merge 1'; eval $cmd",
    "cmd='gh pr merge 1'; bash -c \"$cmd\"",
    "cmd='gh pr merge 1'; echo $cmd | sh",
    "echo 'gh pr merge 1' | bash",
    "echo gh pr merge 1 | xargs",
    "export GH=gh; bash -c '$GH pr merge 1'",
    "export GH=gh; sh -c 'echo $GH'",
    "unset GH; $GH pr view 1",
    "GH=gh; unset GH; $GH pr view 1",
    "${GH:-gh} pr merge 1",
    "${GH-gh} pr merge 1",
    "${X:-/usr/bin/gh} pr merge 1",
    "$gh pr view 1",
    "eval 'gh pr merge 1'",
    "eval gh pr merge 1",
    "exec gh pr view 1",
    "builtin command gh pr view 1",
    "timeout 5 gh pr view 1",
    "watch gh pr view 1",
    "trap 'gh pr merge 1' EXIT",
    "xargs gh pr view",
    "alias g=gh; g pr merge 1",
    "alias gh=echo; gh pr merge 1",
    "f() { gh pr merge 1; }; f",
    "function f { gh repo delete x; }; f",
    "f() ( gh pr view 1 ); f",
    "f() { echo hi; }; f",
    "f() { f2() { gh pr merge 1; }; }; f",
    "a() { b() { c() { d() { gh pr view 1; }; }; }; }; a",
    "echo $(gh pr merge 1)",
    "echo $(echo $(echo $(echo $(echo $(gh pr view 1)))))",
    "x=$(gh pr view 1); echo $x",
    "echo `gh pr merge 1`",
    "diff <(gh pr view 1) <(gh pr view 2)",
    "echo hi > >(gh pr merge 1)",
    "gh pr view 1 > out.txt",
    "gh pr view 1 >> out.txt",
    "gh pr view 1 > /dev/null",
    "gh pr view 1 2> /dev/null",
    "gh pr view 1 2>/dev/null",
    "gh pr view 1 &>/dev/null",
    "gh pr view 1 < input.txt",
    "gh pr comment 1 --body-file - <<< hi",
    "gh pr comment 1 --body-file - << EOF\nhi\nEOF",
    "gh api graphql -f query='mutation { x }'",
    "gh api -X DELETE /repos/o/r",
    "gh api repos/o/r | jq '.x' | tee out",
    "gh pr list | wc -l",
    "gh pr list | grep fix | head",
    "gh pr list | sh",
    "gh pr list --json number | jq '.[]' | xargs -I{} gh pr merge {}",
    "echo start; gh pr view 1; echo end",
    "GH_TOKEN=x; gh pr view 1",
    "FOO=bar gh pr view 1",
    "env FOO=bar gh pr view 1",
    "env gh pr merge 1",
    "command gh pr merge 1",
    "sudo gh pr merge 1",
    "nohup gh pr merge 1 &",
    "gh pr merge 1 & gh pr merge 2",
    "(cd repo && gh pr merge 1)",
    "cd repo; gh pr merge 1",
    "gh --repo o/r pr merge 1",
    "gh extension install x/y",
    "gh auth login",
    "gh auth status",
    "gh alias set x 'pr merge'",
    "gh workflow run x.yml",
    "gh release create v1",
    "gh repo view",
    "echo ${GH} pr",
    "echo $GH | sh",
    "x=gh; y=$x; $y pr merge 1",
    "x=gh; export x; bash -c '$x pr merge 1'",
    "x=gh; declare -x x; bash -c '$x pr merge 1'",
    "x=gh; export -n x; bash -c '$x pr merge 1'",
    "x=gh; readonly x; $x pr merge 1",
    "x=gh && $x pr merge 1",
    "false && x=gh; $x pr merge 1",
    "x=gh || true; $x pr merge 1",
    "local x=gh; $x pr view 1",
    "typeset -x x=gh; $x pr view 1",
)


DOCKER_EXTRAS = (
    "docker run alpine true",
    "docker login registry.example",
    "docker push example/app:1",
    "docker ps",
    "docker --help",
    "docker build --help",
    "docker build -t app .",
    "docker build --build-arg API_TOKEN=abc .",
    "docker build --build-arg TOKEN .",
    "docker build --build-arg NAME=$SECRET_KEY .",
    "docker build --secret id=x,src=.env .",
    "docker build -o type=local,dest=out .",
    "docker build --label token=ghp_abc .",
    "docker buildx build --push -t app .",
    "docker buildx --builder b build --secret id=x .",
    "docker buildx ls",
    "docker buildx build --build-arg PASSWORD=x .",
    "docker compose up -d",
    "docker compose ps",
    "docker compose exec web sh",
    "docker compose run web true",
    "docker compose --env-file prod.env up",
    "docker compose -f a.yml -p proj config",
    "docker compose build --build-arg API_KEY=x",
    "docker compose frobnicate",
    "docker compose -- up",
    "docker compose -- run web",
    "docker --context prod ps",
    "docker --context default ps",
    "docker -c prod ps",
    "docker -cprod ps",
    "docker -H tcp://host:2375 ps",
    "docker -Htcp://host ps",
    "docker --host=ssh://u@h ps",
    "docker --tlsverify ps",
    "docker --tls ps",
    "docker --config /tmp/x ps",
    "docker --config=/tmp/x ps",
    "DOCKER_HOST=tcp://h:1 docker ps",
    "DOCKER_HOST=unix:///var/run/docker.sock docker ps",
    "DOCKER_CONTEXT=prod docker ps",
    "DOCKER_CONTEXT=default docker ps",
    "DOCKER_TLS_VERIFY=1 docker ps",
    "DOCKER_TLS_VERIFY=0 docker ps",
    "DOCKER_CERT_PATH=/x docker ps",
    "DOCKER_CONFIG=/x docker ps",
    "export DOCKER_HOST=tcp://h:1 && docker ps",
    "export DOCKER_HOST=unix:///x; docker ps",
    "export DOCKER_CONTEXT=prod; docker compose ps",
    "env DOCKER_HOST=tcp://h docker ps",
    "env -i DOCKER_HOST=tcp://h docker ps",
    "env -u DOCKER_HOST docker ps",
    "env -S 'docker run x'",
    "env docker run x",
    "env",
    "env FOO=1",
    "sudo docker ps",
    "cd /tmp && docker ps && docker login",
    "docker ps | docker run x",
    "docker ps && echo hi > .docker/config.json",
    "cat ~/.docker/config.json",
    "docker --debug ps",
    "docker -D run x",
    "docker -l debug build -t a .",
    "docker image build --build-arg X=1 .",
    "docker builder build .",
)


SCRIPT_EXTRAS = (
    "import os as o; o.remove('x')",
    "import os, sys as s",
    "import os.path as p",
    "import json as j, subprocess",
    "from subprocess import run as r",
    "from os import path",
    "from os import path as p",
    "from os.path import join as j",
    "from .os import path as p",
    "from collections import OrderedDict as od",
    "from os import (\n    path as p,\n)",
    "if True:\n    import shutil as sh",
    "x = 1; import pathlib as pl",
    "print('import os as o')",
    "# import os as o\nprint(1)",
    "x = \"\"\"\nimport os as o\n\"\"\"",
    "import os as",
    "def broken(:\n  import os as o",
    "sleep 1",
    "sleep 1.5",
    "import time; time.sleep(2)",
    "time.sleep( 3 )",
    "print(open('f').read())",
    "open('f', 'w').write('x')",
    "Path('f').write_text('x')",
    "print(1)",
    "",
    "  ",
)


def _walk(value: object, found: set[str]) -> None:
    if isinstance(value, str):
        if 2 < len(value) < 2000 and " " in value and not any(marker in value for marker in HOST_MARKERS):
            found.add(value)
    elif isinstance(value, dict):
        for item in value.values():
            _walk(item, found)
    elif isinstance(value, list):
        for item in value:
            _walk(item, found)


def _corpus(fixture_dir: Path) -> list[str]:
    found: set[str] = set()
    for path in sorted(fixture_dir.glob("*.json.gz")):
        if path.name.startswith("intermediate_"):
            continue
        document = json.loads(gzip.decompress(path.read_bytes()))
        for vector in document["vectors"]:
            _walk(vector["args"], found)
    found.update(DOCKER_EXTRAS)
    found.update(GITHUB_EXTRAS)
    return sorted(found)[:MAX_TEXTS]


def _filters(segments: list[list[str]], parts: list[str]) -> dict[str, object]:
    safe = read_only_filters._read_only_lookup_target_is_safe
    filters = read_only_filters
    return {
        "targets": [[safe(part, allow_dirs=False), safe(part, allow_dirs=True)] for part in parts],
        "redirections": [
            [
                filters._read_only_lookup_arg_is_redirection(part),
                list(filters._split_attached_redirection_token(part) or []) or None,
            ]
            for part in parts
        ],
        "segments": [
            [
                filters._read_only_lookup_filter_segment_is_safe(segment[0], segment[1:]),
                filters._read_only_lookup_filter_segment_is_safe(segment[0], segment[1:], require_explicit_rg_no_config=True),
                filters._read_only_lookup_sed_args_are_safe(segment[1:], require_target=True),
                filters._read_only_lookup_head_tail_args_are_safe(segment[1:], require_target=True),
                filters._read_only_lookup_filter_grep_args_are_safe(segment[1:]),
                filters._read_only_lookup_filter_rg_args_are_safe(segment[1:]),
            ]
            for segment in segments
        ],
    }


def _operands(segments: list[list[str]], parts: list[str]) -> dict[str, object]:
    operands = local_read_operands
    return {
        "globs": [operands._search_glob_pattern_is_safe(part, root=None) for part in parts],
        "segments": [
            {
                "tokens": list(operands._shell_segment_file_operand_tokens(segment)),
                "hidden": operands._ripgrep_args_expand_hidden_files(segment[1:]),
                "roles": [
                    [list(role) for role in operands._search_file_operand_roles(name, segment[1:])]
                    for name in ("grep", "rg")
                ],
                "cat": list(operands._cat_file_operand_tokens(segment[1:])),
                "plain": list(operands._plain_file_operand_tokens(segment[1:])),
                "sed": list(operands._sed_file_operand_tokens(segment[1:])),
                "search": [operands.search_operands_are_safe(name, segment[1:], root=None) for name in ("grep", "rg")],
            }
            for segment in segments
        ],
    }


def _quote_tokens(text: str) -> dict[str, object]:
    tokens = shell_quote_tokens.shell_tokens_preserving_quote_context(text)
    segments = shell_quote_tokens.shell_token_segments(tokens)
    return {
        "tokens": [[token.raw, token.plain] for token in tokens],
        "segments": [[[token.raw, token.plain] for token in segment] for segment in segments],
    }


def _static(text: str, parts: list[str], segments: list[list[str]]) -> dict[str, object]:
    safety = shell_static_safety
    cwd, root = Path("/sfrs-nonexistent-cwd"), Path("/sfrs-nonexistent-root")
    return {
        "jq": [safety._github_jq_filter_args_are_safe(segment[1:]) for segment in segments],
        "texts": list(safety._script_interpreter_texts(parts)),
        "redirections": [safety._without_safe_inspection_redirections(segment) for segment in segments],
        "syntax": [safety._shell_syntax_check_segment_is_safe(segment[0], segment[1:]) for segment in segments],
        "escapes": [safety._shell_token_escapes_root(part, cwd=cwd, root=root) for part in parts],
        "substitution": [safety._shell_token_has_command_substitution(part) for part in parts],
        "interpreter": [
            [safety._is_python_interpreter_command(part), safety._is_script_interpreter_command(part)] for part in parts
        ],
        "payloads": [
            [None if (found := safety._interpreter_flag_payload(parts, index)) is None else [found.script_text, found.tokens_consumed]]
            for index in range(len(parts))
        ],
    }


def _github(text: str, parts: list[str], segments: list[list[str]]) -> dict[str, object]:
    gh = github_services
    return {
        "substitutions": list(gh._shell_command_substitution_payloads(text)),
        "dynamic": gh._github_shell_has_dynamic_arguments(text),
        "tokens": [
            [gh._shell_token_has_expansion(part), gh.github_argument_token_has_untrusted_expansion(part), gh._github_environment_name(part)]
            for part in parts
        ],
        "pipelines": gh._iter_shell_pipelines(parts),
        "env_index": [gh._shell_segment_env_index(segment) for segment in segments],
        "env_split": list(gh._env_split_string_payloads(parts)),
        "scripts": list(gh._shell_command_scripts(parts)),
        "persistent": gh._persistent_github_environment_requires_review(parts),
        "builtin": [gh._shell_segment_is_command_builtin_lookup(segment) for segment in segments],
        "companion": [
            gh._github_pipeline_companion_is_read_only(segment, home_dir=None, command_text=text)
            for segment in segments
        ],
        "script_review": gh._github_script_requires_review(text),
    }


ENVIRONMENT_CASES = (
    (),
    (("GH_TOKEN", "x"),),
    (("GITHUB_TOKEN", ""),),
    (("GH_CONFIG_DIR", "/tmp"),),
    (("GH_HOST", "github.com"),),
    (("GH_HOST", "GitHub.com"),),
    (("GH_HOST", "ghe.example"),),
    (("GH_HOST", "GITHUB.COM"),),
    (("GH_REPO", "owner/repo"),),
    (("GH_REPO", "../x"),),
    (("GH_REPO", "https://github.com/a/b"),),
    (("GH_REPO", "ghe.example/a/b"),),
    (("GH_REPO", "$X"),),
    (("OTHER", "1"), ("GH_ENTERPRISE_TOKEN", "t")),
)


def _environments() -> list[object]:
    gh = github_services
    return [[[list(item) for item in case], gh._github_environment_requires_review(case)] for case in ENVIRONMENT_CASES]


def _stand_in(args):
    """Deterministic substitute for the native GitHub CLI classifier."""

    joined = " ".join(args)
    if joined.startswith("pr merge"):
        capability = "merge_remote"
    elif "delete" in joined:
        capability = "delete_remote"
    elif joined.startswith(("pr view", "repo view")):
        capability = "read_remote"
    else:
        capability = "unknown"
    return github_assessment(capability, f"stub.{joined}", "stub")


def _assessment(found: object) -> object:
    if found is None:
        return None
    return {
        "capability": found.capability,
        "capabilities": list(found.capabilities),
        "reason_code": found.reason_code,
        "detail": found.detail,
    }


def _stubbed_assessment(text: str) -> object:
    original = runtime_gh_capabilities.classify_github_cli
    runtime_gh_capabilities.classify_github_cli = _stand_in
    try:
        return _assessment(github_services.classify_github_shell_capabilities(text, home_dir=None))
    finally:
        runtime_gh_capabilities.classify_github_cli = original


def _gh_shell(text: str, parts: list[str], segments: list[list[str]]) -> dict[str, object]:
    gh, b = github_services, gh_bindings
    primary = shell_tokenization._shell_segment_primary_command
    pipelines = gh._iter_shell_pipelines(parts)
    conditional, skipped = gh_control_flow.pipeline_control_flow(parts, pipelines, primary_command=primary)
    names = [frozenset(), frozenset({"x"}), frozenset({"gh2", "y"})]
    prefix = [(index, primary(segment)[1]) for index, segment in enumerate(segments)]
    return {
        "assessment": _stubbed_assessment(text),
        "normalized": b.normalize_github_lookup_assignments(text),
        "command_text": b.contains_github_command_text(text),
        "functions": [[body, head, end - start] for body, head, start, end in b.function_definition_payloads(text)],
        "parent": sorted(b.parent_expanded_variable_names(text)),
        "complex": [
            b.complex_control_flow_may_invoke_github(text, github_command_variables=one, github_command_text_variables=two)
            for one in names
            for two in names
        ],
        "connectors": sorted([key, value] for key, value in b.conditional_pipeline_connectors(parts).items()),
        "control": [sorted(conditional), sorted(skipped)],
        "scoped": [list(item) for item in b.scoped_command_substitutions(text, payloads=gh._shell_command_substitution_payloads)],
        "executes": [[b.pipeline_executes_github_text(pipeline, primary_command=primary, github_command_text_variables=one) for one in names] for pipeline in pipelines],
        "tokens": [
            [
                b.value_names_github_executable(part),
                b.is_shell_variable_name(part),
                b.token_is_shell_assignment(part),
                [b.dynamic_command_may_invoke_github(part, github_command_variables=one, github_command_text_variables=two) for one in names for two in names],
                [b.tokens_reference_github_variable([part], github_command_variables=one, github_command_text_variables=two) for one in names for two in names],
            ]
            for part in parts
        ],
        "segments": [
            {
                "exec": b.executable_control_flow_segment(segment),
                "case": [list(arm) for arm in b.case_arm_segments(segment)],
                "standalone": b.segment_is_standalone_assignment(segment),
                "updates": [
                    [list(item) for item in b.assignment_updates(segment, command_index=index, text_values=flag)]
                    for flag in (False, True)
                ],
                "persistent": [
                    [
                        list(item)
                        for item in b.persistent_assignment_updates(
                            segment, command_name=name, command_index=index, text_values=flag
                        )
                    ]
                    for flag in (False, True)
                ],
                "redirection": None if index is None else list(gh_redirections.github_shell_args_and_redirection(segment, index)),
                "definition": None
                if index is None or name is None
                else [
                    b.definition_payload(segment, command_name=kind, command_index=index) for kind in ("alias", "function")
                ],
                "exported": [
                    _exported(segment, name, index, current, suppress)
                    for current in (frozenset(), frozenset({"x", "gh2"}))
                    for suppress in (False, True)
                ],
            }
            for segment in segments
            for name, index in [primary(segment)]
        ],
    }


def _exported(segment: list[str], name: str | None, index: int | None, current: frozenset[str], suppress: bool) -> list[str]:
    exported = {"x", "z"}
    gh_bindings.update_exported_bindings(
        segment,
        command_name=name,
        command_index=index,
        current_bindings=set(current),
        exported_bindings=exported,
        suppress_removals=suppress,
    )
    return sorted(exported)


def _parses(text: str) -> bool:
    try:
        ast.parse(text)
    except (SyntaxError, ValueError):
        return False
    return True


def _script(text: str) -> dict[str, object]:
    safety = shell_static_safety
    return {
        "text": text,
        "parses": _parses(text),
        "aliased": safety._script_has_aliased_risky_import(text),
        "wait": safety._script_is_benign_wait(text),
        "observer": safety._script_is_read_only_observer(text),
    }


def _record(text: str) -> dict[str, object]:
    parts = shell_tokenization._split_shell_parts(text)
    segments = shell_tokenization._iter_shell_command_segments(parts)
    primaries = [list(shell_tokenization._shell_segment_primary_command(segment)) for segment in segments]
    return {
        "text": text,
        "parts": parts,
        "segments": segments,
        "primaries": primaries,
        "variables": list(request_artifacts._shell_variable_names(text)),
        "docker": [
            [
                shell_tokenization._docker_subcommand_index(segment[1:]),
                shell_tokenization._docker_build_args_are_sensitive(segment[1:]),
                request_artifacts._docker_buildx_subcommand_index(segment[1:]),
                shell_tokenization._docker_subcommand_help_requested(segment[1:]),
            ]
            for segment in segments
        ],
        "docker_reason": docker_requests._docker_sensitive_reason(text),
        "names": [request_artifacts._normalized_shell_command_name(part) for part in parts],
        "filters": _filters(segments, parts),
        "operands": _operands(segments, parts),
        "quote": _quote_tokens(text),
        "static": _static(text, parts, segments),
        "github": _github(text, parts, segments),
        "gh_shell": _gh_shell(text, parts, segments),
    }


def main() -> None:
    fixture_dir = Path(sys.argv[1])
    os.environ.pop("RIPGREP_CONFIG_PATH", None)
    corpus = _corpus(fixture_dir)
    records = [_record(text) for text in corpus]
    scripts = sorted({*SCRIPT_EXTRAS, *(text for record in records for text in record["static"]["texts"])})
    document = {
        "schema": "sfrs-intermediate.v1",
        "tokens": records,
        "scripts": [_script(text) for text in scripts],
        "environments": _environments(),
    }
    out = fixture_dir / "intermediate_tokens.json.gz"
    out.write_bytes(gzip.compress(json.dumps(document, sort_keys=True).encode("utf-8"), mtime=0))
    print(f"{len(records)} records -> {out}")


if __name__ == "__main__":
    main()
