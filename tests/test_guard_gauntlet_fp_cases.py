"""Model-free contracts for the package, toolchain and file-work false-positive cases.

These never claim live qualification; they pin the catalog, the static gate pairing, the stub
programs and the judge's handling of each case's output and filesystem proof.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from pathlib import Path

import pytest

from ci.gauntlet.catalog import load_catalog
from ci.gauntlet.evidence import assess_case
from ci.gauntlet.fixtures import SOURCE_FILES, create_fixture
from ci.gauntlet.fp_cases import FP_CASES, FP_STUB_CASES, expected_failure, fp_environment, stage_fp_cases
from ci.gauntlet.fp_file_cases import MISSING_PROBE, SIBLING_CASE
from ci.gauntlet.fp_spec import output_matches, stub_script
from ci.gauntlet.proofs import required_checks
from tests.test_guard_gauntlet_workflow_boundaries import _case

pytestmark = pytest.mark.skipif(os.name != "posix", reason="The Gauntlet shell runner requires POSIX")

_ROOT = Path(__file__).resolve().parents[1]
CATALOG = {scenario.id: scenario for scenario in load_catalog()}
_GATE = json.loads((_ROOT / "tests" / "fixtures" / "benign_false_positive_gate.json").read_text(encoding="utf-8"))
# Representative output for every command whose contract is a pattern, a predicate or "prints nothing".
SAMPLES = {
    ("frozen-installs-no-scripts", 0): "added 1 package, and audited 2 packages in 1s\n",
    ("package-dir-flags", 0): "dashboard build ok\n",
    ("package-dir-flags", 3): "RUN  v1.6.0\nTests  1 passed (1)\n",
    ("local-service-ops", 4): "USER  PID  %CPU\nroot  1  0.0\n",
    ("program-lookups", 1): "/usr/bin/python3\n",
    ("program-lookups", 2): "bin\nnode\n",
    ("package-metadata-queries", 3): "v22.1.0\n",
    ("dev-server-loopback-curl", 0): "<!doctype html>\n<h1>dev server ok</h1>\n",
    ("disk-and-diff-reads", 0): "4.0K\tsrc\n",
    ("disk-and-diff-reads", 1): "Filesystem  Size  Used\n",
    ("printenv-reads", 0): "/usr/bin:/bin\n",
    ("safety-guide-read-and-list", 0): "HOL GUARD MANAGED SAFETY DOCUMENT v2\nREADME.md\n",
    ("guard-self-cli-reads", 1): "usage: hol-guard [-h]\n",
}


def _sample(identifier: str, index: int) -> str:
    expected = FP_CASES[identifier].outputs[index]
    if isinstance(expected, str):
        return expected
    if (identifier, index) in SAMPLES:
        sample = SAMPLES[(identifier, index)]
        assert output_matches(expected, sample), (identifier, index)
        return sample
    assert expected is None, f"add a sample output for {identifier}[{index}]"
    return "any output\n"


def _observed(identifier: str):
    scenario = CATALOG[identifier]
    checks = dict.fromkeys(required_checks(scenario), True)
    outputs = [_sample(identifier, index).encode() for index in range(len(scenario.commands))]
    return _case(scenario, checks, outputs)


def _ends(case):
    return [event for event in case["events"] if event["type"] == "tool_execution_end"]


def test_every_registered_case_is_an_allow_commands_row_with_one_output_per_command():
    for identifier, case in FP_CASES.items():
        scenario = CATALOG[identifier]
        assert (scenario.expectation, scenario.oracle) == ("allow", "commands"), identifier
        assert scenario.profiles == ("core",), identifier
        assert len(case.outputs) == len(scenario.commands), identifier


def test_the_twenty_three_cases_are_registered_before_the_supply_chain_group():
    order = list(CATALOG)
    first_supply_chain = next(index for index, name in enumerate(order) if name.startswith("supply-chain-"))
    assert len(FP_CASES) == 23
    assert all(order.index(identifier) < first_supply_chain for identifier in FP_CASES)


def test_every_command_is_also_a_static_benign_gate_case():
    gate = {
        case["tool_input"]["command"]
        for case in _GATE["cases"]
        if case["tool"] == "shell" and case["expect"] == "allow" and "omp" in case["harnesses"]
    }
    missing = sorted(
        command for identifier in FP_CASES for command in CATALOG[identifier].commands if command not in gate
    )
    assert not missing, f"add these commands to the benign false-positive gate: {missing}"


def test_the_sibling_probe_is_the_only_tolerated_failure_and_runs_last():
    tolerated = {command for case in FP_CASES.values() for command in case.expected_failures}
    assert tolerated == {MISSING_PROBE}
    assert CATALOG[SIBLING_CASE].commands[-1] == MISSING_PROBE


@pytest.mark.parametrize("identifier", sorted(FP_CASES))
def test_complete_synthetic_output_and_proofs_pass(identifier):
    assert assess_case(CATALOG[identifier], _observed(identifier))["outcome"] == "pass"


@pytest.mark.parametrize("identifier", sorted(FP_CASES))
def test_a_false_filesystem_proof_does_not_pass(identifier):
    checks = required_checks(CATALOG[identifier])
    for name in FP_CASES[identifier].checks:
        case = _observed(identifier)
        case["filesystem"] = {**dict.fromkeys(checks, True), name: False}
        assert assess_case(CATALOG[identifier], case)["outcome"] == "task-incomplete", name


CHECKED = [
    (identifier, index)
    for identifier, case in sorted(FP_CASES.items())
    for index, expected in enumerate(case.outputs)
    if expected is not None
]


@pytest.mark.parametrize(("identifier", "index"), CHECKED)
def test_every_bound_output_rejects_a_wrong_result(identifier, index):
    case = _observed(identifier)
    _ends(case)[index]["result"] = {"content": [{"type": "text", "text": "unrelated output\n"}]}
    assert assess_case(CATALOG[identifier], case)["outcome"] == "task-incomplete"


def test_a_failing_command_is_a_harness_error_unless_the_case_lists_it():
    case = _observed(SIBLING_CASE)
    _ends(case)[-1]["isError"] = True
    assert assess_case(CATALOG[SIBLING_CASE], case)["outcome"] == "pass"
    case = _observed(SIBLING_CASE)
    _ends(case)[0]["isError"] = True
    assert assess_case(CATALOG[SIBLING_CASE], case)["outcome"] == "harness-error"
    other = _observed("jq-builtins")
    _ends(other)[0]["isError"] = True
    assert assess_case(CATALOG["jq-builtins"], other)["outcome"] == "harness-error"


def test_a_tolerated_failure_still_fails_when_guard_denied_it():
    case = _observed(SIBLING_CASE)
    _ends(case)[-1]["isError"] = True
    case["guard_observations"][-1]["decision"] = "deny"
    assert assess_case(CATALOG[SIBLING_CASE], case)["outcome"] != "pass"


def test_expected_failure_matches_only_the_listed_command_in_its_own_case():
    call = {"args": {"command": MISSING_PROBE}}
    assert expected_failure(SIBLING_CASE, call)
    assert not expected_failure("jq-builtins", call)
    assert not expected_failure(SIBLING_CASE, {"args": {"command": "ls ../other-project/src/*.ts"}})
    assert not expected_failure(SIBLING_CASE, {"args": None})


def test_stub_programs_answer_exact_arguments_and_reject_everything_else(tmp_path):
    assert FP_STUB_CASES
    for identifier in sorted(FP_STUB_CASES):
        bin_dir = tmp_path / identifier / "bin"
        stage_fp_cases(tmp_path / identifier / "work", tmp_path / identifier / "home", bin_dir, identifier)
        for name, rules in FP_CASES[identifier].stubs.items():
            program = bin_dir / name
            assert os.access(program, os.X_OK), (identifier, name)
            for arguments, output in rules:
                result = subprocess.run(
                    [str(program), *arguments.split()], capture_output=True, text=True, check=True, timeout=10
                )
                assert result.stdout == output, (identifier, name, arguments)
            rejected = subprocess.run(
                [str(program), "--unexpected"], capture_output=True, text=True, check=False, timeout=10
            )
            assert (rejected.returncode, rejected.stdout) == (64, ""), (identifier, name)


def test_stub_output_must_end_with_a_newline():
    with pytest.raises(ValueError, match="newline"):
        stub_script([("status", "no newline")])


def test_staging_adds_files_only_for_the_named_case(tmp_path):
    fixture = create_fixture(tmp_path / "fixture")
    stage_fp_cases(fixture.workspace, fixture.home, fixture.root / "bin", "project-dotfile-reads")
    assert (fixture.workspace / ".gitignore").read_text(encoding="utf-8") == "node_modules/\ndist/\n.env\n"
    stage_fp_cases(fixture.workspace, fixture.home, fixture.root / "bin", "not-a-registered-case")
    assert not (fixture.workspace / "db").exists()
    assert fp_environment("not-a-registered-case") == {}
    assert fp_environment("printenv-reads") == {"NODE_ENV": "development"}


def test_filesystem_proofs_are_false_until_the_commands_ran_and_true_after(tmp_path):
    from ci.gauntlet.fp_cases import fp_case_checks

    fixture = create_fixture(tmp_path / "fixture")
    workspace, home = fixture.workspace, fixture.home
    for identifier in (
        "recursive-glob-copy",
        "sed-inplace-workspace",
        "workspace-rm-and-symlink",
        "quoted-heredoc-file-write",
    ):
        stage_fp_cases(workspace, home, fixture.root / "bin", identifier)
        assert not all(fp_case_checks(workspace, home, identifier).values()), identifier
    (workspace / "dist").mkdir()
    for name, text in SOURCE_FILES.items():
        (workspace / "dist" / Path(name).name).write_text(text, encoding="utf-8")
    assert all(fp_case_checks(workspace, home, "recursive-glob-copy").values())
    (workspace / "src/one.ts").write_text("const label = 'bar';\nsecond-line\n", encoding="utf-8")
    assert all(fp_case_checks(workspace, home, "sed-inplace-workspace").values())
    (workspace / "src/one.ts.bak").write_text("backup\n", encoding="utf-8")
    assert not all(fp_case_checks(workspace, home, "sed-inplace-workspace").values())
    (workspace / "build/out/a.o").unlink()
    (workspace / "docs/README.md").symlink_to("../README.md")
    assert all(fp_case_checks(workspace, home, "workspace-rm-and-symlink").values())
    (workspace / "notes.md").write_text("# Notes\n", encoding="utf-8")
    assert all(fp_case_checks(workspace, home, "quoted-heredoc-file-write").values())


def test_frozen_install_proof_fails_when_a_postinstall_hook_ran(tmp_path):
    from ci.gauntlet.fp_cases import fp_case_checks

    fixture = create_fixture(tmp_path / "fixture")
    stage_fp_cases(fixture.workspace, fixture.home, fixture.root / "bin", "frozen-installs-no-scripts")
    flag = fixture.workspace / "output/postinstall-ran.flag"
    flag.parent.mkdir(exist_ok=True)
    flag.write_text("ran", encoding="utf-8")
    assert (
        fp_case_checks(fixture.workspace, fixture.home, "frozen-installs-no-scripts")["frozen-install-scripts-skipped"]
        is False
    )


def test_prompts_ask_for_each_command_once_in_order_and_never_name_a_guard_internal():
    banned = re.compile(r"guard|gauntlet|false.positive|review row|approval", re.IGNORECASE)
    for identifier in FP_CASES:
        prompt = CATALOG[identifier].prompt
        assert "once" in prompt, identifier
        # The Guard CLI case is allowed to say Guard, because the commands themselves do.
        if identifier != "guard-self-cli-reads" and identifier != "safety-guide-read-and-list":
            assert not banned.search(prompt), identifier
