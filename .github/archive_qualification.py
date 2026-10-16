"""Compare every archived test identity, including the two partition union."""

import argparse
import json
import os
import subprocess
from pathlib import Path

import yaml

CANDIDATE = "705faaf471e6bf70b5c59998dbeca1e950e18635"


def extract():
    result = subprocess.run(
        ["git", "show", f"{CANDIDATE}:.github/workflows/ci.yml"],
        check=True, capture_output=True, text=True,
    )
    steps = yaml.safe_load(result.stdout)["jobs"]["native-workspace"]["steps"]
    names = {
        "Configure the checked test profile": "configure",
        "Route workspace crates through the compiler cache": "wrapper",
        "Archive the complete runtime test build": "archive",
        "Validate the locked Rust workspace": "validate",
    }
    for step in steps:
        if step.get("name") in names:
            (Path(os.environ["RUNNER_TEMP"]) / f"{names[step['name']]}.sh").write_text(step["run"])


def normalize(source, output, selected):
    rows = []
    for suite, metadata in json.loads(Path(source).read_text())["rust-suites"].items():
        for name, case in metadata["testcases"].items():
            if not selected or case["filter-match"]["status"] == "matches":
                rows.append([suite, name, case["ignored"]])
    rows.sort()
    assert rows, "empty test inventory"
    Path(output).write_text(json.dumps(rows))
    print(f"inventory_count={len(rows)}")


def verify_union(expected, actual):
    eligible = [row for row in expected if not row[2]]
    assert actual == eligible, "partition union changed or duplicated runnable test identities"


def aggregate(baseline, parts):
    expected = json.loads(Path(baseline).read_text())
    actual = sorted(row for part in parts for row in json.loads(Path(part).read_text()))
    assert len(expected) > 2000
    verify_union(expected, actual)
    for invalid in (actual[:-1], sorted([*actual, actual[0]])):
        try:
            verify_union(expected, invalid)
        except AssertionError:
            continue
        raise AssertionError("union validator accepted a missing or duplicated test")
    print(f"full_inventory={len(expected)} existing_ignored_helpers={len(expected) - len(actual)}")
    print(f"complete_disjoint_runnable_partition_union={len(actual)} negative_controls=passed")


parser = argparse.ArgumentParser()
parser.add_argument("operation", choices=["extract", "normalize", "selected", "aggregate"])
parser.add_argument("paths", nargs="*")
args = parser.parse_args()
if args.operation == "extract":
    extract()
elif args.operation in {"normalize", "selected"}:
    normalize(*args.paths, selected=args.operation == "selected")
else:
    aggregate(args.paths[0], args.paths[1:])
