"""Order-balanced CI test-profile comparison; no production compiler settings change."""

import json
import os
import platform
import shutil
import subprocess
import time
from pathlib import Path

root = Path.cwd()
scratch = Path(os.environ["RUNNER_TEMP"])
order = os.environ["PROFILE_ORDER"].split(",")
assert sorted(order) == ["0", "1"]
result = {
    "source": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
    "cpu_count": os.cpu_count(),
    "platform": platform.platform(),
    "order": order,
    "profiles": {},
}
inventories = {}
command = ["cargo", "nextest"]
source_args = ["--manifest-path", "rust/Cargo.toml", "--locked", "--package", "hol-guard-runtime", "--all-targets"]

try:
    # Keep the primary CI target path and identical seed bytes for both profiles.
    target = root / "rust/target"
    seed = scratch / "restored-target-seed"
    shutil.copytree(target, seed, symlinks=True)
    for level in order:
        target.rename(scratch / f"target-before-profile-{level}")
        shutil.copytree(seed, target, symlinks=True)
        env = {**os.environ, "CARGO_PROFILE_TEST_OPT_LEVEL": level}
        build_started = time.monotonic()
        listing = scratch / f"profile-{level}-inventory.json"
        with listing.open("w") as output:
            subprocess.run(
                [*command, "list", *source_args, "--message-format", "json"],
                env=env,
                stdout=output,
                check=True,
                timeout=900,
            )
        build_seconds = time.monotonic() - build_started
        data = json.loads(listing.read_text())
        inventory = sorted(
            (suite_id, name, test["ignored"], test["filter-match"])
            for suite_id, suite in data["rust-suites"].items()
            for name, test in suite["testcases"].items()
        )
        assert inventory and len(inventory) == data["test-count"]
        inventories[level] = inventory
        if len(inventories) == 2:
            assert inventories["0"] == inventories["1"], "The compiled test inventory changed"
        test_started = time.monotonic()
        subprocess.run(
            [
                *command,
                "run",
                *source_args,
                "--profile",
                "ci",
                "--test-threads",
                "4",
                "--retries",
                "0",
                "--no-fail-fast",
            ],
            env=env,
            check=True,
            timeout=900,
        )
        result["profiles"][level] = {
            "build_seconds": round(build_seconds, 3),
            "test_seconds": round(time.monotonic() - test_started, 3),
            "test_inventory": len(inventory),
            "all_tests_passed": True,
        }
        print(json.dumps({"profile": level, **result["profiles"][level]}), flush=True)
    result["same_test_inventory"] = True
finally:
    Path("test-profile-result.json").write_text(json.dumps(result, indent=2) + "\n")
