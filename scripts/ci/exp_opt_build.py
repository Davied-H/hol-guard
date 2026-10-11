"""Experiment only: build the runtime with workspace-member opt-level overrides, then time a clean member rebuild."""
import json
import os
import subprocess
import sys
from pathlib import Path

level = sys.argv[1]
manifest = ["--manifest-path", "rust/Cargo.toml"]
build = ["cargo", "build", *manifest, "--locked", "--release", "-p", "hol-guard-runtime", "--bin", "hol-guard-runtime"]
members = sorted(
    p["name"]
    for p in json.loads(subprocess.check_output(["cargo", "metadata", *manifest, "--no-deps", "--format-version", "1"]))[
        "packages"
    ]
)
extra = []
if level != "s":
    config = Path(os.environ["RUNNER_TEMP"]) / "exp-opt-level.toml"
    config.write_text("".join(f'[profile.release.package."{name}"]\nopt-level = {level[2:]}\n\n' for name in members))
    print(config.read_text())
    extra = ["--config", str(config)]
subprocess.check_call([*build, *extra])
clean = ["cargo", "clean", *manifest, "--release"]
for name in members:
    clean += ["-p", name]
subprocess.check_call(clean)
subprocess.check_call([*build, "--timings", *extra])
