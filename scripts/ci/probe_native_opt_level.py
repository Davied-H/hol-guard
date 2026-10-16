"""Measure compiler cost only; this does not qualify a native test or shipping profile."""

import hashlib
import json
import os
import subprocess
import time
from pathlib import Path

root = Path.cwd()
command = [
    "cargo",
    "build",
    "--manifest-path",
    "rust/Cargo.toml",
    "--locked",
    "--offline",
    "--release",
    "-p",
    "guard-command",
    "-p",
    "hol-guard-runtime",
    "--bin",
    "guard-command-source",
    "--bin",
    "hol-guard-runtime",
]
inputs = hashlib.sha256()
for path in sorted((root / "rust").rglob("*")):
    if path.is_file() and "target" not in path.relative_to(root / "rust").parts:
        inputs.update(str(path.relative_to(root)).encode())
        inputs.update(path.read_bytes())
identity = inputs.hexdigest()
for level in (3, 1):
    target = Path(os.environ["RUNNER_TEMP"]) / f"native-opt-{level}"
    assert not target.exists()
    environment = {**os.environ, "CARGO_PROFILE_RELEASE_OPT_LEVEL": str(level), "CARGO_TARGET_DIR": str(target)}
    environment.pop("RUSTC_WORKSPACE_WRAPPER", None)
    environment.pop("RUSTC_WRAPPER", None)
    start = time.monotonic()
    subprocess.run(command, env=environment, check=True, timeout=900)
    seconds = time.monotonic() - start
    sizes = {name: (target / "release" / name).stat().st_size for name in ("guard-command-source", "hol-guard-runtime")}
    print(
        json.dumps(
            {
                "native_inputs": identity,
                "optimization_level": level,
                "cold_seconds": round(seconds, 2),
                "binary_sizes": sizes,
                "qualification": "compile-only",
                "order": [3, 1],
            },
            sort_keys=True,
        ),
        flush=True,
    )
