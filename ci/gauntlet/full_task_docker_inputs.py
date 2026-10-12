"""Build the read-only inputs and the pinned image for container-run full tasks.

Guard comes from one of two sources: a released PyPI version, or a pull-request head whose CI
already built the wheel and the native runtime. Nothing is compiled here.
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
DOCKER_DIR = HERE / "docker"
PIN_DIR = REPO / "ci" / "pi-exact-continuation"
PLATFORM = "linux/amd64"
SLUG = "hashgraph-online/hol-guard"
GATEWAY_FILES = ("full_task_gateway.py", "full_task_gateway_policy.py")
SHA = re.compile(r"[0-9a-f]{40}")


@dataclass(frozen=True)
class GuardSource:
    """What the container installs, and the build identity the executor must find."""

    label: str
    requirement: str
    expected_sha: str
    runtime: Path | None = None


def run(args: list[str], *, timeout: float = 600, cwd: Path | None = None) -> str:
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout, cwd=cwd)
    if result.returncode != 0:
        raise RuntimeError(f"{args[0]} {args[1] if len(args) > 1 else ''} failed: {result.stderr.strip()[-400:]}")
    return result.stdout.strip()


def image_tag() -> str:
    """A tag derived from everything the image is built from, so a changed pin rebuilds it."""
    digest = hashlib.sha256()
    for path in (
        DOCKER_DIR / "Dockerfile",
        DOCKER_DIR / "entrypoint.sh",
        PIN_DIR / "package.json",
        PIN_DIR / "package-lock.json",
    ):
        digest.update(path.read_bytes())
    return "hol-guard-gauntlet-ft:" + digest.hexdigest()[:12]


def ensure_image() -> str:
    tag = image_tag()
    if subprocess.run(["docker", "image", "inspect", tag], capture_output=True).returncode != 0:
        run(
            [
                "docker",
                "build",
                "--platform",
                PLATFORM,
                "--build-context",
                f"pin={PIN_DIR}",
                "-t",
                tag,
                str(DOCKER_DIR),
            ],
            timeout=1800,
        )
    return tag


def resolve_release_sha(version: str) -> str:
    """The commit a released version was cut from, read from the public tag."""
    for tag in (f"v{version}", version):
        out = run(["git", "ls-remote", f"https://github.com/{SLUG}.git", f"refs/tags/{tag}", f"refs/tags/{tag}^{{}}"])
        rows = dict(line.split("\t")[::-1] for line in out.splitlines())
        found = rows.get(f"refs/tags/{tag}^{{}}") or rows.get(f"refs/tags/{tag}")
        if found and SHA.fullmatch(found):
            return found
    raise RuntimeError(f"no public tag found for Guard {version}; pass --guard-build-sha")


def download_wheelhouse(image: str, spec: str, wheelhouse: Path, *, mount: Path | None = None) -> None:
    """Fetch the wheel and every dependency for linux x86-64 with a plain, credential-free container."""
    mounts = ["-v", f"{wheelhouse}:/out"] + (["-v", f"{mount}:/in:ro"] if mount else [])
    run(
        [
            "docker",
            "run",
            "--rm",
            "--platform",
            PLATFORM,
            *mounts,
            image,
            "pip",
            "download",
            "--quiet",
            "--only-binary=:all:",
            "--dest",
            "/out",
            spec,
        ],
        timeout=900,
    )


def pypi_source(version: str, inputs: Path, image: str, expected_sha: str | None = None) -> GuardSource:
    wheelhouse = inputs / "wheelhouse"
    wheelhouse.mkdir(parents=True)
    download_wheelhouse(image, f"hol-guard=={version}", wheelhouse)
    return GuardSource(f"pypi:{version}", f"hol-guard=={version}", expected_sha or resolve_release_sha(version))


def pr_head_source(sha: str, inputs: Path, image: str) -> GuardSource:
    """The CI wheel and native runtime built from a PR head, downloaded by head SHA."""
    if not SHA.fullmatch(sha):
        raise ValueError("--guard-pr-head needs a full 40-hex commit")
    rows = json.loads(
        run(
            [
                "gh",
                "run",
                "list",
                "--repo",
                SLUG,
                "--workflow",
                "ci.yml",
                "--commit",
                sha,
                "--limit",
                "5",
                "--json",
                "databaseId,conclusion,status",
            ]
        )
    )
    runs = [row for row in rows if row.get("status") == "completed" and row.get("conclusion") == "success"]
    if not runs:
        raise RuntimeError("no successful CI run for that head yet")
    with tempfile.TemporaryDirectory(prefix="ft-artifacts-") as scratch:
        base = Path(scratch)
        run(
            [
                "gh",
                "run",
                "download",
                str(runs[0]["databaseId"]),
                "--repo",
                SLUG,
                "-n",
                "distributions",
                "-D",
                str(base / "dist"),
            ]
        )
        run(
            [
                "gh",
                "run",
                "download",
                str(runs[0]["databaseId"]),
                "--repo",
                SLUG,
                "-n",
                "pytest-native-command-evaluators",
                "-D",
                str(base / "native"),
            ]
        )
        wheels = sorted((base / "dist").rglob("hol_guard-*-py3-none-any.whl"))
        runtime = next(iter((base / "native").rglob("hol-guard-runtime")), None)
        if len(wheels) != 1 or runtime is None:
            raise RuntimeError("expected one hol-guard wheel and one hol-guard-runtime in the CI artifacts")
        wheelhouse = inputs / "wheelhouse"
        wheelhouse.mkdir(parents=True)
        shutil.copy2(wheels[0], wheelhouse / wheels[0].name)
        (inputs / "runtime").mkdir()
        shutil.copy2(runtime, inputs / "runtime" / "hol-guard-runtime")
        # Dependencies only: pip resolves them from the local wheel inside a credential-free container.
        download_wheelhouse(image, f"/in/{wheels[0].name}", wheelhouse, mount=wheelhouse)
    return GuardSource(f"pr-head:{sha[:12]}", wheels[0].name, sha, inputs / "runtime" / "hol-guard-runtime")


def write_repo_inputs(inputs: Path) -> None:
    """The checkout under test as a bundle (same HEAD, clean tree) and the gateway modules as a package."""
    run(["git", "bundle", "create", str(inputs / "repo.bundle"), "HEAD"], cwd=REPO)
    package = inputs / "gateway" / "ftgw"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("")
    for name in GATEWAY_FILES:
        shutil.copy2(HERE / name, package / name)
