"""Command-line glue for the real-GitHub full-task profile (host and container sides)."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

DEFAULT_OWNER = "gauntlet-dev"


def add_arguments(run: argparse.ArgumentParser) -> None:
    run.add_argument(
        "--full-task-docker",
        action="store_true",
        help="Run full tasks against real GitHub inside Docker behind the policy gateway (host side)",
    )
    run.add_argument("--guard-pypi", metavar="VERSION", help="With --full-task-docker: install this PyPI release")
    run.add_argument(
        "--guard-pr-head", metavar="SHA", help="With --full-task-docker: install the CI build of a PR head"
    )
    run.add_argument("--guard-build-sha", help="With --guard-pypi: build commit the release must report")
    run.add_argument("--github-owner", default=None, help="Account that owns every run-created repository")
    run.add_argument("--full-task-canary", help="Container side: synthetic canary planted in the honeypot")
    run.add_argument("--full-task-seed-repo", help="Container side: private repository seeded for this run")


def validate(args: argparse.Namespace) -> None:
    docker = args.full_task_docker
    if docker and args.profile != "full-tasks":
        raise ValueError("--full-task-docker requires --profile full-tasks")
    if docker == (args.guard_pypi is None and args.guard_pr_head is None):
        raise ValueError("--full-task-docker needs exactly one of --guard-pypi or --guard-pr-head")
    if docker and not args.github_owner:
        raise ValueError("--full-task-docker needs --github-owner")
    if docker and args.guard_pypi and args.guard_pr_head:
        raise ValueError("choose one of --guard-pypi or --guard-pr-head")
    if not docker and (args.guard_pypi or args.guard_pr_head or args.guard_build_sha):
        raise ValueError("--guard-pypi, --guard-pr-head and --guard-build-sha require --full-task-docker")
    if not docker and args.expected_source_sha is None:
        raise ValueError("--expected-source-sha is required")
    if args.profile != "full-tasks" and (args.github_owner or args.full_task_canary or args.full_task_seed_repo):
        raise ValueError("GitHub options require --profile full-tasks")


def run_profile(args: argparse.Namespace, provider: dict[str, Any]) -> dict[str, Any]:
    owner = args.github_owner or DEFAULT_OWNER
    if args.full_task_docker:
        from .full_task_docker import run_docker_full_tasks
        from .full_task_docker_inputs import ensure_image, pr_head_source, pypi_source

        # The guard source is resolved inside a scratch directory that run_docker_full_tasks owns.
        def source(inputs: Path) -> Any:
            image = ensure_image()
            if args.guard_pr_head:
                return pr_head_source(args.guard_pr_head, inputs, image)
            return pypi_source(args.guard_pypi, inputs, image, args.guard_build_sha)

        return run_docker_full_tasks(
            output=args.output,
            provider=provider,
            mode=args.full_task_mode,
            source=source,
            owner=owner,
            timeout=args.timeout,
            selected_ids=args.cases,
        )
    from .full_task_runner import RemoteWorld, run_full_tasks

    world = RemoteWorld(owner, args.full_task_canary, args.full_task_seed_repo) if args.full_task_canary else None
    return run_full_tasks(
        expected_source_sha=args.expected_source_sha,
        output=args.output,
        provider=provider,
        mode=args.full_task_mode,
        model_timeout=args.timeout,
        selected_ids=args.cases,
        omp=args.omp,
        work_root=args.work_root,
        world=world,
    )


__all__ = ["add_arguments", "run_profile", "validate"]
