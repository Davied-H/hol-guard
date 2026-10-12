"""Local launcher shims for Guard-managed harness execution."""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .runtime_transition import TransitionFile

from .native_shim_admin import (
    SUPPORTED_PACKAGE_SHIM_MANAGERS,
    HarnessContextLike,
    activate_package_shims,
    ensure_package_shim_path_in_shell_profile,
    get_path_order_status,
    guard_profile_plan,
    install_package_shims,
    package_shim_cloud_coverage,
    package_shim_dashboard_status,
    package_shim_status,
    package_shim_supported_managers,
    probe_package_shim_intercepts,
    remove_guard_profile_blocks,
    render_guard_shim,
    repair_package_shims,
    uninstall_package_shims,
)
from .package_shim_frozen import (
    FROZEN_PACKAGE_SHIM_SENTINEL,
    resolve_frozen_package_shim_path,
    run_frozen_package_shim,
)

HarnessContext = HarnessContextLike

_PACKAGE_SHIM_COMMANDS = {manager: manager for manager in SUPPORTED_PACKAGE_SHIM_MANAGERS}
_GUARD_PROFILE_MARKER = "# HOL Guard harness launchers"


@dataclass(frozen=True)
class PreparedGuardShim:
    files: tuple[TransitionFile, ...]
    manifest: dict[str, object]


def prepare_guard_shim(
    harness: str,
    context: HarnessContextLike,
    *,
    launcher_name: str | None = None,
    display_name: str | None = None,
) -> PreparedGuardShim:
    """Render and snapshot both launchers without creating or changing files."""
    from .codex_hook_recovery import _snapshot
    from .runtime_transition import TransitionFile

    rendered = render_guard_shim(harness, context, launcher_name=launcher_name, display_name=display_name)
    manifest = rendered["manifest"]
    posix_path = Path(str(manifest["shim_path"]))
    windows_path = Path(str(manifest["windows_shim_path"]))
    files = []
    for path, text, executable in (
        (posix_path, rendered["posix_source"], True),
        (windows_path, rendered["windows_source"], False),
    ):
        before = _snapshot(path)
        before_mode = path.stat().st_mode & 0o777 if before is not None else 0o644
        change = TransitionFile(
            path.resolve(strict=False),
            before,
            text.replace("\n", os.linesep).encode("utf-8"),
            before_mode=before_mode,
            after_mode=before_mode | 0o755 if executable else before_mode,
        )
        change.payload()  # Reject unsafe modes/targets before any publication.
        files.append(change)
    return PreparedGuardShim(tuple(files), manifest)


def install_guard_shim(
    harness: str,
    context: HarnessContextLike,
    *,
    launcher_name: str | None = None,
    display_name: str | None = None,
) -> dict[str, object]:
    """Publish the same prepared launcher bytes used by runtime transitions."""
    from .codex_hook_integrity import atomic_write_bytes
    from .codex_install_transaction import codex_install_transaction
    from .runtime_transition import assert_transition_mutation_allowed

    with codex_install_transaction(context.guard_home, context.guard_home / "bin", actor="harness-shim.install"):
        assert_transition_mutation_allowed(context.guard_home)
        prepared = prepare_guard_shim(harness, context, launcher_name=launcher_name, display_name=display_name)
        for change in prepared.files:
            assert change.after is not None
            atomic_write_bytes(change.path, change.after, mode=change.after_mode, private=False)
        return prepared.manifest


def remove_guard_shim(
    harness: str,
    context: HarnessContextLike,
    *,
    launcher_name: str | None = None,
    legacy_launcher_names: tuple[str, ...] = (),
    display_name: str | None = None,
) -> dict[str, object]:
    """Remove a previously installed Guard launcher shim."""
    from .codex_install_transaction import codex_install_transaction
    from .runtime_transition import assert_transition_mutation_allowed

    with codex_install_transaction(context.guard_home, context.guard_home / "bin", actor="harness-shim.uninstall"):
        assert_transition_mutation_allowed(context.guard_home)
        return _remove_guard_shim_owned(
            harness,
            context,
            launcher_name=launcher_name,
            legacy_launcher_names=legacy_launcher_names,
            display_name=display_name,
        )


def _remove_guard_shim_owned(
    harness: str,
    context: HarnessContextLike,
    *,
    launcher_name: str | None,
    legacy_launcher_names: tuple[str, ...],
    display_name: str | None,
) -> dict[str, object]:

    shim_dir = context.guard_home / "bin"
    shim_name = launcher_name or harness
    harness_label = display_name or harness
    shim_paths = [
        shim_dir / f"guard-{name}{suffix}" for name in (shim_name, *legacy_launcher_names) for suffix in ("", ".cmd")
    ]
    removed_paths: list[str] = []
    for path in shim_paths:
        if path.exists():
            path.unlink()
            removed_paths.append(str(path))
    posix_path = shim_dir / f"guard-{shim_name}"
    return {
        "shim_path": str(posix_path),
        "shim_dir": str(shim_dir),
        "removed_paths": removed_paths,
        "shim_command": posix_path.name,
        "notes": [f"Removed the Guard launcher shim for {harness_label}."],
    }


def prepare_guard_shim_shell_profile(context: HarnessContext) -> PreparedGuardShim:
    """Capture the selected shell profile and render its PATH block without writes."""
    from .adapters.base import _ensure_path_within_root
    from .codex_hook_recovery import _snapshot
    from .runtime_transition import TransitionFile

    plan = guard_profile_plan(context)
    if plan["skip"]:
        return PreparedGuardShim((), dict(plan["manifest"]))
    shim_dir = Path(str(plan["shim_dir"]))
    profile_path = Path(str(plan["profile_path"]))
    _ensure_path_within_root(context.home_dir, profile_path, label="Guard shell profile")
    before = _snapshot(profile_path)
    existing = before.decode("utf-8") if before is not None else ""
    after = str(guard_profile_plan(context, existing_profile=existing)["content"]).encode("utf-8")
    mode = profile_path.stat().st_mode & 0o777 if before is not None else 0o600
    change = TransitionFile(
        profile_path.resolve(strict=False), before, after, before_mode=mode, after_mode=mode, no_follow=True
    )
    change.payload()
    return PreparedGuardShim(
        (change,),
        {
            "changed": before != after,
            "profile_path": str(profile_path),
            "shim_dir": str(shim_dir),
            "restart_shell_required": True,
        },
    )


def ensure_guard_shim_path_in_shell_profile(context: HarnessContext) -> dict[str, object]:
    """Prepend the harness launcher shim dir in the user's normal shell profile."""
    from .codex_install_transaction import codex_install_transaction
    from .runtime_transition import RuntimeTransition, assert_transition_mutation_allowed

    prepared = prepare_guard_shim_shell_profile(context)
    if not prepared.files:
        return prepared.manifest
    assert_transition_mutation_allowed(context.guard_home)
    with codex_install_transaction(context.guard_home, context.guard_home / "bin", actor="harness-profile.install"):
        assert_transition_mutation_allowed(context.guard_home)
        prepared = prepare_guard_shim_shell_profile(context)
        payload: dict[str, object] = {"files": [change.payload() for change in prepared.files]}
        RuntimeTransition._compare(payload, "before")
        for change in prepared.files:
            RuntimeTransition._write_file(change.payload(), "after")
        RuntimeTransition._compare(payload, "after")
        return prepared.manifest


def _is_transient_path(path: Path) -> bool | None:
    """Test seam: one verdict for every path, or ``None`` to let the resident decide.

    The resident applies the real ephemeral-location check (static temp roots and
    the process ``TMPDIR``/``TEMP``/``TMP``); a test patches this to force a verdict.
    """

    del path
    return None


def _trusted_python_flags() -> list[str]:
    flags = ["-I"]
    if tuple(sys.version_info[:2]) >= (3, 11):
        flags.append("-P")
    return flags


def _trusted_import_root() -> Path:
    return Path(__file__).resolve().parents[2]


__all__ = [
    "FROZEN_PACKAGE_SHIM_SENTINEL",
    "activate_package_shims",
    "ensure_guard_shim_path_in_shell_profile",
    "ensure_package_shim_path_in_shell_profile",
    "get_path_order_status",
    "install_guard_shim",
    "install_package_shims",
    "package_shim_cloud_coverage",
    "package_shim_dashboard_status",
    "package_shim_status",
    "package_shim_supported_managers",
    "probe_package_shim_intercepts",
    "remove_guard_profile_blocks",
    "remove_guard_shim",
    "repair_package_shims",
    "resolve_frozen_package_shim_path",
    "run_frozen_package_shim",
    "uninstall_package_shims",
]
