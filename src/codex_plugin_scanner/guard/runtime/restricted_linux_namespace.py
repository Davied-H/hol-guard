"""Bound native namespace argv and private inode-pinned execution plan."""

import sys
from pathlib import Path

from ..native_restricted_linux import linux_native
from .restricted_pytest_model import RestrictedPytestPlan


def linux_readonly_argv(plan: RestrictedPytestPlan, *, private_root: Path) -> list[str]:
    from .restricted_pytest_sandbox import _profile_fields

    return linux_native(
        "linux_readonly_argv",
        {**_profile_fields(plan, private_root), "backend": plan.backend, "platform": sys.platform},
        list,
    )
