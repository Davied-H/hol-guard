"""The lanes a qualification run drove, and the ones it left alone.

`qualify` drives one lane: Oh My Pi on the core profile, the only combination
that qualifies a merge. The harness lanes and the full-task profile cover the
work a person actually does, and a release can be green on the qualifying lane
while being unpleasant to use through Claude Code or Codex. A bare
`qualified: true` reads as coverage the run never had, so the record names the
lane it drove and every lane it did not.
"""

from __future__ import annotations

HARNESSES = ("omp", "claude-code", "codex", "cursor")
PROFILES = ("core", "contained-bun-vitest", "full-tasks", "approval-retry")
QUALIFYING_LANE = ("omp", "core")

# Oh My Pi owns the contained Bun/Vitest profile; the approve-then-retry lane
# runs through an installed harness CLI and so is never Oh My Pi's.
_OMP_ONLY_PROFILES = frozenset({"contained-bun-vitest"})
_HARNESS_ONLY_PROFILES = frozenset({"approval-retry"})


def lane_profiles(harness: str) -> tuple[str, ...]:
    """The profiles this harness can drive."""
    if harness not in HARNESSES:
        raise ValueError(f"unknown Gauntlet harness: {harness}")
    excluded = _HARNESS_ONLY_PROFILES if harness == "omp" else _OMP_ONLY_PROFILES
    return tuple(profile for profile in PROFILES if profile not in excluded)


def lanes() -> tuple[tuple[str, str], ...]:
    """Every harness and profile pair the runner accepts."""
    return tuple((harness, profile) for harness in HARNESSES for profile in lane_profiles(harness))


def lane_coverage(harness: str = "omp", profile: str = "core") -> dict:
    """Name the driven lane, whether that lane can qualify a merge, and the rest."""
    if profile not in lane_profiles(harness):
        raise ValueError(f"unsupported Gauntlet lane: {harness} {profile}")
    return {
        "driven": {"harness": harness, "profile": profile},
        "is_qualifying_lane": (harness, profile) == QUALIFYING_LANE,
        "not_driven": [
            {"harness": other_harness, "profile": other_profile}
            for other_harness, other_profile in lanes()
            if (other_harness, other_profile) != (harness, profile)
        ],
    }
