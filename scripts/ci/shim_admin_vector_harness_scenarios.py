"""Scenario builders for the harness-launcher and audit-stamp shim-admin operations.

These cover the three subops added once the harness launcher renderer, the
managed profile plan and the audit stamp moved to the resident: ``render_guard_shim``,
``guard_profile_plan`` and ``record_audit``. The recorder replays them against the
pre-cutover Python (``prepare_guard_shim``, ``prepare_guard_shim_shell_profile`` and
``package_shim_status.record_package_shim_audit_result``) and stores the result in
``shim_admin_vectors_harness.v1.json.gz``.
"""

from __future__ import annotations

from shim_admin_vector_profile_scenarios import EXPORT, GUARD, PKG, write_b64
from shim_admin_vector_scenarios import (
    Scenario,
    Step,
    base_facts,
    call,
    env,
    manifest_step,
    mkdir,
    scenario,
    symlink,
    write,
)

# The recorder runs on the host that owns the Python implementation; the platform
# string is an input of the launcher renderer (it selects the Desktop data root).
PLATFORM = "darwin"
DESKTOP_SHIM = "home/Library/Application Support/org.hol.guard.desktop/core/current-hol-guard"
GUARD_EXPORT = "export PATH={root}/guard/bin:$PATH"


def render(harness: str = "codex", **args: object) -> Step:
    values: dict[str, object] = {
        "harness": harness,
        "launcher_name": None,
        "display_name": None,
        "launcher_env": [],
        "platform": PLATFORM,
    }
    values.update(args)
    return call("render_guard_shim", **values)


def runnable(path: str) -> Step:
    return write(path, "#!/bin/sh\nexit 0\n", executable=True)


def audit_scenarios() -> list[Scenario]:
    stamp = "2026-01-02T03:04:05+00:00"
    manifest = "guard/package-shims/manifest.json"
    scenarios = [
        scenario("audit-missing-manifest", [call("record_audit")], durable=True),
        scenario("audit-explicit-stamp", [call("record_audit", audited_at=stamp)], durable=True),
        scenario(
            "audit-keeps-other-keys",
            [
                manifest_step(
                    {"installed_managers": ["npm"], "content_hashes": {"npm": "a" * 64}, "z": [1, {"k": None}]}
                ),
                call("record_audit", audited_at=stamp),
                call("record_audit"),
            ],
            durable=True,
        ),
        scenario(
            "audit-after-install",
            [call("install", managers=["npm"]), call("record_audit", audited_at=stamp), call("status")],
            durable=True,
        ),
        scenario("audit-non-object", [write(manifest, "[1, 2]"), call("record_audit", audited_at=stamp)], durable=True),
        scenario("audit-not-json", [write(manifest, "{nope"), call("record_audit", audited_at=stamp)], durable=True),
        scenario(
            "audit-invalid-utf8",
            [write_b64(manifest, b"\xff\xfe"), call("record_audit", audited_at=stamp)],
            durable=True,
        ),
        scenario(
            "audit-unicode-keys",
            [write(manifest, '{"caf\\u00e9": "\\u2603"}'), call("record_audit", audited_at=stamp)],
            durable=True,
        ),
        scenario("audit-directory-manifest", [mkdir(manifest), call("record_audit", audited_at=stamp)], durable=True),
        scenario(
            "audit-symlinked-manifest-directory",
            [
                mkdir("outside"),
                mkdir("guard"),
                symlink("guard/package-shims", "{root}/outside"),
                call("record_audit", audited_at=stamp),
            ],
            durable=True,
        ),
        scenario(
            "audit-symlinked-manifest-file",
            [
                mkdir("guard/package-shims"),
                write("outside.json", "{}"),
                symlink(manifest, "{root}/outside.json"),
                call("record_audit", audited_at=stamp),
            ],
            durable=True,
        ),
        scenario(
            "audit-guard-home-is-file", [write("guard", "x"), call("record_audit", audited_at=stamp)], durable=True
        ),
    ]
    return scenarios


def render_variant_scenarios() -> list[Scenario]:
    pythonpath = "{root}/pp"
    native = [["PYTHONPATH", pythonpath], ["HOL_GUARD_NATIVE", "1"], ["HOL_GUARD_NATIVE_BINARY", "{root}/native/guard"]]
    native_env = env(PYTHONPATH=pythonpath, HOL_GUARD_NATIVE="1", HOL_GUARD_NATIVE_BINARY="{root}/native/guard")
    scenarios = [
        scenario("render-plain", [render()], durable=True),
        scenario("render-claude", [render("claude-code")], durable=True),
        scenario("render-workspace", [render()], workspace_dir="{root}/work", durable=True),
        scenario(
            "render-workspace-quoted", [mkdir("it's here"), render()], workspace_dir="{root}/it's here", durable=True
        ),
        scenario("render-home-differs", [mkdir("other"), render()], home_dir="{root}/other", durable=True),
        scenario(
            "render-home-differs-symlink",
            [mkdir("other"), symlink("alias", "{root}/other"), render()],
            home_dir="{root}/alias",
            durable=True,
        ),
        scenario(
            "render-home-same-via-symlink",
            [symlink("homelink", "{root}/home"), render()],
            home_dir="{root}/homelink",
            durable=True,
        ),
        scenario("render-home-explicit", [render()], home_override_explicit=True, durable=True),
        scenario("render-names", [render(launcher_name="codex-cli", display_name="Codex CLI")], durable=True),
        scenario("render-name-blank", [render(launcher_name="", display_name="")], durable=True),
        scenario("render-name-spaces", [render("weird harness 'x'")], durable=True),
        scenario("render-guard-home-quoted", [render()], guard_home="{root}/it's guard $x", durable=True),
        scenario("render-env", [render(launcher_env=native)], facts=base_facts(environ=native_env), durable=True),
        scenario(
            "render-env-pythonpath",
            [render(launcher_env=[["PYTHONPATH", "{root}/pp"]])],
            facts=base_facts(environ=env(PYTHONPATH="{root}/pp")),
            durable=True,
        ),
    ]
    for version in ([3, 8], [3, 11], [3, 12], [3, 13]):
        scenarios.append(
            scenario(
                f"render-python-{version[0]}-{version[1]}",
                [render()],
                facts=base_facts(python_version=version),
                durable=True,
            )
        )
    scenarios.append(
        scenario("render-import-root-quoted", [render()], facts=base_facts(import_root="{root}/it's src"), durable=True)
    )
    scenarios.append(
        scenario(
            "render-executable-spaces", [render()], facts=base_facts(executable="{root}/my py/python3"), durable=True
        )
    )
    return scenarios


def render_durable_scenarios() -> list[Scenario]:
    frozen = base_facts(frozen=True, executable="{root}/nope/py")
    owner = "HOL_GUARD_DESKTOP_RUNTIME_OWNER"
    scenarios = [
        scenario("render-frozen-no-candidate", [render()], facts=frozen, durable=True),
        scenario("render-frozen-runtime-executable", [render()], facts=base_facts(frozen=True), durable=True),
        scenario(
            "render-frozen-local-bin", [runnable("home/.local/bin/hol-guard"), render()], facts=frozen, durable=True
        ),
        scenario(
            "render-frozen-local-bin-not-executable",
            [write("home/.local/bin/hol-guard", "x"), render()],
            facts=frozen,
            durable=True,
        ),
        scenario(
            "render-frozen-local-bin-directory",
            [mkdir("home/.local/bin/hol-guard"), render()],
            facts=frozen,
            durable=True,
        ),
        scenario(
            "render-frozen-owner",
            [runnable("owner/hol-guard"), render()],
            facts=base_facts(
                frozen=True, environ=env(**{owner: "{root}/owner/hol-guard"}), executable="{root}/nope/py"
            ),
            durable=True,
        ),
        scenario(
            "render-frozen-owner-missing",
            [render()],
            facts=base_facts(frozen=True, environ=env(**{owner: "{root}/owner/gone"}), executable="{root}/nope/py"),
            durable=True,
        ),
        scenario(
            "render-frozen-owner-transient",
            [runnable("tmp/o/hol-guard"), render()],
            facts=base_facts(
                frozen=True, environ=env(**{owner: "{root}/tmp/o/hol-guard"}), executable="{root}/nope/py"
            ),
            durable=True,
        ),
        scenario(
            "render-frozen-owner-tilde",
            [runnable("home/own/hol-guard"), render()],
            facts=base_facts(frozen=True, environ=env(**{owner: "~/own/hol-guard"}), executable="{root}/nope/py"),
            durable=True,
        ),
        scenario("render-frozen-desktop-current", [runnable(DESKTOP_SHIM), render()], facts=frozen, durable=True),
        scenario(
            "render-frozen-desktop-current-not-executable",
            [write(DESKTOP_SHIM, "x"), render()],
            facts=frozen,
            durable=True,
        ),
        scenario(
            "render-frozen-desktop-wins-over-local-bin",
            [runnable(DESKTOP_SHIM), runnable("home/.local/bin/hol-guard"), render()],
            facts=frozen,
            durable=True,
        ),
        scenario("render-desktop-current-without-freeze", [runnable(DESKTOP_SHIM), render()], durable=True),
        scenario(
            "render-frozen-xdg-data-home",
            [runnable("xdg/org.hol.guard.desktop/core/current-hol-guard"), render()],
            facts=base_facts(frozen=True, environ=env(XDG_DATA_HOME="{root}/xdg"), executable="{root}/nope/py"),
            durable=True,
        ),
        scenario(
            "render-frozen-xdg-data-home-blank",
            [runnable("home/.local/share/org.hol.guard.desktop/core/current-hol-guard"), render()],
            facts=base_facts(frozen=True, environ=env(XDG_DATA_HOME="   "), executable="{root}/nope/py"),
            durable=True,
        ),
        scenario(
            "render-frozen-local-share",
            [runnable("home/.local/share/org.hol.guard.desktop/core/current-hol-guard"), render()],
            facts=frozen,
            durable=True,
        ),
        scenario(
            "render-frozen-versioned-core",
            [
                runnable("desk/versions/1.0/hol-guard"),
                runnable("desk/current-hol-guard"),
                mkdir("home/.local/bin"),
                symlink("home/.local/bin/hol-guard", "{root}/desk/versions/1.0/hol-guard"),
                render(),
            ],
            facts=frozen,
            durable=True,
        ),
        scenario(
            "render-frozen-versioned-core-no-shim",
            [
                runnable("desk/versions/1.0/hol-guard"),
                mkdir("home/.local/bin"),
                symlink("home/.local/bin/hol-guard", "{root}/desk/versions/1.0/hol-guard"),
                render(),
            ],
            facts=frozen,
            durable=True,
        ),
        scenario(
            "render-frozen-versioned-core-shim-not-executable",
            [
                runnable("desk/versions/1.0/hol-guard"),
                write("desk/current-hol-guard", "x"),
                mkdir("home/.local/bin"),
                symlink("home/.local/bin/hol-guard", "{root}/desk/versions/1.0/hol-guard"),
                render(),
            ],
            facts=frozen,
            durable=True,
        ),
        scenario(
            "render-frozen-bundled-bin",
            [
                runnable("desk/bundled/1.0/bin/hol-guard"),
                runnable("desk/current-hol-guard"),
                mkdir("home/.local/bin"),
                symlink("home/.local/bin/hol-guard", "{root}/desk/bundled/1.0/bin/hol-guard"),
                render(),
            ],
            facts=frozen,
            durable=True,
        ),
        scenario(
            "render-frozen-bundled-lib",
            [
                runnable("desk/bundled/1.0/lib/hol-guard-core/hol-guard"),
                runnable("desk/current-hol-guard"),
                mkdir("home/.local/bin"),
                symlink("home/.local/bin/hol-guard", "{root}/desk/bundled/1.0/lib/hol-guard-core/hol-guard"),
                render(),
            ],
            facts=frozen,
            durable=True,
        ),
        scenario(
            "render-frozen-versions-too-deep",
            [
                runnable("desk/versions/1.0/extra/hol-guard"),
                runnable("desk/current-hol-guard"),
                mkdir("home/.local/bin"),
                symlink("home/.local/bin/hol-guard", "{root}/desk/versions/1.0/extra/hol-guard"),
                render(),
            ],
            facts=frozen,
            durable=True,
        ),
        scenario(
            "render-frozen-dangling-local-bin",
            [mkdir("home/.local/bin"), symlink("home/.local/bin/hol-guard", "{root}/nowhere"), render()],
            facts=frozen,
            durable=True,
        ),
        scenario(
            "render-frozen-home-override",
            [mkdir("other"), runnable("other/.local/bin/hol-guard"), render()],
            facts=frozen,
            home_dir="{root}/other",
            durable=True,
        ),
        scenario(
            "render-frozen-workspace",
            [render()],
            facts=base_facts(frozen=True),
            workspace_dir="{root}/work",
            durable=True,
        ),
        scenario(
            "render-frozen-quoted",
            [render("it's")],
            facts=base_facts(frozen=True),
            guard_home="{root}/it's guard $x",
            workspace_dir="{root}/work",
            durable=True,
        ),
        scenario(
            "render-frozen-names",
            [render(launcher_name="codex-cli", display_name="Codex CLI")],
            facts=base_facts(frozen=True),
            durable=True,
        ),
        scenario(
            "render-frozen-env",
            [render(launcher_env=[["HOL_GUARD_NATIVE", "1"]])],
            facts=base_facts(frozen=True, environ=env(HOL_GUARD_NATIVE="1")),
            durable=True,
        ),
        scenario(
            "render-appimage-executable",
            [render()],
            facts=base_facts(executable="{root}/tmp/.mount_abc/usr/bin/python3"),
            durable=True,
        ),
        scenario(
            "render-appimage-private-tmp",
            [render()],
            facts=base_facts(executable="{root}/private/tmp/.mount_abc/python3"),
            durable=True,
        ),
        scenario(
            "render-appimage-with-local-bin",
            [runnable("home/.local/bin/hol-guard"), render()],
            facts=base_facts(executable="{root}/tmp/.mount_abc/python3"),
            durable=True,
        ),
    ]
    return scenarios


def render_scenarios() -> list[Scenario]:
    return [*render_variant_scenarios(), *render_durable_scenarios()]


PROFILE_PLAN_CONTENTS: list[tuple[str, str]] = [
    ("empty", ""),
    ("user-only", "alias ll='ls -l'\n"),
    ("no-trailing-newline", "alias ll='ls -l'"),
    ("current-block", f"{GUARD}\n{GUARD_EXPORT}\n"),
    ("current-block-plus-user", f"alias a=b\n{GUARD}\n{GUARD_EXPORT}\nalias c=d\n"),
    ("stale-block", f"{GUARD}\nexport PATH=/old:$PATH\n"),
    ("two-blocks", f"{GUARD}\nexport PATH=/a:$PATH\nuser\n{GUARD}\nexport PATH=/b:$PATH\n"),
    ("blank-sandwich", f"before\n\n{GUARD}\n{GUARD_EXPORT}\n\nafter\n"),
    ("marker-last-line", f"user\n{GUARD}\n"),
    ("package-block-untouched", f"{PKG}\n{EXPORT}\n"),
    ("crlf", f"user\r\n{GUARD}\r\n{GUARD_EXPORT}\r\nmore\r\n"),
    ("only-blank-lines", "\n\n\n"),
    ("unicode", "# café ☃\n"),
]


def profile_plan_scenarios() -> list[Scenario]:
    scenarios: list[Scenario] = []
    for label, content in PROFILE_PLAN_CONTENTS:
        for shell in ("/bin/zsh", "/bin/bash", "/usr/bin/fish"):
            name = shell.rsplit("/", 1)[1]
            profile = "home/.config/fish/config.fish" if name == "fish" else f"home/.{name}rc"
            scenarios.append(
                scenario(
                    f"plan-{label}-{name}",
                    [write(profile, content), call("guard_profile_plan"), call("guard_profile_plan")],
                    facts=base_facts(environ=env(shell=shell)),
                    durable=True,
                )
            )
    for label, shell in (
        ("empty", ""),
        ("unset", None),
        ("tcsh", "/usr/bin/tcsh"),
        ("bare-bash", "bash"),
        ("trailing-slash", "/bin/bash/"),
        ("path-fish", "/opt/fish/bin/fish"),
    ):
        scenarios.append(
            scenario(
                f"plan-shell-{label}",
                [call("guard_profile_plan")],
                facts=base_facts(environ=env(shell=shell)),
                durable=True,
            )
        )
    scenarios += [
        scenario(
            "plan-invalid-utf8", [write_b64("home/.zshrc", b"\xff\xfe"), call("guard_profile_plan")], durable=True
        ),
        scenario("plan-profile-is-directory", [mkdir("home/.zshrc"), call("guard_profile_plan")], durable=True),
        scenario(
            "plan-fish-parent-is-file",
            [write("home/.config", "x"), call("guard_profile_plan")],
            facts=base_facts(environ=env(shell="/usr/bin/fish")),
            durable=True,
        ),
        scenario(
            "plan-guard-home-quoted", [call("guard_profile_plan")], guard_home="{root}/it's guard $x", durable=True
        ),
        scenario(
            "plan-guard-home-quoted-fish",
            [call("guard_profile_plan")],
            guard_home="{root}/it's guard $x",
            facts=base_facts(environ=env(shell="/usr/bin/fish")),
            durable=True,
        ),
        scenario(
            "plan-home-other", [mkdir("other"), call("guard_profile_plan")], home_dir="{root}/other", durable=True
        ),
        scenario("plan-transient-guard-home", [call("guard_profile_plan")], guard_home="{root}/tmp/guard"),
        scenario("plan-transient-var-folders", [call("guard_profile_plan")], guard_home="{root}/var/folders/x/guard"),
        scenario("plan-transient-pytest", [call("guard_profile_plan")], guard_home="{root}/pytest-of-me/guard"),
        scenario("plan-transient-temp", [call("guard_profile_plan")], guard_home="{root}/Temp/guard"),
        scenario(
            "plan-transient-env",
            [mkdir("scratch"), call("guard_profile_plan")],
            facts=base_facts(environ=env(TMPDIR="{root}/scratch")),
            guard_home="{root}/scratch/guard",
        ),
        scenario(
            "plan-transient-env-other",
            [call("guard_profile_plan")],
            facts=base_facts(environ=env(TMPDIR="{root}/elsewhere")),
            durable=True,
        ),
    ]
    return scenarios


def all_harness_scenarios() -> list[Scenario]:
    return [*audit_scenarios(), *render_scenarios(), *profile_plan_scenarios()]


def run_harness_call(shims: object, context: object, subop: str, args: dict[str, object]) -> object:
    """Run one harness subop against the pre-cutover Python; the result matches the resident's JSON."""

    import sys

    from codex_plugin_scanner.guard import package_shim_status
    from codex_plugin_scanner.guard.launcher import merge_guard_launcher_env

    if subop == "record_audit":
        package_shim_status.record_package_shim_audit_result(context, audited_at=args.get("audited_at"))  # type: ignore[arg-type]
        return None
    if subop == "render_guard_shim":
        assert args["platform"] == sys.platform, "the harness vectors are recorded on one platform"
        recorded_env = [list(item) for item in merge_guard_launcher_env().items()]
        assert recorded_env == args["launcher_env"], f"launcher_env drifted: {recorded_env!r}"
        prepared = shims.prepare_guard_shim(  # type: ignore[attr-defined]
            str(args["harness"]),
            context,
            launcher_name=args["launcher_name"],
            display_name=args["display_name"],
        )
        posix, windows = (change.after.decode("utf-8") for change in prepared.files)
        return {"posix_source": posix, "windows_source": windows, "manifest": prepared.manifest}
    if subop == "guard_profile_plan":
        prepared = shims.prepare_guard_shim_shell_profile(context)  # type: ignore[attr-defined]
        if not prepared.files:
            return {"skip": True, "manifest": prepared.manifest}
        return {
            "skip": False,
            "profile_path": prepared.manifest["profile_path"],
            "shim_dir": prepared.manifest["shim_dir"],
            "content": prepared.files[0].after.decode("utf-8"),
        }
    raise ValueError(f"unknown harness subop {subop!r}")


HARNESS_SUBOPS = frozenset({"record_audit", "render_guard_shim", "guard_profile_plan"})

__all__ = ["HARNESS_SUBOPS", "all_harness_scenarios", "run_harness_call"]
