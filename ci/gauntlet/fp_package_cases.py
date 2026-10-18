"""Package, toolchain and local-service cases for earlier false-positive fixes.

npm, node, curl, ps and the shell builtins are real. Every other toolchain (pnpm, bun, uv,
cargo, go, yarn, docker, kubectl, brew, pg_ctl, pgrep, pip) and the registry-backed npm
queries are stubs that print fixed text, so no case needs a registry, a daemon or a host
that happens to carry the tool. Projects are synthetic and every dependency is vendored.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from .fp_spec import Check, FpCase, absent, exact_file, stub_script

# npm prints an update notice on stderr for old versions; keep every real npm run quiet.
NPM_QUIET = {"npm_config_update_notifier": "false", "npm_config_fund": "false", "npm_config_audit": "false"}


def _json(value: object) -> str:
    return json.dumps(value, indent=2) + "\n"


def _linked(path: Path, target: str) -> bool:
    return path.is_symlink() and path.resolve() == (path.parent / target).resolve() and path.resolve().is_dir()


FROZEN_CASE = "frozen-installs-no-scripts"
_LINK_MANIFEST = {
    "name": "fixture-app",
    "version": "1.0.0",
    "private": True,
    "scripts": {"postinstall": "node -e \"require('fs').writeFileSync('output/postinstall-ran.flag', 'ran')\""},
    "dependencies": {"ui-kit": "file:vendor/ui-kit"},
}
_LINK_LOCK = {
    "name": "fixture-app",
    "version": "1.0.0",
    "lockfileVersion": 3,
    "requires": True,
    "packages": {
        "": {
            "name": "fixture-app",
            "version": "1.0.0",
            "hasInstallScript": True,
            "dependencies": {"ui-kit": "file:vendor/ui-kit"},
        },
        "node_modules/ui-kit": {"resolved": "vendor/ui-kit", "link": True},
        "vendor/ui-kit": {"version": "1.0.0"},
    },
}
_PNPM_INSTALL = (
    "Lockfile is up to date, resolution step is skipped\nAlready up to date\n\nDone in 312ms using pnpm v9.12.0\n"
)
_UV_SYNC = "Resolved 1 package in 1ms\nAudited 1 package in 0.04ms\n"

PACKAGE_DIR_CASE = "package-dir-flags"
_DASHBOARD_BUILD = (
    "const fs = require('node:fs');\n"
    "fs.mkdirSync('dist', { recursive: true });\n"
    "fs.writeFileSync('dist/bundle.js', \"console.log('dashboard bundle');\\n\");\n"
    "console.log('dashboard build ok');\n"
)
_VITEST = "#!/usr/bin/env node\nconsole.log('RUN  v1.6.0');\nconsole.log('Tests  1 passed (1)');\n"
_PNPM_TEST = "\n> dashboard@1.0.0 test /project/dashboard\n> node --test\n\n# tests 3\n# pass 3\n# fail 0\n"
_BUN_TEST = "bun test v1.1.34\n\n 3 pass\n 0 fail\nRan 3 tests across 1 files.\n"

TOOLCHAIN_CASE = "contained-toolchain-tests"
_PYTEST_UV = "..                                                                       [100%]\n2 passed in 0.02s\n"
_PYTEST_VENV = "..                                                                       [100%]\n2 passed in 0.03s\n"
_CARGO_TEST = (
    "   Compiling app v0.1.0\n    Finished `test` profile [unoptimized + debuginfo] target(s) in 0.31s\n"
    "     Running unittests src/lib.rs\n\nrunning 2 tests\ntest tests::adds ... ok\ntest tests::subtracts ... ok\n\n"
    "test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out\n"
)
_GO_TEST = "ok  \texample.com/app\t0.004s\n"
_PRETTIER = "Checking formatting...\nAll matched files use Prettier code style!\n"
_YARN_TEST = "yarn run v1.22.22\n$ node --test\n# tests 2\n# pass 2\n# fail 0\nDone in 0.21s.\n"
_PRETTIER_BIN = (
    "#!/usr/bin/env node\nconsole.log('Checking formatting...');\n"
    "console.log('All matched files use Prettier code style!');\n"
)
_VENV_PYTHON = stub_script([("-m pytest -q", _PYTEST_VENV)])

DOCKER_CASE = "docker-read-commands"
_DOCKER_VERSION = (
    "Client:\n Version:           27.3.1\n API version:       1.47\n Go version:        go1.22.7\n\n"
    "Server: Docker Desktop\n Engine:\n  Version:          27.3.1\n  API version:      1.47 (minimum version 1.24)\n"
)
_DOCKER_PS = "CONTAINER ID   IMAGE     COMMAND   CREATED   STATUS    PORTS     NAMES\n"
_DOCKER_COMPOSE = "NAME      STATUS      CONFIG FILES\n"
_DOCKER_BUILDX = (
    "NAME/NODE       DRIVER/ENDPOINT   STATUS    BUILDKIT   PLATFORMS\ndefault*        docker\n"
    " \\_ default     \\_ default       running   v0.16.0    linux/arm64\n"
)

SERVICE_CASE = "local-service-ops"
_KUBECONFIG = (
    "apiVersion: v1\nkind: Config\nclusters:\n- name: example\n  cluster:\n    server: https://k8s.example.invalid\n"
    "contexts:\n- name: example\n  context:\n    cluster: example\n    user: example\ncurrent-context: example\n"
    "users:\n- name: example\n  user: {}\n"
)
_KUBECTL_PODS = (
    "NAME    READY   STATUS    RESTARTS   AGE\n"
    "web-0   1/1     Running   0          2d\nweb-1   1/1     Running   0          2d\n"
)
_BREW_SERVICES = (
    "Name            Status  User      File\n"
    "postgresql@16   started developer ~/Library/LaunchAgents/homebrew.mxcl.postgresql@16.plist\n"
)
_PG_STATUS = 'pg_ctl: server is running (PID: 4242)\n/opt/postgres/bin/postgres "-D" "./db"\n'
_PGREP = "4242 node dev-server.js\n4310 node worker.js\n"

LOOKUP_CASE = "program-lookups"

METADATA_CASE = "package-metadata-queries"
_NPM_CACHE = "make-fetch-happen:request-cache:https://registry.npmjs.org/zod/-/zod-3.23.8.tgz\n"
_PIP_SHOW = (
    "Name: pip\nVersion: 24.3.1\nSummary: The PyPA recommended tool for installing Python packages.\n"
    "Location: /usr/lib/python3/dist-packages\nRequires: \nRequired-by: \n"
)

DEV_SERVER_CASE = "dev-server-loopback-curl"
_DEV_SERVER = (
    "const http = require('node:http');\n"
    "const at = process.argv.indexOf('--port');\n"
    "const port = at > 0 ? Number(process.argv[at + 1]) : 4173;\n"
    "http.createServer((request, response) => {\n"
    "  response.setHeader('content-type', 'text/html');\n"
    "  response.end('<!doctype html>\\n<title>dev</title>\\n<h1>dev server ok</h1>\\n');\n"
    "}).listen(port, '127.0.0.1');\n"
    "// A server left behind by a missed cleanup stops on its own.\n"
    "setTimeout(() => process.exit(0), 10000);\n"
)

_NODE_VERSION = re.compile(r"\Av\d+\.\d+\.\d+\n\Z")


def _frozen_checks() -> dict[str, Check]:
    return {
        "frozen-install-link-real": lambda workspace, _home: _linked(
            workspace / "node_modules/ui-kit", "../vendor/ui-kit"
        ),
        "frozen-install-scripts-skipped": lambda workspace, _home: absent(workspace / "output/postinstall-ran.flag"),
    }


def _dashboard_checks() -> dict[str, Check]:
    return {
        "dashboard-bundle-exact": lambda workspace, _home: exact_file(
            workspace / "dashboard/dist/bundle.js", "console.log('dashboard bundle');\n"
        )
    }


PACKAGE_CASES: dict[str, FpCase] = {
    FROZEN_CASE: FpCase(
        files={
            ".npmrc": "offline=true\naudit=false\nfund=false\nupdate-notifier=false\n",
            "package.json": _json(_LINK_MANIFEST),
            "package-lock.json": _json(_LINK_LOCK),
            "vendor/ui-kit/package.json": _json({"name": "ui-kit", "version": "1.0.0", "main": "index.js"}),
            "vendor/ui-kit/index.js": "module.exports = 'ui-kit';\n",
            "pnpm-lock.yaml": "lockfileVersion: '9.0'\n\nimporters:\n\n  .: {}\n",
            "pyproject.toml": (
                '[project]\nname = "fixture-app"\nversion = "1.0.0"\nrequires-python = ">=3.9"\ndependencies = []\n'
            ),
            "uv.lock": (
                'version = 1\nrequires-python = ">=3.9"\n\n[[package]]\nname = "fixture-app"\n'
                'version = "1.0.0"\nsource = { virtual = "." }\n'
            ),
        },
        stubs={
            "pnpm": [("install --frozen-lockfile", _PNPM_INSTALL)],
            "uv": [("sync --frozen", _UV_SYNC)],
        },
        outputs=(re.compile(r"added 1 package"), _PNPM_INSTALL, _UV_SYNC),
        checks=_frozen_checks(),
    ),
    PACKAGE_DIR_CASE: FpCase(
        files={
            "package.json": _json(
                {"name": "app", "version": "1.0.0", "private": True, "devDependencies": {"vitest": "1.6.0"}}
            ),
            "dashboard/package.json": _json(
                {
                    "name": "dashboard",
                    "version": "1.0.0",
                    "private": True,
                    "scripts": {"build": "node build.js", "test": "node --test"},
                }
            ),
            "dashboard/build.js": _DASHBOARD_BUILD,
        },
        executables={"node_modules/.bin/vitest": _VITEST},
        stubs={
            "pnpm": [("-C dashboard test", _PNPM_TEST)],
            "bun": [("--cwd dashboard test", _BUN_TEST)],
        },
        environment=NPM_QUIET,
        outputs=(re.compile(r"dashboard build ok"), _PNPM_TEST, _BUN_TEST, re.compile(r"Tests\s+1 passed \(1\)")),
        checks=_dashboard_checks(),
    ),
    TOOLCHAIN_CASE: FpCase(
        files={
            "package.json": _json(
                {"name": "app", "version": "1.0.0", "private": True, "scripts": {"test": "node --test"}}
            ),
            "yarn.lock": "# yarn lockfile v1\n\n\n",
            "pyproject.toml": '[project]\nname = "app"\nversion = "1.0.0"\nrequires-python = ">=3.9"\n',
            ".venv/pyvenv.cfg": "home = /usr/bin\ninclude-system-site-packages = false\nversion = 3.12.0\n",
            "Cargo.toml": '[package]\nname = "app"\nversion = "0.1.0"\nedition = "2021"\n',
            "go.mod": "module example.com/app\n\ngo 1.22\n",
            "src/a.js": "const answer = 42;\nmodule.exports = answer;\n",
        },
        executables={
            ".venv/bin/python": _VENV_PYTHON,
            "node_modules/.bin/prettier": _PRETTIER_BIN,
        },
        stubs={
            "uv": [("run pytest -q", _PYTEST_UV)],
            "cargo": [("test", _CARGO_TEST)],
            "go": [("test ./...", _GO_TEST)],
            "yarn": [("test", _YARN_TEST)],
        },
        environment=NPM_QUIET,
        outputs=(_PYTEST_UV, _PYTEST_VENV, _CARGO_TEST, _GO_TEST, _PRETTIER, None, _YARN_TEST),
    ),
    DOCKER_CASE: FpCase(
        stubs={
            "docker": [
                ("version", _DOCKER_VERSION),
                ("ps", _DOCKER_PS),
                ("compose ls", _DOCKER_COMPOSE),
                ("buildx ls", _DOCKER_BUILDX),
            ]
        },
        outputs=(_DOCKER_VERSION, _DOCKER_PS, _DOCKER_COMPOSE, _DOCKER_BUILDX),
    ),
    SERVICE_CASE: FpCase(
        files={"kube.yaml": _KUBECONFIG, "db/PG_VERSION": "16\n"},
        stubs={
            "kubectl": [("get pods", _KUBECTL_PODS)],
            "brew": [("services list", _BREW_SERVICES)],
            "pg_ctl": [("status -D ./db", _PG_STATUS)],
            "pgrep": [("-fl node", _PGREP)],
        },
        outputs=(_KUBECTL_PODS, _BREW_SERVICES, _PG_STATUS, _PGREP, re.compile(r"\AUSER\s+PID\s")),
    ),
    LOOKUP_CASE: FpCase(
        outputs=(
            "y\n",
            re.compile(r"(?m)^/\S*python3$"),
            lambda text: "node" in text.splitlines(),
        )
    ),
    METADATA_CASE: FpCase(
        stubs={
            "npm": [("view zod version", "3.23.8\n"), ("cache ls", _NPM_CACHE), ("-v", "10.9.2\n")],
            "pip": [("show pip", _PIP_SHOW)],
        },
        outputs=("3.23.8\n", _NPM_CACHE, _PIP_SHOW, _NODE_VERSION, "10.9.2\n"),
    ),
    DEV_SERVER_CASE: FpCase(
        files={
            "package.json": _json(
                {"name": "app", "version": "1.0.0", "private": True, "scripts": {"dev": "node dev-server.js"}}
            ),
            "dev-server.js": _DEV_SERVER,
        },
        environment=NPM_QUIET,
        outputs=(lambda text: "<h1>dev server ok</h1>" in text,),
    ),
}
