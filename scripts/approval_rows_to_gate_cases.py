"""Turn redacted approval-queue rows into model-free benign false-positive gate cases.

Input is a JSON array (or JSON lines) of rows with ``harness``, ``tool_name``, ``tool_input`` (or
``command``) and ``reason_code``. Output is a JSON array of gate case entries for
``tests/fixtures/benign_false_positive_gate.json``.

Two separate things are stripped before anything is written, because an approval row is a verbatim
record of the user's own machine:

* paths and repository slugs become the generic gate tokens, and
* every remaining project, feature, file and symbol name becomes a deterministic generic stand-in,

so a case built from a real queue row carries the shape the gate measures and none of the names
that produced it.

Rows are also classified. Only commands a careful reviewer would call unambiguously read-only are
emitted, because a gate case asserts ``expect: allow`` and a mis-sorted write would assert that
Guard should let it through. Everything else is dropped unless ``--keep-unclassified`` is passed,
which is for inspecting the discarded population, not for building a fixture.

Usage:

    python scripts/approval_rows_to_gate_cases.py rows.json \\
        --existing tests/fixtures/benign_false_positive_gate.json \\
        --reasons reasons.json > cases.json

Review the result before merging: this tool decides that a row *reads*, not that it was benign.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any

SHELL_TOOLS = {"bash", "shell", "Bash", "exec_command"}
FAMILY = {"read": "read", "Read": "read", "glob": "glob", "Glob": "glob", "grep": "grep", "Grep": "grep"}
FAMILY |= {"write": "write", "Write": "write", "eval": "eval", "task": "task", "wait": "wait"}
FAMILY |= {"todo": "todo", "todo_write": "todo_write", "ls": "ls"}

_HOME = re.compile(r"(?:/Users|/home)/[^/\s'\"]+|C:\\Users\\[^\\\s'\"]+")
# Any non-hidden folder under home is treated as a project checkout; the path inside it is kept.
_PROJECT = re.compile(r"\$\{HOME\}/[A-Za-z][^/\s'\"]*(?=/|$|[\s'\"])")
# GitHub owner/repository pairs are replaced even when no --owner is given.
_GITHUB_REPO = re.compile(
    r"(github\.com[/:]|\brepos/|--repo[= ]|-R )[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+?(?=\.git\b|[/\s'\"]|$)"
)
_TEMP = re.compile(r"(?:/private)?/tmp/[A-Za-z0-9._-]+")


def scrub(text: str, owners: list[str]) -> str:
    """Replace identifying path and name fragments with generic fixture values."""
    text = _HOME.sub("${HOME}", text)
    text = _PROJECT.sub("${WORKTREE}", text)
    text = _TEMP.sub("${PRIVATE_TMP}", text)
    text = _GITHUB_REPO.sub(r"\1o/r", text)
    for owner in owners:
        text = re.sub(re.escape(owner) + r"/[A-Za-z0-9._-]+", "o/r", text, flags=re.IGNORECASE)
        text = re.sub(re.escape(owner), "o", text, flags=re.IGNORECASE)
    return text


def scrub_value(value: Any, owners: list[str]) -> Any:
    if isinstance(value, str):
        return scrub(value, owners)
    if isinstance(value, list):
        return [scrub_value(item, owners) for item in value]
    if isinstance(value, dict):
        return {key: scrub_value(item, owners) for key, item in value.items()}
    return value


# --- read-only classification -------------------------------------------------------------------

READ_VERBS = {
    "ls", "cat", "head", "tail", "wc", "rg", "grep", "egrep", "find", "stat", "file", "du", "df",
    "which", "type", "pwd", "echo", "printf", "tree", "sort", "uniq", "cut", "basename", "dirname",
    "realpath", "date", "awk", "column", "jq", "yq", "diff", "comm", "tr", "nl", "xxd", "shasum",
    "sha256sum", "readlink", "env", "locale", "uname", "whoami", "hostname", "sleep", "true", "false",
}
# Subcommand-gated tools: only these subcommands read.
SUB_READ: dict[str, set[str]] = {
    "git": {"log", "status", "diff", "show", "branch", "rev-parse", "rev-list", "describe", "blame",
            "cat-file", "ls-files", "ls-tree", "shortlog", "config", "remote", "worktree", "tag",
            "stash", "reflog", "for-each-ref", "symbolic-ref", "merge-base", "count-objects", "grep"},
    "gh": {"pr", "issue", "api", "run", "repo", "release", "workflow", "auth", "search", "label"},
    "docker": {"ps", "images", "logs", "inspect", "version", "info", "stats"},
    "npm": {"ls", "view", "outdated", "config"},
}
# A read subcommand still writes when one of these words follows it.
GIT_WRITE_ARGUMENT = {
    "worktree": {"add", "remove", "prune", "move", "repair"},
    "config": {"--global", "--system", "--local", "--unset", "--add", "--replace-all"},
    "stash": {"push", "pop", "apply", "drop", "clear", "save", "branch", "store", "create"},
    "tag": {"-d", "-a", "-f", "--delete", "-s", "-m"},
    "remote": {"add", "remove", "rm", "rename", "set-url", "prune", "update", "set-head"},
    "branch": {"-d", "-D", "-m", "-M", "-f", "--delete", "--move", "--force", "--set-upstream-to"},
}
GH_WRITE = re.compile(
    r"\b(create|edit|merge|close|reopen|comment|review|delete|rerun|cancel|dispatch|upload|login"
    r"|logout|token|set|add|remove|mutation)\b"
    r"|(^|\s)(-X|--method)\s+(POST|PUT|PATCH|DELETE)|(^|\s)(-f|-F|--field|--raw-field)\s"
)
# Anything that plainly changes state, exfiltrates, or runs code is dropped outright.
BANNED = re.compile(
    r"(^|[;&|]\s*)(rm|mv|cp|mkdir|touch|chmod|chown|ln|kill|pkill|killall|install|curl|wget|ssh|scp"
    r"|rsync|nc|dd|tee|sudo|su|open|osascript|launchctl|systemctl|brew|pip|pip3|apt|apt-get|yum|dnf"
    r"|npm|bun|pnpm|yarn|uv|uvx|cargo|rustc|go|make|cmake|docker|kubectl|helm|terraform|aws|gcloud"
    r"|az|sed|perl|ruby|php|psql|mysql|sqlite3|redis-cli|mongo|eval|exec|source|\.)\b"
)
REDIRECT_WRITE = re.compile(r"(?<![0-9>])>(?!&)|>>")
HARMLESS_REDIRECT = re.compile(r"2>&1|&>|> */dev/null")
SECRET = re.compile(
    r"\b(secret|password|passwd|token|credential|apikey|api_key|private[-_]key|id_rsa|keychain)\b"
    r"|\.env\b|/\.ssh|/\.aws|/\.gnupg",
    re.IGNORECASE,
)
EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
SUBSHELL = re.compile(r"\$\(|`|<\(")
MAX_SEGMENTS = 6


def segments(command: str) -> list[str]:
    return [part.strip() for part in re.split(r"&&|\|\||;|\|", command) if part.strip()]


def _git_reads(words: list[str]) -> bool:
    flat = words[1:]
    if flat and flat[0] == "-C":
        flat = flat[2:]
    subcommand = next((word for word in flat if not word.startswith("-")), "")
    if subcommand not in SUB_READ["git"]:
        return False
    after = flat[flat.index(subcommand) + 1:] if subcommand in flat else []
    if set(after) & GIT_WRITE_ARGUMENT.get(subcommand, set()):
        return False
    bare = [word for word in after if not word.startswith("-")]
    if subcommand == "branch" and bare:
        # Listing branches reads; a bare name after the subcommand creates one.
        return False
    if subcommand == "config" and len(bare) > 1:
        # `git config a.b` reads; a second bare word is the value it writes.
        return False
    return True


def reads(segment: str) -> bool:
    words = segment.split()
    if not words:
        return False
    verb = words[0]
    if verb == "cd" or verb in READ_VERBS:
        return True
    if verb not in SUB_READ:
        return False
    if verb == "git":
        return _git_reads(words)
    rest = [word for word in words[1:] if not word.startswith("-")]
    subcommand = rest[0] if rest else ""
    if verb == "gh":
        return subcommand in SUB_READ["gh"] and not GH_WRITE.search(segment)
    return subcommand in SUB_READ[verb]


def reads_only(command: str) -> bool:
    """Whether every segment of ``command`` is an unambiguous read."""
    if SECRET.search(command) or EMAIL.search(command) or SUBSHELL.search(command):
        return False
    # A write can hide in an earlier segment that only feeds the reader its body.
    if re.search(r"mutation|--input", command):
        return False
    if REDIRECT_WRITE.search(HARMLESS_REDIRECT.sub("", command)):
        return False
    parts = segments(command)
    if not parts or len(parts) > MAX_SEGMENTS:
        return False
    if any(BANNED.search(part) for part in parts):
        return False
    return all(reads(part) for part in parts)


# --- name scrubbing -----------------------------------------------------------------------------

WORD = re.compile(r"[A-Za-z][\w.+-]{2,}")
GENERIC = {
    # shell and tool verbs
    "git", "grep", "cat", "head", "tail", "find", "echo", "ls", "which", "file", "diff", "sort",
    "uniq", "wc", "awk", "jq", "env", "printf", "stat", "node", "bun", "tsx", "npm", "npx", "uv",
    "python", "python3", "pytest", "gh", "rg", "sed", "cut", "tr", "basename", "dirname", "realpath",
    "du", "df", "date", "xargs", "comm", "nl", "readlink", "true", "false", "sleep", "docker",
    # common flags and subcommands spelled as words
    "status", "log", "show", "branch", "config", "remote", "worktree", "stash", "rev-parse",
    "rev-list", "merge-base", "is-ancestor", "ls-tree", "ls-files", "show-current", "show-origin",
    "for-each-ref", "symbolic-ref", "describe", "blame", "reflog", "shortlog", "cat-file",
    "count-objects", "api", "repos", "runs", "jobs", "actions", "check-runs", "annotations",
    "paginate", "list", "get", "check", "install", "global", "source", "type", "tags", "ref",
    "oneline", "porcelain", "short", "cached", "name-only", "iname", "maxdepth", "include",
    "exclude", "glob", "files-with-matches", "rln", "newermt", "git-dir", "work-tree", "no-pager",
    "null", "dev", "not", "path", "name", "all", "main", "HEAD", "FETCH_HEAD", "json", "yaml",
    "html", "jsx", "mjs", "enum", "def", "export", "function", "sub", "the", "opt", "bin", "var",
    "tmp", "org", "files", "tools", "system", "setting", "settings", "content", "object.sha",
    "owner", "user.name", "user.email", "gpg.format", "attr", "versions", "work", "home", "page",
    "test", "tests", "tests__", "src", "lib", "app", "apps", "e2e", "scripts", "docs", "plans",
    "references", "skills", "logs", "coverage", "out", "dist", "build", "target", "node_modules",
    "public", "assets", "crates", "packages", "components", "pages", "fixtures", "contracts",
    "workers", "worktrees", "harness", "catalog", "protection", "billing", "points",
    # fixture substitution tokens
    "HOME", "WORKTREE", "PRIVATE_TMP", "ORG", "ORG_WT", "PARENT", "SCRATCH", "GAUNTLET_ROOT",
    "TMP_ORG", "TMP_ORG_WT", "TMP_REMOTE",
    # generic filenames the gate already uses
    "package.json", "package-lock.json", "tsconfig.json", "README.md", "Cargo.toml", "Cargo.lock",
    "pyproject.toml", "uv.lock", "Makefile", "index.ts", "index.js", "main.py", "conftest.py",
    "settings.json", "config.toml", "zshrc", "gitconfig", "vitest", "VITEST", "postgresql",
    # public tool and vendor names
    "codex", "claude", "guard", "hol-guard", "homebrew", "nvm", "doctl", "github",
    "hashgraph-online", "stripe", "ga4", "posthog",
}
PROJECTS = ("service-api", "app-portal", "web-client", "report-lane", "other-project", "acme-plain")
FEATURES = ("report-lane", "order-intake", "usage-rollup", "signup-funnel", "audit-trail")
EXTENSIONS = {
    "sh": "run-checks.sh", "py": "collect.py", "ts": "index.ts", "tsx": "panel.tsx",
    "md": "notes.md", "json": "report.json", "toml": "config.toml", "lock": "deploy.lock",
    "d": "deploy.lock.d", "git": "other-project.git", "sql": "schema.sql",
}


def pick(options: tuple[str, ...], word: str) -> str:
    return options[hashlib.sha256(word.encode("utf-8")).digest()[0] % len(options)]


def rename(word: str) -> str:
    """A generic stand-in of the same shape as ``word``."""
    stem, _, extension = word.rpartition(".")
    if stem and extension in EXTENSIONS:
        return EXTENSIONS[extension]
    if re.fullmatch(r"[a-z]+(?:[A-Z][a-z0-9]*)+", word):
        return "resolveWorkspaceRecord"
    if re.fullmatch(r"[A-Z][a-z0-9]*(?:[A-Z][a-z0-9]*)+", word):
        return "WorkspaceRecord"
    if "_" in word and word.isupper():
        return "WORKSPACE_RECORD"
    if "_" in word:
        return "read_workspace_record"
    if re.fullmatch(r"[0-9a-f]{7,40}", word):
        return "c9cf0af96c"[: len(word)]
    if re.fullmatch(r"v[\d.]+", word):
        return word
    return pick(FEATURES if "-" in word else PROJECTS, word)


def rename_names(text: str, table: dict[str, str]) -> str:
    """Substitute whole identifier words only.

    Operators, flags, quoting and redirections survive byte for byte, so the command keeps the
    exact shape the gate measures.
    """

    def replace(match: re.Match[str]) -> str:
        word = match.group(0)
        if word in GENERIC:
            return word
        return table.setdefault(word, rename(word))

    return WORD.sub(replace, text)


def rename_value(value: Any, table: dict[str, str]) -> Any:
    if isinstance(value, str):
        return rename_names(value, table)
    if isinstance(value, list):
        return [rename_value(item, table) for item in value]
    if isinstance(value, dict):
        return {key: rename_value(item, table) for key, item in value.items()}
    return value


# --- case construction --------------------------------------------------------------------------


def load_rows(path: Path) -> list[dict[str, Any]]:
    text = path.read_text(encoding="utf-8")
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        data = [json.loads(line) for line in text.splitlines() if line.strip()]
    return [row for row in data if isinstance(row, dict)]


def existing_commands(path: Path) -> set[str]:
    """Commands the gate already covers, so a mined row does not duplicate one."""
    fixture = json.loads(path.read_text(encoding="utf-8"))
    found: set[str] = set()
    for case in fixture.get("cases", []):
        command = case.get("tool_input", {}).get("command")
        if isinstance(command, str):
            found.add(command.strip())
    return found


def payload_of(row: dict[str, Any], owners: list[str]) -> tuple[str, dict[str, Any]] | None:
    tool = str(row.get("tool_name") or row.get("tool") or "")
    tool_input = row.get("tool_input")
    if tool in SHELL_TOOLS:
        command = row.get("command") or (tool_input.get("command") if isinstance(tool_input, dict) else None)
        if not isinstance(command, str) or not command:
            return None
        return "shell", {"command": command}
    if tool in FAMILY and isinstance(tool_input, dict):
        payload = dict(tool_input)
        if "file_path" in payload and "path" not in payload:
            payload["path"] = payload.pop("file_path")
        return FAMILY[tool], payload
    return None


def verb_of(command: str) -> str:
    """The command's own name, skipping the directory change that so often precedes it."""
    words = [word for word in command.split() if re.fullmatch(r"[A-Za-z][\w-]*", word)]
    while words and words[0] == "cd":
        words = words[1:]
    return words[0].lower() if words else "shell"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("rows", type=Path)
    parser.add_argument("--owner", action="append", default=[], help="private owner name to replace with o")
    parser.add_argument("--existing", type=Path, help="gate fixture whose commands are already covered")
    parser.add_argument("--reasons", type=Path, help="write {case id: observed reason code} here")
    parser.add_argument(
        "--keep-unclassified",
        action="store_true",
        help="emit rows that are not unambiguously read-only (for inspection, not for a fixture)",
    )
    args = parser.parse_args()

    covered = existing_commands(args.existing) if args.existing else set()
    table: dict[str, str] = {}
    counts: Counter[str] = Counter()
    cases: list[dict[str, Any]] = []
    reasons: dict[str, str] = {}
    seen: set[str] = set()
    for row in load_rows(args.rows):
        found = payload_of(row, args.owner)
        if found is None:
            continue
        kind, payload = found
        # Classify before renaming: a stand-in name would hide the subcommand that writes.
        payload = scrub_value(payload, args.owner)
        command = payload.get("command", "")
        if kind == "shell" and not args.keep_unclassified and not reads_only(command):
            continue
        signature = json.dumps(payload, sort_keys=True)
        if signature in seen or command.strip() in covered:
            continue
        seen.add(signature)
        verb = verb_of(command) if kind == "shell" else kind
        payload = rename_value(payload, table)
        harness = str(row.get("harness") or (row.get("harnesses") or ["omp"])[0])
        counts[verb] += 1
        identity = f"observed-{verb}-{counts[verb]:02d}"
        cases.append({
            "id": identity,
            "fix_area": "git" if verb == "git" else kind,
            "harnesses": [harness],
            "tool": kind,
            "tool_input": payload,
            "cwd": "worktree",
            "expect": "allow",
        })
        reason = row.get("reason_code") or row.get("observed_reason_code")
        if reason:
            reasons[identity] = scrub(str(reason), args.owner)

    json.dump(cases, sys.stdout, indent=2, ensure_ascii=False)
    sys.stdout.write("\n")
    if args.reasons:
        args.reasons.write_text(json.dumps(reasons, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"cases={len(cases)} renamed_words={len(table)}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
