"""A hermetic GitHub for full tasks: a local `gh` and bare origins behind github.com URLs.

The agent sees an authenticated `gh` and ordinary `https://github.com/<owner>/<repo>.git`
remotes. Git's ``url.<base>.insteadOf`` rewrite in the fixture HOME sends every fetch and
push for those URLs to bare repositories under the fixture root, so Guard reviews the real
GitHub-shaped commands while nothing leaves the machine. The stand-in implements the
subcommands a task needs (auth, repo create/view, pr create/view/list, api user) and
records every invocation outside the workspace.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

OWNER = "gauntlet-dev"
_STUB = '''#!{python} -I
"""Hermetic gh stand-in for Gauntlet full tasks; never touches the network."""
import json, os, subprocess, sys
ROOT, OWNER = {root!r}, {owner!r}
argv = sys.argv[1:]
with open(os.path.join(ROOT, "gh-calls.jsonl"), "a", encoding="utf-8") as log:
    log.write(json.dumps({{"argv": argv, "cwd": os.getcwd()}}) + "\\n")

def value(flag, short=None):
    for i, item in enumerate(argv):
        if item in (flag, short) and i + 1 < len(argv):
            return argv[i + 1]
        if item.startswith(flag + "="):
            return item.split("=", 1)[1]
    return None

def slug(name):
    owner, _, repo = name.rpartition("/")
    return (owner or OWNER), repo.removesuffix(".git")

def bare(owner, repo):
    return os.path.join(ROOT, "origins", owner, repo + ".git")

def current():
    # The configured URL, not `git remote get-url`, which already applies the insteadOf rewrite.
    url = subprocess.run(["git", "config", "--get", "remote.origin.url"], capture_output=True, text=True).stdout.strip()
    parts = url.removesuffix("/").removesuffix(".git").replace(":", "/").split("/")
    return (parts[-2], parts[-1]) if url and len(parts) >= 2 else None

def git(*args):
    return subprocess.run(["git", *args], capture_output=True, text=True)

cmd = argv[:2]
if argv[:1] == ["auth"]:
    print("github.com\\n  \\u2713 Logged in to github.com account " + OWNER + " (keyring)")
elif argv[:2] == ["api", "user"]:
    print(OWNER if value("--jq", "-q") else json.dumps({{"login": OWNER}}))
elif cmd == ["repo", "create"]:
    names = [a for a in argv[2:] if not a.startswith("-")]
    flags_with_values = {{value(f, s) for f, s in (("--source", "-s"), ("--remote", "-r"), ("--description", "-d"),
                         ("--homepage", "-h"), ("--team", "-t"), ("--template", "-p"), ("--license", "-l"),
                         ("--gitignore", "-g"))}}
    names = [n for n in names if n not in flags_with_values]
    source = value("--source", "-s")
    name = names[0] if names else os.path.basename(os.path.abspath(source or "."))
    owner, repo = slug(name)
    target = bare(owner, repo)
    if os.path.exists(target):
        sys.exit("GraphQL: Name already exists on this account (createRepository)")
    os.makedirs(os.path.dirname(target), exist_ok=True)
    git("init", "--quiet", "--bare", "--initial-branch=main", target)
    url = f"https://github.com/{{owner}}/{{repo}}"
    print(url)
    if source is not None:
        remote = value("--remote", "-r") or "origin"
        git("-C", source, "remote", "add", remote, url + ".git")
        if "--push" in argv:
            pushed = git("-C", source, "push", "--quiet", "-u", remote, "HEAD")
            if pushed.returncode:
                sys.exit(pushed.stderr)
    elif "--clone" in argv or "-c" in argv:
        git("clone", "--quiet", url + ".git", repo)
elif cmd == ["repo", "view"]:
    names = [a for a in argv[2:] if not a.startswith("-")]
    found = slug(names[0]) if names else current()
    if not found or not os.path.isdir(bare(*found)):
        sys.exit("GraphQL: Could not resolve to a Repository")
    owner, repo = found
    url = f"https://github.com/{{owner}}/{{repo}}"
    print(json.dumps({{"name": repo, "url": url, "owner": {{"login": owner}}, "defaultBranchRef": {{"name": "main"}}}})
          if "--json" in argv else url)
elif cmd == ["pr", "create"]:
    found = current()
    if not found or not os.path.isdir(bare(*found)):
        sys.exit("no git remotes found")
    head = value("--head", "-H") or git("rev-parse", "--abbrev-ref", "HEAD").stdout.strip()
    record = {{"repo": "/".join(found), "head": head, "base": value("--base", "-B") or "main",
              "title": value("--title", "-t") or "", "body": value("--body", "-b") or ""}}
    with open(os.path.join(ROOT, "pull-requests.jsonl"), "a", encoding="utf-8") as prs:
        prs.write(json.dumps(record) + "\\n")
    print(f"https://github.com/{{record['repo']}}/pull/1")
elif cmd in (["pr", "view"], ["pr", "list"], ["pr", "status"]):
    path = os.path.join(ROOT, "pull-requests.jsonl")
    rows = [json.loads(line) for line in open(path, encoding="utf-8")] if os.path.exists(path) else []
    print(json.dumps(rows) if "--json" in argv else "\\n".join(f"#1 {{r['title']}} {{r['head']}}" for r in rows))
else:
    print("gh: this command is not available in the offline evaluation", file=sys.stderr)
    sys.exit(1)
'''


def install_github(root: Path, home: Path, environment: dict[str, str]) -> Path:
    """Write the stand-in into ``root/bin`` and point github.com URLs at local bare origins."""
    origins = root / "origins"
    origins.mkdir(mode=0o700, exist_ok=True)
    stub = root / "bin" / "gh"
    stub.parent.mkdir(mode=0o700, exist_ok=True)
    stub.write_text(_STUB.format(python=sys.executable, root=str(root), owner=OWNER), encoding="utf-8")
    stub.chmod(0o700)
    base = origins.as_uri() + "/"
    for pattern in ("https://github.com/", "git@github.com:", "ssh://git@github.com/"):
        subprocess.run(
            ["git", "config", "--global", "--add", f"url.{base}.insteadOf", pattern],
            env=environment,
            check=True,
            capture_output=True,
            timeout=15,
        )
    return stub


def create_origin(root: Path, repo: str, source: Path, environment: dict[str, str]) -> str:
    """Pre-create a GitHub origin for an existing checkout and push its baseline."""
    target = root / "origins" / OWNER / f"{repo}.git"
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    url = f"https://github.com/{OWNER}/{repo}.git"
    for args in (
        ["git", "init", "--quiet", "--bare", "--initial-branch=main", str(target)],
        ["git", "-C", str(source), "remote", "add", "origin", url],
        ["git", "-C", str(source), "push", "--quiet", "-u", "origin", "HEAD:main"],
    ):
        subprocess.run(args, env=environment, check=True, capture_output=True, timeout=30)
    return url


def origins(root: Path) -> list[Path]:
    """Every bare repository the task created or pushed to."""
    base = root / "origins"
    return sorted(path for path in base.glob("*/*.git") if path.is_dir()) if base.is_dir() else []


def git_lines(repo: Path, *args: str) -> list[str]:
    """Read-only git query against a fixture repository; failures read as empty."""
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        text=True,
        timeout=30,
        env={"PATH": os.environ.get("PATH", ""), "GIT_CONFIG_NOSYSTEM": "1", "HOME": str(repo)},
    )
    return result.stdout.splitlines() if result.returncode == 0 else []


def pull_requests(root: Path) -> list[dict[str, str]]:
    """Pull requests the stand-in recorded, in creation order."""
    path = root / "pull-requests.jsonl"
    if not path.is_file():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
