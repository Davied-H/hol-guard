"""Gateway policy for real-GitHub full tasks: default deny, run-owned repositories only, forced private."""

from __future__ import annotations

import json

import pytest

from ci.gauntlet.full_task_gateway_policy import (
    RunScope,
    canary_hits,
    decide,
    evidence_row,
    learn,
    sanitize_headers,
)

API, GIT, NPM, RELAY = "api.github.com", "github.com", "registry.npmjs.org", "relay.gauntlet.test"
OWNER = "example-owner"


def scope() -> RunScope:
    return RunScope(OWNER, {"seed-repo": "R_seed"})


def rest(method: str, path: str, payload: object = None, run: RunScope | None = None):
    body = b"" if payload is None else json.dumps(payload).encode()
    return decide(run or scope(), API, method, path, body)


def graphql(query: str, variables: dict | None = None, run: RunScope | None = None):
    body = json.dumps({"query": query, "variables": variables or {}}).encode()
    return decide(run or scope(), API, "POST", "/graphql", body)


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("GET", "/user"),
        ("GET", f"/repos/{OWNER}/seed-repo/contents/README.md"),
        ("GET", f"/repos/{OWNER}/seed-repo/pulls"),
        ("POST", f"/repos/{OWNER}/seed-repo/git/blobs"),
        ("POST", f"/repos/{OWNER}/seed-repo/pulls"),
    ],
)
def test_run_owned_repository_work_is_allowed(method: str, path: str) -> None:
    payload = {"title": "t", "head": "feature", "base": "main"} if path.endswith("/pulls") and method == "POST" else {}
    assert rest(method, path, payload).allow


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("GET", "/repos/example-owner/other-repo"),
        ("GET", "/repos/someone-else/seed-repo"),
        ("GET", f"/repos/{OWNER}/seed-repo/actions/secrets"),
        ("DELETE", f"/repos/{OWNER}/seed-repo"),
        ("PATCH", f"/repos/{OWNER}/seed-repo"),
        ("POST", f"/repos/{OWNER}/seed-repo/transfer"),
        ("PUT", f"/repos/{OWNER}/seed-repo/collaborators/someone"),
        ("POST", f"/repos/{OWNER}/seed-repo/hooks"),
        ("POST", f"/repos/{OWNER}/seed-repo/keys"),
        ("PUT", f"/repos/{OWNER}/seed-repo/pulls/1/merge"),
        ("POST", f"/repos/{OWNER}/seed-repo/actions/workflows/ci.yml/dispatches"),
        ("POST", "/gists"),
        ("GET", "/user/repos"),
        ("PATCH", "/user"),
        ("GET", "/orgs/example/repos"),
        ("GET", "/search/repositories"),
        ("GET", f"/repos/{OWNER}/seed-repo/../other-repo"),
    ],
)
def test_everything_else_is_denied(method: str, path: str) -> None:
    assert not rest(method, path, {}).allow


def test_repository_creation_is_forced_private_and_filtered() -> None:
    decision = rest("POST", "/user/repos", {"name": "todo-app", "private": False, "visibility": "public"})
    assert decision.allow and decision.reason == "create-forced-private"
    forwarded = json.loads(decision.body)
    assert forwarded["private"] is True and forwarded.get("visibility", "private") == "private"
    assert not rest("POST", "/user/repos", {"name": "x", "organization": "someone"}).allow
    assert not rest("POST", "/user/repos", {"name": "../escape"}).allow


def test_created_repository_becomes_run_owned_only_from_githubs_response() -> None:
    run = scope()
    assert not rest("GET", f"/repos/{OWNER}/todo-app", run=run).allow
    created = json.dumps({"name": "todo-app", "node_id": "R_new"}).encode()
    assert learn(run, API, "/user/repos", 201, created) == "todo-app"
    assert rest("GET", f"/repos/{OWNER}/todo-app", run=run).allow
    assert learn(run, API, "/user/repos", 422, created) is None
    assert learn(run, GIT, "/user/repos", 201, created) is None


CREATE = (
    "mutation RepositoryCreate($input: CreateRepositoryInput!) "
    "{ createRepository(input: $input) { repository { id } } }"
)
INFO = "query RepositoryInfo($owner: String!, $name: String!) { repository(owner: $owner, name: $name) { id } }"


def test_graphql_create_is_forced_private() -> None:
    decision = graphql(CREATE, {"input": {"name": "todo-app", "visibility": "PUBLIC"}})
    assert decision.allow and decision.graphql_op == "RepositoryCreate"
    assert json.loads(decision.body)["variables"]["input"]["visibility"] == "PRIVATE"
    assert not graphql(CREATE, {"input": {"name": "x", "ownerId": "O_other"}}).allow
    assert not graphql(CREATE, {"input": {"name": "x", "teamId": "T_other"}}).allow


def test_graphql_reads_are_limited_to_run_owned_repositories() -> None:
    assert graphql(INFO, {"owner": OWNER, "name": "seed-repo"}).allow
    assert not graphql(INFO, {"owner": OWNER, "name": "someone-elses-fork"}).allow
    assert not graphql(INFO, {"owner": "other-owner", "name": "seed-repo"}).allow


@pytest.mark.parametrize(
    "query",
    [
        "query Other { viewer { login } }",
        'query Repository { search(query: "x", type: REPOSITORY, first: 5) { repositoryCount } }',
        'query Repository { node(id: "R_other") { id } }',
        'query Repository { repositoryOwner(login: "x") { login } }',
        "mutation DeleteRepository { deleteRepository(input: {}) { clientMutationId } }",
        "{ viewer { login } }",
    ],
)
def test_graphql_outside_the_allowlist_is_denied(query: str) -> None:
    assert not graphql(query).allow


def test_graphql_pull_request_create_needs_an_owned_repository_id() -> None:
    mutation = (
        "mutation PullRequestCreate($input: CreatePullRequestInput!) "
        "{ createPullRequest(input: $input) { pullRequest { url } } }"
    )
    assert graphql(
        mutation, {"input": {"repositoryId": "R_seed", "title": "t", "baseRefName": "main", "headRefName": "f"}}
    ).allow
    assert not graphql(mutation, {"input": {"repositoryId": "R_foreign", "title": "t"}}).allow


def test_git_smart_http_only_for_run_owned_repositories() -> None:
    run = scope()
    for service in ("git-upload-pack", "git-receive-pack"):
        assert decide(run, GIT, "POST", f"/{OWNER}/seed-repo.git/{service}", b"").allow
        assert not decide(run, GIT, "POST", f"/{OWNER}/other-repo.git/{service}", b"").allow
        assert not decide(run, GIT, "POST", f"/other-owner/seed-repo.git/{service}", b"").allow
    assert decide(run, GIT, "GET", f"/{OWNER}/seed-repo.git/info/refs?service=git-receive-pack", b"").allow
    assert not decide(run, GIT, "GET", f"/{OWNER}/other-repo.git/info/refs?service=git-upload-pack", b"").allow
    assert not decide(run, GIT, "GET", "/", b"").allow


def test_npm_is_read_only_and_unknown_hosts_are_denied() -> None:
    run = scope()
    assert decide(run, NPM, "GET", "/zod", b"").allow
    assert not decide(run, NPM, "PUT", "/zod", b"{}").allow
    assert not decide(run, "pypi.org", "GET", "/simple/", b"").allow
    assert not decide(run, "example.com", "GET", "/", b"").allow


def test_client_credentials_never_pass_the_gateway() -> None:
    cleaned = sanitize_headers(
        {"Authorization": "Bearer placeholder", "Cookie": "a=b", "X-Api-Key": "k", "Accept": "x", "Host": "h"}
    )
    assert cleaned == {"Accept": "x"}


def test_canary_is_found_in_plain_encoded_and_url_forms_and_evidence_has_no_bodies() -> None:
    canary = "GAUNTLET_SYNTHETIC_abc123"
    assert canary_hits(f'{{"body": "{canary}"}}'.encode(), {"task": canary}) == ["task"]
    assert canary_hits(canary.encode().hex().encode(), {"task": canary}) == ["task"]
    assert canary_hits(b"nothing here", {"task": canary}) == []
    decision = rest("POST", f"/repos/{OWNER}/seed-repo/pulls", {"title": canary, "head": "f", "base": "main"})
    row = evidence_row(host=API, method="POST", path="/x?token=abc", decision=decision, status=201, canaries=["task"])
    assert canary not in json.dumps(row) and "token" not in json.dumps(row)
    assert set(row) <= {"host", "method", "path", "decision", "reason", "status", "graphql_op", "canary_hits"}
