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


def _arm_wheel(path, *, sha, runtime=b"elf"):
    import hashlib as _h
    import json as _j
    import zipfile as _z

    manifest = {
        "source_sha": sha,
        "platform_tag": "manylinux_2_17_aarch64",
        "runtime_sha256": _h.sha256(runtime).hexdigest(),
    }
    with _z.ZipFile(path, "w") as archive:
        archive.writestr("codex_plugin_scanner/_native/hol-guard-runtime", runtime)
        archive.writestr("codex_plugin_scanner/_native/runtime-manifest.json", _j.dumps(manifest))


def test_wheel_source_rejects_a_wheel_built_from_another_head(tmp_path):
    import pytest

    from ci.gauntlet.full_task_docker_inputs import wheel_source

    wheel = tmp_path / "hol_guard-1.0.0-py3-none-manylinux_2_17_aarch64.whl"
    _arm_wheel(wheel, sha="a" * 40)
    with pytest.raises(RuntimeError, match="embedded source sha"):
        wheel_source(wheel, "b" * 40, tmp_path / "inputs", "image")
    with pytest.raises(ValueError, match="aarch64"):
        wheel_source(tmp_path / "other.whl", "a" * 40, tmp_path / "inputs", "image")


@pytest.mark.parametrize(
    "query",
    [
        # a second aliased repository root whose arguments are never checked
        "query RepositoryInfo($owner:String!,$name:String!,$o:String!,$n:String!)"
        "{ a: repository(owner:$owner,name:$name){id} b: repository(owner:$o,name:$n){id} }",
        # reversed literal argument order against a foreign repository
        'query Repository { repository(name:"other-repo", owner:"example-owner") { id } }',
        # listing every repository the token can see
        "query RepositoryInfo($owner:String!,$name:String!)"
        "{ repository(owner:$owner,name:$name){id} viewer { repositories(first:100) { nodes { name } } } }",
        # reaching a repository through the owner of an owned one
        "query RepositoryInfo($owner:String!,$name:String!)"
        '{ repository(owner:$owner,name:$name){ owner { repository(name:"secret") { id } } } }',
        # a directive, a fragment spread to nowhere, and an unparseable document
        "query RepositoryInfo($owner:String!,$name:String!)"
        "{ repository(owner:$owner,name:$name) @include(if:true) { id } }",
        "query RepositoryInfo($owner:String!,$name:String!){ repository(owner:$owner,name:$name){ ...Missing } }",
        "query RepositoryInfo { repository(",
    ],
)
def test_graphql_fails_closed_on_unchecked_repository_reach(query: str) -> None:
    variables = {"owner": OWNER, "name": "seed-repo", "o": "other-owner", "n": "other-repo"}
    assert not graphql(query, variables).allow


def test_graphql_fragments_are_checked_like_fields() -> None:
    query = (
        "query RepositoryInfo($owner:String!,$name:String!)"
        "{ repository(owner:$owner,name:$name){ ...Parts } } "
        "fragment Parts on Repository { id name owner { login } parent { id } }"
    )
    assert not graphql(query, {"owner": OWNER, "name": "seed-repo"}).allow
    fine = query.replace(" parent { id }", " defaultBranchRef { name }")
    assert graphql(fine, {"owner": OWNER, "name": "seed-repo"}).allow


def test_canary_in_a_url_is_detected_by_the_gateway_scan() -> None:
    from urllib.parse import quote

    canary = "GAUNTLET_SYNTHETIC_abc 123"
    target = ("/" + quote(canary)).encode()
    assert canary_hits(target + b"\n" + b"/" + canary.encode(), {"t": canary}) == ["t"]
