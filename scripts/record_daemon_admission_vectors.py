#!/usr/bin/env python3
"""Record daemon socket-admission vectors from the retired Python server.

The expected answers come only from the Python ``_GuardDaemonHTTPServer`` that
existed before the Rust listener took over admission (a scratch checkout of the
base commit, passed as ``--base-src``). The Rust runtime never produces them, so
the vectors stay an independent oracle for it.

Usage:
    record_daemon_admission_vectors.py --base-src <base-checkout>/src --output <file>

``--base-src`` is the ``src`` of a checkout of the base commit with its
generated command-catalog artifacts built (the old server cannot import
without them). The checkout's commit is recorded in the output.

The parent builds the case catalogue; a child (``--oracle``) whose ``PYTHONPATH``
is the base checkout drives the old admission code over real socket pairs.
"""

from __future__ import annotations

import argparse
import gzip
import json
import os
import subprocess
import sys
from pathlib import Path

LIMITS = {
    "production": {"request": 32, "control": 8, "critical": 8, "connection": 128, "guard": 64},
    "small": {"request": 3, "control": 1, "critical": 1, "connection": 6, "guard": 5},
    "tight": {"request": 2, "control": 1, "critical": 1, "connection": 3, "guard": 3},
    "wide_guard": {"request": 2, "control": 1, "critical": 1, "connection": 4, "guard": 8},
}
SEEDS_PER_LIMIT = 70
STEPS_PER_SCENARIO = 20

PEEK_CASES = [
    "",
    "G",
    "GET",
    "GET /healthz HTTP/1.1",
    "GET /healthz HTTP/1.1\r\n",
    "GET /healthz HTTP/1.1\n",
    "GET /healthz?x=1 HTTP/1.1\r\nHost: a\r\n\r\n",
    "GET /a?b?c HTTP/1.1\r\n",
    "get /healthz HTTP/1.1\r\n",
    "GET  /healthz HTTP/1.1\r\n",
    "GET /healthz HTTP/1.1 extra\r\n",
    "GET /healthz\r\n",
    "GET /healthz FTP/1.1\r\n",
    "GET /hé HTTP/1.1\r\n",
    "\r\nGET /healthz HTTP/1.1\r\n",
    "\n",
    "GET /v1/healthz/details HTTP/1.1\r\n",
    "GET /v1/healthz/verify HTTP/1.0\n",
    "GET /v1/desktop/bootstrap HTTP/1.1\r\n",
    "GET /v1/daemon/identity-challenge?n=1 HTTP/1.1\r\n",
    "POST /v1/runtime/hook HTTP/1.1\r\n",
    "GET " + "a" * 4090 + " HTTP/1.1\r\n",
    "GET /" + "a" * 4200,
    "x" * 4096,
    "x" * 4095 + "\n",
    "GET /healthz HTTP/1.1\r\r\n",
    "GET /healthz\tHTTP/1.1\r\n",
    "GET /a%20b HTTP/1.1\r\n",
]
HEADER_CASES = [
    "",
    "GET / HTTP/1.1\r\n",
    "GET / HTTP/1.1\r\n\r\n",
    "GET / HTTP/1.1\n\n",
    "GET / HTTP/1.1\r\nHost: x\r\n",
    "GET / HTTP/1.1\r\nHost: x\r\n\r\n",
    "GET / HTTP/1.1\n\nbody",
    "\r\n\r\n",
    "\n\n",
    "a\r\n \r\n",
    "a\n\r\nb",
    "x" * 70_000 + "\r\n\r\n",
    "GET / HTTP/1.1\r\n" + "h: v\r\n" * 3000,
]
KIND_CASES = [
    "/healthz",
    "/healthz?x=1",
    "/healthz/",
    "/v1/healthz/details",
    "/v1/healthz/details?a=b",
    "/v1/healthz/verify",
    "/v1/healthz",
    "/v1/daemon/identity-challenge",
    "/v1/daemon/identity-challenge?x",
    "/v1/desktop/bootstrap",
    "/v1/desktop/bootstrap/",
    "/v1/hook",
    "/",
    "",
    "/HEALTHZ",
    "/v1/runtime/hook?x=/healthz",
]
CURATED = {
    "hook_then_finish": (
        "production",
        [
            {"op": "connect", "name": "a", "data": "GET /v1/hook HTTP/1.1\r\nHost: x\r\n\r\n"},
            {"op": "claim", "name": "a", "path": "/v1/hook"},
            {"op": "finish", "name": "a"},
        ],
    ),
    "challenge_reclaim": (
        "production",
        [
            {"op": "connect", "name": "a", "data": "GET /v1/daemon/identity-challenge HTTP/1.1\r\nHost: x\r\n\r\n"},
            {"op": "claim", "name": "a", "path": "/v1/daemon/identity-challenge"},
            {"op": "claim", "name": "a", "path": "/v1/hook"},
            {"op": "finish", "name": "a"},
        ],
    ),
    "partial_line_completes": (
        "production",
        [
            {"op": "connect", "name": "a", "data": "GET /v1/hook HT"},
            {"op": "tick", "dt": 0.05},
            {"op": "send", "name": "a", "data": "TP/1.1\r\n\r\n"},
            {"op": "tick", "dt": 0.05},
        ],
    ),
    "partial_line_expires": (
        "production",
        [
            {"op": "connect", "name": "a", "data": "GET /v1/hook HT"},
            {"op": "tick", "dt": 0.5},
        ],
    ),
    "saturated_health_probe_runs": (
        "tight",
        [
            {"op": "connect", "name": "n1", "data": "GET /v1/x HTTP/1.1\r\n\r\n"},
            {"op": "connect", "name": "n2", "data": "GET /v1/x HTTP/1.1\r\n\r\n"},
            {"op": "connect", "name": "n3", "data": "GET /v1/x HTTP/1.1\r\n\r\n"},
            {"op": "connect", "name": "p", "data": ""},
            {"op": "send", "name": "p", "data": "GET /healthz HTTP/1.1\r\n\r\n"},
            {"op": "tick", "dt": 0.02},
        ],
    ),
    "closing_rejects": (
        "production",
        [
            {"op": "closing"},
            {"op": "connect", "name": "a", "data": "GET /healthz HTTP/1.1\r\n\r\n"},
        ],
    ),
}


def _run_oracle(base_src: str, payload: dict) -> dict:
    env = dict(os.environ, PYTHONPATH=base_src, PYTHONDONTWRITEBYTECODE="1")
    child = subprocess.run(
        [sys.executable, str(Path(__file__)), "--oracle"],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        env=dict(env, PYTHONPATH=os.pathsep.join([base_src, str(Path(__file__).parent)])),
        check=False,
    )
    if child.returncode != 0:
        raise SystemExit(f"oracle failed:\n{child.stderr[-4000:]}")
    return json.loads(child.stdout)


def _oracle(payload: dict) -> dict:
    import daemon_admission_oracle as oracle

    base_src = payload["base_src"]
    scenarios = []
    jobs = [(name, limits, steps) for name, (limits, steps) in payload["curated"].items()]
    for limits_name, limits in payload["limits"].items():
        for seed in range(payload["seeds"]):
            jobs.append(
                (f"{limits_name}-seed{seed}", limits, oracle.generate(base_src, seed, limits, payload["length"]))
            )
    for name, limits, steps in jobs:
        scenarios.append({"name": name, "limits": limits, "trace": oracle.run_scenario(base_src, limits, steps)})
    pure = oracle.pure_answers(base_src, payload["pure"])
    return {"scenarios": scenarios, "pure": pure}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--oracle", action="store_true")
    parser.add_argument("--base-src")
    parser.add_argument("--output")
    args = parser.parse_args()
    if args.oracle:
        json.dump(_oracle(json.load(sys.stdin)), sys.stdout)
        return
    _record(args.base_src, args.output, _checkout_commit(args.base_src))


def _checkout_commit(base_src: str) -> str | None:
    checkout = Path(base_src).resolve().parent
    result = subprocess.run(
        ["git", "-C", str(checkout), "rev-parse", "HEAD"], capture_output=True, text=True, check=False
    )
    return result.stdout.strip() or None


def _record(base_src: str, output: str, base_commit: str | None) -> None:
    pure = {
        "peek": PEEK_CASES,
        "headers": HEADER_CASES,
        "kind": KIND_CASES,
        "limit": [*list(LIMITS.values()), {"request": 1, "control": 8, "critical": 8, "connection": 9, "guard": 4}],
    }
    payload = {
        "base_src": str(Path(base_src).resolve()),
        "limits": LIMITS,
        "curated": {name: (LIMITS[limits], steps) for name, (limits, steps) in CURATED.items()},
        "seeds": SEEDS_PER_LIMIT,
        "length": STEPS_PER_SCENARIO,
        "pure": pure,
    }
    recorded = _run_oracle(payload["base_src"], payload)
    document = {"schema": "guard-daemon-admission-vectors.v1", "base_commit": base_commit, **recorded}
    with gzip.GzipFile(output, "wb", mtime=0) as handle:
        handle.write(json.dumps(document, sort_keys=True, separators=(",", ":")).encode())


if __name__ == "__main__":
    main()
