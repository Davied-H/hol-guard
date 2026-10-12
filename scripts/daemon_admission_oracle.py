"""Drive the retired Python daemon admission with real socket pairs.

This module runs inside a child process whose ``PYTHONPATH`` is the base
checkout, so the answers come only from the Python that existed before the
Rust listener took over socket admission. It never imports the Rust runtime.

The server is built without its stores or handlers (``object.__new__``): the
admission methods only read the semaphores, counters, tables and executors that
``_GuardDaemonHTTPServer.__init__`` sets, and those are rebuilt here from the
same expressions. Time is virtual so that watchdog deadlines are exact, and the
two admission waits are zero so a blocked acquire fails without sleeping.
"""

from __future__ import annotations

import contextlib
import random
import socket
import threading
from types import SimpleNamespace

PEEK_LIMIT = 4096
CLIENT_PORT_BASE = 40_000


class _Clock:
    def __init__(self) -> None:
        self.now = 1_000.0

    def monotonic(self) -> float:
        return self.now


class _OneTick:
    """A stop event that lets the watchdog loop run exactly one iteration."""

    def __init__(self) -> None:
        self._calls = 0

    def wait(self, _timeout: float) -> bool:
        self._calls += 1
        return self._calls > 1


class _Executor:
    def __init__(self, name: str, sink: list) -> None:
        self.name = name
        self.sink = sink

    def submit(self, request: socket.socket, _address: tuple[str, int]) -> bool:
        self.sink.append((id(request), self.name))
        return True


class Harness:
    def __init__(self, base_src: str, limits: dict) -> None:
        del base_src
        from codex_plugin_scanner.guard.daemon import bounded_http, server

        self.server_module = server
        self.bounded = bounded_http
        self.clock = _Clock()
        server.time = SimpleNamespace(monotonic=self.clock.monotonic, sleep=lambda _s: None, time=self.clock.monotonic)
        server._DAEMON_CONNECTION_ADMISSION_WAIT_SECONDS = 0.0
        server._DAEMON_CONTROL_ADMISSION_WAIT_SECONDS = 0.0
        bounded_http._METRICS = bounded_http._Metrics()
        bounded_http._OVERLOAD_REQUEST_DRAIN_TIMEOUT_SECONDS = 0.005
        self.names: dict[int, str] = {}
        self.client: dict[str, socket.socket] = {}
        self.sock: dict[str, socket.socket] = {}
        self.submitted: list[tuple[int, str]] = []
        self.claimed: dict[str, str] = {}
        self.server = self._build(limits)

    def _build(self, limits: dict):
        server = self.server_module
        instance = object.__new__(server._GuardDaemonHTTPServer)
        instance.request_capacity_limit = limits["request"]
        instance.request_capacity = threading.BoundedSemaphore(limits["request"])
        instance.control_request_capacity_limit = limits["control"]
        instance.control_request_capacity = threading.BoundedSemaphore(limits["control"])
        instance.critical_request_capacity_limit = limits["critical"]
        instance.critical_request_capacity = threading.BoundedSemaphore(limits["critical"])
        instance.connection_capacity_limit = limits["connection"]
        instance.connection_capacity = threading.BoundedSemaphore(limits["connection"])
        instance._guard_capacity_limit = limits["guard"]
        instance._guard_slots = threading.BoundedSemaphore(limits["guard"])
        instance._guard_active_metrics = self.bounded._METRICS
        instance._guard_socket_timeout = 5.0
        instance.active_requests = 0
        instance.rejected_requests = 0
        instance.normal_connections = set()
        instance.request_capacity_kinds = {}
        instance.request_accepted_at = {}
        instance.active_connections = {}
        instance.request_capacity_lock = threading.Lock()
        instance.unclassified_connections = {}
        instance.pending_classifications = {}
        instance.saturation_probes = {}
        instance.unclassified_connections_lock = threading.Lock()
        instance.idle_shutdown_claimed = False
        instance.last_activity_monotonic = self.clock.now
        instance.general_request_executor = _Executor("general", self.submitted)
        instance.control_request_executor = _Executor("control", self.submitted)
        instance.diagnostics = SimpleNamespace(record_exception=lambda _name: None)
        return instance

    def close(self) -> None:
        for sock in list(self.sock.values()) + list(self.client.values()):
            with contextlib.suppress(OSError):
                sock.close()

    def _name(self, sock: socket.socket) -> str:
        return self.names[id(sock)]

    def apply(self, step: dict) -> object:
        op = step["op"]
        server = self.server
        if op == "connect":
            name = step["name"]
            client, accepted = socket.socketpair()
            client.setblocking(False)
            self.client[name], self.sock[name] = client, accepted
            self.names[id(accepted)] = name
            if step["data"]:
                client.sendall(step["data"].encode("latin-1"))
            index = len(self.sock)
            server.process_request(accepted, ("127.0.0.1", CLIENT_PORT_BASE + index))
            return None
        if op == "send":
            with contextlib.suppress(OSError):
                self.client[step["name"]].sendall(step["data"].encode("latin-1"))
            return None
        if op == "peer_close":
            self.client[step["name"]].close()
            return None
        if op == "tick":
            self.clock.now += step["dt"]
            server.unclassified_watchdog_stop = _OneTick()
            server._watch_unclassified_connections()
            return None
        if op == "claim":
            granted = server.claim_request_capacity(self.sock[step["name"]], step["path"])
            if granted:
                self.claimed[step["name"]] = server._request_capacity_kind(step["path"])
            return granted
        if op == "finish":
            accepted = self.sock[step["name"]]
            server.shutdown_request(accepted)
            server._release_request_capacity(accepted)
            self.claimed.pop(step["name"], None)
            return None
        if op == "closing":
            server.idle_shutdown_claimed = True
            return None
        raise ValueError(op)

    def observe(self) -> dict:
        server = self.server
        metrics = self.bounded._METRICS.snapshot()
        conns = {}
        for name, accepted in self.sock.items():
            overload = False
            try:
                overload = self.client[name].recv(65_536).startswith(b"HTTP/1.1 503")
            except (BlockingIOError, OSError):
                overload = False
            conns[name] = {
                "closed": accepted.fileno() == -1,
                "overload": overload,
            }
        for sink_id, executor in self.submitted:
            conns[self.names[sink_id]]["submitted"] = executor
        return {
            "active_requests": server.active_requests,
            "rejected_requests": server.rejected_requests,
            "normal": len(server.normal_connections),
            "connection_free": server.connection_capacity._value,
            "guard_free": server._guard_slots._value,
            "request_free": server.request_capacity._value,
            "control_free": server.control_request_capacity._value,
            "critical_free": server.critical_request_capacity._value,
            "unclassified": len(server.unclassified_connections),
            "pending": len(server.pending_classifications),
            "probes": len(server.saturation_probes),
            "metric_rejected": metrics.rejected,
            "metric_accepted": metrics.accepted,
            "conns": conns,
        }


def run_scenario(base_src: str, limits: dict, steps: list[dict]) -> list[dict]:
    harness = Harness(base_src, limits)
    out = []
    try:
        for step in steps:
            result = harness.apply(step)
            out.append({"step": step, "result": result, "observed": _stable(harness.observe(), harness)})
    finally:
        harness.close()
    return out


def _stable(observation: dict, harness: Harness) -> dict:
    # An overload reply is read once; remember it so later observations agree.
    seen = harness.__dict__.setdefault("_overload_seen", set())
    for name, state in observation["conns"].items():
        if state["overload"]:
            seen.add(name)
        state["overload"] = name in seen
    return observation


_PATHS = [
    "/healthz",
    "/v1/healthz/details",
    "/v1/daemon/identity-challenge",
    "/v1/hook",
    "/v1/runtime/hook",
    "/v1/x?a=1",
]
_PARTIAL = ["GET /v1/hook HT", "GET /healthz", "POST /v1/hook HTTP/1.1\r\nHost: x"]


def _request_bytes(path: str, complete: bool) -> str:
    line = f"GET {path} HTTP/1.1\r\n"
    return line + "Host: x\r\n\r\n" if complete else line + "Host: x"


def generate(base_src: str, seed: int, limits: dict, length: int) -> list[dict]:
    """Build one random scenario, choosing each step from the live oracle state."""

    rng = random.Random(seed)
    harness = Harness(base_src, limits)
    steps: list[dict] = []
    live: list[str] = []
    try:
        for _ in range(length):
            step = _choose(rng, harness, live)
            if step is None:
                continue
            harness.apply(step)
            harness.observe()
            steps.append(step)
    finally:
        harness.close()
    return steps


def _choose(rng: random.Random, harness: Harness, live: list[str]) -> dict | None:
    submitted = {harness.names[sink_id] for sink_id, _ in harness.submitted}
    roll = rng.random()
    if roll < 0.35 or not live:
        name = f"c{len(harness.sock)}"
        live.append(name)
        kind = rng.random()
        if kind < 0.4:
            data = _request_bytes(rng.choice(_PATHS), True)
        elif kind < 0.6:
            data = _request_bytes(rng.choice(_PATHS), False)
        elif kind < 0.8:
            data = rng.choice(_PARTIAL)
        else:
            data = ""
        return {"op": "connect", "name": name, "data": data}
    name = rng.choice(live)
    if roll < 0.5:
        return {
            "op": "send",
            "name": name,
            "data": rng.choice(["\r\n\r\n", "\n", "Host: x\r\n\r\n", "/ HTTP/1.1\r\n\r\n"]),
        }
    if roll < 0.55:
        return {"op": "peer_close", "name": name}
    if roll < 0.7:
        return {"op": "tick", "dt": rng.choice([0.01, 0.05, 0.2, 0.5])}
    if roll < 0.85 and name in submitted:
        return {"op": "claim", "name": name, "path": rng.choice(_PATHS)}
    if roll < 0.97 and name in submitted:
        return {"op": "finish", "name": name}
    if roll >= 0.995:
        return {"op": "closing"}
    return None


def _pair() -> tuple[socket.socket, socket.socket]:
    client, accepted = socket.socketpair()
    for end in (client, accepted):
        end.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 262_144)
        end.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 262_144)
    client.settimeout(2.0)
    return client, accepted


def pure_answers(base_src: str, spec: dict) -> dict:
    """Answer the stateless classification questions with the old methods."""

    del base_src
    from codex_plugin_scanner.guard.daemon import server

    cls = server._GuardDaemonHTTPServer
    out: dict = {"peek": [], "headers": [], "kind": [], "limit": []}
    for text in spec["peek"]:
        client, accepted = _pair()
        try:
            client.sendall(text.encode("latin-1"))
            out["peek"].append({"input": text, "path": cls._peek_request_path(accepted)})
        finally:
            client.close()
            accepted.close()
    for text in spec["headers"]:
        client, accepted = _pair()
        try:
            client.sendall(text.encode("latin-1"))
            out["headers"].append(
                {"input": text, "complete": cls._buffered_request_headers_complete(accepted, pending=True)}
            )
        finally:
            client.close()
            accepted.close()
    for path in spec["kind"]:
        out["kind"].append({"input": path, "kind": cls._request_capacity_kind(path)})
    for limits in spec["limit"]:
        instance = object.__new__(cls)
        instance.connection_capacity_limit = limits["connection"]
        instance._guard_capacity_limit = limits["guard"]
        instance.control_request_capacity_limit = limits["control"]
        instance.critical_request_capacity_limit = limits["critical"]
        instance.request_capacity_lock = threading.Lock()
        instance.normal_connections = set()
        out["limit"].append({"input": limits, "normal_limit": instance._normal_admission_limit()})
    return out
