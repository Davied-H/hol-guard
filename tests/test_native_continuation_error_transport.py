"""Public SQLite exceptions preserve the native error record."""

from __future__ import annotations

import sqlite3

import pytest

from codex_plugin_scanner.guard import native_continuation_authority as native


@pytest.mark.parametrize(
    ("exception", "code", "prefix", "expected_name"),
    [
        ("InternalError", sqlite3.SQLITE_INTERNAL, "SQLITE_INTERNAL", "SQLITE_INTERNAL"),
        ("InternalError", sqlite3.SQLITE_NOTFOUND, "SQLITE_NOTFOUND", "SQLITE_NOTFOUND"),
        ("InterfaceError", sqlite3.SQLITE_RANGE, "SQLITE_RANGE", "SQLITE_RANGE"),
        ("DatabaseError", sqlite3.SQLITE_AUTH, "SQLITE_AUTH", "SQLITE_AUTH"),
        ("OperationalError", sqlite3.SQLITE_BUSY, "SQLITE_BUSY", "SQLITE_BUSY"),
        ("IntegrityError", sqlite3.SQLITE_CONSTRAINT_UNIQUE, "SQLITE_CONSTRAINT", "SQLITE_CONSTRAINT_UNIQUE"),
    ],
)
def test_sqlite_error_transport(monkeypatch, exception, code, prefix, expected_name):
    monkeypatch.setattr(
        native,
        "native_runner_authority",
        lambda *_: {
            "exception": "sqlite3." + exception,
            "error": "original SQLite message",
            "sqlite_errorcode": code,
            "sqlite_errorname_prefix": prefix,
        },
    )
    with pytest.raises(getattr(sqlite3, exception)) as caught:
        native.continuation_authority("store_claim")
    assert str(caught.value) == "original SQLite message"
    assert caught.value.sqlite_errorcode == code
    assert caught.value.sqlite_errorname == expected_name
