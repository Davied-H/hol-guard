"""Update transport bounds and advisory selectors never substitute for authority."""

from __future__ import annotations

import io
import json
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.catalog_delivery import transport


@pytest.mark.parametrize(
    "url",
    [
        "http://github.com/a",
        "https://github.com.evil.invalid/a",
        "https://user:pass@github.com/a",
        "https://github.com:444/a",
        "file:///tmp/data",
    ],
)
def test_transport_rejects_unapproved_destinations(url):
    with pytest.raises(ValueError, match="destination"):
        transport.download(url, 100)


class Response(io.BytesIO):
    def __init__(self, data, headers):
        super().__init__(data)
        self.headers = headers


@pytest.mark.parametrize(
    "data,headers",
    [
        (b"x" * 101, {}),
        (b"x", {"Content-Length": "101"}),
        (b"x", {"Content-Length": "2"}),
        (b"x", {"Content-Encoding": "gzip"}),
    ],
)
def test_transport_bounds_declared_and_actual_bodies(monkeypatch, data, headers):
    monkeypatch.setattr(
        transport.urllib.request,
        "build_opener",
        lambda *args: SimpleNamespace(open=lambda *args, **kwargs: Response(data, headers)),
    )
    with pytest.raises(ValueError):
        transport.download("https://github.com/hashgraph-online/hol-guard/releases/download/data/asset", 100)


def test_pointer_digest_and_publication_are_bound_before_returning_a_root(monkeypatch):
    selection = {
        "schema": "guard.extension-distribution-selector.v2",
        "source_sha": "1" * 40,
        "publication_id": "12.1",
        "root_sha256": "2" * 64,
    }
    monkeypatch.setattr(transport, "root_assets", lambda *args: (b"changed", b"proof"))
    monkeypatch.setattr(
        transport, "verify_distribution", lambda *args, **kwargs: pytest.fail("substituted root reached verification")
    )
    with pytest.raises(ValueError, match="differs from advisory"):
        transport.fetch_root(now=1000, selection=selection)


def test_untrusted_location_cannot_choose_a_url_or_path():
    for value in ({"url": "https://evil.invalid/object"}, {"tag": "../data", "asset": "object-" + "1" * 64 + ".json"}):
        with pytest.raises(ValueError, match="location"):
            transport.fetch_object(value, 100)


def test_selector_is_bounded_and_never_treats_a_local_build_as_published(monkeypatch):
    value = {
        "schema": "guard.extension-distribution-selector.v2",
        "source_sha": "1" * 40,
        "publication_id": "0.0",
        "root_sha256": "2" * 64,
    }
    monkeypatch.setattr(transport, "download", lambda *args: json.dumps(value).encode())
    with pytest.raises(ValueError, match="local publication"):
        transport.selected()
