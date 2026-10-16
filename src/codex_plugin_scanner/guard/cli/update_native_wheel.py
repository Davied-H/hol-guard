"""Install the platform-native wheel from the GitHub release.

PyPI does not carry every native wheel. Alpha publication uploads only the
pure ``py3-none-any`` wheel, and stable publication keeps the platforms with
few users (Intel macOS and Windows ARM64) off PyPI to stay inside the project
storage quota. A pure wheel has no bundled ``_native/hol-guard-runtime``, so
this module picks the platform wheel that matches the running interpreter,
downloads it from the ``v<version>`` release (``alpha/v<version>`` for
alphas), and verifies its digest before the existing wheel installer runs.

Trust model: stable digests come from ``native-wheels.json``, which the
release workflow embeds in the pure wheel it uploads to PyPI. That pure wheel
is either the installed package (when repairing the same version) or a fresh
PyPI download checked against the sha256 PyPI publishes, so a GitHub asset is
accepted only when PyPI vouches for its bytes. Alpha digests come from the
build-provenance bundle on the same prerelease; the statement is checked for
the expected repository and workflow, but the Sigstore signature chain is not
verified here, so for alphas this guards against corrupted or mismatched
downloads and binds the wheel to the release's own attestation.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import shutil
import tempfile
import time
import urllib.error
import urllib.request
import zipfile
from collections.abc import Callable, Iterable
from contextlib import AbstractContextManager
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Protocol

from packaging.tags import sys_tags
from packaging.utils import InvalidWheelFilename, canonicalize_name, parse_wheel_filename
from packaging.version import InvalidVersion, Version

from ..mdm.contracts import ManagedNetworkPolicy
from ..mdm.network import ManagedNetworkError, managed_urlopen
from ..native_runtime import _bundled_runtime_candidate, _installed_package_root

RELEASE_DOWNLOAD_PREFIX = "https://github.com/hashgraph-online/hol-guard/releases/download/"
PYPI_JSON_PREFIX = "https://pypi.org/pypi/hol-guard/"
PYPI_FILES_PREFIX = "https://files.pythonhosted.org/"
ALPHA_UPDATE_COMMAND = "hol-guard update --alpha"
STABLE_UPDATE_COMMAND = "hol-guard update"
PUBLISHED_PLATFORM_TAGS = frozenset(
    {
        "macosx_11_0_arm64",
        "macosx_13_0_x86_64",
        "manylinux_2_17_x86_64",
        "win_amd64",
        "win_arm64",
    }
)
# Stable native wheels for these platforms are attached to the GitHub release and never uploaded to PyPI.
GITHUB_ONLY_PLATFORM_TAGS = frozenset({"macosx_13_0_x86_64", "win_arm64"})
NATIVE_WHEEL_MANIFEST_NAME = "native-wheels.json"
NATIVE_WHEEL_MANIFEST_MEMBER = f"codex_plugin_scanner/{NATIVE_WHEEL_MANIFEST_NAME}"
NATIVE_WHEEL_MANIFEST_SCHEMA = "hol-guard-native-wheels.v1"
_PROVENANCE_REPOSITORY = "https://github.com/hashgraph-online/hol-guard"
_PROVENANCE_WORKFLOW_PATH = ".github/workflows/publish.yml"
_MAX_PROVENANCE_BYTES = 512 * 1024
_MAX_PYPI_JSON_BYTES = 4 * 1024 * 1024
_MAX_MANIFEST_BYTES = 64 * 1024
_MAX_WHEEL_BYTES = 256 * 1024 * 1024
_READ_CHUNK_BYTES = 1024 * 1024
_REQUEST_TIMEOUT_SECONDS = 60.0
_DOWNLOAD_DEADLINE_SECONDS = 600.0
_USER_AGENT = "HOL-Guard-Native-Update"
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_SAFE_VERSION_RE = re.compile(r"^[A-Za-z0-9._-]{1,80}$")
# The marker keeps its alpha-era name so installs recorded by earlier updaters stay managed.
_MARKER_NAME = "alpha-native-wheel.json"
_MARKER_SCHEMA_VERSION = 1


class _Readable(Protocol):
    def read(self, size: int = -1, /) -> bytes: ...


Opener = Callable[[urllib.request.Request], AbstractContextManager[_Readable]]

_FAILURE_MESSAGES = {
    "native_wheel_platform_unsupported": (
        "This release has no native wheel for this platform. The current installation remains active."
    ),
    "native_wheel_release_unavailable": (
        "The GitHub release for this version is not published (an alpha may have been retracted). "
        "The current installation remains active."
    ),
    "native_wheel_provenance_invalid": (
        "The release provenance could not be verified, so no native wheel was installed. "
        "The current installation remains active."
    ),
    "native_wheel_manifest_invalid": (
        "The native wheel digests published on PyPI for this release could not be read, "
        "so no native wheel was installed. The current installation remains active."
    ),
    "native_wheel_asset_missing": (
        "The release has no native wheel for this platform. The current installation remains active."
    ),
    "native_wheel_download_failed": (
        "The native wheel could not be downloaded. The current installation remains active."
    ),
    "native_wheel_digest_mismatch": (
        "The downloaded wheel did not match its published digest and was discarded. "
        "The current installation remains active."
    ),
}


class NativeWheelError(RuntimeError):
    """The native wheel could not be fetched and verified; callers fail closed."""

    reason_code: str

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)

    @property
    def message(self) -> str:
        return _FAILURE_MESSAGES.get(self.reason_code, "The native wheel could not be installed.")


@dataclass(frozen=True, slots=True)
class NativeWheelPlan:
    """Why an update must install the native wheel from the GitHub release."""

    version: str
    reason: Literal["upgrade", "repair"]


@dataclass(frozen=True, slots=True)
class NativeWheelDownload:
    path: Path
    directory: Path
    sha256: str
    version: str

    def cleanup(self) -> None:
        shutil.rmtree(self.directory, ignore_errors=True)


def is_alpha_version(version: object) -> bool:
    if not isinstance(version, str):
        return False
    try:
        parsed = Version(version.strip())
    except InvalidVersion:
        return False
    return parsed.pre is not None and parsed.pre[0] == "a"


def bundled_native_runtime_missing(candidate: Path | None = None) -> bool:
    return not (candidate or _bundled_runtime_candidate()).is_file()


def native_platform_supported(tags: Iterable[str] | None = None) -> bool:
    """True when this interpreter can install a platform wheel the release publishes."""

    return any(tag in PUBLISHED_PLATFORM_TAGS for tag in (tags if tags is not None else _platform_tags()))


def github_only_platform(tags: Iterable[str] | None = None) -> bool:
    """True when this interpreter's stable native wheel is on the GitHub release but not on PyPI."""

    host = set(tags if tags is not None else _platform_tags())
    return bool(host & GITHUB_ONLY_PLATFORM_TAGS) and not host & (PUBLISHED_PLATFORM_TAGS - GITHUB_ONLY_PLATFORM_TAGS)


def update_command_for(version: str | None) -> str:
    return ALPHA_UPDATE_COMMAND if is_alpha_version(version) else STABLE_UPDATE_COMMAND


def plan_native_wheel_update(
    *,
    include_alpha: bool,
    current_version: str,
    target_version: str | None,
    runtime_missing: bool,
    platform_supported: bool,
    github_only: bool = False,
) -> NativeWheelPlan | None:
    """Decide whether the update must install the native wheel from the GitHub release."""

    if not platform_supported:
        # Hosts without a published native wheel keep the ordinary PyPI path.
        return None
    if target_version is not None:
        if is_alpha_version(target_version):
            return NativeWheelPlan(version=target_version, reason="upgrade") if include_alpha else None
        # PyPI already serves the stable native wheel unless this platform is GitHub-only.
        return NativeWheelPlan(version=target_version, reason="upgrade") if github_only else None
    if runtime_missing:
        return NativeWheelPlan(version=current_version.strip(), reason="repair")
    return None


def manual_install_command(version: str, *, tags: Iterable[str] | None = None) -> str | None:
    """Return the pip command that installs this host's native wheel when the download is blocked."""

    if _SAFE_VERSION_RE.fullmatch(version) is None:
        return None
    for tag in tags if tags is not None else _platform_tags():
        if tag in PUBLISHED_PLATFORM_TAGS:
            url = release_url(version, f"hol_guard-{version}-py3-none-{tag}.whl")
            return f'python -m pip install --force-reinstall --no-deps "{url}"'
    return None


def native_runtime_payload(
    runtime_missing: bool,
    *,
    platform_supported: bool = True,
    version: str | None = None,
) -> dict[str, object]:
    if not runtime_missing:
        return {"status": "present", "bundled": True}
    payload: dict[str, object] = {"status": "missing", "bundled": False}
    if platform_supported:
        fix = update_command_for(version)
        payload["fix"] = fix
        payload["message"] = (
            "This install has no bundled native runtime (PyPI only carries the pure wheel for this platform). "
            f"Run `{fix}` to install the native wheel from the GitHub release."
        )
        manual = manual_install_command(version) if version is not None else None
        if manual is not None:
            payload["manual_install"] = manual
    return payload


def failure_payload(payload: dict[str, object], error: NativeWheelError, *, version: str | None = None) -> None:
    message = error.message
    manual = manual_install_command(version) if version is not None else None
    if manual is not None:
        payload["manual_install"] = manual
        message = f"{message} To install it by hand, run: {manual}"
    payload.update(
        {
            "status": "failed",
            "changed": False,
            "reason_code": error.reason_code,
            "error": error.reason_code,
            "message": message,
        }
    )


def prepare_native_wheel(
    plan: NativeWheelPlan,
    *,
    network_policy: ManagedNetworkPolicy | None,
) -> tuple[NativeWheelDownload | None, str | None]:
    """Download the native wheel for ``plan``; a retracted repair target is a note, not a failure."""

    try:
        return download_native_wheel(plan.version, network_policy=network_policy), None
    except NativeWheelError as error:
        if plan.reason == "repair" and error.reason_code in {
            "native_wheel_release_unavailable",
            "native_wheel_platform_unsupported",
            "native_wheel_asset_missing",
            # Releases published before the digest manifest existed cannot be repaired from GitHub.
            "native_wheel_manifest_invalid",
        }:
            return None, f"Could not repair the native runtime: {error.message}"
        raise


def release_url(version: str, name: str) -> str:
    tag = f"alpha%2Fv{version}" if is_alpha_version(version) else f"v{version}"
    return f"{RELEASE_DOWNLOAD_PREFIX}{tag}/{name}"


def provenance_name(version: str) -> str:
    return f"hol-guard-v{version}.intoto.jsonl"


def parse_provenance_subjects(raw: bytes) -> dict[str, str]:
    """Return ``{artifact name: sha256}`` from a release provenance bundle, or raise."""

    try:
        line = next(item for item in raw.decode("utf-8").splitlines() if item.strip())
        document = json.loads(line)
        envelope = document["dsseEnvelope"]
        if envelope["payloadType"] != "application/vnd.in-toto+json":
            raise NativeWheelError("native_wheel_provenance_invalid")
        statement = json.loads(base64.b64decode(envelope["payload"], validate=True))
        if statement.get("_type") != "https://in-toto.io/Statement/v1":
            raise NativeWheelError("native_wheel_provenance_invalid")
        if not str(statement.get("predicateType", "")).startswith("https://slsa.dev/provenance/"):
            raise NativeWheelError("native_wheel_provenance_invalid")
        workflow = statement["predicate"]["buildDefinition"]["externalParameters"]["workflow"]
        if workflow.get("repository") != _PROVENANCE_REPOSITORY or workflow.get("path") != _PROVENANCE_WORKFLOW_PATH:
            raise NativeWheelError("native_wheel_provenance_invalid")
        subjects: dict[str, str] = {}
        for subject in statement["subject"]:
            name = subject["name"]
            digest = subject["digest"]["sha256"]
            if not isinstance(name, str) or not isinstance(digest, str) or _SHA256_RE.fullmatch(digest) is None:
                raise NativeWheelError("native_wheel_provenance_invalid")
            subjects[name] = digest
    except NativeWheelError:
        raise
    except (
        StopIteration,
        KeyError,
        TypeError,
        AttributeError,
        ValueError,
        UnicodeDecodeError,
        binascii.Error,
    ) as error:
        raise NativeWheelError("native_wheel_provenance_invalid") from error
    return subjects


def parse_native_wheel_manifest(raw: bytes, version: str) -> dict[str, str]:
    """Return ``{native wheel name: sha256}`` from the manifest embedded in the pure wheel, or raise."""

    try:
        document = json.loads(raw.decode("utf-8"))
        if (
            not isinstance(document, dict)
            or document.get("schema") != NATIVE_WHEEL_MANIFEST_SCHEMA
            or document.get("version") != version
        ):
            raise NativeWheelError("native_wheel_manifest_invalid")
        wheels = document["wheels"]
        if not isinstance(wheels, dict) or not wheels:
            raise NativeWheelError("native_wheel_manifest_invalid")
        digests: dict[str, str] = {}
        for name, digest in wheels.items():
            if (
                not isinstance(name, str)
                or not isinstance(digest, str)
                or _SHA256_RE.fullmatch(digest) is None
                or _native_wheel_platform_tag(name, version) is None
            ):
                raise NativeWheelError("native_wheel_manifest_invalid")
            digests[name] = digest
    except NativeWheelError:
        raise
    except (KeyError, TypeError, ValueError, UnicodeDecodeError) as error:
        raise NativeWheelError("native_wheel_manifest_invalid") from error
    return digests


def installed_native_wheel_manifest(version: str, *, package_root: Path | None = None) -> dict[str, str] | None:
    """Read the manifest of the installed pure wheel when it describes ``version``."""

    try:
        with ((package_root or _installed_package_root()) / NATIVE_WHEEL_MANIFEST_NAME).open("rb") as handle:
            raw = handle.read(_MAX_MANIFEST_BYTES + 1)
    except OSError:
        return None
    if len(raw) > _MAX_MANIFEST_BYTES:
        return None
    try:
        return parse_native_wheel_manifest(raw, version)
    except NativeWheelError:
        return None


def select_native_wheel(
    subjects: dict[str, str],
    version: str,
    *,
    tags: Iterable[str] | None = None,
) -> tuple[str, str]:
    """Pick the best-matching platform wheel for ``version`` from the published digests."""

    ranked_tags = list(tags if tags is not None else _platform_tags())
    best: tuple[int, str] | None = None
    for name in sorted(subjects):
        platform_tag = _native_wheel_platform_tag(name, version)
        if platform_tag is None or platform_tag not in ranked_tags:
            continue
        rank = ranked_tags.index(platform_tag)
        if best is None or rank < best[0]:
            best = (rank, name)
    if best is None:
        has_wheel = any(_native_wheel_platform_tag(name, version) is not None for name in subjects)
        raise NativeWheelError("native_wheel_platform_unsupported" if has_wheel else "native_wheel_asset_missing")
    return best[1], subjects[best[1]]


def download_native_wheel(
    version: str,
    *,
    network_policy: ManagedNetworkPolicy | None = None,
    opener: Opener | None = None,
    tags: Iterable[str] | None = None,
    package_root: Path | None = None,
) -> NativeWheelDownload:
    """Fetch, verify, and place the native wheel in a private temporary directory."""

    if _SAFE_VERSION_RE.fullmatch(version) is None:
        raise NativeWheelError("native_wheel_release_unavailable")
    try:
        _ = Version(version)
    except InvalidVersion as error:
        raise NativeWheelError("native_wheel_release_unavailable") from error
    open_url = opener or _default_opener(network_policy)
    digests = _published_native_digests(open_url, version, package_root=package_root)
    name, expected_sha256 = select_native_wheel(digests, version, tags=tags)
    # mkdtemp creates the directory owner-only (0700).
    directory = Path(tempfile.mkdtemp(prefix="hol-guard-native-"))
    try:
        target = directory / name
        actual = _download_to_file(open_url, release_url(version, name), target)
        if actual != expected_sha256:
            raise NativeWheelError("native_wheel_digest_mismatch")
    except BaseException:
        shutil.rmtree(directory, ignore_errors=True)
        raise
    return NativeWheelDownload(path=target, directory=directory, sha256=expected_sha256, version=version)


def record_native_wheel_install(guard_home: Path, *, version: str, sha256: str) -> None:
    """Remember the verified native wheel so later updates keep managing this install."""

    payload = json.dumps(
        {"schema_version": _MARKER_SCHEMA_VERSION, "version": version, "wheel_sha256": sha256},
        sort_keys=True,
    )
    temporary = guard_home / f".{_MARKER_NAME}.{os.getpid()}.tmp"
    try:
        temporary.write_text(payload, encoding="utf-8")
        os.replace(temporary, guard_home / _MARKER_NAME)
    except OSError:
        temporary.unlink(missing_ok=True)


def native_wheel_install_recorded(guard_home: Path, *, archive_sha256: str | None) -> bool:
    """True when the installed wheel's digest matches a native wheel this updater installed."""

    if not archive_sha256:
        return False
    try:
        payload = json.loads((guard_home / _MARKER_NAME).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    return (
        isinstance(payload, dict)
        and payload.get("schema_version") == _MARKER_SCHEMA_VERSION
        and payload.get("wheel_sha256") == archive_sha256
    )


def _published_native_digests(open_url: Opener, version: str, *, package_root: Path | None) -> dict[str, str]:
    if is_alpha_version(version):
        provenance = _read_bounded(open_url, release_url(version, provenance_name(version)), _MAX_PROVENANCE_BYTES)
        return parse_provenance_subjects(provenance)
    installed = installed_native_wheel_manifest(version, package_root=package_root)
    if installed is not None:
        return installed
    return _pypi_native_wheel_manifest(open_url, version)


def _pypi_native_wheel_manifest(open_url: Opener, version: str) -> dict[str, str]:
    """Download the pure wheel PyPI publishes for ``version`` and read its embedded manifest."""

    raw = _read_bounded(open_url, f"{PYPI_JSON_PREFIX}{version}/json", _MAX_PYPI_JSON_BYTES)
    pure_name = f"hol_guard-{version}-py3-none-any.whl"
    try:
        files = json.loads(raw.decode("utf-8"))["urls"]
        entry = next(item for item in files if isinstance(item, dict) and item.get("filename") == pure_name)
        url = entry["url"]
        digest = entry["digests"]["sha256"]
    except StopIteration as error:
        raise NativeWheelError("native_wheel_manifest_invalid") from error
    except (KeyError, TypeError, ValueError, UnicodeDecodeError) as error:
        raise NativeWheelError("native_wheel_manifest_invalid") from error
    if (
        not isinstance(url, str)
        or not url.startswith(PYPI_FILES_PREFIX)
        or not isinstance(digest, str)
        or _SHA256_RE.fullmatch(digest) is None
    ):
        raise NativeWheelError("native_wheel_manifest_invalid")
    directory = Path(tempfile.mkdtemp(prefix="hol-guard-pure-"))
    try:
        target = directory / pure_name
        if _download_to_file(open_url, url, target) != digest:
            raise NativeWheelError("native_wheel_digest_mismatch")
        try:
            with zipfile.ZipFile(target) as archive:
                info = archive.getinfo(NATIVE_WHEEL_MANIFEST_MEMBER)
                if info.file_size > _MAX_MANIFEST_BYTES:
                    raise NativeWheelError("native_wheel_manifest_invalid")
                manifest = archive.read(info)
        except (KeyError, OSError, zipfile.BadZipFile) as error:
            raise NativeWheelError("native_wheel_manifest_invalid") from error
    finally:
        shutil.rmtree(directory, ignore_errors=True)
    return parse_native_wheel_manifest(manifest, version)


def _platform_tags() -> list[str]:
    tags: list[str] = []
    for tag in sys_tags():
        if (
            tag.interpreter.startswith("py3")
            and tag.abi == "none"
            and tag.platform != "any"
            and tag.platform not in tags
        ):
            tags.append(tag.platform)
    return tags


def _native_wheel_platform_tag(name: str, version: str) -> str | None:
    try:
        distribution, wheel_version, _build, tags = parse_wheel_filename(name)
    except (InvalidWheelFilename, InvalidVersion):
        return None
    if canonicalize_name(distribution) != "hol-guard" or wheel_version != Version(version):
        return None
    if "/" in name or "\\" in name or len(tags) != 1:
        return None
    tag = next(iter(tags))
    if tag.interpreter != "py3" or tag.abi != "none" or tag.platform == "any":
        return None
    return tag.platform


def _default_opener(policy: ManagedNetworkPolicy | None) -> Opener:
    def open_url(request: urllib.request.Request) -> AbstractContextManager[_Readable]:
        return managed_urlopen(request, timeout=_REQUEST_TIMEOUT_SECONDS, policy=policy)

    return open_url


def _request(url: str) -> urllib.request.Request:
    if not url.startswith((RELEASE_DOWNLOAD_PREFIX, PYPI_JSON_PREFIX, PYPI_FILES_PREFIX)):
        raise NativeWheelError("native_wheel_download_failed")
    accept = "application/json" if url.startswith(PYPI_JSON_PREFIX) else "application/octet-stream"
    return urllib.request.Request(url, headers={"User-Agent": _USER_AGENT, "Accept": accept})


def _http_failure(error: urllib.error.HTTPError) -> NativeWheelError:
    error.close()
    return NativeWheelError("native_wheel_release_unavailable" if error.code == 404 else "native_wheel_download_failed")


def _read_bounded(open_url: Opener, url: str, limit: int) -> bytes:
    deadline = time.monotonic() + _REQUEST_TIMEOUT_SECONDS
    try:
        with open_url(_request(url)) as response:
            payload = bytearray()
            while len(payload) <= limit:
                if time.monotonic() >= deadline:
                    raise NativeWheelError("native_wheel_download_failed")
                chunk = response.read(min(_READ_CHUNK_BYTES, limit + 1 - len(payload)))
                if not chunk:
                    break
                payload.extend(chunk)
    except urllib.error.HTTPError as error:
        raise _http_failure(error) from error
    except (ManagedNetworkError, OSError, TimeoutError, urllib.error.URLError) as error:
        raise NativeWheelError("native_wheel_download_failed") from error
    if not payload or len(payload) > limit:
        raise NativeWheelError("native_wheel_download_failed")
    return bytes(payload)


def _download_to_file(open_url: Opener, url: str, target: Path) -> str:
    digest = hashlib.sha256()
    total = 0
    deadline = time.monotonic() + _DOWNLOAD_DEADLINE_SECONDS
    try:
        with open_url(_request(url)) as response, target.open("xb") as handle:
            while True:
                if time.monotonic() >= deadline:
                    raise NativeWheelError("native_wheel_download_failed")
                chunk = response.read(_READ_CHUNK_BYTES)
                if not chunk:
                    break
                total += len(chunk)
                if total > _MAX_WHEEL_BYTES:
                    raise NativeWheelError("native_wheel_download_failed")
                digest.update(chunk)
                handle.write(chunk)
    except urllib.error.HTTPError as error:
        raise _http_failure(error) from error
    except (ManagedNetworkError, OSError, TimeoutError, urllib.error.URLError) as error:
        raise NativeWheelError("native_wheel_download_failed") from error
    if total == 0:
        raise NativeWheelError("native_wheel_download_failed")
    return digest.hexdigest()
