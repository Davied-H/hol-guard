"""Native portable-policy rows with the existing public Python DTOs."""

from __future__ import annotations

import time
from collections.abc import Iterable, Mapping

from .models import PolicyDecision
from .native_policy_document import NativePolicyDocumentError, policy_query
from .native_runtime import native_runtime_status
from .native_runtime_request_scope import native_status_request_scope
from .policy_document import GuardPolicyDocument
from .policy_document_types import CompiledPolicyRow
from .policy_document_types import PolicyCompilationError as PolicyCompilationError


def build_policy_document_from_rows(
    rows: Iterable[Mapping[str, object]],
    *,
    document_id: str = "local-policy",
    name: str = "Local Guard policy",
    revision: int = 0,
    include_provenance: bool = False,
) -> GuardPolicyDocument:
    value = policy_query(
        "rows",
        {
            "rows": [dict(row) for row in rows],
            "document_id": document_id,
            "name": name,
            "revision": revision,
            "include_provenance": include_provenance,
        },
    )
    return GuardPolicyDocument.from_mapping(value)


def compile_policy_document(document: GuardPolicyDocument) -> tuple[CompiledPolicyRow, ...]:
    """Present native rows in order, sharing one deadline and runtime identity."""
    source = document.to_mapping()
    deadline = time.monotonic() + 30.0
    compiled = []
    offset = 0
    total = None
    with native_status_request_scope():
        status = native_runtime_status(deadline_monotonic=deadline)
        if status.identity is None:
            raise NativePolicyDocumentError("native_policy_document_unavailable")
        while True:
            page = policy_query(
                "compile_page",
                {"document": source, "offset": offset, "limit": 32},
                deadline_monotonic=deadline,
                runtime_sha256=status.identity.sha256,
            )
            if (
                not isinstance(page, dict)
                or set(page) != {"items", "offset", "total"}
                or type(page["offset"]) is not int
                or page["offset"] != offset
                or type(page["total"]) is not int
                or not 0 <= page["total"] <= 10_000
                or (total is not None and page["total"] != total)
                or not isinstance(page["items"], list)
                or len(page["items"]) != min(32, page["total"] - offset)
            ):
                raise NativePolicyDocumentError("native_policy_document_page_unbound")
            total = page["total"]
            for item in page["items"]:
                if (
                    not isinstance(item, dict)
                    or set(item) != {"decision", "rule_id", "provenance_json"}
                    or not isinstance(item["rule_id"], str)
                    or not isinstance(item["provenance_json"], str)
                    or not isinstance(item["decision"], dict)
                    or item["decision"].get("action") not in {"allow", "block"}
                    or item["decision"].get("scope") not in {"artifact", "workspace", "publisher", "harness", "global"}
                    or any(value is not None and not isinstance(value, str) for value in item["decision"].values())
                ):
                    raise NativePolicyDocumentError("native_policy_document_page_malformed")
                try:
                    compiled.append(
                        CompiledPolicyRow(PolicyDecision(**item["decision"]), item["rule_id"], item["provenance_json"])
                    )
                except TypeError as exc:
                    raise NativePolicyDocumentError("native_policy_document_page_malformed") from exc
            offset += len(page["items"])
            if offset == total:
                return tuple(compiled)
