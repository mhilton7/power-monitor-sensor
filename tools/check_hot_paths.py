#!/usr/bin/env python3
"""Semantic repository guard for allocation-sensitive firmware handlers.

This is intentionally a small lexer rather than a collection of whole-file
substring checks.  It locates the actual route handler, ignores comments and
string contents while balancing C++ braces, and applies the compact-status
policy only to that handler.  Native allocation and response-pool tests remain
the runtime enforcement; this check prevents obvious regressions from reaching
those tests.
"""

from __future__ import annotations

import argparse
import re
from dataclasses import dataclass
from pathlib import Path

STATUS_ROUTE = "/api/v1/ui/status"
LOCAL_HEALTH_ROUTE = "/api/local/health"


@dataclass(frozen=True)
class Violation:
    rule: str
    detail: str


def _mask_comments(source: str) -> str:
    """Replace C/C++ comment bytes with spaces while preserving offsets."""

    output = list(source)
    index = 0
    state = "code"
    quote = ""
    while index < len(source):
        char = source[index]
        following = source[index + 1] if index + 1 < len(source) else ""
        if state == "code":
            if char in {'"', "'"}:
                # C++ digit separators (for example 30'000U) are not character
                # literals and must not hide every following brace.
                numeric_separator = (
                    char == "'"
                    and index > 0
                    and source[index - 1].isalnum()
                    and following.isalnum()
                )
                if not numeric_separator:
                    state = "string"
                    quote = char
            elif char == "/" and following == "/":
                output[index] = output[index + 1] = " "
                state = "line_comment"
                index += 1
            elif char == "/" and following == "*":
                output[index] = output[index + 1] = " "
                state = "block_comment"
                index += 1
        elif state == "string":
            if char == "\\":
                index += 1
            elif char == quote:
                state = "code"
        elif state == "line_comment":
            if char in "\r\n":
                state = "code"
            else:
                output[index] = " "
        elif state == "block_comment":
            if char == "*" and following == "/":
                output[index] = output[index + 1] = " "
                state = "code"
                index += 1
            elif char not in "\r\n":
                output[index] = " "
        index += 1
    return "".join(output)


def _matching_brace(source: str, opening: int) -> int:
    if opening >= len(source) or source[opening] != "{":
        raise ValueError("opening offset does not identify a brace")
    depth = 0
    state = "code"
    quote = ""
    index = opening
    while index < len(source):
        char = source[index]
        following = source[index + 1] if index + 1 < len(source) else ""
        if state == "code":
            if char in {'"', "'"}:
                numeric_separator = (
                    char == "'"
                    and index > 0
                    and source[index - 1].isalnum()
                    and following.isalnum()
                )
                if not numeric_separator:
                    state = "string"
                    quote = char
            elif char == "/" and following == "/":
                state = "line_comment"
                index += 1
            elif char == "/" and following == "*":
                state = "block_comment"
                index += 1
            elif char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    return index
        elif state == "string":
            if char == "\\":
                index += 1
            elif char == quote:
                state = "code"
        elif state == "line_comment":
            if char in "\r\n":
                state = "code"
        elif state == "block_comment" and char == "*" and following == "/":
            state = "code"
            index += 1
        index += 1
    raise ValueError("unterminated C++ handler body")


def route_handler(source: str, route: str) -> str:
    masked = _mask_comments(source)
    route_offset = masked.find(f'"{route}"')
    if route_offset < 0:
        raise ValueError(f"route {route} was not found")
    lambda_offset = masked.find("[this]", route_offset)
    if lambda_offset < 0:
        raise ValueError("compact status route has no [this] handler")
    opening = masked.find("{", lambda_offset)
    if opening < 0:
        raise ValueError("compact status route handler has no body")
    closing = _matching_brace(masked, opening)
    return masked[opening : closing + 1]


def status_handler(source: str) -> str:
    return route_handler(source, STATUS_ROUTE)


def named_function(source: str, qualified_name: str) -> str:
    """Return one C++ member function body with comments masked."""

    masked = _mask_comments(source)
    signature = re.search(rf"\b{re.escape(qualified_name)}\s*\(", masked)
    if signature is None:
        raise ValueError(f"function {qualified_name} was not found")
    opening = masked.find("{", signature.end())
    if opening < 0:
        raise ValueError(f"function {qualified_name} has no body")
    closing = _matching_brace(masked, opening)
    return masked[opening : closing + 1]


def named_type(source: str, name: str) -> str:
    """Return one C++ class/struct body with comments masked."""

    masked = _mask_comments(source)
    declaration = re.search(rf"\b(?:class|struct)\s+{re.escape(name)}\b", masked)
    if declaration is None:
        raise ValueError(f"type {name} was not found")
    opening = masked.find("{", declaration.end())
    if opening < 0:
        raise ValueError(f"type {name} has no body")
    closing = _matching_brace(masked, opening)
    return masked[opening : closing + 1]


def inspect_status_handler(source: str) -> list[Violation]:
    try:
        handler = status_handler(source)
    except ValueError as error:
        return [Violation("status-route-shape", str(error))]

    violations: list[Violation] = []
    prohibited_types = (
        "JsonDocument",
        "JsonObject",
        "JsonArray",
        "RuntimeConfig",
        "NetworkStatus",
        "StorageHealth",
        "std::string",
        "std::vector",
        "std::map",
        "std::unordered_map",
    )
    for name in prohibited_types:
        if re.search(rf"(?<![A-Za-z0-9_]){re.escape(name)}(?![A-Za-z0-9_])", handler):
            violations.append(
                Violation(
                    "bounded-status-types",
                    f"compact status handler uses prohibited dynamic/full type {name}",
                )
            )

    prohibited_calls = {
        r"\bserializeJson\s*\(": "general-purpose JSON serialization",
        r"\bshrink_to_fit\s*\(": "allocator-churning shrink_to_fit",
        r"\bnetwork_\s*\.\s*status\s*\(": "full NetworkStatus snapshot",
        r"\bstorage_\s*\.\s*health\s*\(": "full StorageHealth snapshot",
        r"\bstorage_\s*\.\s*(?:history|query|page|scan|read)\w*\s*\(": (
            "microSD/history operation"
        ),
        r"\bdiagnostics_\s*\.\s*(?:bundle|diagnosticBundle|events)\s*\(": (
            "diagnostics bundle/event generation"
        ),
    }
    for pattern, detail in prohibited_calls.items():
        if re.search(pattern, handler):
            violations.append(Violation("bounded-status-calls", detail))

    for required, detail in (
        ("serializeCompactUiStatus", "bounded compact serializer"),
        ("status_response_pool_.acquire", "bounded response-pool lease"),
    ):
        if required not in re.sub(r"\s+", "", handler):
            violations.append(
                Violation(
                    "bounded-status-required",
                    f"compact status handler does not use the {detail}",
                )
            )
    return violations


def inspect_local_health_handler(source: str) -> list[Violation]:
    try:
        handler = route_handler(source, LOCAL_HEALTH_ROUTE)
    except ValueError as error:
        return [Violation("local-health-route-shape", str(error))]

    violations: list[Violation] = []
    for name in (
        "JsonDocument",
        "JsonObject",
        "JsonArray",
        "NetworkStatus",
        "StorageHealth",
        "SyncMetrics",
        "DeviceIdentity",
        "std::string",
        "std::vector",
    ):
        if re.search(rf"(?<![A-Za-z0-9_]){re.escape(name)}(?![A-Za-z0-9_])", handler):
            violations.append(
                Violation(
                    "bounded-local-health-types",
                    f"local health uses prohibited dynamic/full type {name}",
                )
            )
    for pattern, detail in (
        (r"\bserializeJson\s*\(", "general-purpose JSON serialization"),
        (r"\bnetwork_\s*\.\s*status\s*\(", "full NetworkStatus snapshot"),
        (r"\bstorage_\s*\.\s*health\s*\(", "full StorageHealth snapshot"),
        (r"\bdiagnostics_\s*\.\s*syncMetrics\s*\(", "string-bearing sync snapshot"),
        (r"\bconfig_\s*\.\s*identity\s*\(", "string-bearing identity snapshot"),
    ):
        if re.search(pattern, handler):
            violations.append(Violation("bounded-local-health-calls", detail))
    compact = re.sub(r"\s+", "", handler)
    for required, detail in (
        ("local_health_response_pool_.acquire()", "bounded body-pool lease"),
        ("network_.compactStatus()", "compact network snapshot"),
        ("storage_.heartbeatHealth()", "fixed storage snapshot"),
        ("diagnostics_.compactSyncMetrics()", "fixed sync snapshot"),
        ("config_.compactIdentity()", "fixed identity snapshot"),
        ("serializeLocalHealth", "bounded local-health serializer"),
    ):
        if required not in compact:
            violations.append(
                Violation(
                    "bounded-local-health-required",
                    f"local health lacks the {detail}",
                )
            )
    return violations


def inspect_status_dependencies(source: str) -> list[Violation]:
    """Guard allocation-sensitive helpers called by the compact status route."""

    violations: list[Violation] = []
    try:
        authorize = named_function(source, "HttpApi::authorize")
        session_cookie = named_function(source, "HttpApi::sessionCookie")
        local_session = named_function(source, "HttpApi::localSessionResult")
        same_origin = named_function(source, "HttpApi::sameOrigin")
    except ValueError as error:
        return [Violation("bounded-status-auth-shape", str(error))]

    for pattern, detail in (
        (r"\bnetwork_\s*\.\s*status\s*\(", "full NetworkStatus auth snapshot"),
        (r"\bcookieValue\s*\(", "copying cookie parser in authorization"),
    ):
        if re.search(pattern, authorize):
            violations.append(Violation("bounded-status-auth", detail))
    for required, detail in (
        ("network_.setupApActive()", "allocation-free setup-AP snapshot"),
        ("sessionCookie(request)", "single bounded session-cookie parse"),
        ("session_cookie.view()", "bounded session-token view"),
    ):
        if required not in re.sub(r"\s+", "", authorize):
            violations.append(
                Violation(
                    "bounded-status-auth",
                    f"authorization does not use the {detail}",
                )
            )
    if authorize.count("sessionCookie(request)") != 1:
        violations.append(
            Violation(
                "bounded-status-auth",
                "authorization must parse the session cookie exactly once",
            )
        )

    for body, name in (
        (session_cookie, "session-cookie parser"),
        (local_session, "local-session validation"),
        (same_origin, "same-origin validation"),
    ):
        if re.search(r"\bstd::string\b(?!_view)", body):
            violations.append(
                Violation(
                    "bounded-status-auth",
                    f"{name} constructs a dynamic std::string",
                )
            )
    if "parseBoundedCookie" not in session_cookie:
        violations.append(
            Violation(
                "bounded-status-auth",
                "session-cookie parser does not use fixed bounded storage",
            )
        )
    if "cookieValue" in local_session:
        violations.append(
            Violation(
                "bounded-status-auth",
                "local-session validation reparses the Cookie header",
            )
        )
    if re.search(r'"https?://"\s*\+', same_origin):
        violations.append(
            Violation(
                "bounded-status-auth",
                "same-origin validation concatenates dynamic String values",
            )
        )
    pooled_response = named_type(source, "PooledUiStatusResponse")
    for required, detail in (
        (
            "static_assert(sizeof(PooledUiStatusResponse) <= 512U",
            "compile-time response-object size bound",
        ),
        ("heap_after_response", "post-response-allocation heap measurement"),
        (
            "sizeof(PooledUiStatusResponse)",
            "exact response-object size diagnostic",
        ),
    ):
        if required not in source:
            violations.append(
                Violation(
                    "bounded-status-response",
                    f"compact response path lacks the {detail}",
                )
            )
    for required, detail in (
        ("~PooledUiStatusResponse()", "response lifecycle destructor"),
        ("lease_.release()", "disconnect/error response-slot release"),
        (
            "recordUiStatusResponseObjectRelease()",
            "response-object release diagnostic",
        ),
    ):
        if required not in pooled_response:
            violations.append(
                Violation(
                    "bounded-status-response",
                    f"compact response path lacks the {detail}",
                )
            )
    return violations


def inspect_support_types(root: Path) -> list[Violation]:
    violations: list[Violation] = []
    compact_header = root / "include" / "api" / "CompactUiStatus.h"
    pool_header = root / "include" / "api" / "StatusResponsePool.h"
    cookie_header = root / "include" / "api" / "BoundedCookie.h"
    http_header = root / "src" / "api" / "HttpApi.h"
    auth_header = root / "src" / "security" / "AuthService.h"
    local_health_header = root / "include" / "api" / "LocalHealthStatus.h"
    storage_pool_header = root / "include" / "storage" / "BoundedStorageMessagePool.h"
    for path in (
        compact_header,
        pool_header,
        cookie_header,
        http_header,
        auth_header,
        local_health_header,
        storage_pool_header,
    ):
        if not path.is_file():
            violations.append(Violation("bounded-status-support", f"missing {path}"))
            return violations

    compact = _mask_comments(compact_header.read_text(encoding="utf-8"))
    for dynamic_type, pattern in (
        ("std::string", r"\bstd::string\b(?!_view)"),
        ("std::vector", r"\bstd::vector\b"),
        ("JsonDocument", r"\bJsonDocument\b"),
    ):
        if re.search(pattern, compact):
            violations.append(
                Violation(
                    "bounded-status-snapshot",
                    f"CompactUiStatus owns prohibited dynamic type {dynamic_type}",
                )
            )
    if "std::array" not in compact or "CompactUiStatusSnapshot" not in compact:
        violations.append(
            Violation(
                "bounded-status-snapshot",
                "compact status snapshot is not represented by fixed arrays",
            )
        )

    pool = _mask_comments(pool_header.read_text(encoding="utf-8"))
    for marker in ("std::array", "Lease", "acquire", "exhaustions"):
        if marker not in pool:
            violations.append(
                Violation("bounded-status-pool", f"response pool is missing {marker}")
            )
    cookie = _mask_comments(cookie_header.read_text(encoding="utf-8"))
    for marker in ("BoundedCookieValue", "std::array", "StringView", "overflow"):
        if marker not in cookie:
            violations.append(
                Violation(
                    "bounded-status-auth",
                    f"bounded cookie parser is missing {marker}",
                )
            )
    auth = _mask_comments(auth_header.read_text(encoding="utf-8"))
    if auth.count("StringView") < 3:
        violations.append(
            Violation(
                "bounded-status-auth",
                "session validation does not consume allocation-free string views",
            )
        )
    local_health = _mask_comments(local_health_header.read_text(encoding="utf-8"))
    storage_pool_source = storage_pool_header.read_text(encoding="utf-8")
    storage_pool = "\n".join(
        (
            named_type(storage_pool_source, "FixedIntervalRecord"),
            named_type(storage_pool_source, "FixedEventData"),
        )
    )
    for body, label in (
        (local_health, "LocalHealthSnapshot"),
        (storage_pool, "bounded storage queue payloads"),
    ):
        for dynamic_type, pattern in (
            ("std::string", r"\bstd::string\b(?!_view)"),
            ("std::vector", r"\bstd::vector\b"),
            ("JsonDocument", r"\bJsonDocument\b"),
        ):
            if re.search(pattern, body):
                violations.append(
                    Violation(
                        "bounded-hot-path-support",
                        f"{label} owns prohibited dynamic type {dynamic_type}",
                    )
                )
    http = _mask_comments(http_header.read_text(encoding="utf-8"))
    constants = {
        name: int(value)
        for name, value in re.findall(
            r"constexpr\s+std::size_t\s+(\w+)\s*=\s*(\d+)U?\s*;", http
        )
    }
    match = re.search(r"StatusResponsePool\s*<\s*(\w+)\s*,\s*(\w+)\s*>", http)
    if match is None:
        violations.append(
            Violation(
                "bounded-status-pool",
                "HttpApi does not own a fixed-capacity StatusResponsePool",
            )
        )
    else:
        values = [
            int(value.rstrip("U"))
            if value.rstrip("U").isdigit()
            else constants.get(value)
            for value in match.groups()
        ]
        if any(value is None for value in values):
            violations.append(
                Violation(
                    "bounded-status-pool",
                    "StatusResponsePool capacities are not fixed integer constants",
                )
            )
            return violations
        slots, capacity = (int(value) for value in values if value is not None)
        if not 2 <= slots <= 4:
            violations.append(
                Violation(
                    "bounded-status-pool",
                    f"response-pool slot count {slots} is not 2-4",
                )
            )
        if not 1024 <= capacity <= 4096:
            violations.append(
                Violation(
                    "bounded-status-pool",
                    f"response slot capacity {capacity} is outside 1-4 KiB",
                )
            )
    return violations


def inspect_server_sync_hot_paths(root: Path) -> list[Violation]:
    """Guard recurring heartbeat/transport serialization against heap churn."""

    source_path = root / "src" / "network" / "ServerSync.cpp"
    header_path = root / "src" / "network" / "ServerSync.h"
    scratch_path = root / "src" / "network" / "ServerSyncScratch.h"
    storage_path = root / "src" / "storage" / "SdStorage.h"
    paths = (source_path, header_path, scratch_path, storage_path)
    if not all(path.is_file() for path in paths):
        return [
            Violation(
                "bounded-server-sync-support",
                "server-sync bounded snapshot or scratch source is missing",
            )
        ]
    source = source_path.read_text(encoding="utf-8")
    try:
        heartbeat = named_function(source, "ServerSync::heartbeatBody")
        request = named_function(source, "ServerSync::request")
        events = named_function(source, "ServerSync::pushEvents")
    except ValueError as error:
        return [Violation("bounded-server-sync-shape", str(error))]

    violations: list[Violation] = []
    for pattern, detail in (
        (r"\bNetworkStatus\b", "full NetworkStatus heartbeat snapshot"),
        (r"\bStorageHealth\b", "full StorageHealth heartbeat snapshot"),
        (r"\bMeasurementRuntimeConfig\b", "copying measurement configuration"),
        (r"\bServerSyncRuntimeConfig\b", "copying server-sync configuration"),
        (r"\bDeviceIdentity\b", "copying device identity"),
        (r"\bstd::string\b(?!_view)", "dynamic heartbeat string"),
        (r"\.utcIso8601\s*\(", "allocating UTC formatter"),
        (r"\bisoUtc\s*\(", "allocating millisecond UTC formatter"),
    ):
        if re.search(pattern, heartbeat):
            violations.append(Violation("bounded-heartbeat", detail))
    compact_heartbeat = re.sub(r"\s+", "", heartbeat)
    for required, detail in (
        ("network_.compactStatus()", "compact network snapshot"),
        ("storage_.heartbeatHealth()", "fixed heartbeat storage snapshot"),
        ("transport_device_id_", "cached device identity"),
        ("transport_runtime_config_", "cached runtime configuration"),
        ("formatIsoUtc", "fixed-array UTC formatting"),
    ):
        if required not in compact_heartbeat:
            violations.append(
                Violation("bounded-heartbeat", f"heartbeat lacks the {detail}")
            )

    header = header_path.read_text(encoding="utf-8")
    scratch = scratch_path.read_text(encoding="utf-8")
    storage = storage_path.read_text(encoding="utf-8")
    for marker, detail in (
        ("StringView endpoint", "non-owning request endpoint"),
        ("ensureTransportScratch()", "retryable transport scratch gate"),
        ("next_transport_scratch_retry_ms_", "bounded scratch retry deadline"),
    ):
        if marker not in header:
            violations.append(
                Violation("bounded-server-sync-support", f"missing {detail}")
            )
    if "transport_scratch_.canonical_target.assign" in request:
        violations.append(
            Violation(
                "bounded-server-sync-request",
                "fixed request target is copied into a dynamic string",
            )
        )
    compact_request = re.sub(r"\s+", " ", request)
    for required, detail in (
        ("ensureTransportScratch()", "retryable scratch initialization"),
        ("StringView canonical_target = endpoint", "bounded canonical target view"),
        ("containsCharacter(endpoint, '?')", "query-only canonical parser gate"),
    ):
        if required not in compact_request:
            violations.append(
                Violation("bounded-server-sync-request", f"request lacks {detail}")
            )
    for pattern, detail in (
        (r"\bstd::to_string\s*\(", "numeric event-ID allocation"),
        (r"const\s+std::string\s+(?:boot_id|code)\b", "event field string copy"),
    ):
        if re.search(pattern, events):
            violations.append(Violation("bounded-event-batch", detail))
    if "bool ready() const" not in scratch:
        violations.append(
            Violation(
                "bounded-server-sync-support", "scratch readiness is not explicit"
            )
        )
    if "HeartbeatStorageHealth" not in storage or "std::array<char" not in storage:
        violations.append(
            Violation(
                "bounded-server-sync-support",
                "heartbeat storage snapshot is not fixed-capacity",
            )
        )
    for marker in (
        "BeforeClientConstruction",
        "AfterTlsConfiguration",
        "AfterHttpBegin",
        "AfterRequest",
        "AfterHttpEnd",
        "AfterClientDestruction",
        "AfterHighMemoryLeaseRelease",
    ):
        if marker not in source:
            violations.append(
                Violation(
                    "tls-lifecycle-checkpoints",
                    f"server-sync lifecycle is missing {marker}",
                )
            )
    return violations


def check(root: Path) -> list[Violation]:
    source = root / "src" / "api" / "HttpApi.cpp"
    if not source.is_file():
        return [Violation("status-route-shape", f"missing {source}")]
    contents = source.read_text(encoding="utf-8")
    return (
        inspect_status_handler(contents)
        + inspect_local_health_handler(contents)
        + inspect_status_dependencies(contents)
        + inspect_support_types(root)
        + inspect_server_sync_hot_paths(root)
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--root", type=Path, default=Path(__file__).resolve().parents[1]
    )
    arguments = parser.parse_args()
    violations = check(arguments.root.resolve())
    if violations:
        for violation in violations:
            print(f"ERROR [{violation.rule}]: {violation.detail}")
        return 1
    print("compact status and server-sync hot-path policy passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
