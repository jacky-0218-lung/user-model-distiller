#!/usr/bin/env python3
"""Scan normalized JSONL before local use or external review.

The report intentionally contains aggregate finding codes only.  Transcript
text, matched values, source names, and input paths are never included.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import stat
import sys
import tempfile
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable


REPORT_SCHEMA_VERSION = "1.0"
NORMALIZED_SCHEMA_VERSION = "1.0"
VERSION = "0.3.0"

MAX_INPUT_BYTES = 64 * 1024 * 1024
MAX_LINE_BYTES = 1024 * 1024
MAX_RECORDS = 100_000
MAX_TEXT_CHARS = 100_000
MAX_METADATA_STRING_CHARS = 1_024
MAX_CONTAINER_ITEMS = 64
MAX_NESTING_DEPTH = 8

TOP_LEVEL_FIELDS = {
    "schema_version",
    "session_id",
    "message_id",
    "role",
    "created_at",
    "text",
    "redaction_count",
    "source",
}
SOURCE_FIELDS = {"id", "name", "sha256"}
REQUIRED_SOURCE_FIELDS = {"id", "sha256"}
ALLOWED_ROLES = {"user", "assistant"}

SESSION_ID_RE = re.compile(r"^session-[0-9a-f]{20}$")
MESSAGE_ID_RE = re.compile(r"^message-[0-9a-f]{20}$")
SOURCE_ID_RE = re.compile(r"^source-[0-9a-f]{20}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
DATE_ONLY_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")

UUID_RE = re.compile(
    r"(?<![0-9A-Fa-f])"
    r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[1-5][0-9A-Fa-f]{3}-"
    r"[89ABab][0-9A-Fa-f]{3}-[0-9A-Fa-f]{12}"
    r"(?![0-9A-Fa-f])"
)
EMAIL_RE = re.compile(
    r"(?<![\w.+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?![\w.-])"
)
URL_RE = re.compile(
    r"(?i)(?:\b[a-z][a-z0-9+.-]{1,15}://|\bwww\.)[^\s<>\]\[\"']+"
)
IPV4_RE = re.compile(r"(?<![0-9.])(?:\d{1,3}\.){3}\d{1,3}(?![0-9.])")
IPV6_CANDIDATE_RE = re.compile(
    r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![0-9A-Fa-f:])"
)
WINDOWS_PATH_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9])(?:[A-Za-z]:[\\/](?:[^\s<>:\"|?*]+[\\/])*[^\s<>:\"|?*]*|\\\\[^\\/\s]+[\\/][^\s]+)"
)
UNIX_PATH_RE = re.compile(
    r"(?<![:A-Za-z0-9])/(?:[^/\s<>\"']+/)+[^/\s<>\"']+"
)
LONG_TOKEN_RE = re.compile(r"(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{24,}(?![A-Za-z0-9_-])")

SECRET_PATTERNS = (
    re.compile(
        r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
        re.S,
    ),
    re.compile(r"\b(?:sk|rk|pk)-[A-Za-z0-9_-]{16,}\b"),
    re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{12,}"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    re.compile(
        r"(?i)\b(?:password|passwd|api[_ -]?key|access[_ -]?token|refresh[_ -]?token|"
        r"client[_ -]?secret|secret|cookie|session[_ -]?token)\s*[:=]\s*"
        r"(?:[\"'][^\"'\r\n]{6,}[\"']|[^\s,;]{6,})"
    ),
)

TRANSCRIPT_ENVELOPE_PATTERNS = (
    re.compile(r"(?im)^(?:\s{0,8})(?:system|developer|assistant|user|tool)\s*:"),
    re.compile(r"(?i)\b(?:begin|end)\s+(?:chat|conversation|transcript)\b"),
    re.compile(r"(?i)</?(?:system|developer|assistant|user|tool)(?:\s[^>]*)?>"),
    re.compile(r"(?i)[\"']role[\"']\s*:\s*[\"'](?:system|developer|assistant|user|tool)[\"']"),
)
UNSCHEMED_DOMAIN_RE = re.compile(
    r"(?i)(?<![@\w.\u3002\uff0e\uff61-])"
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?[.\u3002\uff0e\uff61])+"
    r"(?:[a-z]{2,63}|xn--[a-z0-9-]{2,59})"
    r"(?![\w-]|[.\u3002\uff0e\uff61][\w])"
)
FILENAME_RE = re.compile(
    r"(?i)(?<![\w.-])[\w][\w .()\-]{0,120}\."
    r"(?:pdf|docx?|xlsx?|pptx?|csv|tsv|jsonl?|ya?ml|toml|txt|md|rtf|zip|tar|gz|7z|"
    r"py|js|jsx|ts|tsx|java|go|rs|c|cc|cpp|h|hpp|sql|log)(?![\w-])"
)
COMMERCIAL_AMOUNT_PATTERNS = (
    re.compile(r"(?i)(?:[$€£¥￥]\s?\d[\d,]*(?:\.\d{1,2})?|\b(?:USD|EUR|GBP|JPY|CNY|RMB)\s?\d[\d,]*(?:\.\d{1,2})?)"),
    re.compile(r"(?i)\b\d[\d,]*(?:\.\d{1,2})?\s?(?:dollars?|euros?|pounds?|yen|yuan)\b"),
)
CONTEXT_RE = re.compile(
    r"(?i)\b(?:project|client|customer|contract|contractor|confidential|proprietary|"
    r"non[- ]disclosure|NDA|statement of work|SOW|trade secret)\b|"
    r"(?:專案|项目|客戶|客户|合約|合同|機密|机密|秘密保持|取引先|顧客|契約|社外秘)"
)


class GuardInputError(ValueError):
    """Raised when the input cannot be inspected safely."""


class GuardOutputError(ValueError):
    """Raised when the aggregate report cannot be written safely."""


class DuplicateKeyError(ValueError):
    """Raised for duplicate JSON object keys."""


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateKeyError("duplicate key")
        result[key] = value
    return result


def _reject_constant(_value: str) -> None:
    raise ValueError("non-finite number")


def _is_normalized_timestamp(value: str) -> bool:
    if not value or len(value) > 64:
        return False
    if DATE_ONLY_RE.fullmatch(value):
        try:
            datetime.strptime(value, "%Y-%m-%d")
        except ValueError:
            return False
        return True
    cleaned = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(cleaned)
    except ValueError:
        return False
    return parsed.tzinfo is not None


def _container_within_limits(value: Any, depth: int = 0) -> bool:
    if depth > MAX_NESTING_DEPTH:
        return False
    if isinstance(value, dict):
        if len(value) > MAX_CONTAINER_ITEMS:
            return False
        return all(
            isinstance(key, str)
            and len(key) <= MAX_METADATA_STRING_CHARS
            and _container_within_limits(item, depth + 1)
            for key, item in value.items()
        )
    if isinstance(value, list):
        if len(value) > MAX_CONTAINER_ITEMS:
            return False
        return all(_container_within_limits(item, depth + 1) for item in value)
    if isinstance(value, str):
        return len(value) <= MAX_TEXT_CHARS
    return value is None or isinstance(value, (bool, int, float))


def _contains_ip(text: str) -> bool:
    for match in IPV4_RE.finditer(text):
        try:
            ipaddress.ip_address(match.group(0))
        except ValueError:
            continue
        return True
    for match in IPV6_CANDIDATE_RE.finditer(text):
        candidate = match.group(0)
        if ":" not in candidate:
            continue
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            continue
        return True
    return False


def _contains_long_identifier(text: str) -> bool:
    for match in LONG_TOKEN_RE.finditer(text):
        token = match.group(0)
        if len(token) >= 32:
            return True
        if any(character.isdigit() for character in token) and any(
            character.isalpha() for character in token
        ):
            return True
        if "_" in token or "-" in token:
            return True
    return False


def _scan_blockers(text: str) -> set[str]:
    findings: set[str] = set()
    if UUID_RE.search(text):
        findings.add("raw_uuid")
    if EMAIL_RE.search(text):
        findings.add("raw_email")
    if URL_RE.search(text):
        findings.add("raw_url")
    if _contains_ip(text):
        findings.add("raw_ip")
    if WINDOWS_PATH_RE.search(text) or UNIX_PATH_RE.search(text):
        findings.add("raw_path")
    if _contains_long_identifier(text):
        findings.add("raw_long_identifier")
    if any(pattern.search(text) for pattern in SECRET_PATTERNS):
        findings.add("raw_secret")
    return findings


def _scan_warnings(text: str) -> set[str]:
    findings: set[str] = set()
    if any(pattern.search(text) for pattern in TRANSCRIPT_ENVELOPE_PATTERNS):
        findings.add("transcript_envelope")
    if UNSCHEMED_DOMAIN_RE.search(text):
        findings.add("unschemed_domain")
    if FILENAME_RE.search(text):
        findings.add("filename_reference")
    if any(pattern.search(text) for pattern in COMMERCIAL_AMOUNT_PATTERNS):
        findings.add("commercial_amount")
    if CONTEXT_RE.search(text):
        findings.add("project_client_contract_confidential_context")
    return findings


def _metadata_strings(record: dict[str, Any]) -> Iterable[str]:
    """Yield bounded metadata strings, excluding text and expected source hashes."""

    stack: list[tuple[Any, int, str | None]] = [(record, 0, None)]
    while stack:
        value, depth, key = stack.pop()
        if depth > MAX_NESTING_DEPTH:
            continue
        if isinstance(value, dict):
            for child_key, child in value.items():
                if child_key == "text" or child_key == "sha256":
                    continue
                if (
                    child_key == "session_id"
                    and isinstance(child, str)
                    and SESSION_ID_RE.fullmatch(child)
                ):
                    continue
                if (
                    child_key == "message_id"
                    and isinstance(child, str)
                    and MESSAGE_ID_RE.fullmatch(child)
                ):
                    continue
                if (
                    child_key == "id"
                    and isinstance(child, str)
                    and SOURCE_ID_RE.fullmatch(child)
                ):
                    continue
                stack.append((child, depth + 1, child_key))
        elif isinstance(value, list):
            for child in value[:MAX_CONTAINER_ITEMS]:
                stack.append((child, depth + 1, key))
        elif isinstance(value, str) and len(value) <= MAX_METADATA_STRING_CHARS:
            yield value


def _validate_record(record: dict[str, Any], mode: str) -> tuple[set[str], set[str], str | None]:
    blockers: set[str] = set()
    warnings: set[str] = set()

    fields = set(record)
    if fields != TOP_LEVEL_FIELDS:
        if fields - TOP_LEVEL_FIELDS:
            blockers.add("unexpected_field")
        if TOP_LEVEL_FIELDS - fields:
            blockers.add("missing_field")

    if record.get("schema_version") != NORMALIZED_SCHEMA_VERSION:
        blockers.add("unexpected_schema_version")

    session_id = record.get("session_id")
    if not isinstance(session_id, str) or not SESSION_ID_RE.fullmatch(session_id):
        blockers.add("invalid_session_id")

    message_id = record.get("message_id")
    if not isinstance(message_id, str) or not MESSAGE_ID_RE.fullmatch(message_id):
        blockers.add("invalid_message_id")

    role = record.get("role")
    normalized_role = role if isinstance(role, str) else None
    if normalized_role not in ALLOWED_ROLES:
        blockers.add("unexpected_role")
    elif mode == "external-review" and normalized_role != "user":
        blockers.add("non_user_review_content")

    created_at = record.get("created_at")
    if created_at is not None and (
        not isinstance(created_at, str) or not _is_normalized_timestamp(created_at)
    ):
        blockers.add("invalid_created_at")

    redaction_count = record.get("redaction_count")
    if (
        isinstance(redaction_count, bool)
        or not isinstance(redaction_count, int)
        or redaction_count < 0
        or redaction_count > 1_000_000
    ):
        blockers.add("invalid_redaction_count")

    source = record.get("source")
    if not isinstance(source, dict):
        blockers.add("invalid_source")
    else:
        source_fields = set(source)
        if source_fields - SOURCE_FIELDS:
            blockers.add("unexpected_source_field")
        if REQUIRED_SOURCE_FIELDS - source_fields:
            blockers.add("missing_source_field")
        source_hash = source.get("sha256")
        if not isinstance(source_hash, str) or not SHA256_RE.fullmatch(source_hash):
            blockers.add("invalid_source_hash")
        source_id = source.get("id")
        if not isinstance(source_id, str) or not SOURCE_ID_RE.fullmatch(source_id):
            blockers.add("invalid_source_id")
        if "name" in source:
            blockers.add("source_name_present")
        source_name = source.get("name")
        if source_name is not None and not isinstance(source_name, str):
            blockers.add("invalid_source_name")
        elif isinstance(source_name, str) and len(source_name) > MAX_METADATA_STRING_CHARS:
            blockers.add("metadata_string_too_long")

    text = record.get("text")
    if not isinstance(text, str):
        blockers.add("invalid_text")
    elif len(text) > MAX_TEXT_CHARS:
        blockers.add("text_too_long")
    else:
        blockers.update(_scan_blockers(text))
        warnings.update(_scan_warnings(text))

    for metadata in _metadata_strings(record):
        if WINDOWS_PATH_RE.search(metadata) or UNIX_PATH_RE.search(metadata):
            blockers.add("absolute_path_metadata")
        blockers.update(_scan_blockers(metadata))

    return blockers, warnings, normalized_role


def _base_report(mode: str) -> dict[str, Any]:
    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "mode": mode,
        "status": "pass",
        "decision": "pass",
        "records_scanned": 0,
        "roles": {"user": 0, "assistant": 0, "other": 0},
        "blocker_count": 0,
        "warning_count": 0,
        "blockers": [],
        "warnings": [],
        "categories": {},
        "records": [],
    }


def _finalize_report(
    report: dict[str, Any], blockers: Counter[str], warnings: Counter[str]
) -> dict[str, Any]:
    report["blockers"] = [
        {"code": code, "records": blockers[code]} for code in sorted(blockers)
    ]
    report["warnings"] = [
        {"code": code, "records": warnings[code]} for code in sorted(warnings)
    ]
    report["blocker_count"] = sum(blockers.values())
    report["warning_count"] = sum(warnings.values())
    report["categories"] = {
        code: count
        for code, count in sorted((blockers + warnings).items())
    }
    should_block = bool(blockers) or (
        report["mode"] == "external-review" and bool(warnings)
    )
    if should_block:
        report["status"] = "blocked"
        report["decision"] = "block"
    elif warnings:
        report["status"] = "pass"
        report["decision"] = "warn"
    else:
        report["status"] = "pass"
        report["decision"] = "pass"
    return report


def scan_path(path: Path, mode: str) -> dict[str, Any]:
    """Return an aggregate privacy report for one normalized JSONL file."""

    if mode not in {"local", "external-review"}:
        raise GuardInputError("invalid mode")
    if path.is_symlink():
        raise GuardInputError("symbolic link input")
    try:
        metadata = path.stat()
    except OSError as exc:
        raise GuardInputError("input unavailable") from exc
    if not stat.S_ISREG(metadata.st_mode):
        raise GuardInputError("input is not a regular file")

    report = _base_report(mode)
    blockers: Counter[str] = Counter()
    warnings: Counter[str] = Counter()

    if metadata.st_size > MAX_INPUT_BYTES:
        blockers["input_too_large"] += 1
        return _finalize_report(report, blockers, warnings)

    line_number = 0
    try:
        with path.open("rb") as handle:
            while True:
                raw_line = handle.readline(MAX_LINE_BYTES + 1)
                if not raw_line:
                    break
                line_number += 1
                if len(raw_line) > MAX_LINE_BYTES:
                    blockers["line_too_large"] += 1
                    break
                if not raw_line.strip():
                    continue
                if report["records_scanned"] >= MAX_RECORDS:
                    blockers["record_limit_exceeded"] += 1
                    break
                try:
                    encoding = "utf-8-sig" if line_number == 1 else "utf-8"
                    line = raw_line.decode(encoding)
                except UnicodeDecodeError:
                    blockers["invalid_utf8"] += 1
                    continue
                try:
                    record = json.loads(
                        line,
                        object_pairs_hook=_strict_object,
                        parse_constant=_reject_constant,
                    )
                except (json.JSONDecodeError, DuplicateKeyError, ValueError, RecursionError):
                    blockers["invalid_json"] += 1
                    continue
                if not isinstance(record, dict):
                    blockers["non_object_record"] += 1
                    continue
                report["records_scanned"] += 1
                if not _container_within_limits(record):
                    blockers["schema_limits_exceeded"] += 1
                    continue

                record_blockers, record_warnings, role = _validate_record(record, mode)
                blockers.update(record_blockers)
                warnings.update(record_warnings)
                if role in ALLOWED_ROLES:
                    report["roles"][role] += 1
                else:
                    report["roles"]["other"] += 1
    except OSError as exc:
        raise GuardInputError("input read failed") from exc

    if report["records_scanned"] == 0 and not blockers:
        blockers["empty_input"] += 1
    return _finalize_report(report, blockers, warnings)


def scan_records(path: Path, mode: str) -> dict[str, Any]:
    """Compatibility entry point used by the deterministic workflow runner."""

    return scan_path(Path(path), mode)


def atomic_write_report(path: Path, report: dict[str, Any], overwrite: bool) -> None:
    """Atomically write a private aggregate JSON report."""

    if path.is_symlink():
        raise GuardOutputError("symbolic link output")
    if path.exists() and not overwrite:
        raise GuardOutputError("output exists")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise GuardOutputError("output directory unavailable") from exc

    temp_name = ""
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            delete=False,
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
        ) as handle:
            temp_name = handle.name
            json.dump(report, handle, ensure_ascii=False, sort_keys=True, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, path)
        try:
            path.chmod(0o600)
        except OSError:
            pass
    except OSError as exc:
        raise GuardOutputError("report write failed") from exc
    finally:
        if temp_name and os.path.exists(temp_name):
            try:
                os.unlink(temp_name)
            except OSError:
                pass


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="Normalized JSONL to inspect")
    parser.add_argument("--mode", required=True, choices=("local", "external-review"))
    parser.add_argument("--output", required=True, type=Path, help="Aggregate JSON report")
    parser.add_argument("--overwrite", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        input_path = args.input.expanduser().resolve()
        output_path = args.output.expanduser().resolve()
        if input_path == output_path:
            raise GuardOutputError("input and output must differ")
        report = scan_path(input_path, args.mode)
        atomic_write_report(output_path, report, args.overwrite)
    except GuardInputError:
        print("error: privacy guard input rejected", file=sys.stderr)
        return 2
    except GuardOutputError:
        print("error: privacy guard report was not written", file=sys.stderr)
        return 2
    except OSError:
        print("error: privacy guard operation failed", file=sys.stderr)
        return 2

    print(
        json.dumps(
            {
                "decision": report["decision"],
                "blocker_count": report["blocker_count"],
                "warning_count": report["warning_count"],
            },
            sort_keys=True,
        )
    )
    return 1 if report["status"] == "blocked" else 0


if __name__ == "__main__":
    raise SystemExit(main())
