#!/usr/bin/env python3
"""Normalize authorized chat exports into privacy-filtered JSONL.

The script performs no network access and never extracts ZIP members to disk.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator


SCHEMA_VERSION = "1.0"
VERSION = "0.2.3"
DEFAULT_MAX_MEMBER_BYTES = 128 * 1024 * 1024
DEFAULT_MAX_TOTAL_BYTES = 256 * 1024 * 1024
MAX_COMPRESSION_RATIO = 200
MAX_SOURCE_FILES = 1_000
MAX_ARCHIVE_MEMBERS = 10_000
ALLOWED_ROLES = {"user", "assistant"}

SECRET_PATTERNS = (
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----", re.S),
    re.compile(r"\b(?:sk|rk|pk)-[A-Za-z0-9_-]{16,}\b"),
    re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{12,}"),
    re.compile(r"(?i)\b(?:password|passwd|api[_ -]?key|access[_ -]?token|secret)\s*[:=]\s*[^\s,;]{6,}"),
)

HIGH_PRIVACY_PATTERNS = (
    (
        "[REDACTED_EMAIL]",
        re.compile(r"(?<![\w.+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?![\w.-])"),
    ),
    ("[REDACTED_PHONE]", re.compile(r"(?<!\d)(?:\+?\d[\d ()-]{7,}\d)(?!\d)")),
    (
        "[REDACTED_IP]",
        re.compile(r"(?<!\d)(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?!\d)"),
    ),
    (
        "[REDACTED_UUID]",
        re.compile(r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b"),
    ),
    ("[REDACTED_URL]", re.compile(r"(?i)\b(?:https?|file|plugin|app)://[^\s<>\"']+")),
    (
        "[REDACTED_PATH]",
        re.compile(r"(?i)(?:[A-Z]:[\\/]|\\\\)[^\s<>\"']+|(?<!\w)/(?:Users|home|tmp|var|etc|mnt|opt)/[^\s<>\"']+"),
    ),
    ("[REDACTED_LONG_ID]", re.compile(r"(?i)\b[0-9a-f]{24,}\b")),
    (
        "[REDACTED_FILENAME]",
        re.compile(r"(?i)(?<![\w.-])[\w][\w .()\[\]-]{0,79}\.(?:pdf|docx?|xlsx?|pptx?|csv|tsv|zip|png|jpe?g|gif|webp)(?![\w.-])"),
    ),
    (
        "[REDACTED_DOMAIN]",
        re.compile(
            r"(?i)(?<![@\w.\u3002\uff0e\uff61-])"
            r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?[.\u3002\uff0e\uff61])+"
            r"(?:[a-z]{2,63}|xn--[a-z0-9-]{2,59})"
            r"(?![\w-]|[.\u3002\uff0e\uff61][\w])"
        ),
    ),
    (
        "[REDACTED_AMOUNT]",
        re.compile(
            r"(?i)(?:[$€£¥]\s?\d[\d,]*(?:\.\d{1,2})?|"
            r"\b(?:USD|EUR|GBP|JPY|TWD|CNY)\s?\d[\d,]*(?:\.\d{1,2})?|"
            r"\b\d[\d,]*(?:\.\d{1,2})?\s?(?:USD|EUR|GBP|JPY|TWD|CNY|元|日圓|美元|台幣)\b)"
        ),
    ),
)


class NormalizationError(ValueError):
    """Raised when an input is unsafe or unsupported."""


class DuplicateKeyError(ValueError):
    """Raised for ambiguous JSON objects."""


def strict_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateKeyError("duplicate JSON key")
        result[key] = value
    return result


def reject_json_constant(_value: str) -> None:
    raise ValueError("non-finite JSON number")


def strict_json_loads(value: str) -> Any:
    return json.loads(
        value,
        object_pairs_hook=strict_json_object,
        parse_constant=reject_json_constant,
    )


def is_reparse_point(path: Path) -> bool:
    try:
        attributes = getattr(path.lstat(), "st_file_attributes", 0)
    except OSError:
        return False
    return bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def stable_id(prefix: str, *parts: object) -> str:
    material = "\x1f".join(str(part) for part in parts).encode("utf-8", errors="replace")
    return f"{prefix}-{hashlib.sha256(material).hexdigest()[:20]}"


def safe_external_id(value: Any, prefix: str, *fallback_parts: object) -> str:
    # Syntactically safe identifiers may still disclose customer or project
    # metadata. Preserve stable provenance without retaining the external value.
    return stable_id(prefix, *fallback_parts, value)


def redact_text(text: str, privacy: str) -> tuple[str, int]:
    count = 0
    for pattern in SECRET_PATTERNS:
        text, replacements = pattern.subn("[REDACTED_SECRET]", text)
        count += replacements
    if privacy == "high":
        for label, pattern in HIGH_PRIVACY_PATTERNS:
            text, replacements = pattern.subn(label, text)
            count += replacements
    return text, count


def to_iso8601(value: Any) -> str | None:
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(value, tz=timezone.utc).isoformat().replace("+00:00", "Z")
        except (OverflowError, OSError, ValueError):
            return None
    if isinstance(value, str):
        cleaned = value.strip()
        if not cleaned:
            return None
        return cleaned
    return None


def privacy_timestamp(value: Any, privacy: str) -> str | None:
    timestamp = to_iso8601(value)
    if privacy != "high" or timestamp is None:
        return timestamp
    match = re.match(r"^(\d{4}-\d{2}-\d{2})", timestamp)
    return match.group(1) if match else None


def content_to_text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for item in content:
            if isinstance(item, str):
                parts.append(item)
            elif isinstance(item, dict):
                text = item.get("text")
                if isinstance(text, str):
                    parts.append(text)
                elif isinstance(item.get("content"), str):
                    parts.append(item["content"])
        return "\n".join(part for part in parts if part)
    if isinstance(content, dict):
        if isinstance(content.get("text"), str):
            return content["text"]
        if "parts" in content:
            return content_to_text(content["parts"])
        if isinstance(content.get("content"), str):
            return content["content"]
    return ""


def normalize_record(
    *,
    session_id: str,
    message_id: str,
    role: str,
    created_at: Any,
    text: str,
    source_name: str,
    source_sha256: str,
    privacy: str,
) -> dict[str, Any] | None:
    role = role.lower().strip()
    if role not in ALLOWED_ROLES:
        return None
    text = text.replace("\x00", "").strip()
    if not text:
        return None
    redacted, redaction_count = redact_text(text, privacy)
    return {
        "schema_version": SCHEMA_VERSION,
        "session_id": session_id,
        "message_id": message_id,
        "role": role,
        "created_at": privacy_timestamp(created_at, privacy),
        "text": redacted,
        "redaction_count": redaction_count,
        "source": {
            "id": stable_id("source", source_sha256),
            "sha256": source_sha256,
        },
    }


def active_chatgpt_nodes(conversation: dict[str, Any]) -> list[dict[str, Any]]:
    mapping = conversation.get("mapping")
    if not isinstance(mapping, dict):
        raise NormalizationError("ChatGPT conversation is missing a mapping object")
    current = conversation.get("current_node")
    if not isinstance(current, str) or current not in mapping:
        raise NormalizationError("ChatGPT conversation is missing a valid current_node")
    chain: list[dict[str, Any]] = []
    visited: set[str] = set()
    while isinstance(current, str):
        if current in visited:
            raise NormalizationError("ChatGPT active branch contains a cycle")
        if current not in mapping:
            raise NormalizationError("ChatGPT active branch references a missing parent")
        visited.add(current)
        node = mapping[current]
        if not isinstance(node, dict):
            raise NormalizationError("ChatGPT active branch contains an invalid node")
        chain.append(node)
        parent = node.get("parent")
        if parent is None:
            break
        if not isinstance(parent, str):
            raise NormalizationError("ChatGPT active branch contains an invalid parent")
        current = parent
    chain.reverse()
    return chain


def parse_chatgpt_conversations(
    conversations: Iterable[Any], source_name: str, source_sha256: str, privacy: str
) -> Iterator[dict[str, Any]]:
    for conversation_index, conversation in enumerate(conversations):
        if not isinstance(conversation, dict):
            continue
        original_session_id = conversation.get("id") or conversation.get("conversation_id")
        session_id = safe_external_id(
            original_session_id, "session", source_sha256, conversation_index
        )
        for message_index, node in enumerate(active_chatgpt_nodes(conversation)):
            message = node.get("message")
            if not isinstance(message, dict):
                continue
            author = message.get("author") or {}
            role = author.get("role") if isinstance(author, dict) else None
            if not isinstance(role, str):
                continue
            text = content_to_text(message.get("content"))
            original_message_id = message.get("id") or node.get("id")
            message_id = safe_external_id(
                original_message_id, "message", session_id, message_index, text
            )
            record = normalize_record(
                session_id=session_id,
                message_id=message_id,
                role=role,
                created_at=message.get("create_time"),
                text=text,
                source_name=source_name,
                source_sha256=source_sha256,
                privacy=privacy,
            )
            if record:
                yield record


def parse_message_list(
    messages: Iterable[Any],
    source_name: str,
    source_sha256: str,
    privacy: str,
    session_hint: str | None = None,
) -> Iterator[dict[str, Any]]:
    session_id = safe_external_id(session_hint, "session", source_sha256)
    for index, item in enumerate(messages):
        if not isinstance(item, dict):
            continue
        role = item.get("role")
        if not isinstance(role, str):
            author = item.get("author") or {}
            role = author.get("role") if isinstance(author, dict) else None
        if not isinstance(role, str):
            continue
        text = content_to_text(item.get("content", item.get("text", "")))
        message_id = safe_external_id(item.get("id"), "message", session_id, index, text)
        external_session_id = item.get("session_id")
        item_session_id = (
            session_id
            if external_session_id in (None, "")
            else safe_external_id(external_session_id, "session", source_sha256)
        )
        record = normalize_record(
            session_id=item_session_id,
            message_id=message_id,
            role=role,
            created_at=item.get("created_at", item.get("create_time", item.get("timestamp"))),
            text=text,
            source_name=source_name,
            source_sha256=source_sha256,
            privacy=privacy,
        )
        if record:
            yield record


def parse_json_document(
    document: Any, source_name: str, source_sha256: str, privacy: str
) -> Iterator[dict[str, Any]]:
    if isinstance(document, list):
        if document and isinstance(document[0], dict) and "mapping" in document[0]:
            yield from parse_chatgpt_conversations(document, source_name, source_sha256, privacy)
        else:
            yield from parse_message_list(document, source_name, source_sha256, privacy)
        return
    if not isinstance(document, dict):
        raise NormalizationError(f"Unsupported JSON root in {source_name}")
    if isinstance(document.get("conversations"), list):
        yield from parse_chatgpt_conversations(
            document["conversations"], source_name, source_sha256, privacy
        )
    elif isinstance(document.get("messages"), list):
        yield from parse_message_list(
            document["messages"], source_name, source_sha256, privacy,
            str(document.get("id") or document.get("session_id") or "") or None,
        )
    elif isinstance(document.get("role"), str):
        yield from parse_message_list([document], source_name, source_sha256, privacy)
    else:
        raise NormalizationError(f"Unsupported JSON structure in {source_name}")


def parse_codex_jsonl(data: bytes, source_name: str, source_sha256: str, privacy: str) -> Iterator[dict[str, Any]]:
    current_session = stable_id("session", source_sha256)
    message_index = 0
    for line_number, raw_line in enumerate(data.decode("utf-8-sig").splitlines(), start=1):
        if not raw_line.strip():
            continue
        try:
            event = strict_json_loads(raw_line)
        except (json.JSONDecodeError, DuplicateKeyError, ValueError, RecursionError) as exc:
            raise NormalizationError(f"Invalid or ambiguous JSONL at {source_name}:{line_number}") from exc
        if not isinstance(event, dict):
            continue
        if event.get("type") == "session_meta":
            payload = event.get("payload") or {}
            if isinstance(payload, dict) and payload.get("id"):
                current_session = safe_external_id(payload["id"], "session", source_sha256, line_number)
            continue
        payload = event.get("payload") if isinstance(event.get("payload"), dict) else event
        if not isinstance(payload, dict):
            continue
        if payload.get("type") not in (None, "message") and "role" not in payload:
            continue
        role = payload.get("role")
        if not isinstance(role, str):
            continue
        text = content_to_text(payload.get("content", payload.get("text", "")))
        message_id = safe_external_id(payload.get("id"), "message", current_session, message_index, text)
        external_session_id = payload.get("session_id")
        record_session_id = (
            current_session
            if external_session_id in (None, "")
            else safe_external_id(external_session_id, "session", source_sha256)
        )
        record = normalize_record(
            session_id=record_session_id,
            message_id=message_id,
            role=role,
            created_at=payload.get("created_at", event.get("timestamp")),
            text=text,
            source_name=source_name,
            source_sha256=source_sha256,
            privacy=privacy,
        )
        message_index += 1
        if record:
            yield record


def read_bounded(path: Path, limit: int) -> bytes:
    if path.is_symlink() or is_reparse_point(path):
        raise NormalizationError(f"Refusing linked or reparse-point input: {path}")
    size = path.stat().st_size
    if size > limit:
        raise NormalizationError(f"Input exceeds {limit} bytes: {path.name}")
    data = path.read_bytes()
    if len(data) > limit:
        raise NormalizationError(f"Input exceeds {limit} bytes: {path.name}")
    return data


def parse_file(path: Path, privacy: str, max_member: int, max_total: int) -> Iterator[dict[str, Any]]:
    suffix = path.suffix.lower()
    if suffix == ".zip":
        yield from parse_zip(path, privacy, max_member, max_total)
        return
    data = read_bounded(path, max_total)
    source_sha256 = sha256_bytes(data)
    if suffix == ".jsonl":
        yield from parse_codex_jsonl(data, path.name, source_sha256, privacy)
    elif suffix == ".json":
        try:
            document = strict_json_loads(data.decode("utf-8-sig"))
        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
            DuplicateKeyError,
            ValueError,
            RecursionError,
        ) as exc:
            raise NormalizationError(f"Invalid or ambiguous JSON in {path.name}") from exc
        yield from parse_json_document(document, path.name, source_sha256, privacy)
    else:
        raise NormalizationError(f"Unsupported input type: {path.name}")


def safe_zip_member(info: zipfile.ZipInfo, max_member: int) -> bool:
    member_path = Path(info.filename.replace("\\", "/"))
    if member_path.is_absolute() or ".." in member_path.parts:
        raise NormalizationError(f"Unsafe ZIP member path: {info.filename}")
    unix_mode = (info.external_attr >> 16) & 0xFFFF
    if unix_mode and stat.S_ISLNK(unix_mode):
        raise NormalizationError(f"Refusing ZIP symbolic link: {info.filename}")
    if info.flag_bits & 0x1:
        raise NormalizationError(f"Encrypted ZIP members are unsupported: {info.filename}")
    if info.file_size > max_member:
        raise NormalizationError(f"ZIP member exceeds size limit: {info.filename}")
    if info.compress_size and info.file_size > 10 * 1024 * 1024:
        if info.file_size / info.compress_size > MAX_COMPRESSION_RATIO:
            raise NormalizationError(f"Suspicious ZIP compression ratio: {info.filename}")
    name = member_path.name.lower()
    return name.startswith("conversations") and name.endswith(".json")


def parse_zip(path: Path, privacy: str, max_member: int, max_total: int) -> Iterator[dict[str, Any]]:
    if path.is_symlink() or is_reparse_point(path):
        raise NormalizationError(f"Refusing linked or reparse-point input: {path}")
    selected: list[zipfile.ZipInfo] = []
    total = 0
    try:
        with zipfile.ZipFile(path) as archive:
            members = archive.infolist()
            if len(members) > MAX_ARCHIVE_MEMBERS:
                raise NormalizationError(f"ZIP exceeds {MAX_ARCHIVE_MEMBERS} members")
            selected_names: set[str] = set()
            for info in members:
                if info.is_dir():
                    continue
                if safe_zip_member(info, max_member):
                    normalized_name = info.filename.replace("\\", "/").casefold()
                    if normalized_name in selected_names:
                        raise NormalizationError(f"Duplicate selected ZIP member: {info.filename}")
                    selected_names.add(normalized_name)
                    total += info.file_size
                    if total > max_total:
                        raise NormalizationError("Selected ZIP data exceeds the total size limit")
                    selected.append(info)
            if not selected:
                raise NormalizationError("No conversations*.json file found in ZIP")
            for info in selected:
                with archive.open(info) as member:
                    data = member.read(max_member + 1)
                if len(data) > max_member:
                    raise NormalizationError(f"ZIP member exceeds size limit: {info.filename}")
                source_name = Path(info.filename).name
                source_sha256 = sha256_bytes(data)
                try:
                    document = strict_json_loads(data.decode("utf-8-sig"))
                except (
                    UnicodeDecodeError,
                    json.JSONDecodeError,
                    DuplicateKeyError,
                    ValueError,
                    RecursionError,
                ) as exc:
                    raise NormalizationError(f"Invalid or ambiguous JSON in {source_name}") from exc
                yield from parse_json_document(document, source_name, source_sha256, privacy)
    except zipfile.BadZipFile as exc:
        raise NormalizationError(f"Invalid ZIP archive: {path.name}") from exc


def iter_inputs(input_path: Path, max_total: int) -> list[Path]:
    if input_path.is_symlink() or is_reparse_point(input_path):
        raise NormalizationError(f"Refusing linked or reparse-point input: {input_path}")
    if input_path.is_file():
        return [input_path]
    if not input_path.is_dir():
        raise NormalizationError(f"Input does not exist: {input_path}")
    files: list[Path] = []
    total = 0
    for path in input_path.rglob("*"):
        if path.is_symlink() or is_reparse_point(path):
            raise NormalizationError(f"Refusing linked or reparse-point source: {path}")
        if not path.is_file() or path.suffix.lower() not in {".zip", ".json", ".jsonl"}:
            continue
        files.append(path)
        if len(files) > MAX_SOURCE_FILES:
            raise NormalizationError(f"Input exceeds {MAX_SOURCE_FILES} source files")
        total += path.stat().st_size
        if total > max_total:
            raise NormalizationError("Directory inputs exceed the cumulative size limit")
    if not files:
        raise NormalizationError("No supported input files found")
    return sorted(files)


def atomic_write_jsonl(output: Path, records: Iterable[dict[str, Any]], overwrite: bool) -> tuple[int, int]:
    if output.exists() and not overwrite:
        raise NormalizationError(f"Output exists; pass --overwrite to replace it: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    redactions = 0
    temp_name = ""
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", newline="\n", delete=False, dir=output.parent,
            prefix=f".{output.name}.", suffix=".tmp"
        ) as handle:
            temp_name = handle.name
            for record in records:
                handle.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")
                count += 1
                redactions += int(record.get("redaction_count", 0))
            handle.flush()
            os.fsync(handle.fileno())
        if count == 0:
            raise NormalizationError("No user or assistant messages were found")
        os.replace(temp_name, output)
        try:
            output.chmod(0o600)
        except OSError:
            pass
        return count, redactions
    finally:
        if temp_name and os.path.exists(temp_name):
            try:
                os.unlink(temp_name)
            except OSError:
                pass


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="Authorized ZIP, JSON, JSONL, or directory")
    parser.add_argument("--output", type=Path, required=True, help="Private normalized JSONL path")
    parser.add_argument("--privacy", choices=("standard", "high"), default="high")
    parser.add_argument("--overwrite", action="store_true")
    parser.add_argument("--max-member-mb", type=int, default=128)
    parser.add_argument("--max-total-mb", type=int, default=256)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        max_total = args.max_total_mb * 1024 * 1024
        inputs = iter_inputs(args.input.expanduser().absolute(), max_total)

        def all_records() -> Iterator[dict[str, Any]]:
            for path in inputs:
                yield from parse_file(
                    path,
                    args.privacy,
                    args.max_member_mb * 1024 * 1024,
                    max_total,
                )

        count, redactions = atomic_write_jsonl(args.output.resolve(), all_records(), args.overwrite)
    except (OSError, NormalizationError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({"messages": count, "redactions": redactions, "output": str(args.output)}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
