#!/usr/bin/env python3
"""Initialize, validate, review, forget, and compile a user preference profile."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "1.1"
VERSION = "0.2.1"
MAX_PROFILE_BYTES = 32 * 1024 * 1024
MAX_EVIDENCE_BYTES = 256 * 1024 * 1024
MAX_PREFERENCES = 5_000
ID_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,127}$")
SOURCE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,199}$")
CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

ALLOWED_CATEGORIES = {
    "response_style", "format", "language", "collaboration", "tooling", "research",
    "coding", "writing", "decision_making", "accessibility", "project", "other",
}
ALLOWED_SCOPE_TYPES = {"global", "task", "project", "temporary"}
ALLOWED_STATUSES = {"candidate", "approved", "rejected", "superseded"}
ALLOWED_SENSITIVITY = {"normal", "sensitive", "prohibited"}
ALLOWED_EVIDENCE_KINDS = {"explicit_preference", "correction", "approval", "repeated_request"}
PROFILE_KEYS = {"schema_version", "updated_at", "preferences"}
PREFERENCE_KEYS = {
    "id", "rule", "category", "scope", "confidence", "status", "sensitivity",
    "first_observed", "last_observed", "evidence", "supersedes", "expires_at", "approval",
}
EVIDENCE_REF_KEYS = {"session_id", "message_id", "kind"}
APPROVAL_KEYS = {"authorization_id", "candidate_digest", "approved_at"}


class ProfileError(ValueError):
    """Raised when profile data fails validation."""


def now_utc() -> str:
    return datetime.now(tz=timezone.utc).isoformat().replace("+00:00", "Z")


def empty_profile() -> dict[str, Any]:
    return {"schema_version": SCHEMA_VERSION, "updated_at": now_utc(), "preferences": []}


def candidate_digest(item: dict[str, Any]) -> str:
    approval_subject = {
        key: item.get(key)
        for key in (
            "id", "rule", "category", "scope", "confidence", "sensitivity",
            "first_observed", "last_observed", "evidence", "supersedes", "expires_at",
        )
    }
    encoded = json.dumps(
        approval_subject, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def load_profile(path: Path) -> dict[str, Any]:
    if path.is_symlink():
        raise ProfileError(f"Refusing symbolic link profile: {path}")
    if not path.is_file():
        raise ProfileError(f"Profile does not exist: {path}")
    if path.stat().st_size > MAX_PROFILE_BYTES:
        raise ProfileError("Profile exceeds size limit")
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ProfileError(f"Invalid profile JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ProfileError("Profile root must be an object")
    return data


def load_evidence(path: Path) -> list[dict[str, Any]]:
    if path.is_symlink():
        raise ProfileError(f"Refusing symbolic link evidence: {path}")
    if not path.is_file():
        raise ProfileError(f"Evidence does not exist: {path}")
    if path.stat().st_size > MAX_EVIDENCE_BYTES:
        raise ProfileError("Evidence exceeds size limit")
    rows: list[dict[str, Any]] = []
    try:
        with path.open("r", encoding="utf-8-sig") as handle:
            for line_number, line in enumerate(handle, start=1):
                if not line.strip():
                    continue
                row = json.loads(line)
                if not isinstance(row, dict):
                    raise ProfileError(f"Evidence line {line_number} must be an object")
                rows.append(row)
    except json.JSONDecodeError as exc:
        raise ProfileError(f"Invalid evidence JSON at line {exc.lineno}: {exc.msg}") from exc
    return rows


def strongest_evidence_kind(kinds: Any) -> str:
    if not isinstance(kinds, list):
        raise ProfileError("Selected evidence is missing kinds")
    for kind in ("correction", "explicit_preference", "approval", "repeated_request"):
        if kind in kinds:
            return kind
    raise ProfileError("Selected evidence has no supported kind")


def add_candidate_from_evidence(
    profile: dict[str, Any],
    evidence_rows: list[dict[str, Any]],
    *,
    identifier: str,
    rule: str,
    category: str,
    scope_type: str,
    scope_value: str | None,
    confidence: float,
    sensitivity: str,
    message_ids: list[str],
    supersedes: list[str] | None = None,
) -> dict[str, Any]:
    existing_errors = validate_profile(profile)
    if existing_errors:
        raise ProfileError("Profile validation failed:\n- " + "\n- ".join(existing_errors))
    if not message_ids:
        raise ProfileError("Select at least one evidence message ID")

    selected: list[dict[str, Any]] = []
    for message_id in dict.fromkeys(message_ids):
        matches = [row for row in evidence_rows if row.get("message_id") == message_id]
        if len(matches) != 1:
            raise ProfileError(
                f"Expected exactly one evidence row with message ID {message_id!r}"
            )
        selected.append(matches[0])

    evidence_refs: list[dict[str, str]] = []
    observed: list[str] = []
    for row in selected:
        if row.get("review_status") != "accepted":
            raise ProfileError("Selected evidence must be explicitly accepted before candidate creation")
        provenance = row.get("provenance")
        if not isinstance(provenance, dict) or provenance.get("role") != "user" or provenance.get("direct") is not True:
            raise ProfileError("Selected evidence must have direct user provenance")
        if row.get("truncated") is True:
            raise ProfileError("Truncated evidence requires a new complete review artifact")
        session_id = row.get("session_id")
        message_id = row.get("message_id")
        if not isinstance(session_id, str) or not SOURCE_ID_RE.fullmatch(session_id):
            raise ProfileError("Selected evidence has an invalid session ID")
        if not isinstance(message_id, str) or not SOURCE_ID_RE.fullmatch(message_id):
            raise ProfileError("Selected evidence has an invalid message ID")
        evidence_refs.append({
            "session_id": session_id,
            "message_id": message_id,
            "kind": strongest_evidence_kind(row.get("kinds")),
        })
        created_at = row.get("created_at")
        if isinstance(created_at, str) and created_at.strip():
            observed.append(created_at.strip())

    supersedes = list(dict.fromkeys(supersedes or []))
    for superseded_id in supersedes:
        matches = [item for item in profile["preferences"] if item.get("id") == superseded_id]
        if len(matches) != 1 or matches[0].get("status") != "approved":
            raise ProfileError("A candidate may supersede only an existing approved preference")

    timestamp = now_utc()
    candidate = {
        "id": identifier,
        "rule": rule,
        "category": category,
        "scope": {
            "type": scope_type,
            "value": None if scope_type == "global" else scope_value,
        },
        "confidence": confidence,
        "status": "candidate",
        "sensitivity": sensitivity,
        "first_observed": min(observed) if observed else timestamp,
        "last_observed": max(observed) if observed else timestamp,
        "evidence": evidence_refs,
        "supersedes": supersedes,
        "expires_at": None,
        "approval": None,
    }
    updated = deepcopy(profile)
    updated["preferences"].append(candidate)
    updated["updated_at"] = timestamp
    errors = validate_profile(updated)
    if errors:
        raise ProfileError("Candidate validation failed:\n- " + "\n- ".join(errors))
    return updated


def review_evidence_rows(
    rows: list[dict[str, Any]],
    *,
    message_ids: list[str],
    decision: str,
    authorization_id: str,
) -> list[dict[str, Any]]:
    if decision not in {"accepted", "rejected"}:
        raise ProfileError("Evidence decision must be accepted or rejected")
    if not SOURCE_ID_RE.fullmatch(authorization_id):
        raise ProfileError("Authorization ID is invalid")
    selected = set(message_ids)
    if not selected:
        raise ProfileError("Select at least one evidence message ID")
    found: set[str] = set()
    updated = deepcopy(rows)
    timestamp = now_utc()
    for row in updated:
        message_id = row.get("message_id")
        if message_id not in selected:
            continue
        if message_id in found:
            raise ProfileError(f"Duplicate evidence message ID: {message_id!r}")
        found.add(message_id)
        provenance = row.get("provenance")
        if not isinstance(provenance, dict) or provenance.get("role") != "user" or provenance.get("direct") is not True:
            raise ProfileError("Only direct user evidence can be reviewed")
        if decision == "accepted" and row.get("truncated") is True:
            raise ProfileError("Truncated evidence cannot be accepted")
        row["review_status"] = decision
        row["review"] = {
            "authorization_id": authorization_id,
            "decision": decision,
            "reviewed_at": timestamp,
        }
    missing = selected - found
    if missing:
        raise ProfileError(f"Evidence IDs were not found: {', '.join(sorted(missing))}")
    return updated


def approve_candidate(
    profile: dict[str, Any],
    *,
    identifier: str,
    authorization_id: str,
    expected_digest: str,
) -> dict[str, Any]:
    errors = validate_profile(profile)
    if errors:
        raise ProfileError("Profile validation failed:\n- " + "\n- ".join(errors))
    if not SOURCE_ID_RE.fullmatch(authorization_id):
        raise ProfileError("Authorization ID is invalid")
    updated = deepcopy(profile)
    item = find_preference(updated, identifier)
    if item["status"] != "candidate":
        raise ProfileError("Only candidate preferences can be approved")
    if item["sensitivity"] != "normal":
        raise ProfileError("Sensitive or prohibited preferences cannot use the standard approval command")
    actual_digest = candidate_digest(item)
    if expected_digest.lower() != actual_digest:
        raise ProfileError("Candidate digest does not match the reviewed candidate")
    item["status"] = "approved"
    item["approval"] = {
        "authorization_id": authorization_id,
        "candidate_digest": actual_digest,
        "approved_at": now_utc(),
    }
    for superseded_id in item["supersedes"]:
        superseded = find_preference(updated, superseded_id)
        if superseded["status"] != "approved":
            raise ProfileError("Superseded preferences must still be approved at approval time")
        superseded["status"] = "superseded"
    updated["updated_at"] = now_utc()
    errors = validate_profile(updated)
    if errors:
        raise ProfileError("Approved profile validation failed:\n- " + "\n- ".join(errors))
    return updated


def validate_profile(profile: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if set(profile) != PROFILE_KEYS:
        errors.append("profile contains missing or unknown fields")
    if profile.get("schema_version") != SCHEMA_VERSION:
        errors.append(f"schema_version must be {SCHEMA_VERSION!r}")
    preferences = profile.get("preferences")
    if not isinstance(preferences, list):
        return errors + ["preferences must be an array"]
    if len(preferences) > MAX_PREFERENCES:
        errors.append(f"preferences exceeds {MAX_PREFERENCES} records")
    seen_ids: set[str] = set()
    all_ids = {
        item.get("id") for item in preferences
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    }
    for index, item in enumerate(preferences):
        prefix = f"preferences[{index}]"
        if not isinstance(item, dict):
            errors.append(f"{prefix} must be an object")
            continue
        if set(item) != PREFERENCE_KEYS:
            errors.append(f"{prefix} contains missing or unknown fields")
        identifier = item.get("id")
        if not isinstance(identifier, str) or not ID_RE.fullmatch(identifier):
            errors.append(f"{prefix}.id is invalid")
        elif identifier in seen_ids:
            errors.append(f"{prefix}.id is duplicated: {identifier}")
        else:
            seen_ids.add(identifier)

        rule = item.get("rule")
        if not isinstance(rule, str) or not rule.strip() or len(rule) > 500:
            errors.append(f"{prefix}.rule must contain 1-500 characters")
        elif CONTROL_RE.search(rule):
            errors.append(f"{prefix}.rule contains control characters")

        if item.get("category") not in ALLOWED_CATEGORIES:
            errors.append(f"{prefix}.category is invalid")

        scope = item.get("scope")
        if not isinstance(scope, dict) or scope.get("type") not in ALLOWED_SCOPE_TYPES:
            errors.append(f"{prefix}.scope is invalid")
        elif scope.get("type") == "global" and scope.get("value") not in (None, ""):
            errors.append(f"{prefix}.scope.value must be null for global scope")
        elif scope.get("type") != "global" and not isinstance(scope.get("value"), str):
            errors.append(f"{prefix}.scope.value must be a string for scoped preferences")
        elif scope.get("type") != "global":
            scope_value = scope.get("value", "")
            if not scope_value.strip() or len(scope_value) > 200 or CONTROL_RE.search(scope_value):
                errors.append(f"{prefix}.scope.value is invalid")

        confidence = item.get("confidence")
        if isinstance(confidence, bool) or not isinstance(confidence, (int, float)) or not 0 <= confidence <= 1:
            errors.append(f"{prefix}.confidence must be between 0 and 1")

        status = item.get("status")
        sensitivity = item.get("sensitivity")
        if status not in ALLOWED_STATUSES:
            errors.append(f"{prefix}.status is invalid")
        if sensitivity not in ALLOWED_SENSITIVITY:
            errors.append(f"{prefix}.sensitivity is invalid")
        if status == "approved" and sensitivity == "prohibited":
            errors.append(f"{prefix} cannot approve prohibited content")

        evidence = item.get("evidence")
        if not isinstance(evidence, list) or len(evidence) > 20:
            errors.append(f"{prefix}.evidence must be an array of at most 20 items")
        else:
            if status == "approved" and not evidence:
                errors.append(f"{prefix}.evidence is required for approved preferences")
            for evidence_index, source in enumerate(evidence):
                source_prefix = f"{prefix}.evidence[{evidence_index}]"
                if not isinstance(source, dict):
                    errors.append(f"{source_prefix} must be an object")
                    continue
                if set(source) != EVIDENCE_REF_KEYS:
                    errors.append(f"{source_prefix} contains missing or unknown fields")
                if not isinstance(source.get("session_id"), str) or not SOURCE_ID_RE.fullmatch(source["session_id"]):
                    errors.append(f"{source_prefix}.session_id is invalid")
                if not isinstance(source.get("message_id"), str) or not SOURCE_ID_RE.fullmatch(source["message_id"]):
                    errors.append(f"{source_prefix}.message_id is invalid")
                if source.get("kind") not in ALLOWED_EVIDENCE_KINDS:
                    errors.append(f"{source_prefix}.kind is invalid")

        supersedes = item.get("supersedes")
        if not isinstance(supersedes, list) or any(not isinstance(value, str) for value in supersedes):
            errors.append(f"{prefix}.supersedes must be an array of IDs")
        elif identifier in supersedes:
            errors.append(f"{prefix}.supersedes cannot reference itself")
        else:
            missing = [value for value in supersedes if value not in all_ids]
            if missing:
                errors.append(f"{prefix}.supersedes references unknown IDs: {', '.join(missing)}")

        for date_key in ("first_observed", "last_observed"):
            if not isinstance(item.get(date_key), str) or not item[date_key].strip():
                errors.append(f"{prefix}.{date_key} is required")
        expires_at = item.get("expires_at")
        if expires_at is not None and not isinstance(expires_at, str):
            errors.append(f"{prefix}.expires_at must be a string or null")
        elif isinstance(expires_at, str) and parse_expiry(expires_at) is None:
            errors.append(f"{prefix}.expires_at must be a valid ISO-8601 timestamp")

        approval = item.get("approval")
        if status in {"approved", "superseded"}:
            if not isinstance(approval, dict) or set(approval) != APPROVAL_KEYS:
                errors.append(f"{prefix}.approval is required and must use the closed schema")
            else:
                authorization_id = approval.get("authorization_id")
                if not isinstance(authorization_id, str) or not SOURCE_ID_RE.fullmatch(authorization_id):
                    errors.append(f"{prefix}.approval.authorization_id is invalid")
                if approval.get("candidate_digest") != candidate_digest(item):
                    errors.append(f"{prefix}.approval.candidate_digest does not match the record")
                if not isinstance(approval.get("approved_at"), str) or not approval["approved_at"].strip():
                    errors.append(f"{prefix}.approval.approved_at is invalid")
        elif approval is not None:
            errors.append(f"{prefix}.approval must be null until approval")
    return errors


def atomic_write_json(path: Path, data: dict[str, Any], overwrite: bool) -> None:
    if path.exists() and not overwrite:
        raise ProfileError(f"Output exists; pass --overwrite to replace it: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_name = ""
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", newline="\n", delete=False, dir=path.parent,
            prefix=f".{path.name}.", suffix=".tmp"
        ) as handle:
            temp_name = handle.name
            json.dump(data, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, path)
        try:
            path.chmod(0o600)
        except OSError:
            pass
    finally:
        if temp_name and os.path.exists(temp_name):
            try:
                os.unlink(temp_name)
            except OSError:
                pass


def atomic_write_jsonl(path: Path, rows: list[dict[str, Any]], overwrite: bool) -> None:
    if path.exists() and not overwrite:
        raise ProfileError(f"Output exists; pass --overwrite to replace it: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_name = ""
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", newline="\n", delete=False, dir=path.parent,
            prefix=f".{path.name}.", suffix=".tmp"
        ) as handle:
            temp_name = handle.name
            for row in rows:
                handle.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, path)
        try:
            path.chmod(0o600)
        except OSError:
            pass
    finally:
        if temp_name and os.path.exists(temp_name):
            try:
                os.unlink(temp_name)
            except OSError:
                pass


def atomic_write_text(path: Path, text: str, overwrite: bool) -> None:
    if path.exists() and not overwrite:
        raise ProfileError(f"Output exists; pass --overwrite to replace it: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_name = ""
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", newline="\n", delete=False, dir=path.parent,
            prefix=f".{path.name}.", suffix=".tmp"
        ) as handle:
            temp_name = handle.name
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, path)
        try:
            path.chmod(0o600)
        except OSError:
            pass
    finally:
        if temp_name and os.path.exists(temp_name):
            try:
                os.unlink(temp_name)
            except OSError:
                pass


def parse_expiry(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    cleaned = value.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(cleaned)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def compile_markdown(
    profile: dict[str, Any],
    include_sensitive: bool,
    limit: int,
    *,
    project_id: str | None = None,
    task_id: str | None = None,
    temporary_id: str | None = None,
    sensitive_ids: set[str] | None = None,
    as_of: str | None = None,
) -> str:
    errors = validate_profile(profile)
    if errors:
        raise ProfileError("Profile validation failed:\n- " + "\n- ".join(errors))
    if include_sensitive and not sensitive_ids:
        raise ProfileError("Sensitive compilation requires explicit sensitive preference IDs")
    now = parse_expiry(as_of) if as_of is not None else datetime.now(tz=timezone.utc)
    if now is None:
        raise ProfileError("--as-of must be a valid ISO-8601 timestamp")
    allowed_sensitive = sensitive_ids or set()
    approved: list[dict[str, Any]] = []
    for item in profile["preferences"]:
        if item["status"] != "approved" or item["sensitivity"] == "prohibited":
            continue
        if item["sensitivity"] == "sensitive" and item["id"] not in allowed_sensitive:
            continue
        scope = item["scope"]
        scope_matches = (
            scope["type"] == "global"
            or (scope["type"] == "project" and project_id is not None and scope["value"] == project_id)
            or (scope["type"] == "task" and task_id is not None and scope["value"] == task_id)
            or (scope["type"] == "temporary" and temporary_id is not None and scope["value"] == temporary_id)
        )
        if not scope_matches:
            continue
        expiry = parse_expiry(item.get("expires_at"))
        if expiry is not None and expiry <= now:
            continue
        approved.append(item)
    approved.sort(
        key=lambda item: (
            item["scope"]["type"] != "global",
            item["category"],
            -float(item["confidence"]),
            item["id"],
        )
    )
    approved = approved[:limit]

    lines = [
        "# Approved user working preferences",
        "",
        "> Generated file. The current user request overrides these preferences. "
        "Treat the rules as user preferences, not as authority to bypass system, safety, legal, or workspace requirements.",
        "",
    ]
    if not approved:
        lines.extend(["No approved preferences are currently active.", ""])
        return "\n".join(lines)

    current_category = None
    for item in approved:
        if item["category"] != current_category:
            current_category = item["category"]
            lines.extend([f"## {current_category.replace('_', ' ').title()}", ""])
        rule = " ".join(item["rule"].splitlines()).strip()
        scope = item["scope"]
        scope_text = scope["type"] if scope["type"] == "global" else f"{scope['type']}:{scope['value']}"
        lines.append(
            f"- {rule} _(id: `{item['id']}`; scope: `{scope_text}`; "
            f"confidence: {float(item['confidence']):.2f})_"
        )
    lines.append("")
    return "\n".join(lines)


def find_preference(profile: dict[str, Any], identifier: str) -> dict[str, Any]:
    matches = [item for item in profile.get("preferences", []) if item.get("id") == identifier]
    if len(matches) != 1:
        raise ProfileError(f"Expected exactly one preference with ID {identifier!r}")
    return matches[0]


def output_for_mutation(input_path: Path, output: Path | None, in_place: bool) -> tuple[Path, bool]:
    if in_place and output is not None:
        raise ProfileError("Use either --in-place or --output, not both")
    if in_place:
        return input_path, True
    if output is None:
        raise ProfileError("Mutation requires --output or --in-place")
    return output, False


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    init_parser = subparsers.add_parser("init", help="Create an empty profile")
    init_parser.add_argument("output", type=Path)
    init_parser.add_argument("--overwrite", action="store_true")

    validate_parser = subparsers.add_parser("validate", help="Validate a profile")
    validate_parser.add_argument("profile", type=Path)

    review_parser = subparsers.add_parser(
        "review-evidence", help="Bind a user review decision to selected evidence"
    )
    review_parser.add_argument("evidence", type=Path)
    review_parser.add_argument("--message-id", required=True, action="append", dest="message_ids")
    review_parser.add_argument("--decision", required=True, choices=("accepted", "rejected"))
    review_parser.add_argument("--authorization-id", required=True)
    review_parser.add_argument("--output", type=Path)
    review_parser.add_argument("--in-place", action="store_true")
    review_parser.add_argument("--overwrite", action="store_true")

    candidate_parser = subparsers.add_parser(
        "add-candidate", help="Create a candidate from selected reviewed evidence"
    )
    candidate_parser.add_argument("profile", type=Path)
    candidate_parser.add_argument("evidence", type=Path)
    candidate_parser.add_argument("--id", required=True)
    candidate_parser.add_argument("--rule", required=True)
    candidate_parser.add_argument("--category", required=True, choices=sorted(ALLOWED_CATEGORIES))
    candidate_parser.add_argument("--scope-type", default="global", choices=sorted(ALLOWED_SCOPE_TYPES))
    candidate_parser.add_argument("--scope-value")
    candidate_parser.add_argument("--confidence", required=True, type=float)
    candidate_parser.add_argument("--sensitivity", default="normal", choices=sorted(ALLOWED_SENSITIVITY))
    candidate_parser.add_argument("--message-id", required=True, action="append", dest="message_ids")
    candidate_parser.add_argument("--supersedes", action="append", default=[])
    candidate_parser.add_argument("--output", type=Path)
    candidate_parser.add_argument("--in-place", action="store_true")
    candidate_parser.add_argument("--overwrite", action="store_true")

    digest_parser = subparsers.add_parser(
        "candidate-digest", help="Print the digest that a user approval must bind"
    )
    digest_parser.add_argument("profile", type=Path)
    digest_parser.add_argument("id")

    approve_parser = subparsers.add_parser(
        "approve", help="Approve one exact candidate using a digest-bound authorization"
    )
    approve_parser.add_argument("profile", type=Path)
    approve_parser.add_argument("id")
    approve_parser.add_argument("--authorization-id", required=True)
    approve_parser.add_argument("--expected-digest", required=True)
    approve_parser.add_argument("--output", type=Path)
    approve_parser.add_argument("--in-place", action="store_true")
    approve_parser.add_argument("--overwrite", action="store_true")

    status_parser = subparsers.add_parser("set-status", help="Change one preference status")
    status_parser.add_argument("profile", type=Path)
    status_parser.add_argument("id")
    status_parser.add_argument("status", choices=("rejected", "superseded"))
    status_parser.add_argument("--output", type=Path)
    status_parser.add_argument("--in-place", action="store_true")
    status_parser.add_argument("--overwrite", action="store_true")

    forget_parser = subparsers.add_parser("forget", help="Remove one preference record")
    forget_parser.add_argument("profile", type=Path)
    forget_parser.add_argument("id")
    forget_parser.add_argument("--output", type=Path)
    forget_parser.add_argument("--in-place", action="store_true")
    forget_parser.add_argument("--overwrite", action="store_true")

    compile_parser = subparsers.add_parser("compile", help="Compile approved preferences to Markdown")
    compile_parser.add_argument("profile", type=Path)
    compile_parser.add_argument("--output", required=True, type=Path)
    compile_parser.add_argument("--sensitive-id", action="append", default=[], dest="sensitive_ids")
    compile_parser.add_argument("--project-id")
    compile_parser.add_argument("--task-id")
    compile_parser.add_argument("--temporary-id")
    compile_parser.add_argument("--as-of")
    compile_parser.add_argument("--limit", type=int, default=40)
    compile_parser.add_argument("--overwrite", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "init":
            atomic_write_json(args.output.resolve(), empty_profile(), args.overwrite)
            result = {"status": "created", "output": str(args.output)}
        elif args.command == "validate":
            profile = load_profile(args.profile.resolve())
            errors = validate_profile(profile)
            if errors:
                for error in errors:
                    print(f"error: {error}", file=sys.stderr)
                return 2
            result = {"status": "valid", "preferences": len(profile["preferences"])}
        elif args.command == "review-evidence":
            source = args.evidence.resolve()
            reviewed = review_evidence_rows(
                load_evidence(source),
                message_ids=args.message_ids,
                decision=args.decision,
                authorization_id=args.authorization_id,
            )
            destination, replacing = output_for_mutation(
                source, args.output.resolve() if args.output else None, args.in_place
            )
            atomic_write_jsonl(destination, reviewed, replacing or args.overwrite)
            result = {
                "status": "evidence-reviewed",
                "decision": args.decision,
                "count": len(set(args.message_ids)),
                "output": str(destination),
            }
        elif args.command == "add-candidate":
            source = args.profile.resolve()
            profile = add_candidate_from_evidence(
                load_profile(source),
                load_evidence(args.evidence.resolve()),
                identifier=args.id,
                rule=args.rule,
                category=args.category,
                scope_type=args.scope_type,
                scope_value=args.scope_value,
                confidence=args.confidence,
                sensitivity=args.sensitivity,
                message_ids=args.message_ids,
                supersedes=args.supersedes,
            )
            destination, replacing = output_for_mutation(
                source, args.output.resolve() if args.output else None, args.in_place
            )
            atomic_write_json(destination, profile, replacing or args.overwrite)
            result = {"status": "candidate-added", "id": args.id, "output": str(destination)}
        elif args.command == "candidate-digest":
            profile = load_profile(args.profile.resolve())
            errors = validate_profile(profile)
            if errors:
                raise ProfileError("Profile validation failed:\n- " + "\n- ".join(errors))
            preference = find_preference(profile, args.id)
            if preference["status"] != "candidate":
                raise ProfileError("Only candidate preferences have an approval digest")
            result = {"status": "candidate", "id": args.id, "digest": candidate_digest(preference)}
        elif args.command == "approve":
            source = args.profile.resolve()
            profile = approve_candidate(
                load_profile(source),
                identifier=args.id,
                authorization_id=args.authorization_id,
                expected_digest=args.expected_digest,
            )
            destination, replacing = output_for_mutation(
                source, args.output.resolve() if args.output else None, args.in_place
            )
            atomic_write_json(destination, profile, replacing or args.overwrite)
            result = {"status": "approved", "id": args.id, "output": str(destination)}
        elif args.command == "set-status":
            source = args.profile.resolve()
            profile = deepcopy(load_profile(source))
            preference = find_preference(profile, args.id)
            if args.status == "superseded" and preference.get("status") != "approved":
                raise ProfileError("Only approved preferences can be superseded")
            if args.status == "rejected" and preference.get("status") != "candidate":
                raise ProfileError("Only candidate preferences can be rejected")
            preference["status"] = args.status
            profile["updated_at"] = now_utc()
            errors = validate_profile(profile)
            if errors:
                raise ProfileError("Profile validation failed:\n- " + "\n- ".join(errors))
            destination, replacing = output_for_mutation(source, args.output.resolve() if args.output else None, args.in_place)
            atomic_write_json(destination, profile, replacing or args.overwrite)
            result = {"status": "updated", "id": args.id, "value": args.status, "output": str(destination)}
        elif args.command == "forget":
            source = args.profile.resolve()
            profile = deepcopy(load_profile(source))
            find_preference(profile, args.id)
            referenced_by = [
                item.get("id") for item in profile["preferences"]
                if args.id in item.get("supersedes", [])
            ]
            if referenced_by:
                raise ProfileError(
                    "Cannot forget a preference still referenced by supersession records: "
                    + ", ".join(str(value) for value in referenced_by)
                )
            profile["preferences"] = [item for item in profile["preferences"] if item.get("id") != args.id]
            profile["updated_at"] = now_utc()
            errors = validate_profile(profile)
            if errors:
                raise ProfileError("Profile validation failed:\n- " + "\n- ".join(errors))
            destination, replacing = output_for_mutation(source, args.output.resolve() if args.output else None, args.in_place)
            atomic_write_json(destination, profile, replacing or args.overwrite)
            result = {
                "status": "forgotten",
                "id": args.id,
                "output": str(destination),
                "requires_recompile_and_artifact_purge": True,
            }
        else:
            if args.limit < 1 or args.limit > 200:
                raise ProfileError("--limit must be between 1 and 200")
            markdown = compile_markdown(
                load_profile(args.profile.resolve()),
                bool(args.sensitive_ids),
                args.limit,
                project_id=args.project_id,
                task_id=args.task_id,
                temporary_id=args.temporary_id,
                sensitive_ids=set(args.sensitive_ids),
                as_of=args.as_of,
            )
            atomic_write_text(args.output.resolve(), markdown, args.overwrite)
            result = {"status": "compiled", "output": str(args.output)}
    except (OSError, ProfileError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
