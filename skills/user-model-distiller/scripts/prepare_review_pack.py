#!/usr/bin/env python3
"""Prepare and verify a privacy-gated external evidence review pack."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Iterable


SCRIPT_DIR = Path(__file__).resolve().parent
SKILL_ROOT = SCRIPT_DIR.parent
REPO_ROOT = SCRIPT_DIR.parents[2]
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import privacy_guard  # noqa: E402


VERSION = "1.0"
MANIFEST_SCHEMA_VERSION = "1.0"
MAPPING_SCHEMA_VERSION = "1.0"
PACK_NAME = "pack.jsonl"
PRIVACY_REPORT_NAME = "privacy-report.json"
MANIFEST_NAME = "manifest.json"
MAX_INPUT_BYTES = 64 * 1024 * 1024
MAX_LINE_BYTES = 1024 * 1024
MAX_RECORDS = 100_000
MAX_TEXT_CHARS = 4_000
MAX_MANIFEST_BYTES = 1024 * 1024
MAX_REPORT_BYTES = 1024 * 1024
REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
CLOUD_SYNC_PREFIXES = (
    "onedrive",
    "dropbox",
    "google drive",
    "googledrive",
    "icloud",
    "box",
    "sharepoint",
    "cloudstorage",
)
AUTHORIZATION_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
SESSION_ID_RE = re.compile(r"^session-[0-9a-f]{20}$")
MESSAGE_ID_RE = re.compile(r"^message-[0-9a-f]{20}$")
REVIEW_ID_RE = re.compile(r"^review-[0-9a-f]{32}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
FINDING_CODE_RE = re.compile(r"^[a-z0-9_]{1,128}$")
ALLOWED_KINDS = {"explicit_preference", "correction", "approval"}

CONSTANT_SESSION_ID = "session-00000000000000000000"
CONSTANT_MESSAGE_ID = "message-00000000000000000000"
CONSTANT_SOURCE_ID = "source-00000000000000000000"
CONSTANT_SOURCE_HASH = "0" * 64

WINDOWS_ACL_QUERY = r"""
$ErrorActionPreference = 'Stop'
$target = $env:USER_MODEL_DISTILLER_ACL_TARGET
$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$acl = [System.IO.Directory]::GetAccessControl(
    $target,
    ([System.Security.AccessControl.AccessControlSections]::Access -bor [System.Security.AccessControl.AccessControlSections]::Owner)
)
$rules = @($acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]) | ForEach-Object {
    [ordered]@{
        sid = $_.IdentityReference.Value
        type = $_.AccessControlType.ToString()
        inherited = [bool]$_.IsInherited
    }
})
[ordered]@{
    current = $identity.User.Value
    owner = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
    protected = [bool]$acl.AreAccessRulesProtected
    rules = $rules
} | ConvertTo-Json -Compress -Depth 5
"""

WINDOWS_ACL_HARDEN = r"""
$ErrorActionPreference = 'Stop'
$target = $env:USER_MODEL_DISTILLER_ACL_TARGET
$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$sid = $identity.User
$acl = [System.IO.Directory]::GetAccessControl(
    $target,
    [System.Security.AccessControl.AccessControlSections]::Access
)
$acl.SetAccessRuleProtection($true, $false)
foreach ($existing in @($acl.Access)) {
    [void]$acl.RemoveAccessRuleAll($existing)
}
$rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
    $sid,
    [System.Security.AccessControl.FileSystemRights]::FullControl,
    ([System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit),
    [System.Security.AccessControl.PropagationFlags]::None,
    [System.Security.AccessControl.AccessControlType]::Allow
)
$acl.AddAccessRule($rule)
[System.IO.Directory]::SetAccessControl($target, $acl)
"""


class ReviewPackError(ValueError):
    """Raised when a review pack operation violates the safety contract."""


class DuplicateKeyError(ValueError):
    """Raised for ambiguous JSON objects."""


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateKeyError("duplicate JSON key")
        result[key] = value
    return result


def _reject_constant(_value: str) -> None:
    raise ValueError("non-finite number")


def is_unc_path(path: Path) -> bool:
    normalized = os.fspath(path).replace("/", "\\")
    return normalized.startswith("\\\\")


def is_cloud_sync_path(path: Path) -> bool:
    return any(
        part.casefold().startswith(prefix)
        for part in path.parts
        for prefix in CLOUD_SYNC_PREFIXES
    )


def has_reparse_attribute(attributes: int) -> bool:
    return bool(attributes & REPARSE_POINT)


def _is_reparse(path: Path) -> bool:
    try:
        details = os.lstat(path)
    except OSError as exc:
        raise ReviewPackError("Unable to inspect a path safely") from exc
    attributes = int(getattr(details, "st_file_attributes", 0))
    return stat.S_ISLNK(details.st_mode) or has_reparse_attribute(attributes)


def _absolute(path: Path) -> Path:
    if is_unc_path(path):
        raise ReviewPackError("UNC and network paths are not allowed")
    expanded = path.expanduser()
    if is_unc_path(expanded):
        raise ReviewPackError("UNC and network paths are not allowed")
    return Path(os.path.abspath(os.fspath(expanded)))


def _assert_existing_components_safe(path: Path) -> None:
    current = path
    while True:
        if os.path.lexists(current) and _is_reparse(current):
            raise ReviewPackError("Links and reparse points are not allowed")
        parent = current.parent
        if parent == current:
            return
        current = parent


def _assert_flat_tree_safe(root: Path) -> None:
    _assert_existing_components_safe(root)
    if not root.is_dir():
        raise ReviewPackError("Review pack directory does not exist")
    try:
        entries = list(os.scandir(root))
    except OSError as exc:
        raise ReviewPackError("Unable to inspect the review pack") from exc
    for entry in entries:
        path = Path(entry.path)
        if _is_reparse(path) or not entry.is_file(follow_symlinks=False):
            raise ReviewPackError("Review pack contains an unsafe entry")


def _same_or_within(path: Path, root: Path) -> bool:
    path_text = os.path.normcase(os.path.abspath(os.fspath(path)))
    root_text = os.path.normcase(os.path.abspath(os.fspath(root)))
    try:
        return os.path.commonpath((path_text, root_text)) == root_text
    except ValueError:
        return False


def _powershell() -> str:
    executable = (
        shutil.which("powershell.exe")
        or shutil.which("powershell")
        or shutil.which("pwsh")
    )
    if not executable:
        raise ReviewPackError("Windows ACL verification requires PowerShell")
    return executable


def _run_powershell(script: str, path: Path) -> str:
    environment = os.environ.copy()
    environment["USER_MODEL_DISTILLER_ACL_TARGET"] = os.fspath(path)
    try:
        result = subprocess.run(
            [
                _powershell(),
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                script,
            ],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=environment,
            timeout=15,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ReviewPackError("Unable to verify mapping directory access controls") from exc
    if result.returncode != 0:
        raise ReviewPackError("Unable to verify mapping directory access controls")
    return result.stdout.strip()


def _validate_windows_acl_details(details: Any) -> None:
    if not isinstance(details, dict):
        raise ReviewPackError("Mapping parent ACL is not access-isolated")
    current_sid = details.get("current")
    trusted_sids = {current_sid, "S-1-5-18", "S-1-5-32-544"}
    rules = details.get("rules")
    if (
        not isinstance(current_sid, str)
        or details.get("owner") not in trusted_sids
        or details.get("protected") is not True
        or not isinstance(rules, list)
        or not rules
    ):
        raise ReviewPackError("Mapping parent ACL is not access-isolated")
    current_allowed = False
    for rule in rules:
        if not isinstance(rule, dict):
            raise ReviewPackError("Mapping parent ACL is not access-isolated")
        if rule.get("inherited") is True:
            raise ReviewPackError("Mapping parent ACL must not inherit access rules")
        if rule.get("type") == "Allow":
            sid = rule.get("sid")
            if sid not in trusted_sids:
                raise ReviewPackError("Mapping parent ACL grants access to another principal")
            current_allowed = current_allowed or sid == current_sid
    if not current_allowed:
        raise ReviewPackError("Mapping parent ACL does not grant the current user access")


def _assert_private_mapping_directory(path: Path) -> None:
    """Require an owner-only location before any source-ID mapping is written."""

    if not path.is_dir() or _is_reparse(path):
        raise ReviewPackError("Mapping parent must be a safe private directory")
    if os.name == "nt":
        try:
            details = json.loads(_run_powershell(WINDOWS_ACL_QUERY, path))
        except (json.JSONDecodeError, TypeError, ValueError) as exc:
            raise ReviewPackError("Unable to verify mapping directory access controls") from exc
        _validate_windows_acl_details(details)
        return
    details = path.stat()
    if hasattr(os, "getuid") and details.st_uid != os.getuid():
        raise ReviewPackError("Mapping parent must be owned by the current user")
    if stat.S_IMODE(details.st_mode) & 0o077:
        raise ReviewPackError("Mapping parent permissions must be owner-only")


def _ensure_private_mapping_directory(path: Path) -> bool:
    """Create a new isolated directory, or verify an existing one without weakening it."""

    created = False
    if not os.path.lexists(path):
        try:
            path.mkdir(mode=0o700)
            created = True
            if os.name == "nt":
                _run_powershell(WINDOWS_ACL_HARDEN, path)
            else:
                path.chmod(0o700)
        except OSError as exc:
            raise ReviewPackError("Unable to create a private mapping directory") from exc
    _assert_private_mapping_directory(path)
    return created


def _path_is_private_location(path: Path) -> bool:
    return not _same_or_within(path, REPO_ROOT) and not _same_or_within(path, SKILL_ROOT)


def validate_prepare_paths(
    input_path: Path, output_dir: Path, mapping_output: Path
) -> tuple[Path, Path, Path]:
    """Canonicalize and validate all prepare paths without creating anything."""

    source = _absolute(input_path)
    destination = _absolute(output_dir)
    mapping = _absolute(mapping_output)
    if any(is_cloud_sync_path(path) for path in (source, destination, mapping)):
        raise ReviewPackError("Cloud-synchronized paths are not allowed")
    for path in (source, destination, mapping):
        _assert_existing_components_safe(path)
    if not _path_is_private_location(source):
        raise ReviewPackError("Evidence input must be outside the repository and Skill tree")
    if not _path_is_private_location(destination) or not _path_is_private_location(mapping):
        raise ReviewPackError("Outputs must be outside the repository and Skill tree")
    if not os.path.lexists(source) or not source.is_file() or _is_reparse(source):
        raise ReviewPackError("Evidence input is not a safe regular file")
    if os.path.lexists(destination):
        raise ReviewPackError("Output directory already exists")
    if os.path.lexists(mapping):
        raise ReviewPackError("Mapping output already exists")
    if not destination.parent.is_dir():
        raise ReviewPackError("Review pack parent directory must already exist")
    if os.path.lexists(mapping.parent):
        _assert_private_mapping_directory(mapping.parent)
    elif not mapping.parent.parent.is_dir():
        raise ReviewPackError("Mapping parent must exist or have an existing parent")
    if destination.parent == destination or mapping.parent == mapping:
        raise ReviewPackError("Filesystem roots cannot be output locations")
    if _same_or_within(mapping, destination):
        raise ReviewPackError("Mapping output must be outside the review pack directory")
    if os.path.normcase(os.fspath(mapping.parent)) == os.path.normcase(
        os.fspath(destination.parent)
    ):
        raise ReviewPackError("Mapping output must use an access-isolated parent directory")
    if source == mapping or _same_or_within(source, destination):
        raise ReviewPackError("Input and output paths must not overlap")
    return source, destination, mapping


def validate_verify_path(run_dir: Path) -> Path:
    directory = _absolute(run_dir)
    if is_cloud_sync_path(directory):
        raise ReviewPackError("Cloud-synchronized paths are not allowed")
    if not _path_is_private_location(directory):
        raise ReviewPackError("Review pack must be outside the repository and Skill tree")
    _assert_flat_tree_safe(directory)
    return directory


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(block)
    except OSError as exc:
        raise ReviewPackError("Unable to hash an artifact") from exc
    return digest.hexdigest()


def _artifact_record(path: Path) -> dict[str, Any]:
    return {"sha256": sha256_file(path), "bytes": path.stat().st_size}


def _atomic_write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> int:
    temporary_name = ""
    count = 0
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
            temporary_name = handle.name
            for row in rows:
                handle.write(
                    json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n"
                )
                count += 1
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, path)
        temporary_name = ""
        try:
            path.chmod(0o600)
        except OSError:
            pass
        return count
    except OSError as exc:
        raise ReviewPackError("Unable to write a private artifact") from exc
    finally:
        if temporary_name and os.path.exists(temporary_name):
            try:
                os.unlink(temporary_name)
            except OSError:
                pass


def _atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    temporary_name = ""
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
            temporary_name = handle.name
            json.dump(payload, handle, ensure_ascii=False, sort_keys=True, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, path)
        temporary_name = ""
        try:
            path.chmod(0o600)
        except OSError:
            pass
    except OSError as exc:
        raise ReviewPackError("Unable to write a private artifact") from exc
    finally:
        if temporary_name and os.path.exists(temporary_name):
            try:
                os.unlink(temporary_name)
            except OSError:
                pass


def _read_json(path: Path, maximum_bytes: int) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > maximum_bytes:
        raise ReviewPackError("JSON artifact is missing or unsafe")
    try:
        payload = json.loads(
            path.read_text(encoding="utf-8-sig"),
            object_pairs_hook=_strict_object,
            parse_constant=_reject_constant,
        )
    except (OSError, UnicodeError, json.JSONDecodeError, DuplicateKeyError, ValueError) as exc:
        raise ReviewPackError("JSON artifact is invalid") from exc
    if not isinstance(payload, dict):
        raise ReviewPackError("JSON artifact must be an object")
    return payload


def _validate_kind_list(value: Any) -> list[str]:
    if (
        not isinstance(value, list)
        or not value
        or len(value) > len(ALLOWED_KINDS)
        or any(not isinstance(kind, str) or kind not in ALLOWED_KINDS for kind in value)
        or len(set(value)) != len(value)
    ):
        raise ReviewPackError("Evidence kinds are invalid")
    return list(value)


def read_evidence(path: Path) -> list[dict[str, Any]]:
    """Read and validate direct user evidence without returning source text in errors."""

    try:
        metadata = path.stat()
    except OSError as exc:
        raise ReviewPackError("Evidence input is unavailable") from exc
    if metadata.st_size > MAX_INPUT_BYTES:
        raise ReviewPackError("Evidence input exceeds the size limit")
    records: list[dict[str, Any]] = []
    source_keys: set[tuple[str, str]] = set()
    line_number = 0
    try:
        with path.open("rb") as handle:
            while True:
                raw_line = handle.readline(MAX_LINE_BYTES + 1)
                if not raw_line:
                    break
                line_number += 1
                if len(raw_line) > MAX_LINE_BYTES:
                    raise ReviewPackError("Evidence line exceeds the size limit")
                if not raw_line.strip():
                    continue
                if len(records) >= MAX_RECORDS:
                    raise ReviewPackError("Evidence input exceeds the record limit")
                try:
                    encoding = "utf-8-sig" if line_number == 1 else "utf-8"
                    record = json.loads(
                        raw_line.decode(encoding),
                        object_pairs_hook=_strict_object,
                        parse_constant=_reject_constant,
                    )
                except (
                    UnicodeError,
                    json.JSONDecodeError,
                    DuplicateKeyError,
                    ValueError,
                    RecursionError,
                ) as exc:
                    raise ReviewPackError("Evidence input contains invalid JSON") from exc
                if not isinstance(record, dict):
                    raise ReviewPackError("Evidence record is not an object")
                if record.get("schema_version") != "1.0":
                    raise ReviewPackError("Evidence schema version is unsupported")
                session_id = record.get("session_id")
                message_id = record.get("message_id")
                if not isinstance(session_id, str) or not SESSION_ID_RE.fullmatch(session_id):
                    raise ReviewPackError("Evidence session identifier is invalid")
                if not isinstance(message_id, str) or not MESSAGE_ID_RE.fullmatch(message_id):
                    raise ReviewPackError("Evidence message identifier is invalid")
                source_key = (session_id, message_id)
                if source_key in source_keys:
                    raise ReviewPackError("Evidence contains a duplicate source message")
                source_keys.add(source_key)
                provenance = record.get("provenance")
                if (
                    not isinstance(provenance, dict)
                    or provenance.get("role") != "user"
                    or provenance.get("direct") is not True
                ):
                    raise ReviewPackError("Evidence is not direct user content")
                text = record.get("user_text")
                if not isinstance(text, str) or not text or len(text) > MAX_TEXT_CHARS:
                    raise ReviewPackError("Evidence text is invalid")
                records.append(
                    {
                        "session_id": session_id,
                        "message_id": message_id,
                        "kinds": _validate_kind_list(record.get("kinds")),
                        "text": text,
                    }
                )
    except OSError as exc:
        raise ReviewPackError("Evidence input could not be read") from exc
    return records


def _normalized_view(records: Iterable[dict[str, Any]]) -> Iterable[dict[str, Any]]:
    for record in records:
        yield {
            "schema_version": "1.0",
            "session_id": CONSTANT_SESSION_ID,
            "message_id": CONSTANT_MESSAGE_ID,
            "role": "user",
            "created_at": None,
            "text": record["text"],
            "redaction_count": 0,
            "source": {"id": CONSTANT_SOURCE_ID, "sha256": CONSTANT_SOURCE_HASH},
        }


def _safe_nonnegative_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ReviewPackError(f"Privacy guard returned an invalid {label}")
    return value


def _safe_findings(value: Any, total: int, fallback_code: str) -> list[dict[str, Any]]:
    if value is None:
        return [] if total == 0 else [{"code": fallback_code, "records": total}]
    if not isinstance(value, list):
        raise ReviewPackError("Privacy guard returned invalid finding data")
    findings: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, dict) or set(item) != {"code", "records"}:
            raise ReviewPackError("Privacy guard returned invalid finding data")
        code = item.get("code")
        count = item.get("records")
        if not isinstance(code, str) or not FINDING_CODE_RE.fullmatch(code):
            raise ReviewPackError("Privacy guard returned an invalid finding code")
        findings.append({"code": code, "records": _safe_nonnegative_int(count, "finding count")})
    return findings


def _sanitize_privacy_report(report: Any, expected_records: int) -> dict[str, Any]:
    """Copy only aggregate, bounded fields from the sibling guard report."""

    if not isinstance(report, dict):
        raise ReviewPackError("Privacy guard returned an invalid report")
    blocker_count = _safe_nonnegative_int(report.get("blocker_count"), "blocker count")
    warning_count = _safe_nonnegative_int(report.get("warning_count"), "warning count")
    records_scanned = _safe_nonnegative_int(
        report.get("records_scanned", expected_records), "record count"
    )
    if records_scanned != expected_records:
        raise ReviewPackError("Privacy guard scanned an unexpected record count")
    roles = report.get(
        "roles", {"user": expected_records, "assistant": 0, "other": 0}
    )
    if not isinstance(roles, dict) or set(roles) != {"user", "assistant", "other"}:
        raise ReviewPackError("Privacy guard returned invalid role counts")
    safe_roles = {
        role: _safe_nonnegative_int(roles[role], "role count")
        for role in ("user", "assistant", "other")
    }
    if safe_roles != {"user": expected_records, "assistant": 0, "other": 0}:
        raise ReviewPackError("Privacy guard did not scan a user-only view")
    status_value = report.get("status")
    decision_value = report.get("decision")
    if status_value not in {"pass", "blocked"}:
        raise ReviewPackError("Privacy guard returned an invalid status")
    if decision_value is not None and decision_value not in {"pass", "warn", "block"}:
        raise ReviewPackError("Privacy guard returned an invalid decision")
    blocked = (
        blocker_count > 0
        or warning_count > 0
        or status_value == "blocked"
        or decision_value == "block"
    )
    blockers = _safe_findings(
        report.get("blockers"), blocker_count, "privacy_guard_blocker"
    )
    warnings = _safe_findings(
        report.get("warnings"), warning_count, "privacy_guard_warning"
    )
    categories: dict[str, int] = {}
    for item in blockers + warnings:
        categories[item["code"]] = categories.get(item["code"], 0) + item["records"]
    return {
        "schema_version": "1.0",
        "mode": "external-review",
        "status": "blocked" if blocked else "pass",
        "decision": "block" if blocked else "pass",
        "records_scanned": records_scanned,
        "roles": safe_roles,
        "blocker_count": blocker_count,
        "warning_count": warning_count,
        "blockers": blockers,
        "warnings": warnings,
        "categories": dict(sorted(categories.items())),
        "records": [],
    }


def _new_review_id(used: set[str]) -> str:
    for _attempt in range(100):
        value = f"review-{secrets.token_hex(16)}"
        if value not in used:
            used.add(value)
            return value
    raise ReviewPackError("Unable to allocate unique review identifiers")


def _build_manifest(
    staging: Path,
    *,
    status: str,
    record_count: int,
    mapping_sha256: str | None = None,
) -> dict[str, Any]:
    artifact_names = {PRIVACY_REPORT_NAME}
    if status == "pass":
        artifact_names.add(PACK_NAME)
    manifest: dict[str, Any] = {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "tool_version": VERSION,
        "status": status,
        "record_count": record_count,
        "artifacts": {
            name: _artifact_record(staging / name) for name in sorted(artifact_names)
        },
    }
    if status == "pass":
        if not isinstance(mapping_sha256, str) or not SHA256_RE.fullmatch(mapping_sha256):
            raise ReviewPackError("Mapping digest is invalid")
        manifest["mapping_sha256"] = mapping_sha256
    return manifest


def prepare_review_pack(
    input_path: Path,
    output_dir: Path,
    *,
    mapping_output: Path,
    authorization_id: str,
) -> dict[str, Any]:
    """Prepare a new review directory and a separately isolated private mapping."""

    if not isinstance(authorization_id, str) or not AUTHORIZATION_ID_RE.fullmatch(
        authorization_id
    ):
        raise ReviewPackError("Authorization ID is invalid")
    source, destination, mapping = validate_prepare_paths(
        input_path, output_dir, mapping_output
    )
    records = read_evidence(source)
    staging = Path(
        tempfile.mkdtemp(prefix=f".{destination.name}.staging-", dir=destination.parent)
    )
    mapping_temporary = ""
    mapping_published = False
    mapping_parent_created = False
    directory_published = False
    try:
        try:
            staging.chmod(0o700)
        except OSError:
            pass

        view_path = staging / ".external-review-view.jsonl"
        try:
            _atomic_write_jsonl(view_path, _normalized_view(records))
            raw_report = privacy_guard.scan_records(
                view_path, mode="external-review"
            )
            privacy_report = _sanitize_privacy_report(raw_report, len(records))
        finally:
            if os.path.lexists(view_path):
                try:
                    view_path.unlink()
                except OSError:
                    pass

        report_path = staging / PRIVACY_REPORT_NAME
        _atomic_write_json(report_path, privacy_report)
        if privacy_report["status"] == "blocked":
            manifest = _build_manifest(
                staging, status="blocked", record_count=len(records)
            )
            _atomic_write_json(staging / MANIFEST_NAME, manifest)
            _assert_existing_components_safe(destination.parent)
            if os.path.lexists(destination):
                raise ReviewPackError("Output directory already exists")
            os.replace(staging, destination)
            directory_published = True
            return {"status": "blocked", "records": len(records)}

        used_review_ids: set[str] = set()
        pack_rows: list[dict[str, Any]] = []
        mapping_rows: dict[str, dict[str, str]] = {}
        for record in records:
            review_id = _new_review_id(used_review_ids)
            pack_rows.append(
                {
                    "review_id": review_id,
                    "kinds": record["kinds"],
                    "text": record["text"],
                }
            )
            mapping_rows[review_id] = {
                "session_id": record["session_id"],
                "message_id": record["message_id"],
            }
        pack_path = staging / PACK_NAME
        _atomic_write_jsonl(pack_path, pack_rows)
        mapping_payload = {
            "schema_version": MAPPING_SCHEMA_VERSION,
            "authorization_id": authorization_id,
            "mapping": mapping_rows,
        }
        _assert_existing_components_safe(mapping.parent.parent)
        if os.path.lexists(mapping):
            raise ReviewPackError("Mapping output already exists")
        mapping_parent_created = _ensure_private_mapping_directory(mapping.parent)
        _assert_existing_components_safe(mapping.parent)
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            delete=False,
            dir=mapping.parent,
            prefix=f".{mapping.name}.",
            suffix=".tmp",
        ) as handle:
            mapping_temporary = handle.name
            json.dump(mapping_payload, handle, ensure_ascii=False, sort_keys=True, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        temporary_mapping_path = Path(mapping_temporary)
        try:
            temporary_mapping_path.chmod(0o600)
        except OSError:
            pass
        mapping_digest = sha256_file(temporary_mapping_path)
        manifest = _build_manifest(
            staging,
            status="pass",
            record_count=len(records),
            mapping_sha256=mapping_digest,
        )
        _atomic_write_json(staging / MANIFEST_NAME, manifest)

        _assert_existing_components_safe(destination.parent)
        _assert_existing_components_safe(mapping.parent)
        if os.path.lexists(destination) or os.path.lexists(mapping):
            raise ReviewPackError("An output location was created during preparation")
        os.replace(mapping_temporary, mapping)
        mapping_temporary = ""
        mapping_published = True
        try:
            mapping.chmod(0o600)
        except OSError:
            pass
        os.replace(staging, destination)
        directory_published = True
        return {"status": "pass", "records": len(records)}
    except OSError as exc:
        raise ReviewPackError("Review pack publication failed") from exc
    finally:
        if mapping_temporary and os.path.exists(mapping_temporary):
            try:
                os.unlink(mapping_temporary)
            except OSError:
                pass
        if mapping_published and not directory_published and os.path.lexists(mapping):
            try:
                mapping.unlink()
            except OSError:
                pass
        if mapping_parent_created and not directory_published and mapping.parent.is_dir():
            try:
                mapping.parent.rmdir()
            except OSError:
                pass
        if not directory_published and os.path.lexists(staging):
            shutil.rmtree(staging, ignore_errors=True)


def _validate_artifact_record(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {"sha256", "bytes"}:
        raise ReviewPackError("Manifest artifact record is invalid")
    digest = value.get("sha256")
    size = value.get("bytes")
    if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
        raise ReviewPackError("Manifest artifact digest is invalid")
    if isinstance(size, bool) or not isinstance(size, int) or size < 0:
        raise ReviewPackError("Manifest artifact size is invalid")
    return value


def _read_and_validate_pack(path: Path, expected_count: int) -> None:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_INPUT_BYTES:
        raise ReviewPackError("Review pack is missing or unsafe")
    seen: set[str] = set()
    count = 0
    try:
        with path.open("rb") as handle:
            while True:
                raw_line = handle.readline(MAX_LINE_BYTES + 1)
                if not raw_line:
                    break
                if len(raw_line) > MAX_LINE_BYTES:
                    raise ReviewPackError("Review pack line exceeds the size limit")
                if not raw_line.strip():
                    continue
                try:
                    record = json.loads(
                        raw_line.decode("utf-8"),
                        object_pairs_hook=_strict_object,
                        parse_constant=_reject_constant,
                    )
                except (
                    UnicodeError,
                    json.JSONDecodeError,
                    DuplicateKeyError,
                    ValueError,
                ) as exc:
                    raise ReviewPackError("Review pack contains invalid JSON") from exc
                if not isinstance(record, dict) or set(record) != {
                    "review_id",
                    "kinds",
                    "text",
                }:
                    raise ReviewPackError("Review pack fields are invalid")
                review_id = record.get("review_id")
                if (
                    not isinstance(review_id, str)
                    or not REVIEW_ID_RE.fullmatch(review_id)
                    or review_id in seen
                ):
                    raise ReviewPackError("Review identifier is invalid")
                seen.add(review_id)
                _validate_kind_list(record.get("kinds"))
                text = record.get("text")
                if not isinstance(text, str) or not text or len(text) > MAX_TEXT_CHARS:
                    raise ReviewPackError("Review text is invalid")
                count += 1
                if count > MAX_RECORDS:
                    raise ReviewPackError("Review pack exceeds the record limit")
    except OSError as exc:
        raise ReviewPackError("Review pack could not be read") from exc
    if count != expected_count:
        raise ReviewPackError("Review pack record count does not match the manifest")


def verify_review_pack(run_dir: Path) -> dict[str, Any]:
    """Verify the published directory without needing access to its mapping file."""

    directory = validate_verify_path(run_dir)
    manifest = _read_json(directory / MANIFEST_NAME, MAX_MANIFEST_BYTES)
    base_keys = {
        "schema_version",
        "tool_version",
        "status",
        "record_count",
        "artifacts",
    }
    status = manifest.get("status")
    if status == "pass":
        expected_keys = base_keys | {"mapping_sha256"}
        expected_artifacts = {PACK_NAME, PRIVACY_REPORT_NAME}
        mapping_digest = manifest.get("mapping_sha256")
        if not isinstance(mapping_digest, str) or not SHA256_RE.fullmatch(mapping_digest):
            raise ReviewPackError("Manifest mapping digest is invalid")
    elif status == "blocked":
        expected_keys = base_keys
        expected_artifacts = {PRIVACY_REPORT_NAME}
    else:
        raise ReviewPackError("Manifest status is invalid")
    if set(manifest) != expected_keys:
        raise ReviewPackError("Manifest fields do not match the schema")
    if manifest.get("schema_version") != MANIFEST_SCHEMA_VERSION:
        raise ReviewPackError("Manifest schema version is unsupported")
    if manifest.get("tool_version") != VERSION:
        raise ReviewPackError("Manifest tool version is unsupported")
    record_count = manifest.get("record_count")
    if (
        isinstance(record_count, bool)
        or not isinstance(record_count, int)
        or record_count < 0
        or record_count > MAX_RECORDS
    ):
        raise ReviewPackError("Manifest record count is invalid")
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, dict) or set(artifacts) != expected_artifacts:
        raise ReviewPackError("Manifest artifact set is invalid")
    for value in artifacts.values():
        _validate_artifact_record(value)

    actual_names = {entry.name for entry in directory.iterdir()}
    if actual_names != expected_artifacts | {MANIFEST_NAME}:
        raise ReviewPackError("Review directory contains an unexpected artifact")
    for name in expected_artifacts:
        path = directory / name
        artifact = artifacts[name]
        if path.stat().st_size != artifact["bytes"] or sha256_file(path) != artifact["sha256"]:
            raise ReviewPackError("Review artifact does not match the manifest")

    report = _read_json(directory / PRIVACY_REPORT_NAME, MAX_REPORT_BYTES)
    sanitized_report = _sanitize_privacy_report(report, record_count)
    if report != sanitized_report or report["status"] != status:
        raise ReviewPackError("Privacy report is inconsistent with the manifest")
    if status == "pass":
        _read_and_validate_pack(directory / PACK_NAME, record_count)
    return {"status": "verified", "pack_status": status, "records": record_count}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    prepare = subparsers.add_parser("prepare", help="Prepare a new external review pack")
    prepare.add_argument("input", type=Path)
    prepare.add_argument("--output-dir", required=True, type=Path)
    prepare.add_argument("--mapping-output", required=True, type=Path)
    prepare.add_argument("--authorization-id", required=True)

    verify = subparsers.add_parser("verify", help="Verify a published review pack")
    verify.add_argument("run_dir", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "prepare":
            result = prepare_review_pack(
                args.input,
                args.output_dir,
                mapping_output=args.mapping_output,
                authorization_id=args.authorization_id,
            )
            exit_code = 3 if result["status"] == "blocked" else 0
        else:
            result = verify_review_pack(args.run_dir)
            exit_code = 0
    except (OSError, ReviewPackError, RuntimeError):
        print("error: review pack operation failed", file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
