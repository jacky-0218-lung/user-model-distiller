#!/usr/bin/env python3
"""Run and verify a private, local-only user-model distillation preview."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import sys
import tempfile
from pathlib import Path
from typing import Any, Iterable


SCRIPT_DIR = Path(__file__).resolve().parent
SKILL_ROOT = SCRIPT_DIR.parent
REPO_ROOT = SCRIPT_DIR.parents[2]
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import collect_evidence  # noqa: E402
import normalize_sessions  # noqa: E402
import privacy_guard  # noqa: E402
import profile_tool  # noqa: E402


WORKFLOW_VERSION = "1.0"
MANIFEST_SCHEMA_VERSION = "1.0"
AUTHORIZATION_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
CLOUD_SYNC_PREFIXES = ("onedrive", "dropbox", "google drive", "googledrive", "icloud")
MANIFEST_NAME = "run-manifest.json"
NORMALIZED_NAME = "normalized.jsonl"
PRIVACY_REPORT_NAME = "privacy-report.json"
EVIDENCE_NAME = "evidence.jsonl"
PROFILE_NAME = "profile.json"
MAX_MANIFEST_BYTES = 1024 * 1024

COMPLETE_ARTIFACTS = {
    NORMALIZED_NAME,
    PRIVACY_REPORT_NAME,
    EVIDENCE_NAME,
    PROFILE_NAME,
}
BLOCKED_ARTIFACTS = {PRIVACY_REPORT_NAME}


class WorkflowError(ValueError):
    """Raised when workflow inputs or artifacts violate the safety contract."""


def is_unc_path(path: Path) -> bool:
    """Return whether a path uses a Windows UNC/network form."""
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
        raise WorkflowError("Unable to inspect a path safely") from exc
    attributes = int(getattr(details, "st_file_attributes", 0))
    return stat.S_ISLNK(details.st_mode) or has_reparse_attribute(attributes)


def _absolute(path: Path) -> Path:
    if is_unc_path(path):
        raise WorkflowError("UNC and network paths are not allowed")
    expanded = path.expanduser()
    if is_unc_path(expanded):
        raise WorkflowError("UNC and network paths are not allowed")
    return Path(os.path.abspath(os.fspath(expanded)))


def _assert_existing_components_safe(path: Path) -> None:
    current = path
    while True:
        if os.path.lexists(current) and _is_reparse(current):
            raise WorkflowError("Symbolic links and reparse points are not allowed")
        parent = current.parent
        if parent == current:
            return
        current = parent


def _assert_tree_safe(root: Path) -> None:
    _assert_existing_components_safe(root)
    if not root.is_dir():
        return
    pending = [root]
    while pending:
        directory = pending.pop()
        try:
            entries = list(os.scandir(directory))
        except OSError as exc:
            raise WorkflowError("Unable to inspect the input tree safely") from exc
        for entry in entries:
            entry_path = Path(entry.path)
            if _is_reparse(entry_path):
                raise WorkflowError("Symbolic links and reparse points are not allowed")
            try:
                if entry.is_dir(follow_symlinks=False):
                    pending.append(entry_path)
            except OSError as exc:
                raise WorkflowError("Unable to inspect the input tree safely") from exc


def _same_or_within(path: Path, root: Path) -> bool:
    path_text = os.path.normcase(os.path.abspath(os.fspath(path)))
    root_text = os.path.normcase(os.path.abspath(os.fspath(root)))
    try:
        return os.path.commonpath((path_text, root_text)) == root_text
    except ValueError:
        return False


def _paths_overlap(left: Path, right: Path) -> bool:
    return _same_or_within(left, right) or _same_or_within(right, left)


def validate_preview_paths(input_path: Path, output_dir: Path) -> tuple[Path, Path]:
    """Return canonical paths after enforcing the workflow path policy."""
    source = _absolute(input_path)
    destination = _absolute(output_dir)
    if is_cloud_sync_path(source) or is_cloud_sync_path(destination):
        raise WorkflowError("Cloud-synchronized paths are not allowed")
    if not os.path.lexists(source):
        raise WorkflowError("Input does not exist")
    _assert_tree_safe(source)
    _assert_existing_components_safe(destination)
    if os.path.lexists(destination):
        raise WorkflowError("Output directory already exists")
    if _same_or_within(destination, REPO_ROOT) or _same_or_within(destination, SKILL_ROOT):
        raise WorkflowError("Output must be outside the repository and skill tree")
    if _paths_overlap(source, destination):
        raise WorkflowError("Input and output paths must not overlap")
    if destination.parent == destination:
        raise WorkflowError("A filesystem root cannot be used as the output directory")
    return source, destination


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def source_set_digest(paths: Iterable[Path]) -> str:
    entries = sorted(
        (bytes.fromhex(sha256_file(path)), path.stat().st_size)
        for path in paths
    )
    digest = hashlib.sha256(b"user-model-distiller-source-set-v1\0")
    for content_digest, size in entries:
        digest.update(size.to_bytes(8, "big"))
        digest.update(content_digest)
    return digest.hexdigest()


def _module_version(module: Any, fallback: str = "1.0") -> str:
    for attribute in ("__version__", "VERSION", "SCHEMA_VERSION"):
        value = getattr(module, attribute, None)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return fallback


def _artifact_record(path: Path) -> dict[str, Any]:
    return {"sha256": sha256_file(path), "bytes": path.stat().st_size}


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
            json.dump(payload, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, path)
        try:
            path.chmod(0o600)
        except OSError:
            pass
    finally:
        if temporary_name and os.path.exists(temporary_name):
            try:
                os.unlink(temporary_name)
            except OSError:
                pass


def _validate_authorization_id(value: str) -> str:
    if not AUTHORIZATION_ID_RE.fullmatch(value):
        raise WorkflowError(
            "Authorization ID must contain 1-128 safe identifier characters"
        )
    return value


def _validate_privacy_report(report: Any) -> dict[str, Any]:
    if not isinstance(report, dict):
        raise WorkflowError("Privacy guard returned an invalid report")
    if report.get("status") not in {"pass", "blocked"}:
        raise WorkflowError("Privacy guard returned an invalid status")
    for key in ("blocker_count", "warning_count"):
        value = report.get(key)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise WorkflowError(f"Privacy guard returned an invalid {key}")
    if not isinstance(report.get("categories"), (dict, list)):
        raise WorkflowError("Privacy guard returned invalid categories")
    if not isinstance(report.get("records"), list):
        raise WorkflowError("Privacy guard returned invalid records")
    return report


def _normalized_records(
    inputs: Iterable[Path], privacy: str
) -> Iterable[dict[str, Any]]:
    for path in inputs:
        yield from normalize_sessions.parse_file(
            path,
            privacy,
            normalize_sessions.DEFAULT_MAX_MEMBER_BYTES,
            normalize_sessions.DEFAULT_MAX_TOTAL_BYTES,
        )


def _build_manifest(
    staging: Path,
    *,
    stage: str,
    authorization_id: str,
    privacy: str,
    counts: dict[str, int],
    artifact_names: set[str],
    input_digest: str,
) -> dict[str, Any]:
    artifacts = {
        name: _artifact_record(staging / name)
        for name in sorted(artifact_names)
    }
    return {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "workflow_version": WORKFLOW_VERSION,
        "stage": stage,
        "authorization_id": authorization_id,
        "source_set_digest": input_digest,
        "privacy": privacy,
        "counts": counts,
        "versions": {
            "normalize_sessions": _module_version(normalize_sessions),
            "privacy_guard": _module_version(privacy_guard),
            "collect_evidence": _module_version(collect_evidence),
            "profile_tool": _module_version(profile_tool),
        },
        "artifacts": artifacts,
    }


def run_preview(
    input_path: Path,
    output_dir: Path,
    *,
    authorization_id: str,
    privacy: str = "high",
) -> dict[str, Any]:
    """Run all preview stages in a sibling staging directory and publish atomically."""
    if privacy not in {"high", "standard"}:
        raise WorkflowError("Privacy must be 'high' or 'standard'")
    authorization_id = _validate_authorization_id(authorization_id)
    source, destination = validate_preview_paths(input_path, output_dir)

    destination.parent.mkdir(parents=True, exist_ok=True)
    _assert_existing_components_safe(destination.parent)
    if os.path.lexists(destination):
        raise WorkflowError("Output directory already exists")

    staging = Path(
        tempfile.mkdtemp(prefix=f".{destination.name}.staging-", dir=destination.parent)
    )
    published = False
    try:
        try:
            staging.chmod(0o700)
        except OSError:
            pass
        normalized_path = staging / NORMALIZED_NAME
        inputs = normalize_sessions.iter_inputs(
            source, normalize_sessions.DEFAULT_MAX_TOTAL_BYTES
        )
        input_digest = source_set_digest(inputs)
        message_count, redaction_count = normalize_sessions.atomic_write_jsonl(
            normalized_path,
            _normalized_records(inputs, privacy),
            overwrite=False,
        )

        privacy_report = _validate_privacy_report(
            privacy_guard.scan_records(normalized_path, mode="local")
        )
        privacy_report_path = staging / PRIVACY_REPORT_NAME
        privacy_guard.atomic_write_report(
            privacy_report_path, privacy_report, overwrite=False
        )

        counts = {
            "messages": message_count,
            "source_files": len(inputs),
            "redactions": redaction_count,
            "privacy_blockers": privacy_report["blocker_count"],
            "privacy_warnings": privacy_report["warning_count"],
            "evidence_candidates": 0,
            "profile_preferences": 0,
        }
        if privacy_report["status"] == "blocked":
            normalized_path.unlink()
            stage = "privacy_blocked"
            artifacts = BLOCKED_ARTIFACTS
        else:
            evidence_path = staging / EVIDENCE_NAME
            normalized_records = collect_evidence.read_records(normalized_path)
            evidence_count = collect_evidence.atomic_write(
                evidence_path,
                collect_evidence.build_evidence(
                    normalized_records, min_score=2, per_session=100
                ),
                overwrite=False,
            )
            profile_path = staging / PROFILE_NAME
            profile = profile_tool.empty_profile()
            profile_tool.atomic_write_json(profile_path, profile, overwrite=False)
            counts["evidence_candidates"] = evidence_count
            counts["profile_preferences"] = len(profile["preferences"])
            stage = "complete"
            artifacts = COMPLETE_ARTIFACTS

        manifest = _build_manifest(
            staging,
            stage=stage,
            authorization_id=authorization_id,
            privacy=privacy,
            counts=counts,
            artifact_names=artifacts,
            input_digest=input_digest,
        )
        _atomic_write_json(staging / MANIFEST_NAME, manifest)
        for artifact in staging.iterdir():
            try:
                artifact.chmod(0o600)
            except OSError:
                pass

        _assert_existing_components_safe(destination.parent)
        if os.path.lexists(destination):
            raise WorkflowError("Output directory already exists")
        os.replace(staging, destination)
        published = True
        return {"stage": stage, "counts": counts, "authorization_id": authorization_id}
    finally:
        if not published and os.path.lexists(staging):
            shutil.rmtree(staging, ignore_errors=True)


def _load_manifest(run_dir: Path) -> dict[str, Any]:
    manifest_path = run_dir / MANIFEST_NAME
    if not manifest_path.is_file() or manifest_path.is_symlink():
        raise WorkflowError("Run manifest is missing or unsafe")
    if manifest_path.stat().st_size > MAX_MANIFEST_BYTES:
        raise WorkflowError("Run manifest exceeds the size limit")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as exc:
        raise WorkflowError("Run manifest is invalid JSON") from exc
    if not isinstance(manifest, dict):
        raise WorkflowError("Run manifest must be an object")
    return manifest


def _validate_manifest_shape(manifest: dict[str, Any]) -> set[str]:
    expected_keys = {
        "schema_version",
        "workflow_version",
        "stage",
        "authorization_id",
        "source_set_digest",
        "privacy",
        "counts",
        "versions",
        "artifacts",
    }
    if set(manifest) != expected_keys:
        raise WorkflowError("Run manifest fields do not match the schema")
    if manifest.get("schema_version") != MANIFEST_SCHEMA_VERSION:
        raise WorkflowError("Unsupported run manifest schema")
    if manifest.get("workflow_version") != WORKFLOW_VERSION:
        raise WorkflowError("Unsupported workflow version")
    _validate_authorization_id(str(manifest.get("authorization_id", "")))
    if not isinstance(manifest.get("source_set_digest"), str) or not SHA256_RE.fullmatch(
        manifest["source_set_digest"]
    ):
        raise WorkflowError("Run manifest has an invalid source-set digest")
    if manifest.get("privacy") not in {"high", "standard"}:
        raise WorkflowError("Run manifest has an invalid privacy mode")
    stage = manifest.get("stage")
    if stage == "complete":
        required = COMPLETE_ARTIFACTS
    elif stage == "privacy_blocked":
        required = BLOCKED_ARTIFACTS
    else:
        raise WorkflowError("Run manifest has an invalid stage")

    counts = manifest.get("counts")
    expected_count_keys = {
        "messages",
        "source_files",
        "redactions",
        "privacy_blockers",
        "privacy_warnings",
        "evidence_candidates",
        "profile_preferences",
    }
    if not isinstance(counts, dict) or set(counts) != expected_count_keys:
        raise WorkflowError("Run manifest counts do not match the schema")
    if any(
        isinstance(value, bool) or not isinstance(value, int) or value < 0
        for value in counts.values()
    ):
        raise WorkflowError("Run manifest contains invalid counts")
    if counts["source_files"] < 1 or counts["messages"] < 1:
        raise WorkflowError("Run manifest contains empty source or message counts")
    if stage == "privacy_blocked" and (
        counts["privacy_blockers"] < 1
        or counts["evidence_candidates"] != 0
        or counts["profile_preferences"] != 0
    ):
        raise WorkflowError("Blocked run counts are inconsistent")

    versions = manifest.get("versions")
    expected_version_keys = {
        "normalize_sessions",
        "privacy_guard",
        "collect_evidence",
        "profile_tool",
    }
    if not isinstance(versions, dict) or set(versions) != expected_version_keys:
        raise WorkflowError("Run manifest versions do not match the schema")
    if any(not isinstance(value, str) or not value for value in versions.values()):
        raise WorkflowError("Run manifest contains invalid versions")

    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, dict) or set(artifacts) != required:
        raise WorkflowError("Run manifest artifact set is inconsistent")
    for name, record in artifacts.items():
        if name not in required or not isinstance(record, dict):
            raise WorkflowError("Run manifest contains an invalid artifact")
        if set(record) != {"sha256", "bytes"}:
            raise WorkflowError("Run manifest artifact fields are invalid")
        if not isinstance(record.get("sha256"), str) or not SHA256_RE.fullmatch(
            record["sha256"]
        ):
            raise WorkflowError("Run manifest contains an invalid artifact hash")
        size = record.get("bytes")
        if isinstance(size, bool) or not isinstance(size, int) or size < 0:
            raise WorkflowError("Run manifest contains an invalid artifact size")
    return required


def verify_run(run_dir: Path) -> dict[str, Any]:
    """Validate path safety, required artifacts, sizes, and SHA-256 digests."""
    directory = _absolute(run_dir)
    if not directory.is_dir():
        raise WorkflowError("Run directory does not exist")
    _assert_tree_safe(directory)
    manifest = _load_manifest(directory)
    required = _validate_manifest_shape(manifest)

    actual_names: set[str] = set()
    for entry in directory.iterdir():
        if not entry.is_file():
            raise WorkflowError("Run directory contains an unexpected entry")
        actual_names.add(entry.name)
    if actual_names != required | {MANIFEST_NAME}:
        raise WorkflowError("Run directory artifact set is inconsistent")

    for name in required:
        path = directory / name
        record = manifest["artifacts"][name]
        if path.stat().st_size != record["bytes"]:
            raise WorkflowError(f"Artifact size mismatch: {name}")
        if sha256_file(path) != record["sha256"]:
            raise WorkflowError(f"Artifact hash mismatch: {name}")
    return {
        "status": "verified",
        "stage": manifest["stage"],
        "artifacts": len(required),
        "authorization_id": manifest["authorization_id"],
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    preview = subparsers.add_parser("preview", help="Create a private review preview")
    preview.add_argument("input", type=Path)
    preview.add_argument("--output-dir", required=True, type=Path)
    preview.add_argument("--authorization-id", required=True)
    preview.add_argument("--privacy", choices=("high", "standard"), default="high")

    verify = subparsers.add_parser("verify", help="Verify a published preview")
    verify.add_argument("run_dir", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "preview":
            result = run_preview(
                args.input,
                args.output_dir,
                authorization_id=args.authorization_id,
                privacy=args.privacy,
            )
            exit_code = 3 if result["stage"] == "privacy_blocked" else 0
        else:
            result = verify_run(args.run_dir)
            exit_code = 0
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
