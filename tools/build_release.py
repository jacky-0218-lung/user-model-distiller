#!/usr/bin/env python3
"""Build and verify a deterministic, path-free release bundle for the Skill."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
SKILL_ROOT = REPO_ROOT / "skills" / "user-model-distiller"
MAX_FILES = 1_000
MAX_FILE_BYTES = 2_000_000
MAX_TOTAL_BYTES = 20_000_000
MAX_MANIFEST_BYTES = 2_000_000
MAX_RELEASE_ARTIFACT_BYTES = 50_000_000
VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$")
SKIP_PARTS = {"__pycache__"}
SKIP_SUFFIXES = {".pyc", ".pyo"}
ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)
EXPECTED_OUTPUTS = {
    "archive",
    "sbom",
    "checksums",
}
BUILDER_ID = "user-model-distiller-release-builder-1.1"
CANONICAL_TEXT_SUFFIXES = {
    ".json",
    ".md",
    ".py",
    ".toml",
    ".txt",
    ".yaml",
    ".yml",
}
CANONICAL_TEXT_NAMES = {"LICENSE"}


class ReleaseError(ValueError):
    """Raised when a release cannot be safely built or verified."""


class DuplicateKeyError(ValueError):
    """Raised for ambiguous JSON objects."""


def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateKeyError("duplicate JSON key")
        result[key] = value
    return result


def reject_constant(_value: str) -> None:
    raise ValueError("non-finite JSON number")


def is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def is_reparse_point(path: Path) -> bool:
    try:
        info = path.lstat()
    except OSError:
        raise
    flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    attributes = int(getattr(info, "st_file_attributes", 0))
    is_junction = getattr(path, "is_junction", None)
    return bool(attributes & flag) or path.is_symlink() or bool(is_junction and is_junction())


def assert_existing_chain_safe(path: Path) -> None:
    current = path
    while True:
        if current.exists() and is_reparse_point(current):
            raise ReleaseError("Release paths must not contain links or reparse points")
        parent = current.parent
        if parent == current:
            return
        current = parent


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha1_bytes(data: bytes) -> str:
    return hashlib.sha1(data, usedforsecurity=False).hexdigest()


def read_version() -> str:
    text = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r'^version\s*=\s*"([^"]+)"\s*$', text, re.MULTILINE)
    if not match or not VERSION_RE.fullmatch(match.group(1)):
        raise ReleaseError("pyproject.toml must contain a valid semantic version")
    return match.group(1)


def source_date(source_date_epoch: int) -> str:
    if source_date_epoch < 0:
        raise ReleaseError("SOURCE_DATE_EPOCH must be non-negative")
    try:
        value = datetime.fromtimestamp(source_date_epoch, timezone.utc)
    except (OverflowError, OSError, ValueError) as exc:
        raise ReleaseError("SOURCE_DATE_EPOCH is outside the supported range") from exc
    return value.isoformat(timespec="seconds").replace("+00:00", "Z")


def canonical_source_bytes(name: str, data: bytes) -> bytes:
    path = PurePosixPath(name)
    if path.name not in CANONICAL_TEXT_NAMES and path.suffix.lower() not in CANONICAL_TEXT_SUFFIXES:
        return data
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ReleaseError(f"Canonical text source is not UTF-8: {name}") from exc
    return text.replace("\r\n", "\n").replace("\r", "\n").encode("utf-8")


def collect_files() -> list[tuple[str, bytes]]:
    root = SKILL_ROOT.resolve(strict=True)
    if is_reparse_point(root) or not root.is_dir():
        raise ReleaseError("Skill root must be a regular directory")
    records: list[tuple[str, bytes]] = []
    total = 0
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        relative_path = path.relative_to(root)
        if any(part in SKIP_PARTS for part in relative_path.parts) or path.suffix in SKIP_SUFFIXES:
            continue
        if is_reparse_point(path):
            raise ReleaseError(f"Refusing link or junction: {relative_path.as_posix()}")
        mode = path.lstat().st_mode
        if stat.S_ISDIR(mode):
            continue
        if not stat.S_ISREG(mode):
            raise ReleaseError(f"Refusing non-regular file: {relative_path.as_posix()}")
        size = path.stat().st_size
        if size > MAX_FILE_BYTES:
            raise ReleaseError(f"Source file exceeds {MAX_FILE_BYTES} bytes: {relative_path.as_posix()}")
        archive_name = (PurePosixPath("user-model-distiller") / relative_path.as_posix()).as_posix()
        data = canonical_source_bytes(archive_name, path.read_bytes())
        total += len(data)
        if total > MAX_TOTAL_BYTES:
            raise ReleaseError(f"Skill exceeds {MAX_TOTAL_BYTES} total bytes")
        records.append((archive_name, data))
        if len(records) > MAX_FILES:
            raise ReleaseError(f"Skill exceeds {MAX_FILES} files")
    if not records:
        raise ReleaseError("Skill contains no release files")
    license_path = REPO_ROOT / "LICENSE"
    if (
        not license_path.is_file()
        or is_reparse_point(license_path)
        or license_path.stat().st_size > MAX_FILE_BYTES
    ):
        raise ReleaseError("Repository license is missing or unsafe")
    license_name = "user-model-distiller/LICENSE"
    if any(name == license_name for name, _data in records):
        raise ReleaseError("Skill tree unexpectedly shadows the release license")
    records.append(
        (license_name, canonical_source_bytes(license_name, license_path.read_bytes()))
    )
    records.sort(key=lambda item: item[0])
    return records


def canonical_tree_digest(records: list[tuple[str, bytes]]) -> str:
    digest = hashlib.sha256(b"user-model-distiller-release-tree-v1\0")
    for name, data in records:
        encoded = name.encode("utf-8")
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
        digest.update(bytes.fromhex(sha256_bytes(data)))
    return digest.hexdigest()


def zip_bytes(records: list[tuple[str, bytes]]) -> bytes:
    with tempfile.SpooledTemporaryFile(max_size=MAX_TOTAL_BYTES * 2) as handle:
        with zipfile.ZipFile(handle, mode="w", compression=zipfile.ZIP_STORED) as archive:
            for name, data in records:
                info = zipfile.ZipInfo(name, date_time=ZIP_TIMESTAMP)
                info.create_system = 3
                info.external_attr = 0o100644 << 16
                info.compress_type = zipfile.ZIP_STORED
                archive.writestr(info, data)
        handle.seek(0)
        return handle.read()


def spdx_document(
    records: list[tuple[str, bytes]],
    *,
    version: str,
    tree_digest: str,
    created: str,
) -> dict[str, Any]:
    files: list[dict[str, Any]] = []
    verification_hashes: list[str] = []
    relationships: list[dict[str, str]] = []
    for index, (name, data) in enumerate(records, start=1):
        spdx_id = f"SPDXRef-File-{index}"
        sha1 = sha1_bytes(data)
        verification_hashes.append(sha1)
        files.append(
            {
                "SPDXID": spdx_id,
                "fileName": f"./{name}",
                "checksums": [
                    {"algorithm": "SHA1", "checksumValue": sha1},
                    {"algorithm": "SHA256", "checksumValue": sha256_bytes(data)},
                ],
                "licenseConcluded": "NOASSERTION",
                "copyrightText": "NOASSERTION",
            }
        )
        relationships.append(
            {
                "spdxElementId": "SPDXRef-Package",
                "relationshipType": "CONTAINS",
                "relatedSpdxElement": spdx_id,
            }
        )
    package_verification = hashlib.sha1(
        "".join(sorted(verification_hashes)).encode("ascii"), usedforsecurity=False
    ).hexdigest()
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"user-model-distiller-{version}",
        "documentNamespace": (
            f"https://spdx.org/spdxdocs/user-model-distiller-{version}-{tree_digest}"
        ),
        "creationInfo": {
            "created": created,
            "creators": [f"Tool: {BUILDER_ID}"],
        },
        "documentDescribes": ["SPDXRef-Package"],
        "packages": [
            {
                "SPDXID": "SPDXRef-Package",
                "name": "user-model-distiller",
                "versionInfo": version,
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": True,
                "licenseConcluded": "Apache-2.0",
                "licenseDeclared": "Apache-2.0",
                "copyrightText": "NOASSERTION",
                "packageVerificationCode": {
                    "packageVerificationCodeValue": package_verification,
                },
            }
        ],
        "files": files,
        "relationships": relationships,
    }


def canonical_json(data: Any) -> bytes:
    return (json.dumps(data, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")


def write_new(path: Path, data: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        try:
            path.unlink()
        except OSError:
            pass
        raise


def validate_output_parent(output_dir: Path) -> tuple[Path, Path]:
    requested = output_dir.expanduser().absolute()
    repo = REPO_ROOT.resolve()
    if is_relative_to(requested, repo):
        raise ReleaseError("Release output must be outside the repository")
    if requested.exists():
        raise ReleaseError("Release output directory must not already exist")
    parent = requested.parent.resolve(strict=True)
    assert_existing_chain_safe(requested.parent.absolute())
    if is_relative_to(parent, repo) or is_reparse_point(parent):
        raise ReleaseError("Release output parent must be outside the repository and not a link")
    return requested, parent


def build_release(
    output_dir: Path,
    *,
    source_date_epoch: int = 0,
    expected_tag: str | None = None,
) -> dict[str, Any]:
    output, parent = validate_output_parent(output_dir)
    records = collect_files()
    version = read_version()
    if expected_tag is not None and expected_tag != f"v{version}":
        raise ReleaseError(f"Release tag must exactly match v{version}")
    created = source_date(source_date_epoch)
    tree_digest = canonical_tree_digest(records)
    archive_name = f"user-model-distiller-{version}.zip"
    sbom_name = f"user-model-distiller-{version}.spdx.json"
    archive = zip_bytes(records)
    sbom = canonical_json(
        spdx_document(records, version=version, tree_digest=tree_digest, created=created)
    )
    checksum_lines = [
        f"{sha256_bytes(archive)}  {archive_name}",
        f"{sha256_bytes(sbom)}  {sbom_name}",
    ]
    checksums = ("\n".join(checksum_lines) + "\n").encode("ascii")
    artifacts = {
        "archive": {"name": archive_name, "sha256": sha256_bytes(archive), "size": len(archive)},
        "sbom": {"name": sbom_name, "sha256": sha256_bytes(sbom), "size": len(sbom)},
        "checksums": {"name": "SHA256SUMS", "sha256": sha256_bytes(checksums), "size": len(checksums)},
    }
    manifest = {
        "schema_version": "1.0",
        "builder": BUILDER_ID,
        "package": "user-model-distiller",
        "version": version,
        "source_date_epoch": source_date_epoch,
        "source_tree_sha256": tree_digest,
        "source_files": [
            {"path": name, "sha256": sha256_bytes(data), "size": len(data)}
            for name, data in records
        ],
        "artifacts": artifacts,
    }
    manifest_bytes = canonical_json(manifest)
    stage = Path(tempfile.mkdtemp(prefix=f".{output.name}.", dir=parent))
    try:
        write_new(stage / archive_name, archive)
        write_new(stage / sbom_name, sbom)
        write_new(stage / "SHA256SUMS", checksums)
        write_new(stage / "release-manifest.json", manifest_bytes)
        os.replace(stage, output)
    except Exception:
        for path in sorted(stage.glob("*"), reverse=True):
            try:
                path.unlink()
            except OSError:
                pass
        try:
            stage.rmdir()
        except OSError:
            pass
        raise
    return {"status": "built", "output": str(output), **manifest}


def safe_manifest(path: Path) -> dict[str, Any]:
    if (
        not path.is_file()
        or is_reparse_point(path)
        or path.stat().st_size > MAX_MANIFEST_BYTES
    ):
        raise ReleaseError("Release manifest is missing or unsafe")
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=strict_object,
            parse_constant=reject_constant,
        )
    except (OSError, UnicodeError, json.JSONDecodeError, DuplicateKeyError, ValueError) as exc:
        raise ReleaseError("Release manifest is missing or invalid") from exc
    if not isinstance(value, dict):
        raise ReleaseError("Release manifest must be an object")
    return value


def verify_release(output_dir: Path) -> dict[str, Any]:
    root = output_dir.expanduser().resolve(strict=True)
    if not root.is_dir() or is_reparse_point(root):
        raise ReleaseError("Release directory must be a regular directory")
    manifest = safe_manifest(root / "release-manifest.json")
    if set(manifest) != {
        "schema_version",
        "builder",
        "package",
        "version",
        "source_date_epoch",
        "source_tree_sha256",
        "source_files",
        "artifacts",
    }:
        raise ReleaseError("Release manifest has unexpected or missing fields")
    if manifest.get("schema_version") != "1.0":
        raise ReleaseError("Release manifest schema version is unsupported")
    if manifest.get("builder") != BUILDER_ID:
        raise ReleaseError("Release manifest builder identity is invalid")
    if manifest.get("package") != "user-model-distiller":
        raise ReleaseError("Release manifest package identity is invalid")
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, dict) or set(artifacts) != EXPECTED_OUTPUTS:
        raise ReleaseError("Release manifest artifact set is invalid")
    allowed = {"release-manifest.json"}
    for kind in sorted(EXPECTED_OUTPUTS):
        entry = artifacts[kind]
        if not isinstance(entry, dict) or set(entry) != {"name", "sha256", "size"}:
            raise ReleaseError(f"Invalid artifact entry: {kind}")
        name = entry["name"]
        if not isinstance(name, str) or PurePosixPath(name).name != name:
            raise ReleaseError(f"Invalid artifact name: {kind}")
        artifact = root / name
        if not artifact.is_file() or is_reparse_point(artifact):
            raise ReleaseError(f"Missing regular artifact: {name}")
        if (
            isinstance(entry["size"], bool)
            or not isinstance(entry["size"], int)
            or entry["size"] < 0
            or entry["size"] > MAX_RELEASE_ARTIFACT_BYTES
        ):
            raise ReleaseError(f"Artifact size is invalid: {name}")
        if not isinstance(entry["sha256"], str) or not re.fullmatch(
            r"[0-9a-f]{64}", entry["sha256"]
        ):
            raise ReleaseError(f"Artifact digest is invalid: {name}")
        data = artifact.read_bytes()
        if len(data) != entry["size"] or sha256_bytes(data) != entry["sha256"]:
            raise ReleaseError(f"Artifact hash or size mismatch: {name}")
        allowed.add(name)
    version = manifest.get("version")
    if not isinstance(version, str) or not VERSION_RE.fullmatch(version):
        raise ReleaseError("Release manifest version is invalid")
    if artifacts["archive"]["name"] != f"user-model-distiller-{version}.zip":
        raise ReleaseError("Archive name does not match the release version")
    if artifacts["sbom"]["name"] != f"user-model-distiller-{version}.spdx.json":
        raise ReleaseError("SBOM name does not match the release version")
    if artifacts["checksums"]["name"] != "SHA256SUMS":
        raise ReleaseError("Checksum artifact name is invalid")
    actual = {path.name for path in root.iterdir() if path.is_file()}
    if actual != allowed or any(path.is_dir() for path in root.iterdir()):
        raise ReleaseError("Release directory contains unexpected artifacts")
    checksums = (root / artifacts["checksums"]["name"]).read_text(encoding="ascii")
    expected_lines = {
        f"{artifacts['archive']['sha256']}  {artifacts['archive']['name']}",
        f"{artifacts['sbom']['sha256']}  {artifacts['sbom']['name']}",
    }
    if set(checksums.splitlines()) != expected_lines:
        raise ReleaseError("SHA256SUMS does not match the manifest")
    archive_path = root / artifacts["archive"]["name"]
    source_files = manifest.get("source_files")
    if not isinstance(source_files, list) or not source_files:
        raise ReleaseError("Source file manifest is invalid")
    expected_files: dict[str, dict[str, Any]] = {}
    ordered_names: list[str] = []
    for entry in source_files:
        if not isinstance(entry, dict) or set(entry) != {"path", "sha256", "size"}:
            raise ReleaseError("Source file manifest entry is invalid")
        name = entry.get("path")
        digest = entry.get("sha256")
        size = entry.get("size")
        if (
            not isinstance(name, str)
            or not name.startswith("user-model-distiller/")
            or PurePosixPath(name).is_absolute()
            or ".." in PurePosixPath(name).parts
            or not isinstance(digest, str)
            or not re.fullmatch(r"[0-9a-f]{64}", digest)
            or isinstance(size, bool)
            or not isinstance(size, int)
            or size < 0
        ):
            raise ReleaseError("Source file manifest entry is invalid")
        ordered_names.append(name)
        expected_files[name] = entry
    if len(expected_files) != len(source_files) or ordered_names != sorted(ordered_names):
        raise ReleaseError("Source file manifest contains duplicates or invalid entries")
    archive_records: list[tuple[str, bytes]] = []
    with zipfile.ZipFile(archive_path, "r") as archive:
        infos = archive.infolist()
        if len(infos) != len(expected_files) or len({info.filename for info in infos}) != len(infos):
            raise ReleaseError("Archive file set is invalid")
        if len(infos) > MAX_FILES or sum(info.file_size for info in infos) > MAX_TOTAL_BYTES:
            raise ReleaseError("Archive exceeds release limits")
        for info in infos:
            if (
                info.filename not in expected_files
                or info.is_dir()
                or info.file_size > MAX_FILE_BYTES
                or info.compress_type != zipfile.ZIP_STORED
                or info.flag_bits & 0x1
            ):
                raise ReleaseError("Archive contains an unexpected path")
            data = archive.read(info)
            expected = expected_files[info.filename]
            if len(data) != expected.get("size") or sha256_bytes(data) != expected.get("sha256"):
                raise ReleaseError(f"Archive entry mismatch: {info.filename}")
            archive_records.append((info.filename, data))
    archive_records.sort(key=lambda item: item[0])
    if canonical_tree_digest(archive_records) != manifest.get("source_tree_sha256"):
        raise ReleaseError("Source tree digest does not match the archive")
    if zip_bytes(archive_records) != archive_path.read_bytes():
        raise ReleaseError("Archive metadata or ordering is not deterministic")
    epoch = manifest.get("source_date_epoch")
    if isinstance(epoch, bool) or not isinstance(epoch, int):
        raise ReleaseError("Source date epoch is invalid")
    expected_sbom = canonical_json(
        spdx_document(
            archive_records,
            version=version,
            tree_digest=manifest["source_tree_sha256"],
            created=source_date(epoch),
        )
    )
    if expected_sbom != (root / artifacts["sbom"]["name"]).read_bytes():
        raise ReleaseError("SBOM is inconsistent with the release archive")
    return {
        "status": "verified",
        "package": manifest["package"],
        "version": manifest["version"],
        "source_tree_sha256": manifest["source_tree_sha256"],
        "artifacts": artifacts,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    build = subparsers.add_parser("build", help="Build a fresh deterministic release directory")
    build.add_argument("--output-dir", required=True, type=Path)
    build.add_argument(
        "--source-date-epoch",
        type=int,
        default=int(os.environ.get("SOURCE_DATE_EPOCH", "0")),
    )
    build.add_argument("--expected-tag", help="Require an exact v<pyproject-version> release tag")
    verify = subparsers.add_parser("verify", help="Verify an existing release directory")
    verify.add_argument("release_dir", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "build":
            result = build_release(
                args.output_dir,
                source_date_epoch=args.source_date_epoch,
                expected_tag=args.expected_tag,
            )
        else:
            result = verify_release(args.release_dir)
    except (OSError, ReleaseError, zipfile.BadZipFile) as exc:
        print(f"error: {exc}", file=os.sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
