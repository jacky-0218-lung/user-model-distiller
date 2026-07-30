#!/usr/bin/env python3
"""Create or verify an integrity receipt for a staged Skill directory."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import stat
import sys
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


ALGORITHM = "user-model-distiller-bundle-v1"
FULL_SHA_RE = re.compile(r"^[0-9a-f]{40}$", re.I)
DIGEST_RE = re.compile(r"^[0-9a-f]{64}$", re.I)
REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
# A digest proves that the approved bytes did not change. It cannot prove that a
# reviewer saw all of them, so a bundle carrying characters the reviewer's editor
# hides but the agent still reads is refused before a receipt exists. Keep this
# class identical to normalize_sessions.DECEPTIVE_INVISIBLE_PATTERN and write it
# with escapes so this tool can never match its own source.
DECEPTIVE_INVISIBLE = re.compile(
    "["
    "\u00ad"  # soft hyphen
    "\u200b"  # zero-width space
    "\u202a-\u202e"  # bidi embedding and override controls
    "\u2060-\u2064"  # word joiner and invisible math operators
    "\u2066-\u2069"  # bidi isolate controls
    "\ufeff"  # zero-width no-break space / byte-order mark
    "\ufff9-\ufffb"  # interlinear annotation controls
    "\U000e0000-\U000e007f"  # Unicode Tag characters
    "]"
)


class BundleError(ValueError):
    """Raised when a bundle is unsafe or does not match its receipt."""


def has_reparse_attribute(file_attributes: int) -> bool:
    flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(file_attributes & flag)


def is_reparse_point(path: Path) -> bool:
    try:
        if has_reparse_attribute(int(getattr(path.lstat(), "st_file_attributes", 0))):
            return True
    except OSError:
        raise
    is_junction = getattr(path, "is_junction", None)
    return path.is_symlink() or bool(is_junction and is_junction())


def hash_file(path: Path) -> bytes:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.digest()


def bundle_records(root: Path) -> list[tuple[bytes, bytes, str]]:
    root = root.expanduser().absolute()
    if is_reparse_point(root) or not root.is_dir():
        raise BundleError(f"Bundle root must be a regular directory: {root}")
    records: list[tuple[bytes, bytes, str]] = []
    for path in root.rglob("*"):
        if is_reparse_point(path):
            raise BundleError(f"Refusing link or junction: {path.relative_to(root)}")
        mode = path.lstat().st_mode
        if stat.S_ISDIR(mode):
            continue
        if not stat.S_ISREG(mode):
            raise BundleError(f"Refusing non-regular file: {path.relative_to(root)}")
        relative = path.relative_to(root).as_posix()
        try:
            relative_bytes = relative.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise BundleError(f"Path is not valid UTF-8: {relative!r}") from exc
        records.append((relative_bytes, hash_file(path), relative))
    return sorted(records, key=lambda record: record[0])


def canonical_bundle_digest(root: Path) -> tuple[str, list[str]]:
    bundle = hashlib.sha256(ALGORITHM.encode("ascii") + b"\0")
    files: list[str] = []
    for relative_bytes, content_digest, relative in bundle_records(root):
        bundle.update(len(relative_bytes).to_bytes(8, "big"))
        bundle.update(relative_bytes)
        bundle.update(content_digest)
        files.append(relative)
    return bundle.hexdigest(), files


def scan_invisible_characters(root: Path) -> dict[str, Any]:
    """Refuse a bundle whose text hides characters from the approving reviewer."""
    root = root.expanduser().absolute()
    text_files = 0
    non_text_files = 0
    for _, _, relative in bundle_records(root):
        data = (root / relative).read_bytes()
        try:
            decoded = data.decode("utf-8")
        except UnicodeDecodeError:
            non_text_files += 1
            continue
        hidden = DECEPTIVE_INVISIBLE.search(decoded)
        if hidden:
            raise BundleError(
                f"Invisible or bidi control character "
                f"U+{ord(hidden.group()):04X} found: {relative}"
            )
        text_files += 1
    return {"status": "clean", "text_files": text_files, "non_text_files": non_text_files}


def build_receipt(
    root: Path,
    *,
    repository: str,
    origin: str,
    commit: str,
    destination: str,
) -> dict[str, Any]:
    repository = repository.strip()
    if not REPOSITORY_RE.fullmatch(repository):
        raise BundleError("Repository must be an owner/name identity")
    parsed_origin = urlparse(origin)
    try:
        origin_port = parsed_origin.port
    except ValueError as exc:
        raise BundleError("Origin contains an invalid port") from exc
    if (
        parsed_origin.scheme.lower() != "https"
        or parsed_origin.hostname is None
        or parsed_origin.hostname.casefold() != "github.com"
        or origin_port is not None
        or parsed_origin.username is not None
        or parsed_origin.password is not None
        or parsed_origin.params
        or parsed_origin.query
        or parsed_origin.fragment
    ):
        raise BundleError("Origin must be an exact github.com HTTPS repository URL")
    origin_path = parsed_origin.path.rstrip("/")
    if origin_path.lower().endswith(".git"):
        origin_path = origin_path[:-4]
    if origin_path.casefold() != "/" + repository.casefold():
        raise BundleError("Origin path does not match the repository identity")
    if not FULL_SHA_RE.fullmatch(commit):
        raise BundleError("Commit must be a full 40-character SHA")
    if not destination.strip():
        raise BundleError("Destination is required")
    destination_path = Path(destination).expanduser()
    if (
        not destination_path.is_absolute()
        or destination_path == Path(destination_path.anchor)
    ):
        raise BundleError("Destination must be an unambiguous absolute path")
    current = destination_path
    while True:
        if current.exists() and is_reparse_point(current):
            raise BundleError("Destination path contains a link or junction")
        parent = current.parent
        if parent == current:
            break
        current = parent
    invisible_character_scan = scan_invisible_characters(root)
    digest, files = canonical_bundle_digest(root)
    destination_exists = destination_path.exists()
    return {
        "schema_version": "1.1",
        "algorithm": ALGORITHM,
        "repository": repository,
        "origin": origin,
        "commit": commit.lower(),
        "bundle_digest": digest,
        "files": files,
        "invisible_character_scan": invisible_character_scan,
        "destination": destination,
        "destination_exists": destination_exists,
    }


def verify_digest(root: Path, expected: str) -> str:
    if not DIGEST_RE.fullmatch(expected):
        raise BundleError("Expected digest must contain 64 hexadecimal characters")
    actual, _ = canonical_bundle_digest(root)
    if not hmac.compare_digest(actual, expected.lower()):
        raise BundleError(f"Bundle digest mismatch: expected {expected.lower()}, got {actual}")
    return actual


def atomic_write_json(path: Path, data: dict[str, Any], overwrite: bool) -> None:
    if path.exists() and not overwrite:
        raise BundleError(f"Output exists; pass --overwrite to replace it: {path}")
    if path.is_symlink():
        raise BundleError(f"Refusing symbolic link output: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
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
            json.dump(data, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, path)
    finally:
        if temp_name and os.path.exists(temp_name):
            try:
                os.unlink(temp_name)
            except OSError:
                pass


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    receipt = subparsers.add_parser("receipt", help="Create an approval receipt")
    receipt.add_argument("root", type=Path, help="Staged Skill directory")
    receipt.add_argument("--repository", required=True)
    receipt.add_argument("--origin", required=True)
    receipt.add_argument("--commit", required=True)
    receipt.add_argument("--destination", required=True)
    receipt.add_argument("--output", type=Path)
    receipt.add_argument("--overwrite", action="store_true")

    verify = subparsers.add_parser("verify", help="Verify a staged or copied Skill")
    verify.add_argument("root", type=Path)
    verify.add_argument("--expected", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "receipt":
            result = build_receipt(
                args.root,
                repository=args.repository,
                origin=args.origin,
                commit=args.commit,
                destination=args.destination,
            )
            if args.output:
                atomic_write_json(args.output.resolve(), result, args.overwrite)
                result = {**result, "output": str(args.output)}
        else:
            result = {
                "status": "verified",
                "algorithm": ALGORITHM,
                "bundle_digest": verify_digest(args.root, args.expected),
                "invisible_character_scan": scan_invisible_characters(args.root),
            }
    except (OSError, BundleError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
