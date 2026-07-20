#!/usr/bin/env python3
"""Fail CI when privacy artifacts or insecure workflow constructs enter the repo."""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MAX_FILE_BYTES = 1_000_000
PRIVATE_TOP_LEVEL = {"work", "private", "data", "exports"}
FORBIDDEN_NAMES = (
    re.compile(r"^conversations(?:-\d+)?\.json$", re.I),
    re.compile(r"^(?:normalized|evidence)(?:[-_.].*)?\.jsonl$", re.I),
    re.compile(r"^(?:profile|user_model)(?:[-_.].*)?\.json$", re.I),
    re.compile(r"^user_model\.md$", re.I),
    re.compile(r"^\.env(?:\..*)?$", re.I),
)
ABSOLUTE_USER_PATH = re.compile(rb"[A-Za-z]:\\Users\\[^\\\r\n]+", re.I)
ACTION_USE = re.compile(r"^\s*uses:\s*([^\s]+)\s*$", re.M)
FULL_SHA = re.compile(r"^[^@]+@[0-9a-f]{40}(?:\s+#.*)?$", re.I)


def relevant_files():
    for path in ROOT.rglob("*"):
        try:
            relative = path.relative_to(ROOT)
        except ValueError:
            continue
        if relative.parts and relative.parts[0].casefold() in PRIVATE_TOP_LEVEL:
            continue
        if not path.is_file() or ".git" in path.parts or "__pycache__" in path.parts:
            continue
        yield path


def main() -> int:
    errors: list[str] = []
    for path in relevant_files():
        relative = path.relative_to(ROOT)
        if any(pattern.fullmatch(path.name) for pattern in FORBIDDEN_NAMES):
            errors.append(f"forbidden privacy artifact: {relative}")
        size = path.stat().st_size
        if size > MAX_FILE_BYTES:
            errors.append(f"file exceeds {MAX_FILE_BYTES} bytes: {relative}")
            continue
        data = path.read_bytes()
        if b"\x00" in data:
            errors.append(f"binary or NUL-containing file: {relative}")
        if path != Path(__file__) and ABSOLUTE_USER_PATH.search(data):
            errors.append(f"local user path found: {relative}")
        if relative.parts[:2] == (".github", "workflows"):
            text = data.decode("utf-8", errors="replace")
            if "pull_request_target:" in text:
                errors.append(f"pull_request_target is forbidden: {relative}")
            if not re.search(r"^permissions:\s*\n\s+contents:\s+read\s*$", text, re.M):
                errors.append(f"workflow lacks top-level read-only permissions: {relative}")
            for use in ACTION_USE.findall(text):
                if use.startswith("./"):
                    continue
                if not FULL_SHA.fullmatch(use):
                    errors.append(f"action is not pinned to a full SHA in {relative}: {use}")
            if "actions/checkout@" in text and "persist-credentials: false" not in text:
                errors.append(f"checkout must disable persisted credentials: {relative}")
            if relative.as_posix() == ".github/workflows/release.yml":
                required_release_markers = (
                    "git merge-base --is-ancestor",
                    "environment: release",
                    "id-token: write",
                    "attestations: write",
                    "actions/attest@",
                    "actions/upload-artifact@",
                    "actions/download-artifact@",
                )
                for marker in required_release_markers:
                    if marker not in text:
                        errors.append(f"release workflow lacks required control {marker!r}")
                build_split = text.split("\n  attest:", 1)
                if len(build_split) != 2:
                    errors.append("release workflow lacks a distinct attest job")
                else:
                    build_section, remainder = build_split
                    publish_split = remainder.split("\n  publish:", 1)
                    if len(publish_split) != 2:
                        errors.append("release workflow lacks a distinct publish job")
                        continue
                    attest_section, publish_section = publish_split
                    if "contents: write" in build_section:
                        errors.append("release build job must not have contents: write")
                    if "id-token: write" in build_section or "attestations: write" in build_section:
                        errors.append("release build job must not hold attestation credentials")
                    if "id-token: write" not in attest_section or "attestations: write" not in attest_section:
                        errors.append("release attest job lacks attestation credentials")
                    if "contents: write" in attest_section:
                        errors.append("release attest job must not have contents: write")
                    if "actions/checkout@" in attest_section or "python3 " in attest_section:
                        errors.append("privileged release attest job must not execute repository code")
                    if "contents: write" not in publish_section:
                        errors.append("release publish job lacks contents: write")
                    if "actions/checkout@" in publish_section or "python3 " in publish_section:
                        errors.append("privileged release publish job must not execute repository code")
    if errors:
        for error in errors:
            print(f"error: {error}", file=sys.stderr)
        return 1
    print("repository guard: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
