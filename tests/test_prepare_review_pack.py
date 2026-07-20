from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_ROOT = REPO_ROOT / "skills" / "user-model-distiller" / "scripts"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


review_pack = load_module(
    "prepare_review_pack", SCRIPT_ROOT / "prepare_review_pack.py"
)


SESSION_ID = "session-11111111111111111111"
MESSAGE_ID = "message-22222222222222222222"
AUTHORIZATION_ID = "external-review-approval-1"


def evidence_record(text: str = "Please keep answers concise.") -> dict:
    return {
        "schema_version": "1.0",
        "session_id": SESSION_ID,
        "message_id": MESSAGE_ID,
        "created_at": "2026-07-20",
        "score": 3,
        "kinds": ["explicit_preference"],
        "user_text": text,
        "context_message_id": None,
        "source": {
            "id": "source-33333333333333333333",
            "sha256": "4" * 64,
        },
        "provenance": {
            "role": "user",
            "direct": True,
            "suppressed_envelopes": [],
        },
        "truncated": False,
        "review_status": "unreviewed",
        "notice": "Candidate evidence only. Do not activate without user review.",
    }


def write_evidence(path: Path, text: str = "Please keep answers concise.") -> None:
    path.write_text(
        json.dumps(evidence_record(text), separators=(",", ":")) + "\n",
        encoding="utf-8",
    )


class PrivatePaths:
    def __init__(self, root: Path):
        self.source = root / "evidence.jsonl"
        self.pack_parent = root / "review-output"
        self.mapping_parent = root / "access-isolated"
        self.pack_parent.mkdir()
        self.destination = self.pack_parent / "one-time-pack"
        self.mapping = self.mapping_parent / "mapping.json"


class PrepareReviewPackTests(unittest.TestCase):
    def test_pass_publishes_minimum_pack_and_separate_mapping(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = PrivatePaths(Path(directory))
            write_evidence(paths.source)

            result = review_pack.prepare_review_pack(
                paths.source,
                paths.destination,
                mapping_output=paths.mapping,
                authorization_id=AUTHORIZATION_ID,
            )

            self.assertEqual(result, {"status": "pass", "records": 1})
            self.assertTrue(paths.mapping_parent.is_dir())
            review_pack._assert_private_mapping_directory(paths.mapping_parent)
            self.assertEqual(
                {path.name for path in paths.destination.iterdir()},
                {
                    review_pack.PACK_NAME,
                    review_pack.PRIVACY_REPORT_NAME,
                    review_pack.MANIFEST_NAME,
                },
            )
            pack_rows = [
                json.loads(line)
                for line in (paths.destination / review_pack.PACK_NAME)
                .read_text(encoding="utf-8")
                .splitlines()
            ]
            self.assertEqual(set(pack_rows[0]), {"review_id", "kinds", "text"})
            self.assertEqual(pack_rows[0]["kinds"], ["explicit_preference"])
            self.assertEqual(pack_rows[0]["text"], "Please keep answers concise.")

            mapping = json.loads(paths.mapping.read_text(encoding="utf-8"))
            self.assertEqual(mapping["authorization_id"], AUTHORIZATION_ID)
            self.assertEqual(
                mapping["mapping"][pack_rows[0]["review_id"]],
                {"session_id": SESSION_ID, "message_id": MESSAGE_ID},
            )
            manifest_text = (
                paths.destination / review_pack.MANIFEST_NAME
            ).read_text(encoding="utf-8")
            manifest = json.loads(manifest_text)
            self.assertEqual(
                manifest["mapping_sha256"],
                hashlib.sha256(paths.mapping.read_bytes()).hexdigest(),
            )
            self.assertNotIn(str(paths.mapping), manifest_text)
            self.assertNotIn(paths.mapping.name, manifest_text)
            self.assertNotIn(AUTHORIZATION_ID, manifest_text)

            published_text = "\n".join(
                path.read_text(encoding="utf-8") for path in paths.destination.iterdir()
            )
            self.assertNotIn(SESSION_ID, published_text)
            self.assertNotIn(MESSAGE_ID, published_text)
            self.assertNotIn(AUTHORIZATION_ID, published_text)
            self.assertEqual(
                review_pack.verify_review_pack(paths.destination)["status"], "verified"
            )

    def test_guard_receives_only_user_text_and_constant_identifiers(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = PrivatePaths(Path(directory))
            write_evidence(paths.source)
            original_scan = review_pack.privacy_guard.scan_records
            inspected = {}

            def inspect(path, mode):
                inspected["mode"] = mode
                inspected["path"] = Path(path)
                row = json.loads(Path(path).read_text(encoding="utf-8"))
                inspected["row"] = row
                return original_scan(path, mode)

            with mock.patch.object(
                review_pack.privacy_guard, "scan_records", side_effect=inspect
            ):
                review_pack.prepare_review_pack(
                    paths.source,
                    paths.destination,
                    mapping_output=paths.mapping,
                    authorization_id=AUTHORIZATION_ID,
                )

            self.assertEqual(inspected["mode"], "external-review")
            self.assertEqual(inspected["row"]["role"], "user")
            self.assertEqual(
                inspected["row"]["session_id"], review_pack.CONSTANT_SESSION_ID
            )
            self.assertEqual(
                inspected["row"]["message_id"], review_pack.CONSTANT_MESSAGE_ID
            )
            self.assertEqual(
                inspected["row"]["source"],
                {
                    "id": review_pack.CONSTANT_SOURCE_ID,
                    "sha256": review_pack.CONSTANT_SOURCE_HASH,
                },
            )
            self.assertNotEqual(inspected["row"]["session_id"], SESSION_ID)
            self.assertNotEqual(inspected["row"]["message_id"], MESSAGE_ID)
            self.assertFalse(inspected["path"].exists())

    def test_warning_blocks_and_never_creates_mapping_or_pack(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = PrivatePaths(Path(directory))
            write_evidence(paths.source, "Keep notes for project Alpha.")

            result = review_pack.prepare_review_pack(
                paths.source,
                paths.destination,
                mapping_output=paths.mapping,
                authorization_id=AUTHORIZATION_ID,
            )

            self.assertEqual(result["status"], "blocked")
            self.assertFalse(paths.mapping.exists())
            self.assertEqual(
                {path.name for path in paths.destination.iterdir()},
                {review_pack.PRIVACY_REPORT_NAME, review_pack.MANIFEST_NAME},
            )
            manifest = json.loads(
                (paths.destination / review_pack.MANIFEST_NAME).read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(manifest["status"], "blocked")
            self.assertNotIn("mapping_sha256", manifest)
            self.assertEqual(
                review_pack.verify_review_pack(paths.destination)["pack_status"],
                "blocked",
            )

    def test_unschemed_domains_block_pack_without_mapping(self):
        fixtures = (
            "Keep api.example.com. in the notes.",
            "Keep api\u3002example\uff0ecom in the notes.",
        )
        for text in fixtures:
            with self.subTest(text=text), tempfile.TemporaryDirectory() as directory:
                paths = PrivatePaths(Path(directory))
                write_evidence(paths.source, text)
                result = review_pack.prepare_review_pack(
                    paths.source,
                    paths.destination,
                    mapping_output=paths.mapping,
                    authorization_id=AUTHORIZATION_ID,
                )
                self.assertEqual(result["status"], "blocked")
                self.assertFalse(paths.mapping.exists())
                self.assertFalse(paths.mapping_parent.exists())

    def test_windows_acl_validation_rejects_foreign_or_inherited_access(self):
        current = "S-1-5-21-1000"
        private = {
            "current": current,
            "owner": current,
            "protected": True,
            "rules": [{"sid": current, "type": "Allow", "inherited": False}],
        }
        review_pack._validate_windows_acl_details(private)
        for mutation in (
            {**private, "protected": False},
            {**private, "owner": "S-1-5-21-2000"},
            {**private, "rules": [{"sid": current, "type": "Allow", "inherited": True}]},
            {
                **private,
                "rules": [
                    {"sid": current, "type": "Allow", "inherited": False},
                    {"sid": "S-1-1-0", "type": "Allow", "inherited": False},
                ],
            },
        ):
            with self.subTest(mutation=mutation), self.assertRaises(review_pack.ReviewPackError):
                review_pack._validate_windows_acl_details(mutation)

    def test_existing_shared_mapping_parent_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = PrivatePaths(Path(directory))
            write_evidence(paths.source)
            paths.mapping_parent.mkdir()
            if os.name != "nt":
                paths.mapping_parent.chmod(0o755)
            with self.assertRaises(review_pack.ReviewPackError):
                review_pack.validate_prepare_paths(
                    paths.source, paths.destination, paths.mapping
                )

    def test_mocked_blocker_cannot_publish_mapping(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = PrivatePaths(Path(directory))
            write_evidence(paths.source)
            report = {
                "status": "blocked",
                "decision": "block",
                "records_scanned": 1,
                "roles": {"user": 1, "assistant": 0, "other": 0},
                "blocker_count": 1,
                "warning_count": 0,
                "blockers": [{"code": "raw_secret", "records": 1}],
                "warnings": [],
            }
            with mock.patch.object(
                review_pack.privacy_guard, "scan_records", return_value=report
            ):
                result = review_pack.prepare_review_pack(
                    paths.source,
                    paths.destination,
                    mapping_output=paths.mapping,
                    authorization_id=AUTHORIZATION_ID,
                )
            self.assertEqual(result["status"], "blocked")
            self.assertFalse(paths.mapping.exists())

    def test_existing_and_nonisolated_outputs_are_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = PrivatePaths(Path(directory))
            write_evidence(paths.source)
            paths.destination.mkdir()
            with self.assertRaises(review_pack.ReviewPackError):
                review_pack.validate_prepare_paths(
                    paths.source, paths.destination, paths.mapping
                )

            paths.destination.rmdir()
            same_parent_mapping = paths.pack_parent / "mapping.json"
            with self.assertRaises(review_pack.ReviewPackError):
                review_pack.validate_prepare_paths(
                    paths.source, paths.destination, same_parent_mapping
                )

            descendant_mapping = paths.destination / "mapping.json"
            with self.assertRaises(review_pack.ReviewPackError):
                review_pack.validate_prepare_paths(
                    paths.source, paths.destination, descendant_mapping
                )

    def test_repository_local_output_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "evidence.jsonl"
            mapping_parent = root / "isolated"
            mapping_parent.mkdir()
            write_evidence(source)
            destination = REPO_ROOT / "forbidden-review-pack"
            self.assertFalse(destination.exists())
            with self.assertRaises(review_pack.ReviewPackError):
                review_pack.validate_prepare_paths(
                    source, destination, mapping_parent / "mapping.json"
                )

    def test_prepare_cli_never_echoes_content_or_identifiers(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = PrivatePaths(Path(directory))
            write_evidence(paths.source)
            stdout = io.StringIO()
            stderr = io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                exit_code = review_pack.main(
                    [
                        "prepare",
                        str(paths.source),
                        "--output-dir",
                        str(paths.destination),
                        "--mapping-output",
                        str(paths.mapping),
                        "--authorization-id",
                        AUTHORIZATION_ID,
                    ]
                )
            output = stdout.getvalue() + stderr.getvalue()
            self.assertEqual(exit_code, 0)
            self.assertNotIn(SESSION_ID, output)
            self.assertNotIn(MESSAGE_ID, output)
            self.assertNotIn(AUTHORIZATION_ID, output)
            self.assertNotIn("Please keep answers concise", output)


class VerifyReviewPackTests(unittest.TestCase):
    def test_verify_detects_pack_tampering(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = PrivatePaths(Path(directory))
            write_evidence(paths.source)
            review_pack.prepare_review_pack(
                paths.source,
                paths.destination,
                mapping_output=paths.mapping,
                authorization_id=AUTHORIZATION_ID,
            )
            with (paths.destination / review_pack.PACK_NAME).open(
                "a", encoding="utf-8"
            ) as handle:
                handle.write("{}\n")
            with self.assertRaises(review_pack.ReviewPackError):
                review_pack.verify_review_pack(paths.destination)

    def test_verify_rejects_mapping_inside_pack_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = PrivatePaths(Path(directory))
            write_evidence(paths.source)
            review_pack.prepare_review_pack(
                paths.source,
                paths.destination,
                mapping_output=paths.mapping,
                authorization_id=AUTHORIZATION_ID,
            )
            (paths.destination / "mapping.json").write_text(
                paths.mapping.read_text(encoding="utf-8"), encoding="utf-8"
            )
            with self.assertRaises(review_pack.ReviewPackError):
                review_pack.verify_review_pack(paths.destination)

    def test_unc_and_cloud_paths_are_detected(self):
        self.assertTrue(review_pack.is_unc_path(Path(r"\\server\share\pack")))
        self.assertTrue(review_pack.is_unc_path(Path("//server/share/pack")))
        self.assertTrue(
            review_pack.is_cloud_sync_path(Path("C:/Users/example/OneDrive/pack"))
        )
        self.assertFalse(review_pack.is_cloud_sync_path(Path("C:/private/pack")))

    def test_symlink_evidence_is_refused_when_supported(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = PrivatePaths(Path(directory))
            target = Path(directory) / "target.jsonl"
            write_evidence(target)
            try:
                os.symlink(target, paths.source)
            except (OSError, NotImplementedError):
                self.skipTest("symbolic links are not available")
            with self.assertRaises(review_pack.ReviewPackError):
                review_pack.validate_prepare_paths(
                    paths.source, paths.destination, paths.mapping
                )


if __name__ == "__main__":
    unittest.main()
