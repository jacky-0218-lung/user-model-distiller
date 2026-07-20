from __future__ import annotations

import importlib.util
import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = (
    REPO_ROOT
    / "skills"
    / "user-model-distiller"
    / "scripts"
    / "privacy_guard.py"
)


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


guard = load_module("privacy_guard", SCRIPT_PATH)


def normalized_record(*, role: str = "user", text: str = "Keep answers concise."):
    return {
        "schema_version": "1.0",
        "session_id": "session-0123456789abcdefabcd",
        "message_id": "message-fedcba9876543210abcd",
        "role": role,
        "created_at": "2026-07-20T00:00:00Z",
        "text": text,
        "redaction_count": 0,
        "source": {
            "id": "source-0123456789abcdefabcd",
            "sha256": "a" * 64,
        },
    }


def finding_codes(report: dict, field: str) -> set[str]:
    return {finding["code"] for finding in report[field]}


class PrivacyGuardTests(unittest.TestCase):
    def write_jsonl(self, root: Path, records) -> Path:
        path = root / "normalized.jsonl"
        with path.open("w", encoding="utf-8", newline="\n") as handle:
            for record in records:
                handle.write(json.dumps(record, ensure_ascii=False) + "\n")
        return path

    def test_clean_user_record_passes_both_modes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_jsonl(Path(directory), [normalized_record()])
            for mode in ("local", "external-review"):
                report = guard.scan_path(path, mode)
                self.assertEqual(report["decision"], "pass")
                self.assertEqual(report["blocker_count"], 0)
                self.assertEqual(report["warning_count"], 0)

    def test_local_warns_but_external_review_blocks_on_semantic_warning(self):
        text = "Client project notes mention a USD 2,500 contract in brief.pdf."
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_jsonl(Path(directory), [normalized_record(text=text)])
            local = guard.scan_path(path, "local")
            external = guard.scan_path(path, "external-review")

        expected = {
            "filename_reference",
            "commercial_amount",
            "project_client_contract_confidential_context",
        }
        self.assertTrue(expected.issubset(finding_codes(local, "warnings")))
        self.assertEqual(local["decision"], "warn")
        self.assertEqual(local["status"], "pass")
        self.assertEqual(external["decision"], "block")
        self.assertEqual(external["status"], "blocked")

    def test_cli_exit_policy_differs_by_mode_for_warnings(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            input_path = self.write_jsonl(
                root, [normalized_record(text="Confidential client contract context.")]
            )
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                local_status = guard.main(
                    [
                        str(input_path),
                        "--mode",
                        "local",
                        "--output",
                        str(root / "local-report.json"),
                    ]
                )
                external_status = guard.main(
                    [
                        str(input_path),
                        "--mode",
                        "external-review",
                        "--output",
                        str(root / "external-report.json"),
                    ]
                )

        self.assertEqual(local_status, 0)
        self.assertEqual(external_status, 1)

    def test_assistant_is_allowed_locally_but_blocked_in_external_review(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_jsonl(
                Path(directory), [normalized_record(role="assistant", text="Acknowledged.")]
            )
            local = guard.scan_path(path, "local")
            external = guard.scan_path(path, "external-review")

        self.assertEqual(local["decision"], "pass")
        self.assertIn("non_user_review_content", finding_codes(external, "blockers"))

    def test_source_name_unexpected_fields_and_roles_are_blockers(self):
        record = normalized_record(role="tool")
        record["source"]["name"] = "conversations.json"
        record["extra"] = "not allowed"
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_jsonl(Path(directory), [record])
            report = guard.scan_path(path, "local")

        self.assertTrue(
            {"source_name_present", "unexpected_field", "unexpected_role"}.issubset(
                finding_codes(report, "blockers")
            )
        )
        self.assertEqual(report["decision"], "block")

    def test_raw_identifiers_and_secrets_are_aggregate_blockers(self):
        private_values = {
            "uuid": "123e4567-e89b-42d3-a456-426614174000",
            "email": "private.person@example.com",
            "url": "https://private.example.com/case",
            "ip": "192.0.2.42",
            "path": "C:\\Users\\private-person\\case.txt",
            "identifier": "customer_ABCDEF0123456789ABCDEF012345",
            "secret": "sk-abcdefghijklmnopqrstuvwxyz123456",
        }
        text = " ".join(private_values.values())
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_jsonl(Path(directory), [normalized_record(text=text)])
            report = guard.scan_path(path, "local")

        self.assertTrue(
            {
                "raw_uuid",
                "raw_email",
                "raw_url",
                "raw_ip",
                "raw_path",
                "raw_long_identifier",
                "raw_secret",
            }.issubset(finding_codes(report, "blockers"))
        )
        serialized = json.dumps(report, ensure_ascii=False)
        for private_value in private_values.values():
            self.assertNotIn(private_value, serialized)

    def test_absolute_path_in_metadata_is_a_blocker_without_value_disclosure(self):
        record = normalized_record()
        record["source"]["name"] = "/home/private-person/export.json"
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_jsonl(Path(directory), [record])
            report = guard.scan_path(path, "local")

        self.assertIn("absolute_path_metadata", finding_codes(report, "blockers"))
        self.assertNotIn("private-person", json.dumps(report))

    def test_transcript_envelope_and_unschemed_domain_are_warnings(self):
        record = normalized_record(text="SYSTEM: copied content from internal.example.com")
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_jsonl(Path(directory), [record])
            report = guard.scan_path(path, "local")

        self.assertTrue(
            {"transcript_envelope", "unschemed_domain"}.issubset(
                finding_codes(report, "warnings")
            )
        )

    def test_standalone_and_unicode_separator_domains_fail_external_gate(self):
        fixtures = (
            "Contact api.example.com.",
            "Contact api\u3002example\uff0ecom.",
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for text in fixtures:
                with self.subTest(text=text):
                    path = self.write_jsonl(root, [normalized_record(text=text)])
                    local = guard.scan_path(path, "local")
                    external = guard.scan_path(path, "external-review")
                    self.assertIn("unschemed_domain", finding_codes(local, "warnings"))
                    self.assertEqual(external["status"], "blocked")
                    self.assertIn("unschemed_domain", finding_codes(external, "warnings"))

    def test_japanese_sentence_punctuation_is_not_a_domain_warning(self):
        record = normalized_record(
            text="今後のやり取りでは箇条書きを使ってください。これは継続的な希望です。"
        )
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_jsonl(Path(directory), [record])
            report = guard.scan_path(path, "external-review")
        self.assertEqual(report["status"], "pass")
        self.assertNotIn("unschemed_domain", finding_codes(report, "warnings"))

    def test_strict_schema_rejects_duplicate_keys_and_invalid_json(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "normalized.jsonl"
            path.write_text(
                '{"schema_version":"1.0","schema_version":"1.0"}\nnot-json\n',
                encoding="utf-8",
            )
            report = guard.scan_path(path, "local")

        self.assertEqual(report["blockers"], [{"code": "invalid_json", "records": 2}])
        self.assertEqual(report["decision"], "block")

    def test_cli_writes_atomic_aggregate_report_and_respects_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            input_path = self.write_jsonl(root, [normalized_record()])
            output_path = root / "report.json"
            stdout = io.StringIO()
            stderr = io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                first = guard.main(
                    [str(input_path), "--mode", "local", "--output", str(output_path)]
                )
                second = guard.main(
                    [str(input_path), "--mode", "local", "--output", str(output_path)]
                )

            report = json.loads(output_path.read_text(encoding="utf-8"))
            serialized_report = output_path.read_text(encoding="utf-8")

        self.assertEqual(first, 0)
        self.assertEqual(second, 2)
        self.assertEqual(report["decision"], "pass")
        self.assertNotIn(str(input_path), serialized_report)
        self.assertNotIn("Keep answers concise", stdout.getvalue() + stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
