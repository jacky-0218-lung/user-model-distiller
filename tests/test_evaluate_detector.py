from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "skills" / "user-model-distiller" / "scripts" / "evaluate_detector.py"


def load_module():
    spec = importlib.util.spec_from_file_location("evaluate_detector", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


evaluate = load_module()


def detector_row(message_id: str, session_id: str, kinds: list[str] | None = None):
    return {
        "schema_version": "1.0",
        "session_id": session_id,
        "message_id": message_id,
        "created_at": None,
        "score": 3,
        "kinds": kinds or ["explicit_preference"],
        "user_text": "private detector text that must not enter the report",
        "context_message_id": None,
        "source": {"id": "source-123", "sha256": "a" * 64},
        "provenance": {"role": "user", "direct": True, "suppressed_envelopes": []},
        "truncated": False,
        "review_status": "unreviewed",
        "notice": "Candidate evidence only. Do not activate without user review.",
    }


def write_jsonl(path: Path, rows):
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")


class ScoringTests(unittest.TestCase):
    def setUp(self):
        self.gold = [
            {"message_id": "p1", "session_id": "s1", "label": "positive", "kinds": ["style"]},
            {"message_id": "p2", "session_id": "s1", "label": "positive", "kinds": ["style", "format"]},
            {"message_id": "n1", "session_id": "s2", "label": "negative", "kinds": ["ordinary"]},
            {"message_id": "n2", "session_id": "s3", "label": "negative", "kinds": ["sensitive"]},
            {"message_id": "a1", "session_id": "s3", "label": "ambiguous", "kinds": ["unclear"]},
        ]
        self.detector = [detector_row("p1", "s1"), detector_row("n2", "s3"), detector_row("a1", "s3")]

    def test_confusion_metrics_intervals_slices_and_privacy(self):
        report = evaluate.build_report(self.gold, self.detector, seed=17, bootstrap_samples=200)

        self.assertEqual(
            report["confusion_matrix"],
            {
                "tp": 1,
                "fp": 1,
                "fn": 1,
                "tn": 1,
                "gold_positive": 2,
                "gold_negative": 2,
                "gold_ambiguous": 1,
                "detected_ambiguous": 1,
                "detected_total": 3,
            },
        )
        for name in ("precision", "recall", "f1", "specificity"):
            self.assertEqual(report["metrics"][name]["value"], 0.5)
            self.assertIsNotNone(report["metrics"][name]["wilson_95"])
            self.assertIsNotNone(report["metrics"][name]["bootstrap_95"])
        self.assertEqual(report["metrics"]["sensitive_leakage"]["value"], 1.0)
        self.assertEqual(report["per_kind_recall"]["style"]["value"], 0.5)
        self.assertEqual(report["per_kind_recall"]["format"]["value"], 0.0)
        serialized = json.dumps(report)
        for secret in ("p1", "s1", "private detector text"):
            self.assertNotIn(secret, serialized)

    def test_session_bootstrap_is_deterministic_and_seeded(self):
        first = evaluate.build_report(self.gold, self.detector, seed=42, bootstrap_samples=300)
        second = evaluate.build_report(self.gold, self.detector, seed=42, bootstrap_samples=300)
        different = evaluate.build_report(self.gold, self.detector, seed=43, bootstrap_samples=300)
        self.assertEqual(first, second)
        self.assertEqual(first["bootstrap"]["seed"], 42)
        self.assertEqual(different["bootstrap"]["seed"], 43)

    def test_ambiguous_rows_do_not_enter_confusion_matrix(self):
        gold = [{"message_id": "a", "session_id": "s", "label": "ambiguous", "kinds": []}]
        report = evaluate.build_report(gold, [detector_row("a", "s")], seed=0, bootstrap_samples=10)
        self.assertEqual(report["confusion_matrix"]["detected_ambiguous"], 1)
        self.assertEqual(sum(report["confusion_matrix"][name] for name in ("tp", "fp", "fn", "tn")), 0)
        self.assertIsNone(report["metrics"]["recall"]["value"])

    def test_rejects_duplicate_out_of_scope_and_wrong_session_ids(self):
        with self.assertRaisesRegex(evaluate.EvaluationError, "gold message_id values must be unique"):
            evaluate.build_report([self.gold[0], self.gold[0]], [], seed=0, bootstrap_samples=10)
        with self.assertRaisesRegex(evaluate.EvaluationError, "outside the gold scope"):
            evaluate.build_report(self.gold, [detector_row("foreign", "s1")], seed=0, bootstrap_samples=10)
        with self.assertRaisesRegex(evaluate.EvaluationError, "session_id does not match"):
            evaluate.build_report(self.gold, [detector_row("p1", "wrong")], seed=0, bootstrap_samples=10)
        with self.assertRaisesRegex(evaluate.EvaluationError, "detector message_id values must be unique"):
            row = detector_row("p1", "s1")
            evaluate.build_report(self.gold, [row, row], seed=0, bootstrap_samples=10)


class SchemaAndCliTests(unittest.TestCase):
    def run_cli(self, *arguments: str):
        return subprocess.run(
            [sys.executable, str(SCRIPT), *arguments],
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=False,
        )

    def test_closed_gold_and_detector_schemas(self):
        gold = {"message_id": "p", "session_id": "s", "label": "positive", "kinds": []}
        evaluate.validate_gold(gold, 1)
        with self.assertRaisesRegex(evaluate.EvaluationError, "unexpected fields"):
            evaluate.validate_gold({**gold, "text": "leak"}, 1)

        detector = detector_row("p", "s")
        evaluate.validate_detector(detector, 1)
        with self.assertRaisesRegex(evaluate.EvaluationError, "unexpected fields"):
            evaluate.validate_detector({**detector, "extra": True}, 1)
        bad_provenance = {**detector, "provenance": {**detector["provenance"], "assistant": True}}
        with self.assertRaisesRegex(evaluate.EvaluationError, "unexpected fields"):
            evaluate.validate_detector(bad_provenance, 1)

    def test_score_writes_atomic_aggregate_report(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            gold_path, detector_path, report_path = root / "gold.jsonl", root / "detector.jsonl", root / "report.json"
            write_jsonl(gold_path, [{"message_id": "p", "session_id": "s", "label": "positive", "kinds": ["style"]}])
            write_jsonl(detector_path, [detector_row("p", "s")])

            result = self.run_cli(
                "score", str(gold_path), str(detector_path), "--output", str(report_path), "--seed", "8", "--bootstrap", "25"
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(report_path.read_text(encoding="utf-8"))
            self.assertEqual(report["metrics"]["recall"]["value"], 1.0)
            self.assertEqual(report["bootstrap"]["samples"], 25)
            self.assertEqual(list(root.glob(".report.json.*.tmp")), [])
            self.assertNotIn("private detector text", report_path.read_text(encoding="utf-8"))

    def test_gate_passes_and_threshold_failure_is_nonzero(self):
        with tempfile.TemporaryDirectory() as directory:
            report_path = Path(directory) / "report.json"
            report = evaluate.build_report(
                [{"message_id": "p", "session_id": "s", "label": "positive", "kinds": ["style"]}],
                [detector_row("p", "s")],
                seed=0,
                bootstrap_samples=10,
            )
            evaluate.atomic_write_json(report_path, report)
            arguments = (
                "gate", str(report_path), "--min-precision", "1", "--min-recall", "1", "--max-sensitive-leakage", "0"
            )
            self.assertEqual(self.run_cli(*arguments).returncode, 0)

            failing_report = evaluate.build_report(
                [
                    {"message_id": "p", "session_id": "s", "label": "positive", "kinds": ["style"]},
                    {"message_id": "n", "session_id": "s", "label": "negative", "kinds": []},
                ],
                [detector_row("p", "s"), detector_row("n", "s")],
                seed=0,
                bootstrap_samples=10,
            )
            evaluate.atomic_write_json(report_path, failing_report)
            failed_gate = self.run_cli(*arguments)
            self.assertEqual(failed_gate.returncode, 1, failed_gate.stderr + failed_gate.stdout)

    def test_recall_gate_fails_closed_without_gold_positives(self):
        with tempfile.TemporaryDirectory() as directory:
            report_path = Path(directory) / "report.json"
            report = evaluate.build_report(
                [{"message_id": "n", "session_id": "s", "label": "negative", "kinds": []}],
                [],
                seed=0,
                bootstrap_samples=10,
            )
            evaluate.atomic_write_json(report_path, report)
            result = self.run_cli(
                "gate", str(report_path), "--min-precision", "0", "--min-recall", "0", "--max-sensitive-leakage", "0"
            )
            self.assertEqual(result.returncode, 1)
            self.assertIn("non-evaluable", result.stdout)


if __name__ == "__main__":
    unittest.main()
