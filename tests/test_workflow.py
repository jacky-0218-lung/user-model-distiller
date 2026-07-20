from __future__ import annotations

import importlib.util
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


workflow = load_module("distill_workflow", SCRIPT_ROOT / "distill_workflow.py")


def write_input(path: Path, text: str = "Please keep answers concise.") -> None:
    payload = [{"role": "user", "content": text}]
    path.write_text(json.dumps(payload), encoding="utf-8")


class WorkflowPreviewTests(unittest.TestCase):
    def test_preview_publishes_complete_run_and_verify_checks_it(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "authorized.json"
            destination = root / "private-run"
            write_input(source)

            result = workflow.run_preview(
                source,
                destination,
                authorization_id="approval-20260720",
                privacy="high",
            )

            self.assertEqual(result["stage"], "complete")
            self.assertEqual(
                {path.name for path in destination.iterdir()},
                {
                    workflow.NORMALIZED_NAME,
                    workflow.PRIVACY_REPORT_NAME,
                    workflow.EVIDENCE_NAME,
                    workflow.PROFILE_NAME,
                    workflow.MANIFEST_NAME,
                },
            )
            manifest_text = (destination / workflow.MANIFEST_NAME).read_text(
                encoding="utf-8"
            )
            manifest = json.loads(manifest_text)
            self.assertEqual(manifest["authorization_id"], "approval-20260720")
            self.assertEqual(manifest["stage"], "complete")
            self.assertRegex(manifest["source_set_digest"], r"^[0-9a-f]{64}$")
            self.assertEqual(manifest["counts"]["source_files"], 1)
            self.assertNotIn(str(source), manifest_text)
            self.assertNotIn(source.name, manifest_text)
            self.assertNotIn("Please keep answers concise", manifest_text)
            self.assertEqual(workflow.verify_run(destination)["status"], "verified")

    def test_existing_output_is_refused_without_modifying_it(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "authorized.json"
            destination = root / "already-there"
            write_input(source)
            destination.mkdir()
            marker = destination / "marker.txt"
            marker.write_text("keep", encoding="utf-8")

            with self.assertRaises(workflow.WorkflowError):
                workflow.run_preview(
                    source,
                    destination,
                    authorization_id="approval-existing",
                )

            self.assertEqual(marker.read_text(encoding="utf-8"), "keep")

    def test_blocked_gate_publishes_no_evidence_or_profile(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "authorized.json"
            destination = root / "blocked-run"
            write_input(source)
            blocked_report = {
                "status": "blocked",
                "blocker_count": 1,
                "warning_count": 0,
                "categories": ["credential"],
                "records": [],
            }

            def write_report(path, report, overwrite=False):
                self.assertFalse(overwrite)
                path.write_text(json.dumps(report) + "\n", encoding="utf-8")

            with mock.patch.object(
                workflow.privacy_guard, "scan_records", return_value=blocked_report
            ), mock.patch.object(
                workflow.privacy_guard, "atomic_write_report", side_effect=write_report
            ):
                result = workflow.run_preview(
                    source,
                    destination,
                    authorization_id="approval-blocked",
                )

            self.assertEqual(result["stage"], "privacy_blocked")
            self.assertFalse((destination / workflow.EVIDENCE_NAME).exists())
            self.assertFalse((destination / workflow.PROFILE_NAME).exists())
            self.assertEqual(
                {path.name for path in destination.iterdir()},
                {
                    workflow.PRIVACY_REPORT_NAME,
                    workflow.MANIFEST_NAME,
                },
            )
            verified = workflow.verify_run(destination)
            self.assertEqual(verified["stage"], "privacy_blocked")

    def test_failure_before_publish_leaves_no_final_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "authorized.json"
            destination = root / "failed-run"
            write_input(source)

            with mock.patch.object(
                workflow.privacy_guard,
                "scan_records",
                side_effect=RuntimeError("guard failed"),
            ):
                with self.assertRaises(RuntimeError):
                    workflow.run_preview(
                        source,
                        destination,
                        authorization_id="approval-failed",
                    )

            self.assertFalse(destination.exists())
            self.assertEqual(
                [path for path in root.iterdir() if ".failed-run.staging-" in path.name],
                [],
            )


class WorkflowPathTests(unittest.TestCase):
    def test_output_inside_repository_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "authorized.json"
            write_input(source)
            destination = REPO_ROOT / "forbidden-private-run"
            self.assertFalse(destination.exists())
            with self.assertRaises(workflow.WorkflowError):
                workflow.validate_preview_paths(source, destination)
            self.assertFalse(destination.exists())

    def test_output_overlapping_input_directory_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "input-tree"
            source.mkdir()
            write_input(source / "authorized.json")
            with self.assertRaises(workflow.WorkflowError):
                workflow.validate_preview_paths(source, source / "private-run")

    def test_unc_detection_accepts_both_slash_forms(self):
        self.assertTrue(workflow.is_unc_path(Path(r"\\server\share\run")))
        self.assertTrue(workflow.is_unc_path(Path("//server/share/run")))
        self.assertFalse(workflow.is_unc_path(Path(r"C:\private\run")))

    def test_cloud_sync_path_detection(self):
        self.assertTrue(workflow.is_cloud_sync_path(Path("C:/Users/example/OneDrive/project")))
        self.assertTrue(workflow.is_cloud_sync_path(Path("C:/Dropbox/private")))
        self.assertFalse(workflow.is_cloud_sync_path(Path("C:/private/local")))

    def test_symlink_input_is_refused_when_supported(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target.json"
            link = root / "linked.json"
            destination = root / "private-run"
            write_input(target)
            try:
                os.symlink(target, link)
            except (OSError, NotImplementedError):
                self.skipTest("symbolic links are not available")
            with self.assertRaises(workflow.WorkflowError):
                workflow.validate_preview_paths(link, destination)


class WorkflowVerifyTests(unittest.TestCase):
    def test_verify_detects_artifact_tampering(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "authorized.json"
            destination = root / "private-run"
            write_input(source)
            workflow.run_preview(
                source,
                destination,
                authorization_id="approval-tamper",
            )
            with (destination / workflow.NORMALIZED_NAME).open(
                "a", encoding="utf-8"
            ) as handle:
                handle.write("{}\n")

            with self.assertRaises(workflow.WorkflowError):
                workflow.verify_run(destination)

    def test_verify_rejects_untracked_artifact(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "authorized.json"
            destination = root / "private-run"
            write_input(source)
            workflow.run_preview(
                source,
                destination,
                authorization_id="approval-extra",
            )
            (destination / "unexpected.txt").write_text("unexpected", encoding="utf-8")

            with self.assertRaises(workflow.WorkflowError):
                workflow.verify_run(destination)


if __name__ == "__main__":
    unittest.main()
