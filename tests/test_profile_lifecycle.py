from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "skills" / "user-model-distiller" / "scripts" / "profile_tool.py"


def load_module():
    spec = importlib.util.spec_from_file_location("profile_lifecycle_tool", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


tool = load_module()


class ProfileLifecycleCliTests(unittest.TestCase):
    def run_cli(self, argv: list[str]) -> dict:
        output = StringIO()
        with redirect_stdout(output):
            status = tool.main(argv)
        self.assertEqual(status, 0, output.getvalue())
        return json.loads(output.getvalue())

    def test_review_approve_compile_and_forget(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = root / "evidence.jsonl"
            reviewed = root / "reviewed.jsonl"
            empty_profile = root / "profile.json"
            candidate_profile = root / "candidate.json"
            approved_profile = root / "approved.json"
            runtime = root / "USER_MODEL.md"
            forgotten_profile = root / "forgotten.json"
            forgotten_runtime = root / "USER_MODEL-after-forget.md"
            evidence.write_text(
                json.dumps(
                    {
                        "schema_version": "1.0",
                        "session_id": "session-0123456789abcdefabcd",
                        "message_id": "message-fedcba9876543210abcd",
                        "created_at": "2026-07-20",
                        "score": 3,
                        "kinds": ["correction"],
                        "user_text": "Please shorten the answer.",
                        "context_message_id": "message-aaaaaaaaaaaaaaaaaaaa",
                        "source": {"id": "source-0123456789abcdefabcd", "sha256": "a" * 64},
                        "provenance": {"role": "user", "direct": True, "suppressed_envelopes": []},
                        "truncated": False,
                        "review_status": "unreviewed",
                        "notice": "Candidate evidence only. Do not activate without user review.",
                    },
                    separators=(",", ":"),
                )
                + "\n",
                encoding="utf-8",
            )

            self.run_cli(["init", str(empty_profile)])
            self.run_cli(
                [
                    "review-evidence", str(evidence), "--message-id",
                    "message-fedcba9876543210abcd", "--decision", "accepted",
                    "--authorization-id", "review-1", "--output", str(reviewed),
                ]
            )
            self.run_cli(
                [
                    "add-candidate", str(empty_profile), str(reviewed), "--id", "pref.concise",
                    "--rule", "Use concise answers.", "--category", "response_style",
                    "--confidence", "1.0", "--message-id",
                    "message-fedcba9876543210abcd", "--output", str(candidate_profile),
                ]
            )
            digest = self.run_cli(
                ["candidate-digest", str(candidate_profile), "pref.concise"]
            )["digest"]
            self.run_cli(
                [
                    "approve", str(candidate_profile), "pref.concise", "--authorization-id",
                    "approval-1", "--expected-digest", digest, "--output", str(approved_profile),
                ]
            )
            self.run_cli(
                [
                    "compile", str(approved_profile), "--output", str(runtime),
                    "--as-of", "2026-07-20T00:00:00Z",
                ]
            )
            runtime_text = runtime.read_text(encoding="utf-8")
            self.assertIn("Use concise answers.", runtime_text)
            self.assertNotIn("session-", runtime_text)
            self.assertNotIn("message-", runtime_text)

            result = self.run_cli(
                ["forget", str(approved_profile), "pref.concise", "--output", str(forgotten_profile)]
            )
            self.assertTrue(result["requires_recompile_and_artifact_purge"])
            self.run_cli(
                [
                    "compile", str(forgotten_profile), "--output", str(forgotten_runtime),
                    "--as-of", "2026-07-20T00:00:00Z",
                ]
            )
            post_forget = forgotten_profile.read_text(encoding="utf-8") + forgotten_runtime.read_text(
                encoding="utf-8"
            )
            self.assertNotIn("Use concise answers.", post_forget)
            self.assertNotIn("pref.concise", post_forget)


if __name__ == "__main__":
    unittest.main()
