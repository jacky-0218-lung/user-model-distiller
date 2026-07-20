import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "skills" / "user-model-distiller" / "scripts" / "memory_control.py"


def load_module():
    spec = importlib.util.spec_from_file_location("memory_control", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


memory = load_module()


class MemoryControlTests(unittest.TestCase):
    def runtime_view(self, root: Path) -> Path:
        path = root / "private" / "USER_MODEL.md"
        path.parent.mkdir()
        path.write_text(
            "# Approved user working preferences\n\n"
            "> Generated file. The current user request overrides these preferences.\n\n"
            "## Language\n\n- Use Traditional Chinese. _(id: `pref_language`; scope: `global`; confidence: 1.00)_\n",
            encoding="utf-8",
        )
        return path

    def test_plan_apply_status_and_remove_preserve_other_guidance(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runtime = self.runtime_view(root)
            agents = root / "codex" / "AGENTS.md"
            agents.parent.mkdir()
            agents.write_text("# Existing guidance\n\nKeep this.\n", encoding="utf-8")

            plan = memory.build_plan(
                action="install",
                agents_file=agents,
                runtime_view=memory.validate_runtime_view(runtime),
                authorization_id="approval-1",
            )
            plan_path = root / "install-plan.json"
            memory.write_new_json(plan_path, plan)
            result = memory.apply_plan(plan_path, plan["receipt_digest"])
            self.assertEqual(result["status"], "applied")
            installed = agents.read_text(encoding="utf-8")
            self.assertIn("# Existing guidance", installed)
            self.assertIn(memory.START_MARKER, installed)
            self.assertTrue(memory.status(agents)["runtime_ready"])

            remove = memory.build_plan(
                action="remove",
                agents_file=agents,
                runtime_view=None,
                authorization_id="approval-2",
            )
            remove_path = root / "remove-plan.json"
            memory.write_new_json(remove_path, remove)
            memory.apply_plan(remove_path, remove["receipt_digest"])
            final = agents.read_text(encoding="utf-8")
            self.assertIn("Keep this.", final)
            self.assertNotIn(memory.START_MARKER, final)

    def test_apply_rejects_changed_agents_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runtime = self.runtime_view(root)
            agents = root / "AGENTS.md"
            plan = memory.build_plan(
                action="install",
                agents_file=agents,
                runtime_view=memory.validate_runtime_view(runtime),
                authorization_id="approval-1",
            )
            plan_path = root / "plan.json"
            memory.write_new_json(plan_path, plan)
            agents.write_text("changed after review\n", encoding="utf-8")
            with self.assertRaisesRegex(memory.MemoryControlError, "changed after the receipt"):
                memory.apply_plan(plan_path, plan["receipt_digest"])

    def test_apply_rejects_tampered_plan_and_wrong_digest(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runtime = self.runtime_view(root)
            agents = root / "AGENTS.md"
            plan = memory.build_plan(
                action="install",
                agents_file=agents,
                runtime_view=memory.validate_runtime_view(runtime),
                authorization_id="approval-1",
            )
            plan_path = root / "plan.json"
            memory.write_new_json(plan_path, plan)
            with self.assertRaisesRegex(memory.MemoryControlError, "Expected digest"):
                memory.apply_plan(plan_path, "0" * 64)

            value = json.loads(plan_path.read_text(encoding="utf-8"))
            value["after_text"] += "injected\n"
            plan_path.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaisesRegex(memory.MemoryControlError, "receipt digest|after_text"):
                memory.apply_plan(plan_path, plan["receipt_digest"])

    def test_runtime_view_rejects_provenance_and_wrong_header(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "bad.md"
            path.write_text("# Not compiled\n", encoding="utf-8")
            with self.assertRaisesRegex(memory.MemoryControlError, "not generated"):
                memory.validate_runtime_view(path)
            path.write_text(
                "# Approved user working preferences\n\n- source message-123\n", encoding="utf-8"
            )
            with self.assertRaisesRegex(memory.MemoryControlError, "provenance"):
                memory.validate_runtime_view(path)

    def test_duplicate_or_malformed_markers_fail_closed(self):
        malformed = memory.START_MARKER + "\n" + memory.START_MARKER + "\n" + memory.END_MARKER
        with self.assertRaisesRegex(memory.MemoryControlError, "malformed or duplicate"):
            memory.locate_block(malformed)


if __name__ == "__main__":
    unittest.main()
