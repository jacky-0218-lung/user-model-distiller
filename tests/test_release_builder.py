from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools" / "build_release.py"
SPEC = importlib.util.spec_from_file_location("build_release", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class ReleaseBuilderTests(unittest.TestCase):
    def test_build_verify_and_reproduce(self) -> None:
        with tempfile.TemporaryDirectory() as parent:
            first = Path(parent) / "release-a"
            second = Path(parent) / "release-b"
            built = MODULE.build_release(first, source_date_epoch=1_700_000_000)
            verified = MODULE.verify_release(first)
            MODULE.build_release(second, source_date_epoch=1_700_000_000)
            self.assertEqual("built", built["status"])
            self.assertEqual("verified", verified["status"])
            self.assertIn(
                "user-model-distiller/LICENSE",
                {entry["path"] for entry in built["source_files"]},
            )
            self.assertEqual(
                {path.name: path.read_bytes() for path in first.iterdir()},
                {path.name: path.read_bytes() for path in second.iterdir()},
            )

    def test_existing_output_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as parent:
            output = Path(parent) / "release"
            output.mkdir()
            with self.assertRaises(MODULE.ReleaseError):
                MODULE.build_release(output)

    def test_tampered_archive_fails_verification(self) -> None:
        with tempfile.TemporaryDirectory() as parent:
            output = Path(parent) / "release"
            result = MODULE.build_release(output)
            archive_name = result["artifacts"]["archive"]["name"]
            with (output / archive_name).open("ab") as handle:
                handle.write(b"tamper")
            with self.assertRaises(MODULE.ReleaseError):
                MODULE.verify_release(output)

    def test_manifest_tree_digest_and_sbom_are_verified(self) -> None:
        import json

        with tempfile.TemporaryDirectory() as parent:
            output = Path(parent) / "release"
            MODULE.build_release(output)
            manifest_path = output / "release-manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["source_tree_sha256"] = "0" * 64
            manifest_path.write_text(
                json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8"
            )
            with self.assertRaises(MODULE.ReleaseError):
                MODULE.verify_release(output)

    def test_manifest_identity_values_are_verified(self) -> None:
        import json

        for field, value in (
            ("schema_version", "999"),
            ("builder", "other-builder"),
            ("package", "other-package"),
        ):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as parent:
                output = Path(parent) / "release"
                MODULE.build_release(output)
                manifest_path = output / "release-manifest.json"
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                manifest[field] = value
                manifest_path.write_text(
                    json.dumps(manifest, sort_keys=True, indent=2) + "\n",
                    encoding="utf-8",
                )
                with self.assertRaises(MODULE.ReleaseError):
                    MODULE.verify_release(output)

    def test_output_inside_repository_is_refused(self) -> None:
        output = ROOT / "release-output-forbidden"
        with self.assertRaises(MODULE.ReleaseError):
            MODULE.build_release(output)

    def test_release_tag_must_match_version(self) -> None:
        with tempfile.TemporaryDirectory() as parent:
            output = Path(parent) / "release"
            with self.assertRaises(MODULE.ReleaseError):
                MODULE.build_release(output, expected_tag="v999.0.0")
            self.assertFalse(output.exists())

    def test_release_workflow_refetches_annotated_tag_before_validation(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(
            encoding="utf-8"
        )
        refetch = (
            'git fetch --force --no-tags origin '
            '"refs/tags/$RELEASE_TAG:refs/tags/$RELEASE_TAG"'
        )
        type_check = 'test "$(git cat-file -t "$RELEASE_TAG")" = "tag"'
        self.assertIn(refetch, workflow)
        self.assertIn(type_check, workflow)
        self.assertLess(workflow.index(refetch), workflow.index(type_check))


if __name__ == "__main__":
    unittest.main()
