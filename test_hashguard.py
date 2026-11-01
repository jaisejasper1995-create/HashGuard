
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

import hashguard


class TestHashGuard(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)

        self.root = Path(self.temp.name)
        self.folder = self.root / "monitored"
        self.folder.mkdir()

        self.baseline = self.root / "baseline.json"

        (self.folder / "alpha.txt").write_text(
            "Original alpha", encoding="utf-8"
        )
        (self.folder / "beta.txt").write_text(
            "Original beta", encoding="utf-8"
        )
        (self.folder / "gamma.txt").write_text(
            "Original gamma", encoding="utf-8"
        )

    def run_create(self, baseline=None):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = hashguard.create_baseline(
                self.folder, baseline or self.baseline
            )
        return code, output.getvalue()

    def run_verify(self, baseline=None):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = hashguard.verify_folder(
                self.folder, baseline or self.baseline
            )
        return code, output.getvalue()

    def test_01_baseline_creation(self):
        code, output = self.run_create()

        self.assertEqual(code, 0)
        self.assertIn("PASS:", output)
        self.assertTrue(self.baseline.is_file())

        data = json.loads(
            self.baseline.read_text(encoding="utf-8")
        )
        self.assertEqual(data["schema_version"], "1.0")
        self.assertEqual(
            set(data["files"]),
            {"alpha.txt", "beta.txt", "gamma.txt"}
        )

        for fingerprint in data["files"].values():
            self.assertRegex(fingerprint, r"^[0-9a-f]{64}$")

    def test_02_clean_verification(self):
        self.run_create()
        code, output = self.run_verify()

        self.assertEqual(code, 0)
        self.assertIn(
            "PASS: Folder integrity verified (3 files).",
            output
        )

    def test_03_modified_file(self):
        self.run_create()

        (self.folder / "beta.txt").write_text(
            "TAMPERED", encoding="utf-8"
        )

        code, output = self.run_verify()

        self.assertEqual(code, 1)
        self.assertIn("MODIFIED: beta.txt", output)
        self.assertIn(
            "0 missing, 0 added, 1 modified", output
        )

    def test_04_missing_file(self):
        self.run_create()
        (self.folder / "gamma.txt").unlink()

        code, output = self.run_verify()

        self.assertEqual(code, 1)
        self.assertIn("MISSING: gamma.txt", output)
        self.assertIn(
            "1 missing, 0 added, 0 modified", output
        )

    def test_05_added_file(self):
        self.run_create()

        (self.folder / "delta.txt").write_text(
            "Unauthorized new file", encoding="utf-8"
        )

        code, output = self.run_verify()

        self.assertEqual(code, 1)
        self.assertIn("ADDED: delta.txt", output)
        self.assertIn(
            "0 missing, 1 added, 0 modified", output
        )

    def test_06_multiple_violations(self):
        self.run_create()

        (self.folder / "alpha.txt").unlink()
        (self.folder / "beta.txt").write_text(
            "TAMPERED", encoding="utf-8"
        )
        (self.folder / "delta.txt").write_text(
            "NEW", encoding="utf-8"
        )

        code, output = self.run_verify()

        self.assertEqual(code, 1)
        self.assertIn("MISSING: alpha.txt", output)
        self.assertIn("MODIFIED: beta.txt", output)
        self.assertIn("ADDED: delta.txt", output)
        self.assertIn(
            "1 missing, 1 added, 1 modified", output
        )

    def test_07_overwrite_protection(self):
        self.run_create()

        original = self.baseline.read_bytes()

        (self.folder / "alpha.txt").write_text(
            "Changed", encoding="utf-8"
        )

        code, output = self.run_create()

        self.assertEqual(code, 2)
        self.assertIn("already exists", output)
        self.assertEqual(
            self.baseline.read_bytes(), original
        )

    def test_08_missing_baseline(self):
        code, output = self.run_verify()

        self.assertEqual(code, 2)
        self.assertIn("Baseline not found", output)

    def test_09_invalid_baseline_schema(self):
        self.baseline.write_text(
            json.dumps({
                "schema_version": "INVALID",
                "files": {}
            }),
            encoding="utf-8"
        )

        code, output = self.run_verify()

        self.assertEqual(code, 2)
        self.assertIn("Invalid baseline format", output)

    def test_10_invalid_fingerprint(self):
        self.baseline.write_text(
            json.dumps({
                "schema_version": "1.0",
                "files": {"alpha.txt": "not-a-sha256"}
            }),
            encoding="utf-8"
        )

        code, output = self.run_verify()

        self.assertEqual(code, 2)
        self.assertIn("Invalid baseline format", output)

    def test_11_baseline_inside_folder_rejected(self):
        inside = self.folder / "baseline.json"

        code, output = self.run_create(inside)

        self.assertEqual(code, 2)
        self.assertIn(
            "Baseline must be outside", output
        )
        self.assertFalse(inside.exists())

    def test_12_nested_folder_detection(self):
        nested = self.folder / "nested"
        nested.mkdir()

        nested_file = nested / "inside.txt"
        nested_file.write_text(
            "Nested original", encoding="utf-8"
        )

        self.run_create()

        data = json.loads(
            self.baseline.read_text(encoding="utf-8")
        )
        self.assertIn("nested/inside.txt", data["files"])

        nested_file.write_text(
            "Nested tampered", encoding="utf-8"
        )

        code, output = self.run_verify()

        self.assertEqual(code, 1)
        self.assertIn(
            "MODIFIED: nested/inside.txt", output
        )

    def test_13_missing_monitored_folder(self):
        self.folder.rename(self.root / "renamed")

        code, output = self.run_create()

        self.assertEqual(code, 2)
        self.assertIn(
            "Monitored folder does not exist", output
        )

    def test_14_baseline_unchanged_after_verify(self):
        self.run_create()

        original = self.baseline.read_bytes()

        (self.folder / "beta.txt").write_text(
            "TAMPERED", encoding="utf-8"
        )

        code, output = self.run_verify()

        self.assertEqual(code, 1)
        self.assertIn("MODIFIED: beta.txt", output)
        self.assertEqual(
            self.baseline.read_bytes(), original
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
