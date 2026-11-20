"""Regression checks for source export and its overwrite / path boundaries."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
EXPORT = ROOT / "tools/export_portable.py"


class ExportTests(unittest.TestCase):
    def export(self, destination, *options):
        return subprocess.run([sys.executable, str(EXPORT), str(destination), *options],
                              capture_output=True, text=True, encoding="utf-8")

    def test_default_export_hashes_licenses_and_exclusions(self):
        with tempfile.TemporaryDirectory(prefix="se050-export-test-") as temp:
            destination = Path(temp) / "package"
            result = self.export(destination)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            report = json.loads((destination / "PACKAGE_MANIFEST.json").read_text(encoding="utf-8"))
            self.assertEqual(report["package"], "se050e-crypto-middleware")
            self.assertFalse(report["with_tests"])
            self.assertNotIn("source", report)
            for name in ("LICENSE", "NOTICE", "nxp/LICENSE", "nxp/UPSTREAM.md", "README.en.md"):
                self.assertIn(name, report["files_sha256"])
            for name, digest in report["files_sha256"].items():
                self.assertEqual(hashlib.sha256((destination / name).read_bytes()).hexdigest(), digest)
            for excluded in ("tests", "testdata", ".git", ".github", ".local", "build"):
                self.assertFalse((destination / excluded).exists(), excluded)
            checked = subprocess.run([sys.executable, str(destination / "tools/check_project.py")],
                                     capture_output=True, text=True, encoding="utf-8")
            self.assertEqual(checked.returncode, 0, checked.stdout + checked.stderr)

    def test_with_tests_exports_host_sources(self):
        with tempfile.TemporaryDirectory(prefix="se050-export-test-") as temp:
            destination = Path(temp) / "package"
            result = self.export(destination, "--with-tests")
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            report = json.loads((destination / "PACKAGE_MANIFEST.json").read_text(encoding="utf-8"))
            self.assertTrue(report["with_tests"])
            self.assertIn("tests/run.py", report["files_sha256"])
            self.assertIn("tests/portable/se050_port_test.h", report["files_sha256"])
            self.assertFalse(any("__pycache__" in name for name in report["files_sha256"]))

    def test_nonempty_destination_is_preserved(self):
        with tempfile.TemporaryDirectory(prefix="se050-export-test-") as temp:
            destination = Path(temp)
            sentinel = destination / "keep.txt"
            sentinel.write_bytes(b"existing project\n")
            result = self.export(destination)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("no existing files will be overwritten", result.stderr)
            self.assertEqual(sentinel.read_bytes(), b"existing project\n")
            self.assertEqual(list(destination.iterdir()), [sentinel])

    def test_source_and_nested_destination_are_rejected(self):
        nested = ROOT / ".local" / "export-must-not-create"
        self.assertFalse(nested.exists())
        for destination in (ROOT, nested):
            with self.subTest(destination=str(destination)):
                result = self.export(destination)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("outside the source tree", result.stderr)
        self.assertFalse(nested.exists())


if __name__ == "__main__":
    unittest.main()
