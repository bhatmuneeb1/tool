import tempfile
import unittest
from pathlib import Path

from repoguard.scanner import scan_path, scan_text


class ScannerTests(unittest.TestCase):
    def test_private_key_detection(self):
        marker = "-----BEGIN " + "PRIVATE KEY-----"
        findings = scan_text(marker + "\nabc\n", "key.pem")
        self.assertEqual([item.rule_id for item in findings], ["RG001"])

    def test_github_token_detection(self):
        token = "ghp_" + "A" * 30
        findings = scan_text(f"TOKEN='{token}'\n", "config.py")
        self.assertTrue(any(item.rule_id == "RG003" for item in findings))

    def test_write_all_only_applies_to_workflows(self):
        text = "permissions: " + "write-all\n"
        self.assertEqual(scan_text(text, "notes.txt"), [])
        findings = scan_text(text, ".github/workflows/ci.yml")
        self.assertTrue(any(item.rule_id == "RG101" for item in findings))

    def test_subprocess_shell_true(self):
        findings = scan_text("subprocess.run(cmd, shell=" + "True)\n", "app.py")
        self.assertTrue(any(item.rule_id == "RG201" for item in findings))

    def test_binary_files_are_skipped(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            marker = b"-----BEGIN " + b"PRIVATE KEY-----"
            (root / "blob.bin").write_bytes(b"\x00" + marker)
            self.assertEqual(scan_path(root), [])

    def test_git_directory_is_skipped(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            hidden = root / ".git"
            hidden.mkdir()
            (hidden / "config").write_text("password" + "='supersecret123'", encoding="utf-8")
            self.assertEqual(scan_path(root), [])


if __name__ == "__main__":
    unittest.main()
