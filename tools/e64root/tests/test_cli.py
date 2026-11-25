from __future__ import annotations

import contextlib
import io
import unittest

from helpers import FIXTURES  # noqa: F401  (sets sys.path)

from e64root import cli


def run_cli(argv):
    output = io.StringIO()
    error = io.StringIO()
    with contextlib.redirect_stdout(output), contextlib.redirect_stderr(error):
        try:
            code = cli.main(argv)
        except SystemExit as exc:
            code = int(exc.code or 0)
    return code, output.getvalue(), error.getvalue()


class CliTests(unittest.TestCase):
    def test_help_lists_all_commands(self):
        code, output, _ = run_cli(["--help"])
        self.assertEqual(code, 0)
        for command in ("probe", "web", "esp", "ssh", "verify", "revert"):
            self.assertIn(command, output)

    def test_version(self):
        code, output, _ = run_cli(["--version"])
        self.assertEqual(code, 0)
        self.assertIn("e64root 0.1.0", output)

    def test_web_requires_yes(self):
        code, _, error = run_cli(
            ["web", "--host", "127.0.0.1", "--insecure", "--cmd", "id"]
        )
        self.assertEqual(code, 2)
        self.assertIn("changes the device", error)

    def test_web_requires_tls_choice(self):
        code, _, error = run_cli(["web", "--host", "127.0.0.1", "--yes"])
        self.assertEqual(code, 2)
        self.assertIn("self-signed", error)

    def test_web_dry_run_without_yes(self):
        code, output, _ = run_cli(
            ["web", "--host", "127.0.0.1", "--insecure", "--dry-run", "--cmd", "id"]
        )
        self.assertEqual(code, 0)
        self.assertIn("dry-run", output)

    def test_web_dry_run_needs_no_tls_choice_or_contact(self):
        code, output, _ = run_cli(
            ["web", "--host", "127.0.0.1", "--dry-run", "--cmd", "id"]
        )
        self.assertEqual(code, 0)
        self.assertIn("no device contact", output)

    def test_esp_dry_run_without_yes(self):
        code, output, _ = run_cli(
            ["esp", "--host", "127.0.0.1", "--insecure", "--dry-run", "--cmd", "id"]
        )
        self.assertEqual(code, 0)
        self.assertIn("payload/do_flash.sh", output)

    def test_ssh_requires_yes(self):
        code, _, error = run_cli(
            ["ssh", "--host", "127.0.0.1", "--insecure", "--via", "web",
             "--pubkey-file", "/nonexistent", "--dropbear", "/nonexistent"]
        )
        self.assertEqual(code, 2)
        self.assertIn("changes the device", error)

    def test_revert_print_script_needs_no_key(self):
        code, output, _ = run_cli(["revert", "--host", "127.0.0.1", "--print-script"])
        self.assertEqual(code, 0)
        self.assertIn("# e64root revert", output)

    def test_public_target_refused_before_http(self):
        code, _, error = run_cli(
            ["web", "--host", "8.8.8.8", "--insecure", "--yes", "--cmd", "id"]
        )
        self.assertEqual(code, 2)
        self.assertIn("globally routable", error)

    def test_unknown_command(self):
        code, _, _ = run_cli(["nope"])
        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
