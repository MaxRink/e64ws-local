"""Offline tests for ``e64root api deploy/status/revert``.

No device, network, or PHP runtime is used: the SSH transport is faked and the
deploy/status/revert scripts are inspected as text.  The sudoers fragment is
also executed against a temporary directory with stub ``visudo``, ``stat`` and
``chown``, so its install, refusal and removal paths are tested for real.
"""

from __future__ import annotations

import contextlib
import io
import re
import shlex
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from helpers import FakeSSH, args_for

from e64root import cli, commands
from e64root.errors import TransportError, UsageError
from e64root.transports import SSHResult

MODULE = "/usr/local/www/dev/rest_api_dev.php"
TOKEN = "/db/e64local/token"


def captured(callable_, *args, **kwargs):
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        result = callable_(*args, **kwargs)
    return result, output.getvalue()


def run_cli(argv):
    output = io.StringIO()
    error = io.StringIO()
    with contextlib.redirect_stdout(output), contextlib.redirect_stderr(error):
        try:
            code = cli.main(argv)
        except SystemExit as exc:
            code = int(exc.code or 0)
    return code, output.getvalue(), error.getvalue()


class DeployTests(unittest.TestCase):
    def test_module_path_is_the_repository_file(self):
        path = Path(commands._api_module_path())
        self.assertTrue(path.is_file())
        self.assertEqual(path.name, "rest_api_dev.php")
        self.assertIn("function restApiDev", path.read_text(encoding="utf-8"))

    def test_dry_run_prints_script_without_a_device(self):
        args = args_for("api", token="owner-token", dry_run=True)
        _, output = captured(commands.cmd_api, args)
        self.assertIn("no device contact", output)
        self.assertIn("# e64root api deploy", output)
        self.assertIn("E64LOCAL_API_MODULE", output)
        self.assertIn("function restApiDev", output)

    def test_dry_run_needs_a_token(self):
        args = args_for("api", token=None, generate_token=False, dry_run=True)
        with self.assertRaises(UsageError):
            commands.cmd_api(args)

    def test_requires_yes_before_any_transport(self):
        args = args_for("api", token="owner-token", yes=False)
        with self.assertRaises(UsageError):
            commands.cmd_api(args)

    def test_requires_token_when_executing(self):
        args = args_for("api", token=None, generate_token=False, yes=True)
        with self.assertRaises(UsageError):
            commands.cmd_api(args)

    def test_writes_module_and_token_with_safe_modes(self):
        ssh = FakeSSH(run_output="e64root api deploy ok\n")
        args = args_for("api", token="owner-token")
        code, output = captured(commands.cmd_api, args, ssh=ssh)

        self.assertEqual(code, 0)
        self.assertEqual(len(ssh.executed), 1)
        script = ssh.executed[0]
        self.assertIn(f"cat > {MODULE} << 'E64LOCAL_API_MODULE'", script)
        self.assertIn("function restApiDev", script)
        self.assertIn(f"printf '%s\\n' owner-token > {TOKEN}", script)
        self.assertIn(f"chmod 600 {TOKEN}", script)
        self.assertIn(f"chown www-data:www-data {TOKEN}", script)
        self.assertIn("chmod 711 /db/e64local", script)
        self.assertIn('[ "$token_mode" != "600" ]', script)
        self.assertIn("Local API v1 is now installed", output)

    def test_token_is_shell_quoted(self):
        token = "it's-a-token"
        ssh = FakeSSH(run_output="e64root api deploy ok\n")
        args = args_for("api", token=token)
        captured(commands.cmd_api, args, ssh=ssh)

        script = ssh.executed[0]
        self.assertIn(shlex.quote(token), script)
        self.assertNotIn("printf '%s\\n' it's-a-token", script)

    def test_rejects_tokens_with_control_characters(self):
        for token in ("abc\ndef", "abc\rdef", "abc\x00def"):
            with self.subTest(token=token):
                with self.assertRaises(UsageError):
                    commands._api_deploy_script(commands._api_module_path(), token)

    def test_rejects_empty_token(self):
        with self.assertRaises(UsageError):
            commands._api_deploy_script(commands._api_module_path(), "")

    def test_generate_token_prints_and_uses_a_64_hex_token(self):
        ssh = FakeSSH(run_output="e64root api deploy ok\n")
        args = args_for("api", token=None, generate_token=True)
        code, output = captured(commands.cmd_api, args, ssh=ssh)

        self.assertEqual(code, 0)
        match = re.search(r"generated token: ([0-9a-f]{64})", output)
        self.assertIsNotNone(match)
        token = match.group(1)
        self.assertIn(token, ssh.executed[0])
        self.assertIn(f"chmod 600 {TOKEN}", ssh.executed[0])

    def test_generate_token_dry_run_uses_a_placeholder(self):
        args = args_for("api", token=None, generate_token=True, dry_run=True)
        _, output = captured(commands.cmd_api, args)
        self.assertIn("<generated at deploy time>", output)
        self.assertIn("chmod 600", output)

    def test_deploy_failure_raises_transport_error(self):
        class FailingSSH(FakeSSH):
            def run(self, script: str) -> SSHResult:
                self.executed.append(script)
                return SSHResult(1, "", "boom")

        args = args_for("api", token="owner-token")
        with self.assertRaises(TransportError), contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(io.StringIO()):
            commands.cmd_api(args, ssh=FailingSSH())


class StatusTests(unittest.TestCase):
    OUTPUT = (
        "module_present=yes\n"
        f"module_path={MODULE}\n"
        "module_size=12345\n"
        "module_sha256=abc123\n"
        "token_present=yes\n"
        f"token_path={TOKEN}\n"
        "token_mode=600\n"
        "token_owner=www-data\n"
        "token_group=www-data\n"
        "dev_mode=yes\n"
    )

    def test_reports_every_documented_field(self):
        ssh = FakeSSH(run_output=self.OUTPUT)
        args = args_for("api", api_subcommand="status")
        code, output = captured(commands.cmd_api, args, ssh=ssh)

        self.assertEqual(code, 0)
        for key in (
            "module_present",
            "module_path",
            "module_size",
            "module_sha256",
            "token_present",
            "token_path",
            "token_mode",
            "token_owner",
            "token_group",
            "dev_mode",
        ):
            self.assertIn(key, output)
        self.assertIn("installed and configured", output)

    def test_missing_module_is_reported(self):
        ssh = FakeSSH(run_output="module_present=no\ntoken_present=no\n")
        args = args_for("api", api_subcommand="status")
        _, output = captured(commands.cmd_api, args, ssh=ssh)
        self.assertIn("not installed", output)

    def test_missing_token_is_reported(self):
        ssh = FakeSSH(run_output="module_present=yes\ntoken_present=no\n")
        args = args_for("api", api_subcommand="status")
        _, output = captured(commands.cmd_api, args, ssh=ssh)
        self.assertIn("token is missing", output)

    def test_status_is_read_only_and_needs_no_yes(self):
        ssh = FakeSSH(run_output=self.OUTPUT)
        args = args_for("api", api_subcommand="status", yes=False)
        captured(commands.cmd_api, args, ssh=ssh)
        self.assertIn("rest_api_dev.php", ssh.executed[0])

    def test_status_dry_run_prints_the_script(self):
        args = args_for("api", api_subcommand="status", dry_run=True)
        _, output = captured(commands.cmd_api, args)
        self.assertIn("no device contact", output)
        self.assertIn("# e64root api status (read-only)", output)
        self.assertIn("module_present", output)


class RevertTests(unittest.TestCase):
    def test_revert_without_yes_is_a_dry_run(self):
        ssh = FakeSSH()
        args = args_for("api", api_subcommand="revert", yes=False)
        code, output = captured(commands.cmd_api, args, ssh=ssh)

        self.assertEqual(code, 0)
        self.assertEqual(ssh.executed, [])
        self.assertIn("# e64root api revert", output)
        self.assertIn("no changes made", output)

    def test_revert_with_yes_removes_module_and_token(self):
        ssh = FakeSSH(run_output="e64root api revert ok\n")
        args = args_for("api", api_subcommand="revert", yes=True)
        code, output = captured(commands.cmd_api, args, ssh=ssh)

        self.assertEqual(code, 0)
        self.assertEqual(len(ssh.executed), 1)
        script = ssh.executed[0]
        self.assertIn(f"rm -f {MODULE}", script)
        self.assertIn(f"rm -f {TOKEN}", script)
        self.assertIn("rmdir /db/e64local", script)
        self.assertIn("has been removed", output)

    def test_revert_dry_run_flag(self):
        ssh = FakeSSH()
        args = args_for("api", api_subcommand="revert", yes=True, dry_run=True)
        _, output = captured(commands.cmd_api, args, ssh=ssh)
        self.assertEqual(ssh.executed, [])
        self.assertIn("no device contact", output)


SUDOERS_FILE = "/etc/sudoers.d/e64local"
SUDOERS_RULE = "www-data ALL=(root) NOPASSWD: /usr/local/bin/e64local-action-run"
SUDOERS_MARKER = "# e64local: managed by e64root api deploy --enable-actions; do not edit"
SUDOERS_EXPECTED = f"{SUDOERS_MARKER}\n{SUDOERS_RULE}\n"

# Stubs for the sandbox below.  They accept only the shape the fragment is
# supposed to produce, so a broader rule or a second rule fails the run.
VISUDO_STUB = """#!/bin/sh
case "$1" in -cf) file=$2 ;; *) exit 2 ;; esac
[ -f "$file" ] || exit 1
rules=$(grep -cvE '^(#|$)' "$file") || exit 1
[ "$rules" = "1" ] || exit 1
grep -qxF 'www-data ALL=(root) NOPASSWD: /usr/local/bin/e64local-action-run' "$file"
"""

STAT_STUB = f"""#!/bin/sh
case "$1" in -c) fmt=$2; file=$3 ;; *) exit 2 ;; esac
[ -f "$file" ] || exit 1
case "$fmt" in
  '%a') "{sys.executable}" -c 'import os,sys; print(format(os.stat(sys.argv[1]).st_mode & 0o777, "o"))' "$file" ;;
  *) exit 1 ;;
esac
"""

REJECTING_VISUDO_STUB = """#!/bin/sh
exit 1
"""


class SudoersSandbox:
    """Run the generated sudoers fragments against a temporary directory.

    Only the fragment is executed, never the whole deploy script, and every
    absolute path it touches is redirected below a fresh temporary directory.
    """

    def __init__(self, root: Path) -> None:
        self.root = root
        self.sudoers_dir = root / "sudoers.d"
        self.sudoers_dir.mkdir()
        self.bin = root / "bin"
        self.bin.mkdir()
        self.empty_bin = root / "empty-bin"
        self.empty_bin.mkdir()
        self.chown_log = root / "chown.log"
        self.target = self.sudoers_dir / "e64local"
        (self.bin / "visudo").write_text(VISUDO_STUB, encoding="utf-8")
        (self.bin / "stat").write_text(STAT_STUB, encoding="utf-8")
        (self.bin / "chown").write_text(
            '#!/bin/sh\necho "$@" >> ' + shlex.quote(str(self.chown_log)) + "\nexit 0\n",
            encoding="utf-8",
        )
        for stub in self.bin.iterdir():
            stub.chmod(0o755)

    @property
    def path(self) -> str:
        return f"{self.bin}:/usr/bin:/bin"

    def redirect(self, fragment: str) -> str:
        """Point /etc/sudoers.d at the sandbox."""
        return fragment.replace("/etc/sudoers.d", str(self.sudoers_dir))

    def run(self, fragment: str, path: str | None = None) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["/bin/sh", "-eu"],
            input=self.redirect(fragment),
            capture_output=True,
            text=True,
            timeout=30,
            env={"PATH": path or self.path},
        )

    def use_rejecting_visudo(self) -> None:
        (self.bin / "visudo").write_text(REJECTING_VISUDO_STUB, encoding="utf-8")

    def leftovers(self) -> list[str]:
        return sorted(entry.name for entry in self.sudoers_dir.iterdir())


class SudoersInstallTests(unittest.TestCase):
    """`--enable-actions` installs exactly one narrow sudoers rule."""

    def test_the_generated_file_is_the_marker_plus_one_rule(self):
        self.assertEqual(commands._api_sudoers_content(), SUDOERS_EXPECTED)
        self.assertEqual(len(commands._api_sudoers_content().splitlines()), 2)

    def test_the_rule_grants_nothing_beyond_the_runner(self):
        content = commands._api_sudoers_content()
        rule_lines = [line for line in content.splitlines() if not line.startswith("#")]
        self.assertEqual(rule_lines, [SUDOERS_RULE])
        for forbidden in ("*", "SETENV", "NOPASSWD: ALL", "NOPASSWD:ALL", "ALL=(ALL)"):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, content)
        self.assertNotIn(",", content, "a sudoers command list would widen the grant")

    def test_the_rule_is_installed_only_after_visudo_accepts_it(self):
        block = commands._api_sudoers_block()
        self.assertIn("mktemp /etc/sudoers.d/.e64local.XXXXXX", block)
        self.assertIn('visudo -cf "$sudoers_tmp"', block)
        self.assertIn("chmod 0440", block)
        self.assertIn("chown root:root", block)
        self.assertIn("trap sudoers_cleanup EXIT", block)
        self.assertLess(
            block.index('visudo -cf "$sudoers_tmp"'),
            block.index('mv -f "$sudoers_tmp"'),
            "the temporary file must be validated before it replaces the installed file",
        )

    def test_the_deploy_arms_the_gate_only_after_the_rule_is_installed(self):
        script = commands._api_deploy_script(
            commands._api_module_path(), None, enable_actions=True, secret="ab" * 32
        )
        self.assertLess(
            script.index("visudo -cf"),
            script.index("cat > /db/e64local/actions.json"),
            "a refused sudoers rule must leave the gate closed (403), not armed (503)",
        )

    def test_a_read_only_deploy_installs_no_sudoers_file(self):
        script = commands._api_deploy_script(commands._api_module_path(), "owner-token")
        self.assertNotIn(SUDOERS_FILE, script)
        self.assertNotIn(SUDOERS_RULE, script)

    def test_the_install_fragment_writes_the_exact_file_as_root_0440(self):
        with tempfile.TemporaryDirectory() as tmp:
            sandbox = SudoersSandbox(Path(tmp))
            result = sandbox.run(commands._api_sudoers_block())

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(sandbox.target.read_text(encoding="utf-8"), SUDOERS_EXPECTED)
            self.assertEqual(sandbox.target.stat().st_mode & 0o777, 0o440)
            self.assertEqual(sandbox.leftovers(), ["e64local"])
            self.assertIn(
                f"root:root {sandbox.target}",
                sandbox.chown_log.read_text(encoding="utf-8").splitlines(),
            )
            self.assertIn("sudoers_rule=installed", result.stdout)

    def test_the_install_fragment_refuses_a_device_without_visudo(self):
        with tempfile.TemporaryDirectory() as tmp:
            sandbox = SudoersSandbox(Path(tmp))
            result = sandbox.run(commands._api_sudoers_block(), path=str(sandbox.empty_bin))

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("visudo is required", result.stderr)
            self.assertIn("refusing to install an unvalidated sudoers file", result.stderr)
            self.assertEqual(sandbox.leftovers(), [])

    def test_a_rejected_rule_leaves_no_partial_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            sandbox = SudoersSandbox(Path(tmp))
            sandbox.use_rejecting_visudo()
            result = sandbox.run(commands._api_sudoers_block())

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("failed visudo validation", result.stderr)
            self.assertEqual(sandbox.leftovers(), [])

    def test_a_rejected_rule_keeps_the_previous_good_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            sandbox = SudoersSandbox(Path(tmp))
            self.assertEqual(sandbox.run(commands._api_sudoers_block()).returncode, 0)
            sandbox.use_rejecting_visudo()
            self.assertNotEqual(sandbox.run(commands._api_sudoers_block()).returncode, 0)

            self.assertEqual(sandbox.target.read_text(encoding="utf-8"), SUDOERS_EXPECTED)


class SudoersRevertTests(unittest.TestCase):
    """`revert` removes the file only when this tool wrote it."""

    def test_a_marked_file_is_removed(self):
        with tempfile.TemporaryDirectory() as tmp:
            sandbox = SudoersSandbox(Path(tmp))
            sandbox.target.write_text(SUDOERS_EXPECTED, encoding="utf-8")
            result = sandbox.run(commands._api_sudoers_revert_block())

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("sudoers_rule=removed", result.stdout)
            self.assertEqual(sandbox.leftovers(), [])

    def test_an_unmarked_file_is_kept(self):
        with tempfile.TemporaryDirectory() as tmp:
            sandbox = SudoersSandbox(Path(tmp))
            foreign = f"# hand written by an operator\n{SUDOERS_RULE}\n"
            sandbox.target.write_text(foreign, encoding="utf-8")
            result = sandbox.run(commands._api_sudoers_revert_block())

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("sudoers_rule=kept", result.stdout)
            self.assertEqual(sandbox.target.read_text(encoding="utf-8"), foreign)

    def test_an_absent_file_is_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            sandbox = SudoersSandbox(Path(tmp))
            result = sandbox.run(commands._api_sudoers_revert_block())

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("sudoers_rule=absent", result.stdout)


class SudoersCommandTests(unittest.TestCase):
    """The CLI path: dry-run prints the file, status reports it."""

    def test_dry_run_prints_the_exact_content_and_contacts_nothing(self):
        ssh = FakeSSH()
        args = args_for("api", token=None, generate_token=True, enable_actions=True, dry_run=True)
        code, output = captured(commands.cmd_api, args, ssh=ssh)

        self.assertEqual(code, 0)
        self.assertEqual(ssh.executed, [])
        self.assertFalse(ssh.waited)
        begin = f"--- begin exact content of {SUDOERS_FILE} ---\n"
        end = f"--- end exact content of {SUDOERS_FILE} ---"
        self.assertIn(begin, output)
        self.assertEqual(output.split(begin, 1)[1].split(end, 1)[0], SUDOERS_EXPECTED)

    def test_deploy_script_carries_the_rule_in_the_heredoc_and_the_check(self):
        ssh = FakeSSH(run_output="sudoers_rule=installed\ne64root api deploy ok\n")
        args = args_for("api", token="owner-token", enable_actions=True)
        code, _ = captured(commands.cmd_api, args, ssh=ssh)

        self.assertEqual(code, 0)
        script = ssh.executed[0]
        self.assertEqual(script.count(SUDOERS_RULE), 2)  # heredoc body plus the check
        self.assertIn(
            f"cat > \"$sudoers_tmp\" << 'E64LOCAL_SUDOERS'\n{SUDOERS_EXPECTED}E64LOCAL_SUDOERS",
            script,
        )

    def test_status_reports_rule_presence_and_validity(self):
        ssh = FakeSSH(
            run_output=(
                "module_present=yes\n"
                "token_present=yes\n"
                "actions_enabled=yes\n"
                "actions_destructive=no\n"
                f"sudoers_present=yes\n"
                f"sudoers_path={SUDOERS_FILE}\n"
                "sudoers_mode=440\n"
                "sudoers_owner=root\n"
                "sudoers_rule=present\n"
                "sudoers_valid=yes\n"
            )
        )
        args = args_for("api", api_subcommand="status")
        _, output = captured(commands.cmd_api, args, ssh=ssh)

        for key in ("sudoers_present", "sudoers_mode", "sudoers_owner", "sudoers_rule", "sudoers_valid"):
            with self.subTest(key=key):
                self.assertIn(key, output)
        self.assertNotIn("does not carry the rule", output)

    def test_status_warns_when_the_rule_is_missing(self):
        ssh = FakeSSH(
            run_output=(
                "module_present=yes\n"
                "token_present=yes\n"
                "actions_enabled=yes\n"
                "actions_destructive=no\n"
                "sudoers_present=no\n"
                "sudoers_rule=missing\n"
                "sudoers_valid=no\n"
            )
        )
        args = args_for("api", api_subcommand="status")
        _, output = captured(commands.cmd_api, args, ssh=ssh)
        self.assertIn("does not carry the rule", output)
        self.assertIn("otherwise they fail with 503", output)


class ParserTests(unittest.TestCase):
    def test_options_belong_to_the_subcommand(self):
        parser = cli.build_parser()
        args = parser.parse_args(["api", "deploy", "--host", "127.0.0.1", "--token", "t"])
        self.assertEqual(args.command, "api")
        self.assertEqual(args.api_subcommand, "deploy")
        self.assertEqual(args.host, "127.0.0.1")
        self.assertEqual(args.token, "t")
        self.assertIs(args.func, commands.cmd_api)

    def test_all_subcommands_parse(self):
        parser = cli.build_parser()
        for sub in ("deploy", "status", "revert"):
            with self.subTest(sub=sub):
                args = parser.parse_args(["api", sub, "--host", "127.0.0.1"])
                self.assertEqual(args.api_subcommand, sub)
                self.assertFalse(args.dry_run)

    def test_api_dry_run_through_main(self):
        code, output, error = run_cli(
            ["api", "deploy", "--host", "127.0.0.1", "--dry-run", "--generate-token"]
        )
        self.assertEqual(code, 0, error)
        self.assertIn("no device contact", output)

        code, output, error = run_cli(["api", "status", "--host", "127.0.0.1", "--dry-run"])
        self.assertEqual(code, 0, error)
        self.assertIn("# e64root api status (read-only)", output)

        code, output, error = run_cli(["api", "revert", "--host", "127.0.0.1", "--dry-run"])
        self.assertEqual(code, 0, error)
        self.assertIn("# e64root api revert", output)

    def test_api_deploy_without_token_is_a_usage_error(self):
        code, _, error = run_cli(["api", "deploy", "--host", "127.0.0.1", "--dry-run"])
        self.assertEqual(code, 2)
        self.assertIn("--token or --generate-token", error)

    def test_api_help_is_listed(self):
        code, output, _ = run_cli(["--help"])
        self.assertEqual(code, 0)
        self.assertIn("api", output)


if __name__ == "__main__":
    unittest.main()
