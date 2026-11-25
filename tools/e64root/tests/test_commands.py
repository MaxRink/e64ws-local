from __future__ import annotations

import contextlib
import io
import re
import tempfile
import unittest
import urllib.request
from pathlib import Path
from unittest.mock import patch

from helpers import FakeCallback, FakeClient, FakeEsp, FakeSSH, FakeWeb, args_for, callback_factory

from e64root import commands
from e64root.errors import PreconditionError, UsageError, VerificationError
from e64root.httpclient import BannerProbe, TLSProbe, WebSocketProbe
from e64root.payloads import inspect_zip, zip_top_level

KEY = (
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl "
    "owner@test"
)


def captured(callable_, *args, **kwargs):
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        result = callable_(*args, **kwargs)
    return result, output.getvalue()


class WebCommandTests(unittest.TestCase):
    def test_dry_run_does_not_contact(self):
        args = args_for("web", dry_run=True, yes=False)
        _, output = captured(commands.cmd_web, args)
        self.assertIn("dry-run", output)
        self.assertIn("userRole=x';<command>;#", output)
        self.assertIn("id >>", output)

    def test_requires_yes(self):
        args = args_for("web", yes=False)
        with self.assertRaises(UsageError):
            commands.cmd_web(args)

    def test_end_to_end_prints_uid(self):
        client = FakeClient()
        web = FakeWeb()
        callback = FakeCallback()
        args = args_for("web")
        _, output = captured(
            commands.cmd_web, args, client=client, web=web,
            callback_factory=lambda: callback,
        )
        self.assertIn("observed: uid=0(root)", output)
        self.assertEqual(len(web.scripts), 1)
        self.assertTrue(callback.closed)
        self.assertIn("preflight: E64", output)
        self.assertIn("id >>", web.scripts[0])
        self.assertIn(callback.url, web.scripts[0])
        self.assertIn("--post-file /tmp/e64root-last.out", web.scripts[0])

    def test_real_callback_listener(self):
        client = FakeClient()

        class PostingWeb(FakeWeb):
            def run_script(self, script: str) -> int:
                self.scripts.append(script)
                match = re.search(r"http://[^\s']+/e64root/[A-Za-z0-9_-]+", script)
                self.assert_url = match.group(0) if match else ""
                request = urllib.request.Request(
                    self.assert_url, data=b"uid=0(root) gid=0(root)\n", method="POST"
                )
                urllib.request.urlopen(request, timeout=2).close()
                return 1

        web = PostingWeb()
        args = args_for("web", callback_host="127.0.0.1")
        _, output = captured(commands.cmd_web, args, client=client, web=web)
        self.assertIn("observed: uid=0(root)", output)
        self.assertTrue(web.assert_url.startswith("http://127.0.0.1:"))

    def test_non_root_callback_is_rejected(self):
        web = FakeWeb()
        callback = FakeCallback(body=b"uid=33(www-data) gid=33(www-data)\n")
        args = args_for("web")
        with self.assertRaises(VerificationError):
            captured(
                commands.cmd_web, args, client=FakeClient(), web=web,
                callback_factory=lambda: callback,
            )
        self.assertTrue(callback.closed)


class EspCommandTests(unittest.TestCase):
    def test_dry_run_builds_archive(self):
        args = args_for("esp", dry_run=True, yes=False)
        _, output = captured(commands.cmd_esp, args)
        self.assertIn("archive sha256:", output)
        self.assertIn("payload/do_flash.sh", output)
        self.assertIn("restore_esp", output)

    def test_end_to_end_prints_uid(self):
        web = FakeWeb()
        esp = FakeEsp()
        args = args_for("esp")
        _, output = captured(
            commands.cmd_esp, args, client=FakeClient(), web=web, esp=esp,
            callback_factory=callback_factory(
                web.capture_body.encode(), b"uid=0(root) gid=0(root)\n"
            ),
        )
        self.assertIn("observed: uid=0(root)", output)
        self.assertEqual(len(esp.payloads), 1)
        self.assertEqual(zip_top_level(esp.payloads[0]), ["payload"])
        self.assertTrue(inspect_zip(esp.payloads[0])[0].executable)

    def test_preflight_failure_aborts_before_upload(self):
        web = FakeWeb(capture_body="uid=0\nlog_www_writable=no\n")
        esp = FakeEsp()
        args = args_for("esp")
        with self.assertRaises(PreconditionError):
            captured(
                commands.cmd_esp, args, client=FakeClient(), web=web, esp=esp,
                callback_factory=callback_factory(web.capture_body.encode()),
            )
        self.assertEqual(esp.payloads, [])

    def test_skip_preflight_is_explicit(self):
        esp = FakeEsp()
        web = FakeWeb()
        args = args_for("esp", preflight="skip")
        _, output = captured(
            commands.cmd_esp, args, client=FakeClient(), web=web, esp=esp,
            callback_factory=callback_factory(b"uid=0(root) gid=0(root)\n"),
        )
        self.assertIn("skipped by explicit", output)
        self.assertEqual(len(esp.payloads), 1)


class SshCommandTests(unittest.TestCase):
    def _key_file(self, directory: str) -> str:
        path = Path(directory) / "owner.pub"
        path.write_text(KEY + "\n", encoding="utf-8")
        return str(path)

    def test_dry_run_prints_plan(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as directory:
            pub = self._key_file(directory)
            dropbear = Path(directory) / "dropbear"
            dropbear.write_bytes(b"\x7fELFfake")
            args = args_for(
                "ssh", dry_run=True, yes=False, pubkey_file=pub, dropbear=str(dropbear)
            )
            _, output = captured(commands.cmd_ssh, args)
        self.assertIn("daemon: dropbear", output)
        self.assertIn("binary sha256:", output)
        self.assertIn("S85dropbear", output)

    def test_requires_pubkey(self):
        args = args_for("ssh", pubkey_file=None, dropbear="/nonexistent")
        with self.assertRaises(UsageError):
            commands.cmd_ssh(args)

    def test_dropbear_and_existing_daemon_are_mutually_exclusive(self):
        args = args_for(
            "ssh", pubkey_file="/nonexistent", dropbear="/nonexistent",
            existing_daemon="/usr/sbin/dropbear",
        )
        with self.assertRaises(UsageError):
            commands.cmd_ssh(args)

    def test_via_web_installs_and_prints_uid(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as directory:
            pub = self._key_file(directory)
            dropbear = Path(directory) / "dropbear"
            dropbear.write_bytes(b"\x7fELFfake")
            args = args_for(
                "ssh", pubkey_file=pub, dropbear=str(dropbear), ssh_key="unused",
                via="web", ssh_port=2222,
            )
            web = FakeWeb()
            ssh = FakeSSH(id_output="uid=0(root) gid=0(root)\n")
            _, output = captured(
                commands.cmd_ssh, args, client=FakeClient(), web=web, ssh=ssh
            )
        self.assertIn("observed: uid=0(root)", output)
        self.assertTrue(any("e64root-dropbear" in item for item in web.injections))
        self.assertEqual(len(web.scripts), 1)
        self.assertTrue(ssh.waited)

    def test_via_esp_installs_and_prints_uid(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as directory:
            pub = self._key_file(directory)
            dropbear = Path(directory) / "dropbear"
            dropbear.write_bytes(b"\x7fELFfake")
            args = args_for(
                "ssh", pubkey_file=pub, dropbear=str(dropbear), ssh_key="unused",
                via="esp",
            )
            esp = FakeEsp()
            ssh = FakeSSH()
            _, output = captured(
                commands.cmd_ssh, args, client=FakeClient(), esp=esp, ssh=ssh
            )
        self.assertIn("observed: uid=0(root)", output)
        self.assertEqual(len(esp.payloads), 1)
        self.assertEqual(zip_top_level(esp.payloads[0]), ["payload"])

    def test_existing_daemon_avoids_binary_upload(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as directory:
            pub = self._key_file(directory)
            args = args_for(
                "ssh", pubkey_file=pub, dropbear=None,
                existing_daemon="/usr/sbin/dropbear", ssh_key="unused",
            )
            web = FakeWeb()
            ssh = FakeSSH()
            captured(commands.cmd_ssh, args, client=FakeClient(), web=web, ssh=ssh)
        self.assertFalse(any("e64root-dropbear" in item for item in web.injections))


class VerifyCommandTests(unittest.TestCase):
    def test_verify_reports_uid_and_persistence(self):
        inventory = {
            "uid": "0",
            "user": "root",
            "kernel": "6.1.0",
            "dropbear_present": "yes",
            "dropbear_sha256": "abc",
            "dropbear_pid": "123",
            "init_present": "yes",
            "init_managed": "1",
            "manifest_present": "yes",
            "key_block": "1",
            "log_stat": "777 logdata logdata",
            "log_www_writable": "yes",
            "tty_stm5": "yes",
            "flash_script": "yes",
            "root_mount": "rw,relatime",
            "uptime": "42.0",
        }
        ssh = FakeSSH(inventory=inventory)
        args = args_for("verify", ssh_key="unused")
        _, output = captured(commands.cmd_verify, args, ssh=ssh)
        self.assertIn("observed: uid=0", output)
        self.assertIn("persistence", output)
        self.assertIn("/root/.ssh/authorized_keys", output)

    def test_verify_rejects_non_root(self):
        ssh = FakeSSH(inventory={"uid": "1000", "user": "owner"})
        args = args_for("verify", ssh_key="unused")
        with self.assertRaises(VerificationError):
            captured(commands.cmd_verify, args, ssh=ssh)

    def test_verify_json(self):
        ssh = FakeSSH(inventory={"uid": "0", "user": "root", "issue_b64": ""})
        args = args_for("verify", ssh_key="unused", json=True)
        _, output = captured(commands.cmd_verify, args, ssh=ssh)
        self.assertIn('"uid": "0"', output)


class RevertCommandTests(unittest.TestCase):
    def test_dry_run_does_not_execute(self):
        ssh = FakeSSH(inventory={"uid": "0", "manifest_present": "yes", "key_block": "1"})
        args = args_for("revert", ssh_key="unused", yes=False)
        _, output = captured(commands.cmd_revert, args, ssh=ssh)
        self.assertIn("dry run: no changes made", output)
        self.assertEqual(ssh.executed, [])

    def test_yes_executes(self):
        ssh = FakeSSH(inventory={"uid": "0", "manifest_present": "yes", "key_block": "1"})
        args = args_for("revert", ssh_key="unused", yes=True)
        _, output = captured(commands.cmd_revert, args, ssh=ssh)
        self.assertIn("revert finished", output)
        self.assertEqual(len(ssh.executed), 1)
        self.assertIn("# e64root revert", ssh.executed[0])

    def test_print_script_needs_no_ssh(self):
        args = args_for("revert", ssh_key=None, print_script=True)
        _, output = captured(commands.cmd_revert, args)
        self.assertIn("# e64root revert", output)
        self.assertIn("dropbear_sha256", output)


class ProbeCommandTests(unittest.TestCase):
    @patch("e64root.commands.probe_banner", return_value=BannerProbe(False, error="closed"))
    @patch("e64root.commands.probe_websocket", return_value=WebSocketProbe(True, "HTTP/1.1 101"))
    @patch("e64root.commands.probe_tls", return_value=TLSProbe(True, certificate_sha256="abc"))
    @patch("e64root.commands.HTTPClient")
    @patch("e64root.commands._make_client")
    def test_probe_json(self, make_client, http_client, _tls, _ws, _banner):
        fake = FakeClient()
        make_client.return_value = fake
        http_client.return_value = FakeClient(login_html="<html>plain http</html>")
        args = args_for("probe", json=True)
        _, output = captured(commands.cmd_probe, args)
        self.assertIn('"model": "E64"', output)
        self.assertIn('"dev_mode": false', output)
        self.assertIn('"certificate_sha256": "abc"', output)


if __name__ == "__main__":
    unittest.main()
