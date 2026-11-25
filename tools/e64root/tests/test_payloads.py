from __future__ import annotations

import io
import subprocess
import unittest
import zipfile

from helpers import FIXTURES  # noqa: F401  (sets sys.path)

from e64root.errors import UsageError
from e64root.payloads import (
    INIT_MARKER,
    KEY_BEGIN,
    KEY_END,
    capture_script,
    esp_script,
    esp_zip,
    inspect_zip,
    install_init_script,
    install_script,
    inventory_script,
    preflight_script,
    revert_script,
    verify_script,
    web_script,
    zip_top_level,
)
from e64root.target import plan_daemon

KEY = (
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOwnerTestKeyMaterial0000000000000000000000000 "
    "owner@test"
)
CALLBACK = "http://127.0.0.1:9/e64root/test-token"


class WebScriptTests(unittest.TestCase):
    def test_contains_command_uid_and_watchdog(self):
        script = web_script("uname -a", CALLBACK, timeout=17)
        self.assertIn("set -u", script)
        self.assertIn(CALLBACK, script)
        self.assertIn("id >>", script)
        self.assertIn("sleep 17", script)
        self.assertIn("base64 -d", script)
        self.assertIn("http_proxy= HTTP_PROXY= wget -q -O /dev/null --post-file /tmp/e64root-last.out", script)

    def test_rejects_unsafe_callback(self):
        with self.assertRaises(UsageError):
            web_script("id", "http://127.0.0.1:9/e64root/../bad")
        with self.assertRaises(UsageError):
            web_script("id", "file:///tmp/not-a-callback")

    def test_rejects_nul(self):
        with self.assertRaises(UsageError):
            web_script("id\x00", CALLBACK)

    def test_rejects_empty(self):
        with self.assertRaises(UsageError):
            web_script("", CALLBACK)


class EspScriptTests(unittest.TestCase):
    def test_restores_esp_before_anything_else(self):
        script = esp_script("id", CALLBACK)
        restore_at = script.index("restore_esp()")
        mount_at = script.index("mount -o remount")
        self.assertLess(restore_at, mount_at)
        self.assertIn("unsetEspBootmode.sh", script)
        self.assertIn("trap 'kill \"$e64root_watchdog\" 2>/dev/null; restore_esp; exit 124'", script)

    def test_does_not_open_or_write_esp_tty(self):
        script = esp_script("id", CALLBACK)
        self.assertNotIn("/dev/ttySTM5", script)
        self.assertNotIn("esptool", script)
        self.assertNotIn("dd if=", script)

    def test_archive_has_one_top_level_directory(self):
        payload = esp_zip(esp_script("id", CALLBACK))
        self.assertEqual(zip_top_level(payload), ["payload"])
        names = [member.name for member in inspect_zip(payload)]
        self.assertEqual(names, ["payload/do_flash.sh"])
        self.assertTrue(inspect_zip(payload)[0].executable)

    def test_archive_with_binary(self):
        payload = esp_zip(esp_script("id", CALLBACK), b"dropbear-binary")
        names = [member.name for member in inspect_zip(payload)]
        self.assertEqual(names, ["payload/do_flash.sh", "payload/dropbear"])

    def test_rejects_path_traversal_member(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("../do_flash.sh", "id\n")
        with self.assertRaises(UsageError):
            inspect_zip(buffer.getvalue())


class InstallScriptTests(unittest.TestCase):
    def setUp(self):
        self.plan = plan_daemon(b"binary", None)
        self.script = install_script([KEY], self.plan, port=2222)

    def test_backs_up_vendor_files(self):
        self.assertIn("/root/.e64root/backup/authorized_keys", self.script)
        self.assertIn("/root/.e64root/backup/init", self.script)
        self.assertIn("cp -p", self.script)

    def test_key_block_and_permissions(self):
        self.assertIn(KEY_BEGIN, self.script)
        self.assertIn(KEY_END, self.script)
        self.assertIn("chmod 600 /root/.ssh/authorized_keys", self.script)

    def test_binary_digest_and_upload_path(self):
        self.assertIn("/tmp/e64root-dropbear", self.script)
        self.assertIn('$(dirname "$0")/dropbear', self.script)
        self.assertIn("sha256sum", self.script)
        self.assertIn("install -m 0755", self.script)

    def test_init_and_manifest(self):
        self.assertIn("/etc/init.d/S85dropbear", self.script)
        self.assertIn(INIT_MARKER, self.script)
        self.assertIn("/root/.e64root/manifest", self.script)
        self.assertIn("port=2222", self.script)

    def test_never_downloads(self):
        for token in ("curl ", "wget ", "http://", "https://"):
            self.assertNotIn(token, self.script)

    def test_existing_daemon_does_not_upload(self):
        plan = plan_daemon(None, "/usr/sbin/dropbear")
        script = install_script([KEY], plan)
        self.assertNotIn("/tmp/e64root-dropbear", script)
        self.assertIn("is not executable", script)

    def test_init_dropbear_uses_documented_flags(self):
        init = install_init_script(self.plan, 22)
        self.assertIn("-R -p 22", init)
        self.assertIn("start-stop-daemon", init)
        self.assertIn(INIT_MARKER, init)

    def test_init_sshd(self):
        init = install_init_script(plan_daemon(None, "/usr/sbin/sshd"), 2222)
        self.assertIn("-p 2222", init)
        self.assertNotIn("-R", init)


class RevertScriptTests(unittest.TestCase):
    def test_removes_block_and_hash_gated_binary(self):
        script = revert_script([KEY])
        self.assertIn(KEY_BEGIN, script)
        self.assertIn("key-block-removed", script)
        self.assertIn("dropbear_sha256", script)
        self.assertIn("dropbear-kept-not-ours", script)
        self.assertIn("init-kept-not-ours", script)

    def test_exact_key_removal_uses_second_field(self):
        script = revert_script([KEY])
        self.assertIn("$2 != b1", script)
        self.assertIn("authorized_keys", script)
        self.assertNotIn("grep -Fvx", script)

    def test_does_not_restore_authorized_keys_over_newer_keys(self):
        script = revert_script([KEY])
        self.assertNotIn("authorized_keys-restored-from-backup", script)

    def test_purge_backups_is_explicit(self):
        self.assertNotIn("rm -rf /root/.e64root", revert_script([]))
        self.assertIn("rm -rf /root/.e64root", revert_script([], purge_backups=True))

    def test_keep_daemon_avoids_kill(self):
        self.assertIn("start-stop-daemon -K", revert_script([]))
        self.assertNotIn("start-stop-daemon -K", revert_script([], keep_daemon=True))

    def test_no_downloads(self):
        for token in ("curl ", "wget ", "http://", "https://"):
            self.assertNotIn(token, revert_script([KEY]))


class ReadOnlyScriptTests(unittest.TestCase):
    def test_verify_script_fields(self):
        script = verify_script([KEY])
        for token in ("uid", "dropbear_sha256", "init_managed", "key_block",
                      "log_www_writable", "issue_b64"):
            self.assertIn(token, script)

    def test_inventory_script_fields(self):
        script = inventory_script([KEY])
        for token in ("manifest_present", "backup_keys", "backup_init", "key_present_1"):
            self.assertIn(token, script)

    def test_preflight_script_fields(self):
        script = preflight_script()
        for token in ("log_www_writable", "tty_stm5", "flash_script", "set_bootmode"):
            self.assertIn(token, script)

    def test_capture_script_posts_callback(self):
        script = capture_script(verify_script([]), CALLBACK)
        self.assertIn(CALLBACK, script)
        self.assertIn("base64 -d", script)
        self.assertIn("http_proxy= HTTP_PROXY= wget -q -O /dev/null --post-file /tmp/e64root-last.out", script)


class ShellSyntaxTests(unittest.TestCase):
    """The target shell is busybox ash, but ``sh -n`` catches gross errors."""

    def assert_shell_syntax(self, script: str) -> None:
        completed = subprocess.run(
            ["sh", "-n"], input=script.encode(), stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, check=False,
        )
        self.assertEqual(
            completed.returncode,
            0,
            completed.stderr.decode(errors="replace") + "\n---\n" + script,
        )

    def test_web_script(self):
        self.assert_shell_syntax(web_script("id", CALLBACK))

    def test_esp_script(self):
        self.assert_shell_syntax(esp_script("id", CALLBACK))

    def test_install_script(self):
        self.assert_shell_syntax(install_script([KEY], plan_daemon(b"binary", None)))

    def test_dropbear_init(self):
        self.assert_shell_syntax(install_init_script(plan_daemon(b"binary", None), 22))

    def test_sshd_init(self):
        self.assert_shell_syntax(install_init_script(plan_daemon(None, "/usr/sbin/sshd"), 22))

    def test_revert_script(self):
        self.assert_shell_syntax(revert_script([KEY]))

    def test_verify_script(self):
        self.assert_shell_syntax(verify_script([KEY]))

    def test_capture_script(self):
        self.assert_shell_syntax(capture_script(verify_script([]), CALLBACK))


if __name__ == "__main__":
    unittest.main()
