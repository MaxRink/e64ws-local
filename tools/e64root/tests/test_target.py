from __future__ import annotations

import unittest
from unittest.mock import patch

from helpers import fixture

from e64root.errors import PreconditionError, UsageError
from e64root.target import (
    parse_endpoint,
    guard_target,
    parse_login_page,
    validate_public_keys,
    key_blob,
    key_fingerprint,
    plan_daemon,
    is_private_address,
    require_known_target,
)

KEY = (
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl "
    "owner@test"
)
KEY2 = (
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl "
    "owner2@test"
)


class EndpointTests(unittest.TestCase):
    def test_host_only_uses_default_port(self):
        endpoint = parse_endpoint("192.168.1.50", 443)
        self.assertEqual((endpoint.host, endpoint.port), ("192.168.1.50", 443))

    def test_host_and_port(self):
        endpoint = parse_endpoint("grinder.local:28443", 443)
        self.assertEqual((endpoint.host, endpoint.port), ("grinder.local", 28443))
        self.assertEqual(endpoint.authority, "grinder.local:28443")

    def test_ipv6_bracket(self):
        endpoint = parse_endpoint("[fe80::1]:8443", 443)
        self.assertEqual(endpoint.host, "fe80::1")
        self.assertEqual(endpoint.port, 8443)

    def test_rejects_url_and_path(self):
        for value in ("https://192.168.1.50", "192.168.1.50/login.php"):
            with self.subTest(value=value):
                with self.assertRaises(UsageError):
                    parse_endpoint(value, 443)

    def test_rejects_bad_port(self):
        with self.assertRaises(UsageError):
            parse_endpoint("host:not-a-port", 443)
        with self.assertRaises(UsageError):
            parse_endpoint("host:70000", 443)


class GuardTests(unittest.TestCase):
    def test_private_detection(self):
        self.assertTrue(is_private_address("127.0.0.1"))
        self.assertTrue(is_private_address("192.168.1.20"))
        self.assertTrue(is_private_address("fe80::1"))
        self.assertFalse(is_private_address("8.8.8.8"))

    @patch("e64root.target.resolve_addresses", return_value=["192.168.1.20"])
    def test_private_target_allowed(self, _resolve):
        guard = guard_target("grinder.local")
        self.assertTrue(guard.private)
        self.assertEqual(guard.addresses, ("192.168.1.20",))

    @patch("e64root.target.resolve_addresses", return_value=["8.8.8.8"])
    def test_public_target_refused(self, _resolve):
        with self.assertRaises(PreconditionError):
            guard_target("example.com")

    @patch("e64root.target.resolve_addresses", return_value=["8.8.8.8"])
    def test_public_target_allowed_with_opt_in(self, _resolve):
        guard = guard_target("example.com", allow_public=True)
        self.assertFalse(guard.private)


class LoginPageTests(unittest.TestCase):
    def test_shipped_style_page(self):
        fingerprint = parse_login_page(fixture("login.html"), "https://x/login.php", 200)
        self.assertEqual(fingerprint.title, "E64")
        self.assertEqual(fingerprint.model, "E64")
        self.assertEqual(fingerprint.serial, "0123456789AB")
        self.assertEqual(fingerprint.firmware, "V01.16 build #24 from 06.08.2026 (custom)")
        self.assertFalse(fingerprint.dev_mode)
        self.assertTrue(fingerprint.known)
        self.assertEqual(fingerprint.family, "HSG")

    def test_dev_mode_from_option_and_suffix(self):
        fingerprint = parse_login_page(fixture("login_dev.html"))
        self.assertTrue(fingerprint.dev_mode)
        self.assertIn("development", fingerprint.firmware)

    def test_dev_mode_requires_option_or_suffix(self):
        page = fixture("login.html").replace("(custom)", "(custom) development")
        fingerprint = parse_login_page(page)
        self.assertFalse(fingerprint.dev_mode)

    def test_unknown_page(self):
        fingerprint = parse_login_page("<html><title>router</title></html>", "https://x", 200)
        self.assertFalse(fingerprint.known)
        self.assertEqual(fingerprint.model, "")
        self.assertTrue(fingerprint.notes)

    def test_supported_firmware_passes(self):
        require_known_target(parse_login_page(fixture("login.html")))

    def test_unsupported_firmware_refused(self):
        page = fixture("login.html").replace("V01.16", "V02.00")
        with self.assertRaises(PreconditionError):
            require_known_target(parse_login_page(page))

    def test_unsupported_firmware_can_be_overridden(self):
        page = fixture("login.html").replace("V01.16", "V02.00")
        require_known_target(parse_login_page(page), allow_unverified=True)


class KeyTests(unittest.TestCase):
    def test_single_key(self):
        keys = validate_public_keys(KEY + "\n")
        self.assertEqual(len(keys), 1)
        self.assertEqual(key_blob(keys[0]).startswith("AAAAC3"), True)
        self.assertEqual(len(key_fingerprint(keys[0])), 16)

    def test_multiple_keys_comments_and_blanks(self):
        keys = validate_public_keys(f"# owner keys\n\n{KEY}\n{KEY2}\n")
        self.assertEqual(len(keys), 2)

    def test_rejects_unsupported_type(self):
        with self.assertRaises(UsageError):
            validate_public_keys("ssh-dss AAAAB3NzaC1kc3MAAACB owner")

    def test_rejects_control_characters_and_newline_injection(self):
        with self.assertRaises(UsageError):
            validate_public_keys(KEY + "\nrm -rf /")
        with self.assertRaises(UsageError):
            validate_public_keys(KEY.replace("owner@test", "owner\x01@test"))

    def test_rejects_empty(self):
        with self.assertRaises(UsageError):
            validate_public_keys("\n# only comments\n")


class DaemonPlanTests(unittest.TestCase):
    def test_uploaded_dropbear(self):
        plan = plan_daemon(b"\x7fELFbinary", None)
        self.assertEqual(plan.kind, "dropbear")
        self.assertTrue(plan.needs_upload)
        self.assertEqual(plan.remote_path, "/usr/sbin/dropbear")

    def test_existing_daemon(self):
        plan = plan_daemon(None, "/usr/sbin/dropbear")
        self.assertEqual(plan.kind, "dropbear")
        self.assertFalse(plan.needs_upload)
        plan = plan_daemon(None, "/usr/sbin/sshd")
        self.assertEqual(plan.kind, "sshd")

    def test_no_daemon(self):
        with self.assertRaises(UsageError):
            plan_daemon(None, None)

    def test_rejects_shell_injection_in_existing_path(self):
        with self.assertRaises(UsageError):
            plan_daemon(None, "/usr/sbin/dropbear; reboot")


if __name__ == "__main__":
    unittest.main()
