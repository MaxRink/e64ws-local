"""Tests for the E64 client token helpers."""
from __future__ import annotations

import unittest

from tools.e64ws_client import no_password_payload
from tools.vendor_pwhash import vendor_hash


class NoPasswordPayloadTests(unittest.TestCase):
    def test_payload_is_select_only_and_shell_safe(self) -> None:
        role, password, encoded = no_password_payload()
        self.assertTrue(role.startswith('x" UNION SELECT "1$1000$'))
        self.assertTrue(role.endswith('" -- '))
        self.assertNotIn("'", role)
        self.assertNotIn("\n", role)
        self.assertTrue(password)
        self.assertTrue(encoded.startswith("1$1000$"))

    def test_payload_hash_matches_the_supplied_password(self) -> None:
        _, password, encoded = no_password_payload()
        version, rounds, salt, expected = encoded.split("$", 3)
        self.assertEqual(version, "1")
        self.assertEqual(rounds, "1000")
        self.assertEqual(vendor_hash(password, salt, int(rounds)), expected)

    def test_payload_is_random_per_call(self) -> None:
        first = no_password_payload()
        second = no_password_payload()
        self.assertNotEqual(first[0], second[0])


if __name__ == "__main__":
    unittest.main()
