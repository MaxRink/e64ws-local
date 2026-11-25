"""Opt-in integration test against the virtual grinder.

Nothing here runs in a normal unit-test job.  Start the VM first:

    /tmp/virtual-grinder/vg build
    /tmp/virtual-grinder/vg up
    export E64ROOT_VG_URL=https://127.0.0.1:28443
    python3 -m unittest tools.e64root.tests.test_integration_virtual_grinder -v

The test is read-only: it fetches ``/login.php`` and parses the same fields the
``probe`` command uses.  It never sends an injection or uploads an archive.
"""

from __future__ import annotations

import os
import unittest
import urllib.parse

from helpers import FIXTURES  # noqa: F401  (sets sys.path)

from e64root.httpclient import HTTPClient, TLSConfig
from e64root.target import parse_login_page

VG_URL = os.environ.get("E64ROOT_VG_URL", "")


@unittest.skipUnless(VG_URL, "set E64ROOT_VG_URL to run the virtual-grinder integration test")
class VirtualGrinderIntegrationTests(unittest.TestCase):
    def test_read_only_fingerprint(self):
        parsed = urllib.parse.urlparse(VG_URL)
        self.assertIn(parsed.scheme, ("http", "https"))
        from e64root.target import Endpoint

        endpoint = Endpoint(parsed.hostname or "127.0.0.1", parsed.port or (443 if parsed.scheme == "https" else 80))
        client = HTTPClient(
            endpoint,
            scheme=parsed.scheme,
            tls=TLSConfig(insecure=True),
            timeout=10,
        )
        response = client.get("/login.php")
        self.assertEqual(response.status, 200)
        fingerprint = parse_login_page(response.text, client.url("/login.php"), response.status)
        self.assertTrue(fingerprint.known, fingerprint.as_dict())
        self.assertIn("E64", fingerprint.model)
        self.assertTrue(fingerprint.firmware.startswith("V"), fingerprint.firmware)


if __name__ == "__main__":
    unittest.main()
