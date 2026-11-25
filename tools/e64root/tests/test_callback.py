from __future__ import annotations

import unittest
import urllib.error
import urllib.request

from helpers import FIXTURES  # noqa: F401  (sets sys.path)

from e64root.callback import CallbackServer, detect_callback_host
from e64root.errors import VerificationError


class CallbackTests(unittest.TestCase):
    def test_post_is_returned_to_waiter(self):
        with CallbackServer("127.0.0.1", timeout=2) as server:
            request = urllib.request.Request(server.url, data=b"uid=0(root)\n", method="POST")
            with urllib.request.urlopen(request, timeout=2) as response:
                self.assertEqual(response.status, 200)
            result = server.wait(2)
            self.assertEqual(result.body, b"uid=0(root)\n")
            self.assertEqual(result.remote_address, "127.0.0.1")

    def test_wrong_path_is_refused(self):
        with CallbackServer("127.0.0.1", timeout=2) as server:
            wrong = server.url.replace("/e64root/", "/not-e64root/")
            with self.assertRaises(urllib.error.HTTPError) as raised:
                urllib.request.urlopen(
                    urllib.request.Request(wrong, data=b"x", method="POST"), timeout=2
                )
            self.assertEqual(raised.exception.code, 404)
            raised.exception.close()
            # The correct path still works after the rejected request.
            urllib.request.urlopen(
                urllib.request.Request(server.url, data=b"ok", method="POST"), timeout=2
            ).close()
            self.assertEqual(server.wait(2).body, b"ok")

    def test_timeout(self):
        server = CallbackServer("127.0.0.1", timeout=0.05).start()
        try:
            with self.assertRaises(VerificationError):
                server.wait(0.01)
        finally:
            server.close()

    def test_detect_callback_host_loopback(self):
        self.assertEqual(detect_callback_host("127.0.0.1", 443), "127.0.0.1")

    def test_ephemeral_port(self):
        with CallbackServer("127.0.0.1") as server:
            self.assertGreater(server.port, 0)
            self.assertIn(str(server.port), server.url)

    def test_token_is_random_and_path_scoped(self):
        first = CallbackServer("127.0.0.1")
        second = CallbackServer("127.0.0.1")
        self.assertNotEqual(first.path, second.path)
        self.assertTrue(first.path.startswith("/e64root/"))


if __name__ == "__main__":
    unittest.main()
