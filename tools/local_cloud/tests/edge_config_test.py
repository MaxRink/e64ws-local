"""Deployment-configuration tests for the local-cloud stack (INF-01 to INF-10).

These tests read the files an owner actually deploys - ``docker-compose.yml``,
``docker-compose.templates.yml``, ``Caddyfile``, ``Caddyfile.offline``,
``.env.example``, ``gen-dev-certs.sh`` and the two documents that describe them -
and, where the checker is available offline, they run it: ``docker compose
config``, ``caddy adapt`` and a real TLS handshake against a running Caddy.

Why they live here
------------------

Every finding they lock down was a *deployment* finding: the service code was
right and the files an owner copies were not. ``local_cloud_test.py`` starts the
service in-process and would pass with all of them present, which is exactly how
they survived. Each class names the finding it covers so a reader can go from
the audit to the check.

Skips are honest, not silent
----------------------------

Three external checkers are optional: the ``docker compose`` plugin (no daemon
needed - ``config`` only parses), the ``caddy`` image (must already be pulled;
nothing here pulls or needs the network) and ``openssl`` (for certificate
material). A missing checker skips the checks that need it and *says so in the
skip message*; the source-level checks in the same class still run. The suite
therefore works on a clean checkout with no network and on this repository's CI
(``sh tools/run_tests.sh``), where no image may be assumed present.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import socket
import ssl
import stat
import subprocess
import tempfile
import time
import unittest
from contextlib import closing
from pathlib import Path
from unittest import mock

from tools.local_cloud import service, store

ROOT = Path(__file__).resolve().parents[3]
DEPLOY = ROOT / "deploy" / "local-cloud"
COMPOSE = DEPLOY / "docker-compose.yml"
TEMPLATES = DEPLOY / "docker-compose.templates.yml"
CADDY_DEVICE = DEPLOY / "Caddyfile"
CADDY_OFFLINE = DEPLOY / "Caddyfile.offline"
ENV_EXAMPLE = DEPLOY / ".env.example"
README = DEPLOY / "README.md"
GEN_CERTS = DEPLOY / "gen-dev-certs.sh"
DESIGN = ROOT / "docs" / "LOCAL_CLOUD_DESIGN.md"

from tools.required_inputs import skip_without  # noqa: E402  (ROOT is on sys.path)

DEVICE_SITE = "ngx-secured.sync.mahlkoenig.com"
IDENTITY_HEADER = service.CLIENT_CERT_HEADER  # X-Client-Cert-Fingerprint
FORGED_FINGERPRINT = "AB" * 32


# ---------------------------------------------------------------------------
# external checkers: presence, and one place that knows how to call them
# ---------------------------------------------------------------------------


def _run(
    arguments: list[str], *, cwd: Path = ROOT, timeout: float = 120.0, env: dict | None = None
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        arguments,
        cwd=str(cwd),
        capture_output=True,
        text=True,
        timeout=timeout,
        env=env,
        check=False,
    )


def compose_available() -> bool:
    """True when the ``docker compose`` plugin can parse a file.

    ``docker compose config`` does not talk to the daemon, so this is available
    on a machine with only the CLI installed. The check is deliberately a
    ``version`` call: a broken plugin must not look like a failing test.
    """

    try:
        return _run(["docker", "compose", "version"], timeout=60).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def docker_available() -> bool:
    """True when the daemon answers; only the container-based checks need it."""

    try:
        return _run(["docker", "info", "--format", "{{.ServerVersion}}"], timeout=60).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def caddy_image() -> str:
    """The Caddy tag the compose file pins, so the checks follow a version bump."""

    for block in yaml_services(COMPOSE).values():
        match = re.search(r"^\s+image:\s*(caddy:\S+)\s*$", block, re.M)
        if match:
            return match.group(1)
    return "caddy:2.11.9-alpine"


def caddy_image_available() -> bool:
    """True when the pinned Caddy image is already local (nothing is pulled)."""

    try:
        return _run(["docker", "image", "inspect", caddy_image()], timeout=60).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def compose_env(**overrides: str) -> dict[str, str]:
    """A clean environment for ``docker compose``.

    ``COMPOSE_*`` from the caller's shell would silently change which files are
    read, and a stray ``.env`` in the checkout would make "the default" mean
    something different on every machine, so the compose tests pin both.
    """

    env = {key: value for key, value in os.environ.items() if not key.startswith("COMPOSE_")}
    env.update(overrides)
    return env


def empty_env_file(directory: Path) -> Path:
    """An empty ``--env-file``: compose reads it *instead of* the checkout .env."""

    path = directory / "empty.env"
    path.write_text("", encoding="utf-8")
    return path


def compose_json(*arguments: str, env: dict[str, str] | None = None) -> dict:
    """``docker compose … config --format json`` as a dict; fails the test loudly."""

    with tempfile.TemporaryDirectory(prefix="local-cloud-compose-env-") as scratch:
        base = ["docker", "compose", "--env-file", str(empty_env_file(Path(scratch)))]
        result = _run(
            [*base, *arguments, "config", "--format", "json"],
            cwd=DEPLOY,
            env=env or compose_env(),
        )
    if result.returncode != 0:
        raise AssertionError(f"docker compose config failed: {result.stderr}{result.stdout}")
    return json.loads(result.stdout)


def adapt(path: Path) -> dict:
    """``caddy adapt`` for one Caddyfile, run from the pinned image."""

    result = _run(
        [
            "docker", "run", "--rm",
            "-v", f"{path}:/cfg/Caddyfile:ro",
            caddy_image(), "caddy", "adapt", "--config", "/cfg/Caddyfile",
            "--adapter", "caddyfile",
        ],
        timeout=120,
    )
    if result.returncode != 0:
        raise AssertionError(f"caddy adapt failed for {path.name}: {result.stderr}")
    return json.loads(result.stdout)


# ---------------------------------------------------------------------------
# file parsers (stdlib only: a YAML or Caddyfile library is not a dependency)
# ---------------------------------------------------------------------------


def yaml_services(path: Path) -> dict[str, str]:
    """Return ``{service: block text}`` for a compose file.

    The compose files here are block-style mappings with two-space service
    indentation, so splitting on that is enough to answer "does this service
    have a logging key" without adding a YAML dependency to a stdlib-only
    repository.
    """

    services: dict[str, list[str]] = {}
    in_services = False
    current: str | None = None
    for line in path.read_text(encoding="utf-8").splitlines():
        if re.match(r"^services:\s*$", line):
            in_services = True
            current = None
            continue
        if in_services and re.match(r"^\S", line):
            in_services = False
            current = None
            continue
        if not in_services:
            continue
        match = re.match(r"^  ([A-Za-z0-9_.-]+):\s*$", line)
        if match:
            current = match.group(1)
            services[current] = []
            continue
        if current is not None:
            services[current].append(line)
    return {name: "\n".join(body) for name, body in services.items()}


def yaml_top_level_block(path: Path, key: str) -> str:
    """The indented body of one top-level ``key:`` mapping."""

    lines = path.read_text(encoding="utf-8").splitlines()
    body: list[str] = []
    inside = False
    for line in lines:
        if not inside:
            if re.match(rf"^{re.escape(key)}:\s*", line):
                inside = True
            continue
        if re.match(r"^\S", line):
            break
        body.append(line)
    return "\n".join(body)


def caddyfile_blocks(text: str) -> list[tuple[str, str]]:
    """Split a Caddyfile into top-level ``(label, body)`` blocks.

    ``label`` is the site address (``https://host``, ``:8088``, ``localhost:8443``)
    or the empty string for the global options block. Comments are stripped;
    placeholders such as ``{http.request.tls.client.fingerprint}`` are balanced,
    so they do not disturb the brace depth.
    """

    blocks: list[tuple[str, str]] = []
    depth = 0
    label = ""
    body: list[str] = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if depth == 0:
            if line.endswith("{"):
                label = line[:-1].strip()
                depth = 1
                body = []
            continue
        if line == "}" and depth == 1:
            blocks.append((label, "\n".join(body)))
            depth = 0
            label = ""
            body = []
            continue
        body.append(line)
        depth += line.count("{") - line.count("}")
    return blocks


def iter_blocks(text: str) -> list[tuple[str, str]]:
    """Every block in a Caddyfile, nested ones included."""

    found: list[tuple[str, str]] = []
    for label, body in caddyfile_blocks(text):
        found.append((label, body))
        found.extend(iter_blocks(body))
    return found


def site_blocks(text: str) -> list[tuple[str, str]]:
    """Only the site blocks: the global options block has no label."""

    return [(label, body) for label, body in caddyfile_blocks(text) if label]


def site_host(label: str) -> str:
    """``https://host/path`` or ``host:port`` -> ``host``."""

    host = label.split("://", 1)[-1].split("/", 1)[0]
    return host.rsplit(":", 1)[0] if ":" in host else host


def parse_env_file(path: Path) -> dict[str, str]:
    """KEY=VALUE pairs, ignoring comments and blank lines."""

    values: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        values[key.strip()] = value.strip()
    return values


# ---------------------------------------------------------------------------
# small container/network helpers for the end-to-end checks
# ---------------------------------------------------------------------------


def free_port() -> int:
    with closing(socket.socket()) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def http_get(port: int, path: str, headers: dict[str, str] | None = None) -> tuple[int, str]:
    """One plain-HTTP GET against 127.0.0.1:port; returns (status, body)."""

    import http.client

    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    try:
        connection.request("GET", path, headers=headers or {})
        response = connection.getresponse()
        return response.status, response.read().decode("utf-8", "replace")
    finally:
        connection.close()


def wait_for_http(port: int, path: str, *, timeout: float = 45.0) -> None:
    deadline = time.monotonic() + timeout
    last: Exception | None = None
    while time.monotonic() < deadline:
        try:
            status, _ = http_get(port, path)
            if status:
                return
        except OSError as error:  # connection refused while Caddy starts
            last = error
        time.sleep(0.25)
    raise AssertionError(f"nothing answered on 127.0.0.1:{port}{path} within {timeout}s") from last


class DockerTestCase(unittest.TestCase):
    """Base class that guarantees its containers and networks are removed."""

    def docker(self, *arguments: str, timeout: float = 120.0) -> subprocess.CompletedProcess[str]:
        result = _run(["docker", *arguments], timeout=timeout)
        if result.returncode != 0:
            raise AssertionError(f"docker {' '.join(arguments)} failed: {result.stderr.strip()}")
        return result

    def container(self, name: str, *arguments: str) -> str:
        self.addCleanup(self._remove_container, name)
        self.docker("run", "--rm", "-d", "--name", name, *arguments)
        return name

    def network(self, name: str) -> str:
        self.addCleanup(self._remove_network, name)
        self.docker("network", "create", name)
        return name

    def _remove_container(self, name: str) -> None:
        _run(["docker", "rm", "-f", name], timeout=60)

    def _remove_network(self, name: str) -> None:
        _run(["docker", "network", "rm", name], timeout=60)


# ---------------------------------------------------------------------------
# INF-01: the default edge must not publish on 0.0.0.0
# ---------------------------------------------------------------------------


class EdgeBindingTests(unittest.TestCase):
    """INF-01: `proxy` published 8088/8443 on every interface while `admin` was
    correctly loopback-only. A LAN bind is now an explicit ``LOCAL_CLOUD_EDGE_BIND``
    opt-in with a loopback default."""

    def test_every_edge_port_is_bound_through_the_opt_in_variable(self) -> None:
        block = yaml_services(COMPOSE)["proxy"]
        published = re.findall(r'^\s+-\s+"?([^"\s]+:[0-9]+:[0-9]+)"?\s*$', block, re.M)
        self.assertTrue(published, "the proxy service publishes no port at all?")
        for mapping in published:
            host_part = mapping.split(":", 1)[0] if not mapping.startswith("${") else mapping
            self.assertTrue(
                host_part.startswith("${LOCAL_CLOUD_EDGE_BIND:-127.0.0.1}"),
                f"{mapping!r} is not bound through ${{LOCAL_CLOUD_EDGE_BIND:-127.0.0.1}}",
            )

    @unittest.skipUnless(compose_available(), "the docker compose plugin is not installed")
    def test_compose_config_publishes_nothing_on_all_interfaces_by_default(self) -> None:
        config = compose_json()
        published = [
            (name, port)
            for name, definition in sorted(config["services"].items())
            for port in definition.get("ports") or []
        ]
        self.assertTrue(published, "no service publishes a port; the check would be vacuous")
        for name, port in published:
            self.assertEqual(
                port.get("host_ip"),
                "127.0.0.1",
                f"{name} publishes {port['published']} on {port.get('host_ip')!r}, not on loopback",
            )

    @unittest.skipUnless(compose_available(), "the docker compose plugin is not installed")
    def test_the_lan_bind_is_an_opt_in_and_leaves_admin_on_loopback(self) -> None:
        config = compose_json(
            env=compose_env(LOCAL_CLOUD_EDGE_BIND="0.0.0.0"),
        )
        proxy = {
            port["published"]: port.get("host_ip") for port in config["services"]["proxy"]["ports"]
        }
        self.assertEqual(proxy, {"8088": "0.0.0.0", "8443": "0.0.0.0"})
        admin = [port["host_ip"] for port in config["services"]["admin"]["ports"]]
        self.assertEqual(admin, ["127.0.0.1"], "the opt-in must not move the admin console")

    def test_the_readme_states_the_tradeoff(self) -> None:
        text = README.read_text(encoding="utf-8")
        self.assertIn("LOCAL_CLOUD_EDGE_BIND", text)
        self.assertIn("127.0.0.1", text)
        self.assertIn("tradeoff", text.lower())
        self.assertIn("docker-compose.templates.yml", README.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# INF-02: a client-supplied identity header must not survive the default edge
# ---------------------------------------------------------------------------


class ProxyIdentityHeaderTests(DockerTestCase):
    """INF-02: `Caddyfile.offline` forwarded ``X-Client-Cert-Fingerprint``
    untouched and ``.env.example`` shipped ``TRUST_PROXY_IDENTITY=true``, so an
    unauthenticated request was attributed to an enrolled device."""

    def test_every_offline_proxy_deletes_the_identity_header(self) -> None:
        text = CADDY_OFFLINE.read_text(encoding="utf-8")
        proxies = [
            body for label, body in iter_blocks(text) if label.startswith("reverse_proxy")
        ]
        self.assertGreaterEqual(len(proxies), 2, "expected one reverse_proxy per API path")
        for body in proxies:
            self.assertIn(
                f"header_up -{IDENTITY_HEADER}",
                body,
                "a reverse_proxy block forwards the identity header unchanged",
            )
            self.assertNotIn(
                f"{IDENTITY_HEADER} {{http.request.header",
                body,
                "a client-supplied header must never be copied into the upstream request",
            )

    def test_the_device_edge_sets_the_header_from_the_handshake(self) -> None:
        text = CADDY_DEVICE.read_text(encoding="utf-8")
        self.assertIn(
            f"header_up {IDENTITY_HEADER} {{http.request.tls.client.fingerprint}}", text
        )

    def test_the_example_environment_does_not_enable_proxy_identity(self) -> None:
        values = parse_env_file(ENV_EXAMPLE)
        self.assertNotIn("LOCAL_CLOUD_TRUST_PROXY_IDENTITY", values)
        self.assertNotRegex(
            ENV_EXAMPLE.read_text(encoding="utf-8"),
            r"(?m)^LOCAL_CLOUD_TRUST_PROXY_IDENTITY=\s*true",
            ".env.example enables the proxy identity header",
        )

    @unittest.skipUnless(docker_available() and caddy_image_available(), "needs docker and the pinned caddy image")
    def test_adapt_emits_a_delete_for_the_identity_header(self) -> None:
        config = adapt(CADDY_OFFLINE)
        proxies: list[dict] = []

        def walk(routes: list[dict]) -> None:
            for route in routes:
                for handle in route.get("handle") or []:
                    if handle.get("handler") == "reverse_proxy":
                        proxies.append(handle)
                    walk(handle.get("routes") or [])

        for server in config["apps"]["http"]["servers"].values():
            walk(server.get("routes") or [])
        self.assertGreaterEqual(len(proxies), 2)
        for proxy in proxies:
            request = (proxy.get("headers") or {}).get("request", {})
            self.assertIn(IDENTITY_HEADER, request.get("delete", []), proxy.get("upstreams"))
            self.assertNotIn(IDENTITY_HEADER, request.get("set", {}))

    @unittest.skipUnless(docker_available() and caddy_image_available(), "needs docker and the pinned caddy image")
    def test_a_spoofed_fingerprint_does_not_survive_the_default_edge(self) -> None:
        """End to end: a forged header reaches the upstream only if the edge lets it.

        The upstream is a stand-in for the API that answers ``200`` **only** when
        the identity header arrives - the decision the API makes when
        ``TRUST_PROXY_IDENTITY`` is on. The edge under test is the committed
        ``Caddyfile.offline``, unmodified.
        """

        scratch = tempfile.TemporaryDirectory(prefix="local-cloud-edge-stub-")
        self.addCleanup(scratch.cleanup)
        stubfile = Path(scratch.name) / "Caddyfile"
        stubfile.write_text(
            ":8080 {\n"
            f"\t@forged header {IDENTITY_HEADER} *\n"
            '\trespond @forged "forged-identity-header-reached-the-api" 200\n'
            '\trespond "no-identity-header" 401\n'
            "}\n",
            encoding="utf-8",
        )

        network = self.network(f"lc-edge-{os.getpid()}-{int(time.time() * 1000) % 100000}")
        self.container(
            "lc-stub-api",
            "--network", network,
            "--network-alias", "api",
            "-v", f"{stubfile}:/etc/caddy/Caddyfile:ro",
            caddy_image(),
        )
        port = free_port()
        self.container(
            "lc-edge",
            "--network", network,
            "-p", f"127.0.0.1:{port}:8088",
            "-v", f"{CADDY_OFFLINE}:/etc/caddy/Caddyfile:ro",
            caddy_image(),
        )
        wait_for_http(port, "/ping")

        status, body = http_get(
            port, "/api/device-service/device-event/status", {IDENTITY_HEADER: FORGED_FINGERPRINT}
        )
        self.assertEqual(status, 401, body)
        self.assertEqual(body, "no-identity-header")

        # Control: the same request without the header must reach the same stub,
        # so a 401 caused by a broken edge cannot pass the check above.
        status, body = http_get(port, "/api/device-service/device-event/status")
        self.assertEqual(status, 401, body)
        self.assertEqual(body, "no-identity-header")


# ---------------------------------------------------------------------------
# INF-03: no unauthenticated site may share the mTLS listener
# ---------------------------------------------------------------------------


class MtlsListenerTests(DockerTestCase):
    """INF-03: ``https://local-cloud.lan`` sat on the same ``:443`` as the mTLS
    vhost with ``tls internal`` and no ``client_auth``; ``caddy adapt`` emitted a
    catch-all policy, so picking that SNI required no certificate at all."""

    def test_every_site_declares_require_and_verify(self) -> None:
        sites = site_blocks(CADDY_DEVICE.read_text(encoding="utf-8"))
        self.assertTrue(sites)
        for label, body in sites:
            modes = re.findall(r"mode\s+(\w+)", body)
            self.assertIn(
                "require_and_verify",
                modes,
                f"site {label} on the mTLS listener has no require_and_verify client auth",
            )
            self.assertIn("client_auth {", body.replace("\n", " ").replace("  ", " ") + " ", label)
            self.assertIn("trust_pool file {", body, label)

    @unittest.skipUnless(docker_available() and caddy_image_available(), "needs docker and the pinned caddy image")
    def test_adapted_config_requires_a_verified_certificate_for_every_site(self) -> None:
        config = adapt(CADDY_DEVICE)
        servers = config["apps"]["http"]["servers"]
        mtls = {
            name: server
            for name, server in servers.items()
            if any(entry.endswith(":443") for entry in server.get("listen") or [])
        }
        self.assertTrue(mtls, "no :443 listener in the adapted config")
        for name, server in mtls.items():
            policies = server.get("tls_connection_policies") or []
            hosts = [
                host
                for route in server.get("routes") or []
                for entry in route.get("match") or []
                for host in entry.get("host") or []
            ]
            self.assertTrue(hosts, f"{name} serves no hostname")
            for host in hosts:
                verified = [
                    policy
                    for policy in policies
                    if host in (policy.get("match", {}).get("sni") or [])
                    and policy.get("client_authentication", {}).get("mode") == "require_and_verify"
                ]
                self.assertTrue(
                    verified,
                    f"{name} serves {host} without a require_and_verify connection policy",
                )
            # The catch-all policy Caddy appends is acceptable only because no
            # site is served under it; that is what the loop above proves.
            for policy in policies:
                if policy.get("match"):
                    continue
                self.assertFalse(
                    policy.get("client_authentication"),
                    "a catch-all policy sets client auth; the check above assumed it does not",
                )

    @unittest.skipUnless(shutil.which("openssl"), "openssl is needed to make certificate material")
    @unittest.skipUnless(docker_available() and caddy_image_available(), "needs docker and the pinned caddy image")
    def test_handshake_without_a_client_certificate_is_refused_on_every_site(self) -> None:
        """The proof: a TLS client that presents no certificate gets no HTTP reply.

        Every hostname the adapted ``:443`` listener serves is tried, with the
        SNI set to that hostname, plus a hostname the listener does *not* serve
        and one with no SNI at all. Then the same handshake *with* a valid
        client certificate must succeed, so a listener that refuses everything
        (and would pass the first half trivially) cannot pass this test.
        """

        scratch = tempfile.TemporaryDirectory(prefix="local-cloud-mtls-edge-")
        self.addCleanup(scratch.cleanup)
        material = Path(scratch.name) / "material"
        result = _run(["sh", str(GEN_CERTS), str(material)], timeout=180)
        self.assertEqual(result.returncode, 0, result.stderr)

        config = adapt(CADDY_DEVICE)
        hosts: list[str] = []
        for server in config["apps"]["http"]["servers"].values():
            if any(entry.endswith(":443") for entry in server.get("listen") or []):
                for route in server.get("routes") or []:
                    for entry in route.get("match") or []:
                        hosts.extend(entry.get("host") or [])
        self.assertIn(DEVICE_SITE, hosts)
        self.assertNotIn("local-cloud.lan", hosts, "the unauthenticated vhost is back")

        port = free_port()
        self.container(
            "lc-mtls-edge",
            "-p", f"127.0.0.1:{port}:443",
            "-v", f"{CADDY_DEVICE}:/etc/caddy/Caddyfile:ro",
            "-v", f"{material / 'certs'}:/etc/caddy/certs:ro",
            "-v", f"{material / 'pki'}:/etc/caddy/pki:ro",
            caddy_image(),
        )
        # Wait for the listener: a handshake *with* the client certificate.
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            if self._exchange(port, DEVICE_SITE, material) == "answered":
                break
            time.sleep(0.25)
        else:
            self.fail("the mTLS listener never accepted the enrolled client certificate")

        for host in hosts:
            self.assertEqual(
                self._exchange(port, host, None),
                "refused",
                f"{host} completed an HTTP exchange without a client certificate",
            )
        for host in ("local-cloud.lan", "evil.example"):
            self.assertEqual(self._exchange(port, host, None), "refused", host)
        self.assertEqual(self._exchange(port, None, None), "refused", "a client with no SNI got in")

    def _exchange(self, port: int, server_name: str | None, material: Path | None) -> str:
        """``answered`` if HTTP came back, ``refused`` if the connection did not."""

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE  # the point is client auth, not ours
        if material is not None:
            context.load_cert_chain(
                str(material / "certs" / "device-client.crt"),
                str(material / "certs" / "device-client.key"),
            )
        try:
            raw = socket.create_connection(("127.0.0.1", port), timeout=10)
        except OSError:
            return "refused"
        try:
            try:
                tls = context.wrap_socket(raw, server_hostname=server_name)
            except (ssl.SSLError, OSError):
                return "refused"
            try:
                tls.sendall(
                    b"GET /api/device-service/system/time HTTP/1.1\r\n"
                    b"Host: probe\r\nConnection: close\r\n\r\n"
                )
                payload = tls.recv(64)
            except (ssl.SSLError, OSError):
                return "refused"
            finally:
                tls.close()
            return "answered" if payload.startswith(b"HTTP/") else "refused"
        finally:
            raw.close()


# ---------------------------------------------------------------------------
# INF-04: the shipped example must not be a working deployment
# ---------------------------------------------------------------------------


class ExampleEnvironmentTests(unittest.TestCase):
    """INF-04: ``.env.example`` shipped a token the service accepted and a
    ``0.0.0.0`` bind, so copying it produced an open admin API."""

    def test_no_credential_is_shipped_with_a_value(self) -> None:
        values = parse_env_file(ENV_EXAMPLE)
        for key in (
            "LOCAL_CLOUD_ADMIN_TOKEN",
            "POSTGRES_PASSWORD",
            "S3_ACCESS_KEY",
            "S3_SECRET_KEY",
        ):
            self.assertIn(key, values, f"{key} is missing from .env.example")
            self.assertEqual(values[key], "", f".env.example ships a {key}")
        self.assertNotRegex(
            ENV_EXAMPLE.read_text(encoding="utf-8"),
            r"(?m)^[A-Z0-9_]+=\s*replace-me",
            ".env.example assigns a placeholder as if it were a credential",
        )

    def test_the_service_binds_loopback_and_the_container_bind_is_compose_s_own(self) -> None:
        self.assertEqual(parse_env_file(ENV_EXAMPLE)["LOCAL_CLOUD_HOST"], "127.0.0.1")
        block = yaml_services(COMPOSE)["api"]
        self.assertIn('LOCAL_CLOUD_HOST: "0.0.0.0"', block)

    def test_an_empty_token_disables_the_admin_api_instead_of_opening_it(self) -> None:
        """The shipped values, fed to the real service, must fail closed."""

        values = parse_env_file(ENV_EXAMPLE)
        with tempfile.TemporaryDirectory(prefix="local-cloud-example-") as scratch:
            server = service.LocalCloudServer(
                db_path=Path(scratch) / "db.sqlite3",
                audit_file=Path(scratch) / "audit.jsonl",
                port=0,
                admin_token=values["LOCAL_CLOUD_ADMIN_TOKEN"],
                allow_anonymous=values.get("LOCAL_CLOUD_ALLOW_ANONYMOUS") == "true",
                trust_proxy_identity=values.get("LOCAL_CLOUD_TRUST_PROXY_IDENTITY") == "true",
            ).start()
            self.addCleanup(server.close)
            status, payload, _ = _call(server.port, "POST", "/admin/v1/devices", {})
            self.assertEqual(status, 403, payload)
            self.assertEqual(payload["error"]["reason"], "admin-not-configured")  # type: ignore[index]
            status, payload, _ = _call(
                server.port,
                "GET",
                "/api/device-service/device-event/status",
                None,
                headers={IDENTITY_HEADER: FORGED_FINGERPRINT},
            )
            self.assertEqual(status, 401, payload)
            self.assertEqual(payload["error"]["reason"], "client-certificate-required")  # type: ignore[index]


# ---------------------------------------------------------------------------
# INF-05: the template profiles must refuse to start on a placeholder
# ---------------------------------------------------------------------------


class TemplateCredentialTests(unittest.TestCase):
    """INF-05: ``postgres`` and ``minio`` defaulted to ``replace-me``, which both
    servers accept. The compose required-variable form refuses instead."""

    def test_the_templates_use_the_required_variable_form(self) -> None:
        self.assertTrue(TEMPLATES.is_file(), "docker-compose.templates.yml is missing")
        text = TEMPLATES.read_text(encoding="utf-8")
        # Only POSTGRES_PASSWORD is left: the MinIO template went away with the
        # rest of the object store in #57, and nothing reads the S3_* names.
        self.assertRegex(
            text,
            r"\$\{POSTGRES_PASSWORD:\?set POSTGRES_PASSWORD in \.env\}",
            "POSTGRES_PASSWORD has no required-variable form",
        )
        self.assertNotIn(
            "POSTGRES_PASSWORD:-",
            text,
            "POSTGRES_PASSWORD has a default again, so the profile can start on it",
        )

    def test_no_template_default_is_a_credential(self) -> None:
        for path in (COMPOSE, TEMPLATES):
            text = path.read_text(encoding="utf-8")
            for line in text.splitlines():
                if "replace-me" not in line:
                    continue
                self.assertFalse(
                    line.strip().startswith(("POSTGRES_PASSWORD", "MINIO_ROOT", "S3_")),
                    f"{path.name} still defaults a credential: {line.strip()}",
                )

    def test_the_readme_says_the_profile_refuses_to_start(self) -> None:
        text = README.read_text(encoding="utf-8")
        self.assertIn("POSTGRES_PASSWORD", text)
        self.assertIn("refuses to start", text.lower())
        self.assertIn("docker-compose.templates.yml", text)

    @unittest.skipUnless(compose_available(), "the docker compose plugin is not installed")
    def test_an_unset_postgres_password_fails_compose_config(self) -> None:
        with tempfile.TemporaryDirectory(prefix="local-cloud-compose-env-") as scratch:
            base = ["docker", "compose", "--env-file", str(empty_env_file(Path(scratch)))]
            result = _run(
                [
                    *base, "-f", "docker-compose.yml", "-f", "docker-compose.templates.yml",
                    "--profile", "postgres", "config", "--quiet",
                ],
                cwd=DEPLOY,
                env=compose_env(),
            )
        self.assertNotEqual(result.returncode, 0, "an unset POSTGRES_PASSWORD interpolated anyway")
        self.assertIn("POSTGRES_PASSWORD", result.stderr)
        self.assertIn("required variable", result.stderr)

    def test_the_split_is_where_the_readme_says_it_is(self) -> None:
        """The moved command is a trap, so the split is asserted, not assumed.

        `--profile postgres` on its own is a silent no-op now (the profile
        selects nothing and exits 0), and `up -d db` without the second file
        says "no such service". A reviewer has to be able to find that from the
        README, and `db` must not quietly reappear in the default file.
        """

        self.assertNotIn(
            "\n  db:\n",
            COMPOSE.read_text(encoding="utf-8"),
            "db is back in docker-compose.yml; the required variable would break config",
        )
        self.assertIn("\n  db:\n", TEMPLATES.read_text(encoding="utf-8"))
        readme = README.read_text(encoding="utf-8")
        self.assertIn("no such service: db", readme)
        self.assertIn("silent no-op", readme)

    @unittest.skipUnless(compose_available(), "the docker compose plugin is not installed")
    def test_the_default_stack_still_parses_without_any_credential(self) -> None:
        with tempfile.TemporaryDirectory(prefix="local-cloud-compose-env-") as scratch:
            result = _run(
                ["docker", "compose", "--env-file", str(empty_env_file(Path(scratch))), "config", "--quiet"],
                cwd=DEPLOY,
                env=compose_env(),
            )
        self.assertEqual(result.returncode, 0, result.stderr)


# ---------------------------------------------------------------------------
# INF-06: logging, memory, process and filesystem limits
# ---------------------------------------------------------------------------


class ContainerHardeningTests(unittest.TestCase):
    """INF-06: no log rotation, no limits, no read-only rootfs anywhere."""

    def test_both_compose_files_define_the_shared_logging_anchor(self) -> None:
        for path in (COMPOSE, TEMPLATES):
            anchor = yaml_top_level_block(path, "x-logging")
            self.assertIn("max-size", anchor, path.name)
            self.assertIn("max-file", anchor, path.name)

    def test_every_service_uses_the_logging_anchor(self) -> None:
        for path in (COMPOSE, TEMPLATES):
            services = yaml_services(path)
            self.assertTrue(services, path.name)
            for name, block in services.items():
                self.assertIn(
                    "logging: *default-logging",
                    block,
                    f"{name} in {path.name} would grow its log without bound",
                )

    def test_api_has_memory_and_process_limits(self) -> None:
        block = yaml_services(COMPOSE)["api"]
        self.assertRegex(block, r"(?m)^\s+mem_limit:\s*\S+$", msg="api has no mem_limit")
        self.assertRegex(block, r"(?m)^\s+pids_limit:\s*\d+$", msg="api has no pids_limit")
        self.assertIn("ThreadingHTTPServer", block, "the pids_limit rationale is gone")

    def test_admin_is_read_only_with_tmpfs(self) -> None:
        block = yaml_services(COMPOSE)["admin"]
        self.assertRegex(block, r"(?m)^\s+read_only:\s*true$")
        self.assertIn("tmpfs:", block)
        for mount in ("/tmp", "/config", "/data"):
            self.assertIn(mount, block)

    @unittest.skipUnless(compose_available(), "the docker compose plugin is not installed")
    def test_compose_config_carries_the_limits_into_every_container(self) -> None:
        config = compose_json()
        for name, definition in config["services"].items():
            logging = definition.get("logging") or {}
            options = logging.get("options") or {}
            self.assertEqual(logging.get("driver"), "json-file", name)
            self.assertEqual(options.get("max-size"), "10m", name)
            self.assertEqual(options.get("max-file"), "3", name)
        api = config["services"]["api"]
        self.assertEqual(int(api["mem_limit"]), 256 * 1024 * 1024)  # 256 MiB
        self.assertEqual(int(api["pids_limit"]), 200)
        admin = config["services"]["admin"]
        self.assertTrue(admin.get("read_only"))


# ---------------------------------------------------------------------------
# INF-07: audit durability and the honesty of its documentation
# ---------------------------------------------------------------------------


class AuditIntegrityTests(unittest.TestCase):
    """INF-07: the JSONL mirror was written with no ``fsync`` and the design
    claimed a guarantee ("a file the API cannot rewrite") that nothing provided."""

    def setUp(self) -> None:
        # These two cases assert against the design document, which the gate
        # withholds as research prose.  The Docker and compose cases above read
        # only files this repository publishes.
        skip_without(["docs/LOCAL_CLOUD_DESIGN.md"])

    def test_every_audit_append_is_flushed_to_disk(self) -> None:
        with tempfile.TemporaryDirectory(prefix="local-cloud-audit-") as scratch:
            audit = Path(scratch) / "audit.jsonl"
            log = store.Store(Path(scratch) / "db.sqlite3", audit_file=audit)
            synced: list[os.stat_result] = []
            real_fsync = os.fsync

            def record(descriptor: int) -> None:
                synced.append(os.fstat(descriptor))
                real_fsync(descriptor)

            with mock.patch("os.fsync", record):
                log.audit(actor="device:grinder-1", action="GET", subject="/api/x")

            self.assertEqual(len(synced), 1, "the mirrored line was not fsynced")
            self.assertEqual(synced[0].st_ino, audit.stat().st_ino, "fsync hit the wrong file")
            self.assertEqual(json.loads(audit.read_text(encoding="utf-8"))["actor"], "device:grinder-1")

    def test_the_documentation_and_the_module_both_stop_claiming_tamper_evidence(self) -> None:
        design = DESIGN.read_text(encoding="utf-8")
        module = (ROOT / "tools" / "local_cloud" / "store.py").read_text(encoding="utf-8")
        readme = README.read_text(encoding="utf-8")
        self.assertIn("append-only by convention, not tamper-evident", design)
        self.assertIn("fsync", design)
        self.assertIn("not tamper-evident", module)
        self.assertIn("fsync", module)
        self.assertIn("not tamper-evident", readme)
        self.assertNotIn(
            "append-only in the DB and mirrored to a file the API cannot rewrite", design
        )

    def test_source_ip_is_documented_as_the_proxy_not_the_device(self) -> None:
        design = DESIGN.read_text(encoding="utf-8")
        self.assertIn("source_ip", design)
        self.assertIn("the edge container, not the", design)


# ---------------------------------------------------------------------------
# INF-08: the development certificate helper must stay out of the tree
# ---------------------------------------------------------------------------


@unittest.skipUnless(shutil.which("openssl"), "openssl is needed to make certificate material")
class DevelopmentCertificateTests(unittest.TestCase):
    """INF-08: ``gen-dev-certs.sh`` wrote a CA private key into the repository
    directory by default, with the process umask."""

    def test_the_default_run_writes_to_a_private_temporary_directory(self) -> None:
        with tempfile.TemporaryDirectory(prefix="local-cloud-certs-") as scratch:
            mirror = Path(scratch) / "deploy-local-cloud"  # stands in for the checkout
            mirror.mkdir()
            script = mirror / "gen-dev-certs.sh"
            shutil.copy(GEN_CERTS, script)

            result = _run(["sh", str(script)], cwd=Path(scratch), timeout=180)
            self.assertEqual(result.returncode, 0, result.stderr)
            wrote = sorted(
                name for name in ("certs", "pki") if (mirror / name).exists()
            )
            self.assertEqual(
                wrote, [], "the default run wrote into the directory holding the script"
            )

            match = re.search(r"^output directory: (\S+)$", result.stdout, re.M)
            self.assertIsNotNone(match, f"the script did not print its output directory:\n{result.stdout}")
            output = Path(match.group(1))  # type: ignore[union-attr]
            self.addCleanup(shutil.rmtree, output, True)
            self.assertTrue(output.is_dir())
            self.assertNotEqual(output.resolve(), mirror.resolve())
            self.assertEqual(oct(stat.S_IMODE(output.stat().st_mode)), oct(0o700), str(output))
            self.assertTrue((output / "pki" / "device-ca.pem").is_file())

    def test_generated_private_material_is_owner_only(self) -> None:
        with tempfile.TemporaryDirectory(prefix="local-cloud-certs-") as scratch:
            output = Path(scratch) / "out"
            result = _run(["sh", str(GEN_CERTS), str(output)], timeout=180)
            self.assertEqual(result.returncode, 0, result.stderr)
            for directory in (output, output / "certs", output / "pki"):
                self.assertEqual(
                    oct(stat.S_IMODE(directory.stat().st_mode)), oct(0o700), str(directory)
                )
            for key in (
                output / "pki" / "device-ca.key",
                output / "certs" / "device-host.key",
                output / "certs" / "device-client.key",
            ):
                self.assertEqual(oct(stat.S_IMODE(key.stat().st_mode) & 0o077), oct(0), str(key))

    def test_an_existing_ca_is_still_not_overwritten(self) -> None:
        with tempfile.TemporaryDirectory(prefix="local-cloud-certs-") as scratch:
            output = Path(scratch) / "out"
            first = _run(["sh", str(GEN_CERTS), str(output)], timeout=180)
            self.assertEqual(first.returncode, 0, first.stderr)
            second = _run(["sh", str(GEN_CERTS), str(output)], timeout=180)
            self.assertNotEqual(second.returncode, 0)
            self.assertIn("refusing to overwrite existing CA", second.stderr)


# ---------------------------------------------------------------------------
# INF-10: documents must describe the committed state
# ---------------------------------------------------------------------------


class DesignConsistencyTests(unittest.TestCase):
    """INF-10: §11 called the api image a placeholder, named a profile that does
    not exist, and the Caddyfile warned about a version that is not pinned."""

    def setUp(self) -> None:
        # These two cases assert against the design document, which the gate
        # withholds as research prose.  The Docker and compose cases above read
        # only files this repository publishes.
        skip_without(["docs/LOCAL_CLOUD_DESIGN.md"])

    def test_the_design_does_not_call_the_api_image_a_placeholder(self) -> None:
        design = DESIGN.read_text(encoding="utf-8")
        self.assertNotIn("local-cloud/api:dev", design)
        self.assertNotIn("This repository contains no server implementation", design)
        self.assertIn("tools/local_cloud/service.py", design)

    def test_the_design_names_the_profiles_that_exist(self) -> None:
        self.assertTrue(TEMPLATES.is_file(), "docker-compose.templates.yml is missing")
        design = DESIGN.read_text(encoding="utf-8")
        self.assertNotIn("object-store-template", design)
        profiles = set(re.findall(r'profiles:\s*\["([^"]+)"\]', TEMPLATES.read_text(encoding="utf-8")))
        self.assertEqual(profiles, {"postgres"}, "the object store template is gone (#57)")
        for profile in profiles:
            self.assertIn(f'`{profile}`', design)

    def test_the_caddyfiles_do_not_repeat_the_retired_trust_pool_claim(self) -> None:
        """The old note claimed `trust_pool` was not honoured at handshake time.

        Naming the version it was written against is fine and is kept as
        history; claiming the directive does not work is not, because the
        pinned edge does honour it (see the handshake test above).  So this
        asserts the claim, not the string "2.8.4".
        """

        for path in (CADDY_DEVICE, CADDY_OFFLINE):
            text = path.read_text(encoding="utf-8")
            self.assertNotIn("not always honoured at handshake time", text, path.name)
            self.assertNotIn("NOTE (Caddy 2.8.4)", text, path.name)
        device = CADDY_DEVICE.read_text(encoding="utf-8")
        self.assertIn("require_and_verify", device)
        self.assertIn('"client_authentication"', device)

    def test_the_design_documents_the_template_file_split(self) -> None:
        self.assertIn("docker-compose.templates.yml", DESIGN.read_text(encoding="utf-8"))
        self.assertIn("docker-compose.templates.yml", README.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# shared request helper for the in-process service checks
# ---------------------------------------------------------------------------


def _call(
    port: int,
    method: str,
    path: str,
    body: dict | None = None,
    *,
    headers: dict[str, str] | None = None,
) -> tuple[int, dict, dict[str, str]]:
    import http.client

    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    try:
        data = json.dumps(body).encode() if body is not None else None
        merged = {"Content-Type": "application/json"}
        merged.update(headers or {})
        connection.request(method, path, body=data, headers=merged)
        response = connection.getresponse()
        raw = response.read()
        payload = json.loads(raw) if raw else {}
        return response.status, payload, {key.lower(): value for key, value in response.getheaders()}
    finally:
        connection.close()


if __name__ == "__main__":
    unittest.main()
