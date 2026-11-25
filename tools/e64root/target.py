"""Target parsing, owner-safety guards and read-only fingerprint parsing."""

from __future__ import annotations

import base64
import html as html_lib
import ipaddress
import re
import socket
from dataclasses import asdict, dataclass, field

from . import SUPPORTED_MODELS
from .errors import PreconditionError, UsageError

HOST_RE = re.compile(r"^[A-Za-z0-9._:%\-\[\]]+$")
KEY_TYPES = (
    "ssh-ed25519",
    "ssh-rsa",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "sk-ssh-ed25519@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com",
)
MAX_KEYS = 16
SUPPORTED_FIRMWARE_PREFIXES = ("V01.16", "V01.36")
MAX_KEY_BYTES = 8192


@dataclass(frozen=True)
class Endpoint:
    """A validated host and port."""

    host: str
    port: int

    @property
    def authority(self) -> str:
        if ":" in self.host:
            return f"[{self.host}]:{self.port}"
        return f"{self.host}:{self.port}"


def parse_endpoint(value: str, default_port: int) -> Endpoint:
    """Parse ``host`` or ``host:port`` without accepting a URL.

    IPv6 literals must be bracketed when a port is present, matching the usual
    ``[fe80::1]:443`` form.
    """
    value = value.strip()
    if not value:
        raise UsageError("--host must not be empty")
    if "://" in value or "/" in value:
        raise UsageError("--host takes a hostname or IP, not a URL or path")
    if value.startswith("["):
        end = value.find("]")
        if end < 0:
            raise UsageError("unterminated IPv6 literal in --host")
        host = value[1:end]
        tail = value[end + 1 :]
        if tail.startswith(":"):
            port_text = tail[1:]
            if not port_text.isdigit():
                raise UsageError(f"invalid port in --host: {port_text!r}")
            port = int(port_text)
        elif tail:
            raise UsageError(f"unexpected text after IPv6 literal: {tail!r}")
        else:
            port = default_port
    elif value.count(":") == 1:
        host, port_text = value.rsplit(":", 1)
        if not port_text.isdigit():
            raise UsageError(f"invalid port in --host: {port_text!r}")
        port = int(port_text)
    else:
        host, port = value, default_port
    if not host or not HOST_RE.match(host):
        raise UsageError(f"invalid host: {value!r}")
    if not 1 <= port <= 65535:
        raise UsageError(f"port out of range: {port}")
    return Endpoint(host, port)


def resolve_addresses(host: str) -> list[str]:
    """Resolve every A/AAAA address, de-duplicated and ordered."""
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise PreconditionError(f"cannot resolve host {host!r}: {exc}") from exc
    addresses: list[str] = []
    for info in infos:
        address = info[4][0]
        if address not in addresses:
            addresses.append(address)
    return addresses


def is_private_address(address: str) -> bool:
    """True for loopback, RFC1918, link-local and other non-global space."""
    try:
        return not ipaddress.ip_address(address.split("%", 1)[0]).is_global
    except ValueError:
        return False


@dataclass(frozen=True)
class TargetGuard:
    host: str
    addresses: tuple[str, ...]
    private: bool
    allow_public: bool

    def describe(self) -> str:
        scope = "private/link-local" if self.private else "globally routable"
        return f"{self.host} -> {', '.join(self.addresses)} ({scope})"


def guard_target(host: str, allow_public: bool = False) -> TargetGuard:
    """Refuse globally routable targets unless the owner opts in.

    The E64 is a LAN appliance.  A public address is much more likely to be a
    mis-typed target (or a forwarded port) than the owner's own grinder, so the
    default is a hard stop rather than a warning.
    """
    addresses = resolve_addresses(host)
    private = all(is_private_address(address) for address in addresses)
    if not private and not allow_public:
        raise PreconditionError(
            f"{host} resolves to a globally routable address ({', '.join(addresses)}). "
            "This tool is for a device on the owner's local network. "
            "Pass --allow-public only if you are certain this is your grinder."
        )
    return TargetGuard(host, tuple(addresses), private, allow_public)


# --- login-page fingerprint -------------------------------------------------

_TITLE_RE = re.compile(r"<title>\s*Login\s+Hemro\s+([^<]+?)\s*</title>", re.I | re.S)
_LABEL_TEMPLATE = r">\s*{label}\s*</div>\s*<div[^>]*>\s*([^<]*?)\s*</div>"


def _label_value(page: str, label: str) -> str:
    pattern = re.compile(_LABEL_TEMPLATE.format(label=re.escape(label)), re.I | re.S)
    match = pattern.search(page)
    return html_lib.unescape(match.group(1)).strip() if match else ""


@dataclass(frozen=True)
class Fingerprint:
    """Read-only facts taken from the unauthenticated login page."""

    url: str
    http_status: int
    title: str = ""
    model: str = ""
    serial: str = ""
    firmware: str = ""
    dev_mode: bool = False
    raw_bytes: int = 0
    notes: tuple[str, ...] = field(default_factory=tuple)

    @property
    def known(self) -> bool:
        model = self.model.strip()
        return model in SUPPORTED_MODELS or bool(self.firmware)

    @property
    def family(self) -> str:
        if "E65/E80" in self.model or "E65/E80" in self.title or "NG2" in self.firmware:
            return "NG2"
        if "E64" in self.model or "E64" in self.title or "HSG" in self.firmware:
            return "HSG"
        return "unknown"

    def as_dict(self) -> dict[str, object]:
        data = asdict(self)
        data["known"] = self.known
        data["family"] = self.family
        return data


def parse_login_page(page: str, url: str = "", status: int = 200) -> Fingerprint:
    """Extract model, serial, firmware and dev-mode state from ``login.php``.

    ``systemInfo.php`` renders these values from the version JSON and
    ``/etc/issue``.  ``isDev()`` adds the ``Developer`` option only when the
    first whitespace-separated token of ``/etc/issue`` is ``development``, so
    the option is a reliable pre-shell dev-mode signal.
    """
    title_match = _TITLE_RE.search(page)
    title = html_lib.unescape(title_match.group(1)).strip() if title_match else ""
    firmware = _label_value(page, "FW VERSION")
    dev_mode = bool(re.search(r"\(development\)", firmware, re.I)) or bool(
        re.search(r'<option[^>]+value=["\']Developer["\']', page, re.I)
    )
    notes: list[str] = []
    if not title and not firmware:
        notes.append("login page did not contain the expected Hemro markers")
    if firmware and not re.search(r"\bV\d", firmware):
        notes.append("firmware string does not start with V<digits>")
    return Fingerprint(
        url=url,
        http_status=status,
        title=title,
        model=_label_value(page, "MODEL"),
        serial=_label_value(page, "S/N"),
        firmware=firmware,
        dev_mode=dev_mode,
        raw_bytes=len(page.encode("utf-8", errors="replace")),
        notes=tuple(notes),
    )


def require_known_target(fingerprint: Fingerprint, allow_unverified: bool = False) -> None:
    """Fail closed when the login page is not a supported E64/NG2 build."""
    if allow_unverified:
        return
    firmware_supported = (
        not fingerprint.firmware
        or any(prefix in fingerprint.firmware for prefix in SUPPORTED_FIRMWARE_PREFIXES)
    )
    if fingerprint.known and firmware_supported:
        return
    raise PreconditionError(
        "target did not identify itself as a supported E64/NG2 build "
        f"(model={fingerprint.model!r}, firmware={fingerprint.firmware!r}; "
        f"supported firmware prefixes: {', '.join(SUPPORTED_FIRMWARE_PREFIXES)}). "
        "Refusing before sending an injection. Use --allow-unverified-target only "
        "for a device you own and have identified by another means."
    )


# --- public-key validation --------------------------------------------------

def validate_public_keys(text: str) -> list[str]:
    """Validate one or more OpenSSH public-key lines.

    The key is embedded in a remote shell heredoc, so anything that could break
    out of that heredoc (control characters, newlines inside a line, shell
    metacharacters in the key body) is rejected rather than escaped.
    """
    if len(text.encode("utf-8", errors="replace")) > MAX_KEY_BYTES:
        raise UsageError(f"public-key file is larger than {MAX_KEY_BYTES} bytes")
    keys: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 2:
            raise UsageError("public key line must contain a type and a base64 key")
        key_type, body = parts[0], parts[1]
        if key_type not in KEY_TYPES:
            raise UsageError(f"unsupported public-key type: {key_type!r}")
        if not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", body):
            raise UsageError("public key body is not valid base64")
        try:
            decoded = base64.b64decode(body, validate=True)
        except Exception as exc:  # noqa: BLE001 - report a stable message
            raise UsageError("public key body is not valid base64") from exc
        if len(decoded) < 32:
            raise UsageError("public key body is implausibly short")
        if any(ord(char) < 0x20 or ord(char) == 0x7F for char in line):
            raise UsageError("public key line contains control characters")
        keys.append(line)
    if not keys:
        raise UsageError("no public keys found")
    if len(keys) > MAX_KEYS:
        raise UsageError(f"at most {MAX_KEYS} public keys may be installed")
    return keys


def key_blob(key_line: str) -> str:
    return key_line.split()[1]


def key_fingerprint(key_line: str) -> str:
    """A short, stable identifier for display (SHA-256 of the key blob)."""
    import hashlib

    return hashlib.sha256(base64.b64decode(key_blob(key_line))).hexdigest()[:16]


# --- daemon selection -------------------------------------------------------

@dataclass(frozen=True)
class DaemonPlan:
    kind: str                 # "dropbear" or "sshd"
    remote_path: str
    binary: bytes | None = None
    source: str = ""

    @property
    def needs_upload(self) -> bool:
        return self.binary is not None


def plan_daemon(
    dropbear: bytes | None,
    existing_daemon: str | None,
) -> DaemonPlan:
    """Choose between uploading the documented static dropbear and using a
    daemon already present on the image.  Nothing is downloaded."""
    if dropbear is not None:
        if not dropbear:
            raise UsageError("--dropbear file is empty")
        return DaemonPlan("dropbear", "/usr/sbin/dropbear", dropbear, "uploaded --dropbear")
    if existing_daemon:
        if not re.fullmatch(r"/[A-Za-z0-9._/-]+", existing_daemon) or ".." in existing_daemon:
            raise UsageError(
                "--existing-daemon must be an absolute path with no shell metacharacters"
            )
        name = existing_daemon.rsplit("/", 1)[-1]
        if name not in ("dropbear", "sshd"):
            raise UsageError(
                "--existing-daemon must name a dropbear or sshd binary, "
                f"got {existing_daemon!r}"
            )
        kind = "dropbear" if name == "dropbear" else "sshd"
        return DaemonPlan(kind, existing_daemon, None, "existing daemon")
    raise UsageError(
        "no SSH daemon selected. Pass --dropbear PATH with a static armhf "
        "dropbear built as documented in docs/VM_SSH_ACCESS.md, or "
        "--existing-daemon /usr/sbin/dropbear if the image already has one. "
        "This tool never downloads a binary."
    )
