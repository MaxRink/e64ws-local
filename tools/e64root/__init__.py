"""Owner-facing root, SSH and verification helper for an E64 WS / NG2 grinder.

This package implements the two runtime access paths that were verified against
the vendor userspace in the research VM:

* FW-01 -- the ``login.php`` login-form command injection.
* FW-02 -- the unauthenticated ``upload_esp.php`` archive execution.

It is deliberately conservative: every mutating action needs ``--yes``, the
target must resolve to a private/link-local address unless ``--allow-public`` is
given, TLS is verified unless the owner explicitly opts out, and ``revert`` is a
dry run unless ``--yes`` is also supplied.

Owner-authorized use only.  The tools do not contain vendor keys, signed update
packages, cloud credentials, or a network downloader for binaries.
"""

from __future__ import annotations

__version__ = "0.1.0"

SUPPORTED_MODELS = ("E64", "E65/E80")
