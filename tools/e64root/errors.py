"""Exception types used by :mod:`e64root`."""

from __future__ import annotations


class E64RootError(Exception):
    """Base class for expected, user-facing failures."""


class UsageError(E64RootError):
    """The invocation is incomplete or internally inconsistent."""


class PreconditionError(E64RootError):
    """The target does not satisfy a documented precondition."""


class TransportError(E64RootError):
    """An HTTP, TLS, SSH or archive transport failed."""


class VerificationError(E64RootError):
    """The operation completed but the expected root result was not observed."""
