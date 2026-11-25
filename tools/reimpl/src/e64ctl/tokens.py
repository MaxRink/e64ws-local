"""Bearer-token files shared by the PHP login flow and the native WSS server.

PHP ``createToken()`` (sessionHelper.php:172-194) writes
``/tmp/tok_<token>`` with ``{sessionId, token, role, expires}`` and mode 0600.
The native ``WebSocketConnector::validateToken`` (ELF 0x0044dd30):

  * reads the file,
  * requires a non-empty ``role`` and ``expires >= now``,
  * deletes the file,
  * keeps an in-memory record with expiry ``now + 300 s``.

``handleFoundMessage`` refreshes that in-memory expiry by 300 s after every
accepted token-required command.  Nothing ever compares a JSON ``token`` field
with the URL token.
"""
from __future__ import annotations

import json
import os
import secrets
import time
from dataclasses import dataclass
from typing import Callable, Optional

TOKEN_TTL_S = 300
REFRESH_S = 300


def is_token_shaped(token: str) -> bool:
    return len(token) == 64 and all(c in "0123456789abcdef" for c in token)


@dataclass
class Token:
    session_id: str
    token: str
    role: str
    expires: float

    def alive(self, now: float) -> bool:
        return self.expires > now


class TokenStore:
    """Filesystem + in-memory token records (one per websocket connection)."""

    def __init__(
        self,
        directory: str = "/tmp",
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.directory = directory
        self.clock = clock
        self._issued: dict[str, Token] = {}

    # -- PHP-side ---------------------------------------------------------
    def mint(self, session_id: str, role: str, ttl: int = TOKEN_TTL_S) -> str:
        token = secrets.token_hex(32)
        record = {
            "sessionId": session_id,
            "token": token,
            "role": role,
            "expires": int(self.clock()) + ttl,
        }
        path = self.path_for(token)
        os.makedirs(self.directory, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as handle:
            json.dump(record, handle, separators=(",", ":"))
        os.chmod(path, 0o600)
        self._issued[token] = Token(session_id, token, role, record["expires"])
        return token

    def destroy(self, token: str) -> None:
        self._issued.pop(token, None)
        try:
            os.unlink(self.path_for(token))
        except FileNotFoundError:
            pass

    def path_for(self, token: str) -> str:
        return os.path.join(self.directory, f"tok_{token}")

    # -- native-side ------------------------------------------------------
    def consume(self, token: Optional[str]) -> Optional[Token]:
        """Native ``validateToken``: read+unlink the file, then keep a record."""
        if not token:
            return None
        now = self.clock()
        path = self.path_for(token)
        record: Optional[dict] = None
        try:
            with open(path, "r", encoding="utf-8") as handle:
                record = json.load(handle)
        except (FileNotFoundError, ValueError):
            record = None
        finally:
            try:
                os.unlink(path)
            except FileNotFoundError:
                pass

        if record is not None:
            role = record.get("role") or ""
            expires = float(record.get("expires") or 0)
            if role and expires > now:
                stored = Token(
                    str(record.get("sessionId", "")),
                    token,
                    role,
                    now + REFRESH_S,
                )
                self._issued[token] = stored
                return stored
            return None

        # A token already validated by another socket stays valid from the
        # in-memory record (the file is gone after the first validation).
        stored = self._issued.get(token)
        if stored and stored.alive(now):
            return stored
        return None

    def refresh(self, token: Optional[Token]) -> None:
        if token is None:
            return
        token.expires = self.clock() + REFRESH_S
        self._issued[token.token] = token

    def revoke_all(self) -> None:
        for token in list(self._issued):
            self.destroy(token)
