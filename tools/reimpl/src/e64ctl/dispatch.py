"""WSS dispatcher: JsonConnector::handleMessage + handleFoundMessage.

Recovered control flow (ELF 0x003fa25c / 0x003ee9d8 / 0x003ee910):

    for rec in registry:
        if rec.type != message["type"]:            continue
        if rec.dev and not isDevVersion():         continue
        if rec.action is None:                     dispatch(rec)
        elif data is a non-empty object
             and data["actionType"] == rec.action: dispatch(rec)
    return 0                                        # -> socket closed, no reply

``handleFoundMessage`` first runs ``validateTokenWithDef``: when the record has
``token=1``, a token record must exist for this socket and be unexpired.  After
a successful callback it refreshes the token expiry by 300 s.

The caller (``WebSocketConnector::textMessageReceived``) does:

    ok = handleMessage(...)
    if not ok:  deleteLater()          # close, no error frame
    elif out is non-empty: send out as JSON text

so a rejected command produces **no response at all** and the connection is
dropped.  Error bodies built inside ``handleMessage`` (the ``UnknownType``
literal) are therefore never transmitted.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Optional

from . import registry
from .tokens import Token, TokenStore


@dataclass
class DispatchOutcome:
    accepted: bool
    response: Optional[dict[str, Any]] = None
    #: Diagnostic only - the vendor builds this object but never sends it.
    reject_reason: str = ""
    record: Optional[registry.CommandDef] = None


class Dispatcher:
    def __init__(self, handlers: Any, tokens: TokenStore,
                 dev_mode: Callable[[], bool],
                 log: Callable[[str, str], None] = lambda m, l="info": None) -> None:
        self.handlers = handlers
        self.tokens = tokens
        self.dev_mode = dev_mode
        self.log = log

    # -- gate -------------------------------------------------------------
    def _token_ok(self, rec: registry.CommandDef, token: Optional[Token],
                  now: float) -> bool:
        if not rec.token:
            return True
        if token is None:
            return False
        return token.expires > now

    # -- entry point ------------------------------------------------------
    def handle_message(self, message: dict[str, Any],
                       token: Optional[Token]) -> DispatchOutcome:
        if not isinstance(message, dict):
            return DispatchOutcome(False, reject_reason="not an object")
        wire_type = message.get("type")
        if not isinstance(wire_type, str):
            return DispatchOutcome(False, reject_reason="missing type")

        data = message.get("data")
        action = data.get("actionType") if isinstance(data, dict) else None
        dev = self.dev_mode()
        now = self.tokens.clock()

        for rec in registry.records_for_type(wire_type):
            if rec.dev and not dev:
                continue
            if rec.action is not None:
                if not isinstance(data, dict) or not data:
                    continue
                if not isinstance(action, str) or action != rec.action:
                    continue
            if not self._token_ok(rec, token, now):
                return DispatchOutcome(False, reject_reason="invalid token",
                                       record=rec)
            handler = getattr(self.handlers, rec.handler)
            if rec.log:
                self.log(f"{wire_type}"
                         + (f"/{rec.action}" if rec.action else ""), "info")
            response = handler(message, rec)
            if rec.token and token is not None:
                self.tokens.refresh(token)
            return DispatchOutcome(True, response, record=rec)

        return DispatchOutcome(False, reject_reason="unknown type")


#: The object the vendor builds on the reject path (never transmitted).
UNKNOWN_TYPE_BODY = {
    "type": "UnknownType",
    "refId": None,
    "data": {"success": False},
}
