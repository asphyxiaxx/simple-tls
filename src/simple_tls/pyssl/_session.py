import os

from simple_tls import tls


class TicketAEAD:
    def __init__(self) -> None:
        self._sessions: dict[bytes, bytes] = {}

    def seal(self, data: bytes) -> bytes:
        ticket = os.urandom(32)
        self._sessions[ticket] = data
        return ticket

    def open(self, ticket: bytes) -> bytes | None:
        try:
            return self._sessions[ticket]
        except KeyError:
            return None


class SSLSession:
    def __init__(self, session: tls.TLSSession):
        if not isinstance(session, tls.TLSSession):
            raise TypeError(
                f"session must be TLSSession object, not {session}"
            )

        self._session = session

    @property
    def session(self) -> tls.TLSSession:
        return self._session

    @property
    def has_ticket(self) -> bool:
        return True

    @property
    def id(self) -> bytes:
        return b"\x00"

    @property
    def ticket_lifetime_hint(self) -> int:
        return 0

    @property
    def time(self) -> int:
        return int(self._session.time.timestamp())

    @property
    def timeout(self) -> int:
        return int(self._session.timeout.total_seconds())
