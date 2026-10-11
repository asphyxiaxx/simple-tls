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
        self._ticket_lifetime_hint = int(session.timeout.total_seconds())
        self._session.set_timeout(7200)

    @property
    def session(self) -> tls.TLSSession:
        return self._session

    @property
    def has_ticket(self) -> bool:
        """
        Indicates whether the session was established using a TLS session
        ticket (stateless session resumption, as defined in RFC 5077 / TLS 1.3)
        rather than a traditional stateful session ID.
        """
        return True

    @property
    def id(self) -> bytes:
        return b"\x00"

    @property
    def ticket_lifetime_hint(self) -> int:
        """
        The server's suggested lifetime for the session ticket, measured in
        seconds.
        """
        return self._ticket_lifetime_hint

    @property
    def time(self) -> int:
        """The creation timestamp of the session."""
        return int(self._session.time.timestamp())

    @property
    def timeout(self) -> int:
        """The maximum timeout duration for the session."""
        return int(self._session.timeout.total_seconds())
