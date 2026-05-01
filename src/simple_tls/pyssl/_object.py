from __future__ import annotations

import ssl as _ssl
import typing

from simple_tls import tls
from simple_tls.io import serialization

from ._constant import Options
from ._exception import SSLEOFError, SSLError, SSLWantReadError
from ._session import SSLSession
from ._types import ReadableBuffer

if typing.TYPE_CHECKING:
    from ._context import SSLContext


class SSLObject(_ssl.SSLObject):
    _context: "SSLContext"
    _sslobj: tls.TLSConnection
    _session: SSLSession | None

    @classmethod
    def _create(
        cls,
        incoming: _ssl.MemoryBIO,
        outgoing: _ssl.MemoryBIO,
        server_side: bool = False,
        server_hostname: str | None = None,
        session: SSLSession | None = None,
        context: "SSLContext" | None = None,
    ) -> SSLObject:
        if context is None:
            raise ValueError("context not provided")

        self = cls.__new__(cls)
        context._context.owner = self

        if not server_side:
            session_ticket_handler = self._session_ticket_handler
        else:
            session_ticket_handler = None

        if context.options & Options.OP_NO_TICKET:
            session_ticket_handler = None
            context._context.session_keys = None
            context._context.session_storage = None

        sslobj = tls.TLSConnection(
            context=context._context,
            inbio=incoming,
            outbio=outgoing,
            server_side=server_side,
            server_hostname=server_hostname,
            session=(session.session if session is not None else session),
            session_ticket_handler=session_ticket_handler,
        )
        self._sslobj = sslobj
        self._context = context
        return self

    @property  # type: ignore[override]
    def context(self) -> SSLContext:
        """
        The SSLContext that is currently in use.
        """
        return self._context

    @context.setter
    def context(self, value: SSLContext) -> None:
        if not isinstance(value, SSLContext):
            raise TypeError("Not SSLContext")

        self._context = value
        value._context.owner = self
        self._sslobj.context = value._context

    @property
    def session(self) -> SSLSession | None:  # type: ignore[override]
        return self._session

    @property
    def session_reused(self) -> bool:
        """Was the client session reused during handshake"""
        return self._sslobj.session_reused()

    @property
    def server_side(self) -> bool:
        """Whether this is a server-side socket."""
        return self._sslobj.server_side

    @property
    def server_hostname(self) -> str | None:
        """
        The currently set server hostname (for SNI), or ``None`` if no
        server hostname is set.
        """
        return self._sslobj.server_hostname

    @typing.overload  # type: ignore[override]
    def read(self, len: int = 1024, buffer: None = None) -> bytes: ...

    @typing.overload  # type: ignore[override]
    def read(self, len: int = 1024, buffer: bytearray = ...) -> int: ...

    def read(self, len: int = 1024, buffer: bytearray | None = None) -> bytes | int:
        """
        Read up to 'len' bytes from the SSL object and return them.

        If 'buffer' is provided, read into this buffer and return the
        number of bytes read.
        """
        try:
            return self._sslobj.read(len, buffer)
        except tls.TLSWantReadError:
            raise SSLWantReadError()
        except tls.TLSEOFError:
            raise SSLEOFError()

    def write(self, data: ReadableBuffer) -> int:  # type: ignore[override]
        """
        Write 'data' to the SSL object and return the number of bytes
        written.

        The 'data' argument must support the buffer interface.
        """
        return self._sslobj.write(data)  # type: ignore

    @typing.overload
    def getpeercert(
        self, binary_form: typing.Literal[False] = ...
    ) -> dict[str, typing.Any] | None: ...

    @typing.overload
    def getpeercert(self, binary_form: typing.Literal[True] = ...) -> bytes | None: ...

    @typing.overload
    def getpeercert(
        self, binary_form: bool = ...
    ) -> dict[str, typing.Any] | bytes | None: ...

    def getpeercert(
        self, binary_form: bool = False
    ) -> dict[str, typing.Any] | bytes | None:
        """
        Returns a formatted version of the data in the certificate provided
        by the other end of the SSL channel.

        Return None if no certificate was provided, {} if a certificate was
        provided, but not validated.
        """
        cert = self._sslobj.getpeercert()
        if cert is not None:
            if binary_form:
                return cert.public_bytes(serialization.Encoding.DER)
            raise NotImplementedError
        return None

    def get_verified_chain(self):
        """
        Returns verified certificate chain provided by the other
        end of the SSL channel as a list of DER-encoded bytes.

        If certificate verification was disabled method acts the same as
        ``SSLSocket.get_unverified_chain``.
        """
        return self._sslobj.get_verified_chain()

    def get_unverified_chain(self):
        """Returns raw certificate chain provided by the other
        end of the SSL channel as a list of DER-encoded bytes.
        """
        return self._sslobj.get_unverified_chain()

    def selected_npn_protocol(self) -> str | None:
        """
        Return the currently selected NPN protocol as a string, or ``None``
        if a next protocol was not negotiated or if NPN is not supported by one
        of the peers."""
        return self._sslobj.selected_npn_protocol()

    def selected_alpn_protocol(self) -> str | None:
        """
        Return the currently selected ALPN protocol as a string, or ``None``
        if a next protocol was not negotiated or if ALPN is not supported by one
        of the peers."""
        return self._sslobj.selected_alpn_protocol()

    def cipher(self):
        """
        Return the currently selected cipher as a 3-tuple ``(name,
        ssl_version, secret_bits)``.
        """
        return self._sslobj.cipher()

    def shared_ciphers(self):
        """
        Return a list of ciphers shared by the client during the handshake or
        None if this is not a valid server connection.
        """
        return self._sslobj.shared_ciphers()

    def compression(self) -> None:
        """
        Return the current compression algorithm in use, or ``None`` if
        compression was not negotiated or not supported by one of the peers.
        """
        return None

    def pending(self) -> int:
        """
        Return the number of bytes that can be read immediately.
        """
        return self._sslobj.pending()

    def do_handshake(self) -> None:
        """
        Start the SSL/TLS handshake.
        """
        try:
            self._sslobj.do_handshake()
        except tls.TLSWantReadError:
            raise SSLWantReadError()

    def unwrap(self) -> None:
        """
        Start the SSL shutdown handshake.
        """
        self._sslobj.shutdown()

    def get_channel_binding(self, cb_type="tls-unique") -> bytes | None:
        """
        Get channel binding data for current connection.  Raise ValueError
        if the requested `cb_type` is not supported.  Return bytes of the data
        or None if the data is not available (e.g. before the handshake).
        """
        raise NotImplementedError()

    def version(self) -> str:
        """
        Return a string identifying the protocol version used by the
        current SSL channel.
        """
        return self._sslobj.version()

    def verify_client_post_handshake(self):
        if not self._sslobj.server_side:
            raise SSLError("Not server")
        return self._sslobj.verify_client_post_handshake()

    def _session_ticket_handler(self, session: tls.TLSSession) -> None:
        self._session = SSLSession(session)
