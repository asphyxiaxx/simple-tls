from __future__ import annotations

import ssl as _ssl
import typing

from cryptography.hazmat.primitives import serialization

from simple_tls import tls
from simple_tls.crypto.utils import bytes_to_str, str_to_bytes

from ._constant import Options
from ._exception import SSLEOFError, SSLWantReadError
from ._session import SSLSession
from ._util import (
    PeerCertRetDictType,
    ReadableBuffer,
    SrvnmeCbType,
    parse_certificate,
    parse_cipher,
)

if typing.TYPE_CHECKING:
    from ._context import SSLContext


class SSLObject(_ssl.SSLObject):
    _context: SSLContext
    _sslobj: tls.TLSConnection
    _session: SSLSession | None
    _sni_callback: SrvnmeCbType | None
    _server_hostname: str | None

    @classmethod
    def _create(
        cls,
        incoming: _ssl.MemoryBIO,
        outgoing: _ssl.MemoryBIO,
        server_side: bool = False,
        server_hostname: str | None = None,
        session: SSLSession | None = None,
        context: SSLContext | None = None,
    ) -> SSLObject:
        if context is None:
            raise ValueError("context not provided")

        self = cls.__new__(cls)
        self._server_hostname = server_hostname
        self._sni_callback = context._sni_callback

        if context.protocol == _ssl.PROTOCOL_TLS_SERVER and not server_side:
            raise TypeError(
                "Cannot create a client socket with a PROTOCOL_TLS_SERVER "
                "context"
            )
        if context.protocol == _ssl.PROTOCOL_TLS_CLIENT and server_side:
            raise TypeError(
                "Cannot create a server socket with a PROTOCOL_TLS_CLIENT "
                "context"
            )

        if not server_side:
            sni_callback = None
            new_session_handler = self._new_session_handler
            if session is not None:
                tls_session = session.session
            else:
                tls_session = None
        else:
            sni_callback = self._do_sni_callback
            new_session_handler = None
            tls_session = None

        if context.options & Options.OP_NO_TICKET:
            new_session_handler = None

        config = tls.TLSConfiguration(
            is_server=server_side,
            server_hostname=str_to_bytes(server_hostname),
            session=tls_session,
            **context._config_data(),
        )
        sslobj = tls.TLSConnection(
            configuration=config,
            inbio=incoming,
            outbio=outgoing,
            new_session_handler=new_session_handler,
            sni_callback=sni_callback,
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
    def context(self, context: SSLContext) -> None:
        self._context = context

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
        return self._sslobj.is_server

    @property
    def server_hostname(self) -> str | None:
        """
        The currently set server hostname (for SNI), or ``None`` if no
        server hostname is set.
        """
        return self._server_hostname

    @typing.overload  # type: ignore[override]
    def read(self, len: int = 1024, buffer: None = None) -> bytes: ...

    @typing.overload  # type: ignore[override]
    def read(self, len: int = 1024, buffer: bytearray = ...) -> int: ...

    def read(
        self, len: int = 1024, buffer: bytearray | None = None
    ) -> bytes | int:
        """
        Read up to 'len' bytes from the SSL object and return them.

        If 'buffer' is provided, read into this buffer and return the
        number of bytes read.
        """
        try:
            return self._sslobj.read(len, buffer)
        except tls.TLSWantReadError:
            raise SSLWantReadError from None
        except tls.TLSEOFError:
            raise SSLEOFError from None

    def write(self, data: ReadableBuffer) -> int:  # type: ignore[override]
        """
        Write 'data' to the SSL object and return the number of bytes
        written.

        The 'data' argument must support the buffer interface.
        """
        return self._sslobj.write(data)  # type: ignore

    def get_ech_retry_configs(self) -> bytes | None:
        return self._sslobj.ech_retry_configs(binary_form=True)

    def ech_accepted(self) -> bool:
        return self._sslobj.ech_accepted()

    @typing.overload  # type: ignore[override]
    def getpeercert(
        self, binary_form: typing.Literal[False] = False
    ) -> PeerCertRetDictType | None: ...

    @typing.overload  # type: ignore[override]
    def getpeercert(
        self, binary_form: typing.Literal[True]
    ) -> bytes | None: ...

    def getpeercert(
        self, binary_form: bool = False
    ) -> PeerCertRetDictType | bytes | None:
        """
        Returns a formatted version of the data in the certificate provided
        by the other end of the SSL channel.

        Return None if no certificate was provided, {} if a certificate was
        provided, but not validated.
        """
        peercert = self._sslobj.getpeercert()
        if peercert is None:
            return None
        if binary_form:
            return peercert.public_bytes(serialization.Encoding.DER)
        return parse_certificate(peercert)

    def get_verified_chain(self) -> list[bytes]:
        """
        Returns verified certificate chain provided by the other
        end of the SSL channel as a list of DER-encoded bytes.

        If certificate verification was disabled method acts the same as
        ``SSLSocket.get_unverified_chain``.
        """
        chain = self._sslobj.get_verified_chain()
        return [c.public_bytes(serialization.Encoding.DER) for c in chain]

    def get_unverified_chain(self) -> list[bytes]:
        """Returns raw certificate chain provided by the other
        end of the SSL channel as a list of DER-encoded bytes.
        """
        chain = self._sslobj.get_unverified_chain()
        return [c.public_bytes(serialization.Encoding.DER) for c in chain]

    def selected_npn_protocol(self) -> str | None:
        """
        Return the currently selected NPN protocol as a string, or ``None``
        if a next protocol was not negotiated or if NPN is not supported by one
        of the peers."""
        return bytes_to_str(self._sslobj.selected_npn_protocol())

    def selected_alpn_protocol(self) -> str | None:
        """
        Return the currently selected ALPN protocol as a string, or ``None``
        if a next protocol was not negotiated or if ALPN is not supported by
        one of the peers."""
        return bytes_to_str(self._sslobj.selected_alpn_protocol())

    def cipher(self) -> tuple[str, str, int] | None:
        """
        Return the currently selected cipher as a 3-tuple ``(name,
        ssl_version, secret_bits)``.
        """
        cipher = self._sslobj.cipher()
        if cipher is not None:
            return parse_cipher(cipher)
        return None

    def shared_ciphers(self) -> list[tuple[str, str, int]] | None:
        """
        Return a list of ciphers shared by the client during the handshake or
        None if this is not a valid server connection.
        """
        shared_ciphers = self._sslobj.shared_ciphers()
        if shared_ciphers is not None:
            return [parse_cipher(c) for c in shared_ciphers]
        return None

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
            raise SSLWantReadError from None

    def unwrap(self) -> None:
        """
        Start the SSL shutdown handshake.
        """
        self._sslobj.shutdown()

    def get_channel_binding(self, cb_type: str = "tls-unique") -> bytes | None:
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

    def verify_client_post_handshake(self) -> None:
        raise NotImplementedError("Post handshake auth is not supported")

    def _new_session_handler(self, session: tls.TLSSession) -> None:
        self._session = SSLSession(session)

    def _do_sni_callback(
        self, info: tls.ClientHelloInfo, context: tls.HandshakeContext
    ) -> None:
        if self._sni_callback is None:
            return
        sni = bytes_to_str(info.server_name)
        alert_description = self._sni_callback(self, sni, self.context)
        config = self.context._config_data()
        context.alert_description = alert_description
        context.credential = config.get("credential", None)
        context.verify_mode = config.get("verify_mode", context.verify_mode)
