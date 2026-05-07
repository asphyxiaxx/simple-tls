from __future__ import annotations

import errno
import ssl as _ssl
import typing
from socket import SO_TYPE, SOCK_STREAM, SOL_SOCKET, socket

from simple_tls import tls
from simple_tls.io import serialization

from ..utils.math import bytes_to_str
from ._constant import Options
from ._exception import (
    SSLEOFError,
    SSLError,
    SSLWantReadError,
    SSLWantWriteError,
)
from ._session import SSLSession
from ._types import PeerCertRetDictType, ReadableBuffer, WritableBuffer
from ._util import parse_certificate, parse_cipher

if typing.TYPE_CHECKING:
    from socket import _Address, _RetAddress

    from ._context import SSLContext


class SSLSocket(_ssl.SSLSocket):
    _context: SSLContext
    _sslobj: tls.TLSConnection | None
    _session: SSLSession | None
    _connected: bool
    _closed: bool
    _pending_write: bytearray
    server_side: bool
    server_hostname: str | None
    do_handshake_on_connect: bool
    suppress_ragged_eofs: bool

    @classmethod
    def _create(
        cls,
        sock: socket,
        server_side: bool = False,
        do_handshake_on_connect: bool = True,
        suppress_ragged_eofs: bool = True,
        server_hostname: str | bytes | None = None,
        context: SSLContext | None = None,
        session: SSLSession | None = None,
    ) -> SSLSocket:
        if context is None:
            raise ValueError("context not provided")
        if sock.getsockopt(SOL_SOCKET, SO_TYPE) != SOCK_STREAM:
            raise NotImplementedError("only stream sockets are supported")

        sock_timeout = sock.gettimeout()
        kwargs = dict(
            family=sock.family,
            type=sock.type,
            proto=sock.proto,
            fileno=sock.fileno(),
        )
        self = cls.__new__(cls, **kwargs)
        socket.__init__(self, **kwargs)
        sock.detach()

        # Now SSLSocket is responsible for closing the file descriptor.
        self._context = context
        self._session = session
        self._closed = False
        self._sslobj = None
        self._pending_write = bytearray()
        self.server_side = server_side
        self.server_hostname = bytes_to_str(server_hostname)
        self.do_handshake_on_connect = do_handshake_on_connect
        self.suppress_ragged_eofs = suppress_ragged_eofs

        try:
            # See if we are connected
            try:
                self.getpeername()
            except OSError as e:
                if e.errno != errno.ENOTCONN:
                    raise

                connected = False
                blocking = self.getblocking()
                self.setblocking(False)
                try:
                    notconn_pre_handshake_data = self.recv(1)
                except OSError as e2:
                    # EINVAL occurs for recv(1) on non-connected on unix
                    # sockets.
                    if e2.errno not in (errno.ENOTCONN, errno.EINVAL):
                        raise

                    notconn_pre_handshake_data = b""

                self.setblocking(blocking)

                if notconn_pre_handshake_data:
                    # This prevents pending data sent to the socket before it
                    # was closed from escaping to the caller who could
                    # otherwisepresume it came through a successful TLS
                    # connection.
                    reason = (
                        "Closed before TLS handshake with data in recv buffer."
                    )
                    notconn_pre_handshake_data_error = SSLError(
                        e.errno, reason
                    )
                    # Add the SSLError attributes that _ssl.c always adds.
                    notconn_pre_handshake_data_error.reason = reason
                    notconn_pre_handshake_data_error.library = ""
                    try:
                        raise notconn_pre_handshake_data_error
                    finally:
                        # Explicitly break the reference cycle.
                        notconn_pre_handshake_data_error = None  # type: ignore

            else:
                connected = True

            # Must come after setblocking() calls.
            self.settimeout(sock_timeout)
            self._connected = connected

            if connected:
                if not server_side:
                    session_ticket_handler = self._session_ticket_handler
                else:
                    session_ticket_handler = None

                if context.options & Options.OP_NO_TICKET:
                    session_ticket_handler = None
                    context._context.session_keys = None
                    context._context.session_storage = None

                context._context.sni_callback_arg = self

                # create the SSL object
                self._sslobj = tls.TLSConnection(
                    context=self._context._context,
                    server_side=self.server_side,
                    server_hostname=self.server_hostname,
                    session=(
                        session.session if session is not None else session
                    ),
                    session_ticket_handler=session_ticket_handler,
                )

                if do_handshake_on_connect:
                    timeout = self.gettimeout()
                    if timeout == 0.0:
                        # non-blocking
                        raise ValueError(
                            "do_handshake_on_connect should not be specified "
                            "for non-blocking sockets"
                        )
                    self.do_handshake()

        except:
            try:
                self.close()
            except OSError:
                pass
            raise

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
        if self._sslobj is None:
            raise TypeError("set context on closed socket")

        self._context = value
        self._sslobj.context = value._context
        self._sslobj.context.sni_callback_arg = self

    @property
    def session(self) -> SSLSession | None:  # type: ignore[override]
        return self._session

    @property
    def session_reused(self) -> bool | None:
        if self._sslobj is not None:
            return self._sslobj.session_reused()
        return None

    def dup(self) -> SSLSocket:
        raise NotImplementedError(
            f"Can't dup() {self.__class__.__name__} instances"
        )

    def _checkClosed(self, msg: typing.Any | None = None) -> None:  # noqa: N802
        # raise an exception here if you wish to check for spurious closes
        pass

    def _check_connected(self) -> None:
        if not self._connected:
            # getpeername() will raise ENOTCONN if the socket is really
            # not connected; note that we can be connected even without
            # _connected being set, e.g. if connect() first returned
            # EAGAIN.
            self.getpeername()

    def _session_ticket_handler(self, session: tls.TLSSession) -> None:
        self._session = SSLSession(session)

    def _drive_tls(
        self, func: typing.Callable, *args: typing.Any
    ) -> typing.Any:
        """
        Drive a TLS operation safely in non-blocking mode.
        """
        # Always flush pending ciphertext first
        if self._pending_write:
            self._tls_send()

        assert not self._pending_write

        while True:
            try:
                result = func(*args)
                break
            except tls.TLSWantReadError:
                self._tls_send()
                self._tls_recv()
            except tls.TLSEOFError:
                raise SSLEOFError from None
            except tls.TLSError as exc:
                self._tls_send()
                raise SSLError(exc) from exc

        # Flush any newly generated ciphertext
        self._tls_send()

        return result

    def _tls_send(self) -> None:
        """
        Flush pending TLS ciphertext to the underlying socket.
        Correctly handles partial writes.
        """
        sslobj = typing.cast(tls.TLSConnection, self._sslobj)

        # Flush previously unsent ciphertext
        while self._pending_write:
            try:
                sent = socket.send(self, self._pending_write)
            except BlockingIOError:
                raise SSLWantWriteError from None

            if sent == 0:
                raise SSLEOFError("socket closed during TLS write")

            del self._pending_write[:sent]

        # Drain new ciphertext from TLS BIO
        while True:
            try:
                data = sslobj.bio_read(65535)
            except tls.TLSWantReadError:
                return

            total_sent = 0
            while total_sent < len(data):
                try:
                    sent = socket.send(self, data[total_sent:])
                except BlockingIOError:
                    # Store unsent portion
                    self._pending_write.extend(data[total_sent:])
                    raise SSLWantWriteError() from None

                if sent == 0:
                    raise SSLEOFError("socket closed during TLS write")

                total_sent += sent

    def _tls_recv(self) -> None:
        """
        Read raw TLS ciphertext from socket and feed it into SSL BIO.
        """
        sslobj = typing.cast(tls.TLSConnection, self._sslobj)
        try:
            data = socket.recv(self, 65535)
        except BlockingIOError:
            raise SSLWantReadError() from None

        if not data:
            raise SSLEOFError("connection closed")

        sslobj.bio_write(data)

    @typing.overload  # type: ignore[override]
    def read(self, len: int = 1024, buffer: None = None) -> bytes: ...

    @typing.overload  # type: ignore[override]
    def read(self, len: int = 1024, buffer: ReadableBuffer = ...) -> int: ...

    def read(
        self,
        len: int = 1024,
        buffer: ReadableBuffer | None = None,
    ) -> bytes | int:
        """
        Read up to 'len' bytes and return them.
        Return zero-length string on EOF.
        """
        self._checkClosed()
        if self._sslobj is None:
            raise ValueError("Read on closed or unwrapped SSL socket.")

        try:
            return self._drive_tls(self._sslobj.read, len, buffer)
        except SSLEOFError:
            if self.suppress_ragged_eofs:
                if buffer is None:
                    return b""
                return 0
            raise

    def write(self, data: ReadableBuffer) -> int:  # type: ignore[override]
        """
        Write 'data' to the underlying SSL channel.  Returns
        number of bytes of 'data' actually transmitted.
        """
        self._checkClosed()
        if self._sslobj is None:
            raise ValueError("Write on closed or unwrapped SSL socket.")
        return self._drive_tls(self._sslobj.write, data)

    def get_ech_retry_configs(self) -> bytes | None:
        if self._sslobj is None:
            return None
        return self._sslobj.ech_retry_config(binary_form=True)

    def ech_accepted(self) -> bool:
        if self._sslobj is None:
            return False
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
        self._checkClosed()
        self._check_connected()

        if self._sslobj is None:
            return None

        peercert = self._sslobj.getpeercert()
        if peercert is None:
            return None
        if binary_form:
            return peercert.public_bytes(serialization.Encoding.DER)
        return parse_certificate(peercert)

    def get_verified_chain(self) -> list[bytes]:
        if self._sslobj is not None:
            return self._sslobj.get_verified_chain()
        return []

    def get_unverified_chain(self) -> list[bytes]:
        if self._sslobj is not None:
            return self._sslobj.get_unverified_chain()
        return []

    def selected_npn_protocol(self) -> str | None:
        self._checkClosed()
        if self._sslobj is not None:
            return self._sslobj.selected_npn_protocol()
        return None

    def selected_alpn_protocol(self) -> str | None:
        self._checkClosed()

        if self._sslobj is not None:
            return self._sslobj.selected_alpn_protocol()
        return None

    def cipher(self) -> tuple[str, str, int] | None:
        self._checkClosed()

        if self._sslobj is not None:
            cipher = self._sslobj.cipher()
            if cipher is not None:
                return parse_cipher(cipher)
        return None

    def shared_ciphers(self) -> list[tuple[str, str, int]] | None:
        self._checkClosed()

        if self._sslobj is not None:
            shared_ciphers = self._sslobj.shared_ciphers()
            if shared_ciphers is not None:
                return [parse_cipher(c) for c in shared_ciphers]
        return None

    def compression(self) -> None:
        self._checkClosed()
        return None

    def send(self, data: ReadableBuffer, flags: int = 0) -> int:  # type: ignore[override]
        self._checkClosed()
        if self._sslobj is not None:
            if flags != 0:
                raise ValueError(
                    f"non-zero flags not allowed in calls to send() on "
                    f"{self.__class__}"
                )
            return self.write(data)
        else:
            return socket.send(self, data, flags)

    def sendall(self, data: ReadableBuffer, flags: int = 0) -> None:  # type: ignore[override]
        self._checkClosed()
        if self._sslobj is not None:
            if flags != 0:
                raise ValueError(
                    f"non-zero flags not allowed in calls to "
                    f"sendall() on {self.__class__}"
                )
            count = 0
            with memoryview(data) as view, view.cast("B") as byte_view:
                amount = len(byte_view)
                while count < amount:
                    v = self.send(byte_view[count:])
                    count += v
        else:
            return socket.sendall(self, data, flags)

    def sendfile(
        self, file: typing.Any, offset: int = 0, count: int | None = None
    ) -> int:
        """
        Send a file, possibly by using os.sendfile() if this is a
        clear-text socket.  Return the total number of bytes sent.
        """
        raise NotImplementedError

    def recv(self, buflen: int = 1024, flags: int = 0) -> bytes:
        self._checkClosed()
        if self._sslobj is not None:
            if flags != 0:
                raise ValueError(
                    f"non-zero flags not allowed in calls to recv() on "
                    f"{self.__class__}"
                )
            return self.read(buflen)
        else:
            return socket.recv(self, buflen, flags)

    def recv_into(  # type: ignore[override]
        self,
        buffer: WritableBuffer,
        nbytes: int | None = None,
        flags: int = 0,
    ) -> int:
        self._checkClosed()

        if nbytes is None:
            if buffer is not None:
                with memoryview(buffer) as view:
                    nbytes = view.nbytes
                if not nbytes:
                    nbytes = 1024
            else:
                nbytes = 1024

        if self._sslobj is not None:
            if flags != 0:
                raise ValueError(
                    f"non-zero flags not allowed in calls to "
                    f"recv_into() on {self.__class__}"
                )
            return self.read(nbytes, buffer)
        else:
            return socket.recv_into(self, buffer, nbytes, flags)

    def pending(self) -> int:
        self._checkClosed()
        if self._sslobj is not None:
            return self._sslobj.pending()
        return 0

    def unwrap(self) -> socket:
        if self._sslobj is not None:
            self._sslobj.shutdown()
            self._tls_send()
            self._sslobj = None
            return self
        else:
            raise ValueError("No SSL wrapper around " + str(self))

    def verify_client_post_handshake(self) -> None:
        if self._sslobj is not None:
            return self._sslobj.verify_client_post_handshake()
        else:
            raise ValueError("No SSL wrapper around " + str(self))

    def do_handshake(self, block: bool = False) -> None:
        self._check_connected()
        if self._sslobj is None:
            raise ValueError("No SSL wrapper around " + str(self))
        timeout = self.gettimeout()
        try:
            if timeout == 0.0 and block:
                self.settimeout(None)
            self._drive_tls(self._sslobj.do_handshake)
        finally:
            self.settimeout(timeout)

    @typing.overload
    def _real_connect(
        self, addr: _Address, connect_ex: typing.Literal[True]
    ) -> int: ...

    @typing.overload
    def _real_connect(
        self, addr: _Address, connect_ex: typing.Literal[False]
    ) -> None: ...

    @typing.overload
    def _real_connect(
        self, addr: _Address, connect_ex: bool
    ) -> int | None: ...

    def _real_connect(self, addr: _Address, connect_ex: bool) -> int | None:
        if self.server_side:
            raise ValueError("can't connect in server-side mode")

        # Here we assume that the socket is client-side, and not
        # connected at the time of the call.  We connect it, then wrap it.
        if self._connected or self._sslobj is not None:
            raise ValueError("attempt to connect already-connected SSLSocket!")

        if self._session is not None:
            session = self._session.session
        else:
            session = None

        self._sslobj = tls.TLSConnection(
            context=self._context._context,
            server_side=False,
            server_hostname=self.server_hostname,
            session=session,
            session_ticket_handler=self._session_ticket_handler,
        )

        try:
            if connect_ex:
                rc = socket.connect_ex(self, addr)
            else:
                rc = None
                socket.connect(self, addr)

            if not rc:
                self._connected = True
                if self.do_handshake_on_connect:
                    self.do_handshake()
            return rc

        except (OSError, ValueError):
            self._sslobj = None
            raise

    def connect(self, addr: _Address) -> None:
        """
        Connects to remote ADDR, and then wraps the connection in
        an SSL channel.
        """
        self._real_connect(addr, False)

    def connect_ex(self, addr: _Address) -> int:
        """
        Connects to remote ADDR, and then wraps the connection in
        an SSL channel.
        """
        return self._real_connect(addr, True)

    def accept(self) -> tuple[SSLSocket, _RetAddress]:
        """
        Accepts a new connection from a remote client, and returns
        a tuple containing that new connection wrapped with a server-side
        SSL channel, and the address of the remote client.
        """
        newsock, addr = socket.accept(self)
        newsock = self.context.wrap_socket(
            newsock,
            do_handshake_on_connect=self.do_handshake_on_connect,
            suppress_ragged_eofs=self.suppress_ragged_eofs,
            server_side=True,
        )
        return newsock, addr

    def get_channel_binding(self, cb_type: str = "tls-unique") -> bytes | None:
        raise NotImplementedError

    def version(self) -> str | None:
        if self._sslobj is not None:
            return self._sslobj.version()
        return None
