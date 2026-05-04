# Copyright (c) 2026 The simple-tls Contributors
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from __future__ import annotations

import struct
import typing
from ssl import MemoryBIO

from .. import x509
from ..io.serialization import Encoding
from ..utils.math import bytes_to_str, int_to_bytes, str_to_bytes
from ._alert import AlertException
from ._cipher import InvalidTag, NullCipher, TLSCipher
from ._constant import (
    AlertDescription,
    AlertLevel,
    CipherSuite,
    ContentType,
    KeyUpdateMessageType,
    TLSVersion,
)
from ._context import TLSContext
from ._enum import Direction, ECHStatus, Epoch, Shutdown, Status
from ._exception import (
    TLSEOFError,
    TLSError,
    TLSLocalAlert,
    TLSRemoteAlert,
    TLSWantReadError,
)
from ._extension import ECHConfig
from ._handshake import TLSHandshake
from ._handshake_client import SessionTicketHandler, TLSHandshakeClient
from ._handshake_server import TLSHandshakeServer
from ._message import Alert, ChangeCipherSpec, HandshakeMessage
from ._session import TLSSession
from ._types import ReadableBuffer, WritableBuffer

_HEADER_LENGTH = 5
_MAX_EARLY_DATA_SKIPPED = 16384


class SkipDataException(Exception):
    pass


class ConnectionState:
    def __init__(self, epoch: Epoch, cipher: TLSCipher):
        self.epoch = epoch
        self.cipher = cipher

        self.record_splitting = False
        self.hide_content_type = False
        self.max_seal_overhead = 0

        self.sequence_number = 0

    @classmethod
    def create_initial(cls, direction: Direction) -> ConnectionState:
        cipher = NullCipher(direction)
        return ConnectionState(Epoch.INITIAL, cipher)


class TLSConnection:
    def __init__(
        self,
        context: TLSContext,
        inbio: MemoryBIO | None = None,
        outbio: MemoryBIO | None = None,
        server_side: bool = False,
        server_hostname: bytes | str | None = None,
        session: TLSSession | None = None,
        session_ticket_handler: SessionTicketHandler | None = None,
    ) -> None:
        if context.check_hostname and not server_hostname:
            raise ValueError("check_hostname requires server_hostname")

        if server_side:
            if server_hostname:
                raise ValueError(
                    "server_hostname can only be specified in client mode"
                )
            if session is not None or session_ticket_handler is not None:
                raise ValueError(
                    "session can only be specified in client mode"
                )

            handshake = typing.cast(TLSHandshake, TLSHandshakeServer(context))
        else:
            handshake = typing.cast(
                TLSHandshake,
                TLSHandshakeClient(
                    context=context,
                    hostname=str_to_bytes(server_hostname),
                    session=session,
                    session_ticket_handler=session_ticket_handler,
                ),
            )

        self._handshake_status = Status.OK
        self._handshake = handshake
        self._handshake.do_message_cb = self._do_hs_callback
        self._handshake.setup_traffic_cb = self._setup_traffic
        self._handshake.update_traffic_cb = self._update_traffic
        self._handshake.add_ccs_cb = self._add_ccs
        self._handshake.do_sni_cb = self._sni_callback

        self._send_record_limit = 2**14
        """Send record limit"""
        self._recv_record_limit = 2**14
        """Received record limit"""
        self._max_early_data_size = context.max_early_data_size
        """Max early data size allowed"""

        self._inbio = inbio or MemoryBIO()
        """Incoming encrypted bytes"""
        self._outbio = outbio or MemoryBIO()
        """Outgoing encrypted bytes (waiting to be send)"""

        self._header: bytes | None = None
        """cached record header"""
        self._read_buf = memoryview(bytearray(self._recv_record_limit + 2048))
        """temporary buffer to store data decrypted"""
        self._write_buf = memoryview(
            bytearray(self._send_record_limit + 2 * (_HEADER_LENGTH + 2048))
        )
        """temporary buffer to store data encrypted"""
        self._temp_buf = memoryview(bytearray(self._send_record_limit + 2048))
        """temporary buffer to store plaintext for TLSv1.3"""

        self._pending_flight = bytearray()
        """pending encrypted handshake record to send"""
        self._pending_app_data = bytearray()
        """Unconsumed decrypted application data"""

        self._early_data_ignored = 0
        self._early_data_processed = 0

        self._write_shutdown = Shutdown.NONE
        self._read_shutdown = Shutdown.NONE
        self._current_write_epoch = Epoch.INITIAL
        self._current_read_epoch = Epoch.INITIAL
        self._write_states = {
            Epoch.INITIAL: ConnectionState.create_initial(Direction.ENCRYPT)
        }
        self._read_states = {
            Epoch.INITIAL: ConnectionState.create_initial(Direction.DECRYPT)
        }

    @property
    def context(self) -> TLSContext:
        return self._handshake.context

    @context.setter
    def context(self, value: TLSContext) -> None:
        if not isinstance(value, TLSContext):
            raise TypeError("context must be TLSContext object")
        self._handshake.context = value

    @property
    def server_side(self) -> bool:
        return self._handshake.server_side

    @property
    def server_hostname(self) -> str | None:
        return bytes_to_str(self._handshake.hostname)

    def handshake_complete(self) -> bool:
        return self._handshake.done

    def session_reused(self) -> bool:
        return self._handshake.session_reused

    def ech_accepted(self) -> bool:
        return self._handshake.ech_status == ECHStatus.ACCEPTED

    @typing.overload
    def ech_retry_config(
        self, binary_form: typing.Literal[True] = ...
    ) -> bytes | None: ...

    @typing.overload
    def ech_retry_config(
        self, binary_form: typing.Literal[False] = ...
    ) -> list[ECHConfig] | None: ...

    @typing.overload
    def ech_retry_config(
        self, binary_form: bool = ...
    ) -> list[ECHConfig] | bytes | None: ...

    def ech_retry_config(
        self, binary_form: bool = True
    ) -> list[ECHConfig] | bytes | None:
        ech_retry_config = self._handshake.ech_retry_configs
        if ech_retry_config is None:
            return None

        if not binary_form:
            return ech_retry_config

        body = b"".join(c.serialize() for c in ech_retry_config)
        return int_to_bytes(len(body), 2) + body

    def early_data_accepted(self) -> bool:
        return self._handshake.early_data_accepted

    def early_data_offered(self) -> bool:
        return self._handshake.early_data_offered

    def version(self) -> str:
        lookup_map: dict[int, str] = {
            TLSVersion.TLSv1: "TLSv1",
            TLSVersion.TLSv1_1: "TLSv1.1",
            TLSVersion.TLSv1_2: "TLSv1.2",
            TLSVersion.TLSv1_3: "TLSv1.3",
        }
        if self._has_final_version():
            version = self._handshake.protocol_version()
            try:
                return lookup_map[version]
            except KeyError:
                pass
        return "Unknown version"

    def verify_client_post_handshake(self) -> None:
        if not self.server_side:
            raise TLSError("Not server")
        raise NotImplementedError()

    def bio_write(self, data: bytes) -> None:
        """
        Data from the network
        """
        self._inbio.write(data)

    def bio_read(self, bufsiz: int) -> bytes:
        """
        Return data to send
        """
        data = self._outbio.read(bufsiz)
        if not data:
            raise TLSWantReadError()
        return data

    @typing.overload
    def read(self, length: int = 1024, buffer: None = ...) -> bytes: ...

    @typing.overload
    def read(
        self, length: int = 1024, buffer: WritableBuffer = ...
    ) -> int: ...

    def read(
        self, length: int = 1024, buffer: WritableBuffer | None = None
    ) -> int | bytes:
        """
        Read up to 'len' bytes from the SSL object and return them.

        If 'buffer' is provided, read into this buffer and return the number of
        bytes read.
        """
        while not self._pending_app_data:
            if not (self._handshake.done or self._handshake.can_early_read):
                self.do_handshake()

            content_type, data = self._open_record()

            if content_type != ContentType.APPLICATION_DATA:
                if content_type == ContentType.HANDSHAKE:
                    self._handshake.add_hs_data(data)

                    if not self._handshake.done:
                        assert self._handshake.can_early_read
                        self._handshake.can_early_read = False
                    else:
                        self._handshake.trigger_post_handshake()
                else:
                    self._send_alert(
                        AlertDescription.UNEXPECTED_MESSAGE,
                        f"Unexpected ContentType '{content_type}'",
                    )

                continue

            is_early_data_read = (
                self._handshake.server_side and self._handshake.in_early_data
            )
            if is_early_data_read:
                self._early_data_processed += len(data)
                if self._early_data_processed >= self._max_early_data_size:
                    self._send_alert(
                        AlertDescription.UNEXPECTED_MESSAGE,
                        "Too much early data",
                    )

            data_len = len(data)
            if data_len > 0 and data_len <= length:
                if buffer is None:
                    return data.tobytes()
                else:
                    if len(buffer) < data_len:
                        raise ValueError("buffer too small")
                    buffer[:data_len] = data
                    return data_len

            self._pending_app_data.extend(data)

        app_data = self._pending_app_data[:length]
        data_len = len(app_data)

        if buffer is not None:
            if len(buffer) < data_len:
                raise ValueError("buffer too small")
            buffer[:data_len] = app_data
            del self._pending_app_data[:length]
            return data_len

        del self._pending_app_data[:length]
        return bytes(app_data)

    def write(self, data: ReadableBuffer) -> int:
        if not (self._handshake.done or self._handshake.can_early_write):
            self.do_handshake()

        if self._write_shutdown != Shutdown.NONE:
            raise TLSEOFError("protocol is shutdown")

        hs = self._handshake
        max_send_frament = self._send_record_limit
        is_early_data_write = (
            not self.server_side and hs.in_early_data and hs.can_early_write
        )
        if is_early_data_write:
            early_session = hs.early_session
            assert early_session is not None

            if (
                self._early_data_processed
                >= early_session.ticket_max_early_data
            ):
                hs.can_early_write = False

            max_send_frament = min(
                max_send_frament,
                early_session.ticket_max_early_data
                - self._early_data_processed,
            )

        if len(data) > max_send_frament:
            data = data[:max_send_frament]

        self._write(ContentType.APPLICATION_DATA, data)

        if is_early_data_write:
            self._early_data_processed += len(data)

        return len(data)

    def update_key(self, request_receiver_update: bool = False) -> None:
        if request_receiver_update:
            message_type = KeyUpdateMessageType.UPDATE_REQUESTED
        else:
            message_type = KeyUpdateMessageType.UPDATE_NOT_REQUESTED

        self._handshake.send_key_update(message_type)

    def getpeercert(self) -> x509.Certificate | None:
        session = self._handshake.established_session
        if session is not None and session.verified_x509_peer is not None:
            return session.verified_x509_peer
        return None

    def get_verified_chain(self) -> list[bytes]:
        session = self._handshake.established_session
        if (
            session is None
            or session.verified_x509_peer is None
            or session.verified_x509_chain is None
        ):
            return []

        return [
            c.public_bytes(Encoding.DER)
            for c in [session.verified_x509_peer, *session.verified_x509_chain]
        ]

    def get_unverified_chain(self) -> list[bytes]:
        session = self._handshake.established_session
        if (
            session is None
            or session.x509_peer is None
            or session.x509_chain is None
        ):
            return []

        return [
            c.public_bytes(Encoding.DER)
            for c in [session.x509_peer, *session.x509_chain]
        ]

    def selected_npn_protocol(self) -> str | None:
        return bytes_to_str(self._handshake.npn_selected)

    def selected_alpn_protocol(self) -> str | None:
        return bytes_to_str(self._handshake.alpn_selected)

    def cipher(self) -> CipherSuite | None:
        establish_session = self._handshake.established_session
        if establish_session is None:
            return None
        return establish_session.cipher_suite

    def shared_ciphers(self) -> list[CipherSuite] | None:
        if self._handshake.peer_cipher_suites is not None:
            out: list[CipherSuite] = []
            for cipher_suite in self._handshake.peer_cipher_suites:
                try:
                    out.append(CipherSuite(cipher_suite))
                except ValueError:
                    continue
            return out
        return None

    def pending(self) -> int:
        return len(self._pending_app_data)

    def do_handshake(self) -> None:
        while True:
            if self._handshake_status == Status.PACK_FLIGHT:
                self._pack_handshake()
            elif self._handshake_status == Status.FLUSH_MESSAGE:
                self._flush_handshake()
            elif self._handshake_status == Status.READ_MESSAGE:
                self._read_handshake()
            elif self._handshake_status == Status.READ_CHANGE_CIPHER_SPEC:
                self._read_ccs(Epoch.APPLICATION_DATA)
            elif self._handshake_status == Status.EARLY_RETURN:
                if isinstance(self._handshake, TLSHandshakeClient):
                    assert self._handshake.ech_status != ECHStatus.REJECTED
                self._handshake_status = Status.OK
                break
            elif self._handshake_status == Status.READ_END_OF_EARLY_DATA:
                if self._handshake.can_early_read:
                    break
                self._handshake_status = Status.OK

            try:
                self._handshake_status = self._handshake.do_handshake()
            except AlertException as exc:
                self._send_alert(exc.description, exc, exc.fatal)

            if self._handshake_status == Status.OK:
                assert self._handshake.done
                if isinstance(self._handshake, TLSHandshakeClient):
                    assert self._handshake.ech_status != ECHStatus.REJECTED
                break

    def shutdown(self) -> None:
        if self._write_shutdown != Shutdown.NONE:
            return

        self._send_alert(AlertDescription.CLOSE_NOTIFY, fatal=False)
        self._write_shutdown = Shutdown.CLOSE_NOTIFY

    @typing.overload
    def _send_alert(
        self,
        description: AlertDescription,
        reason: typing.Any | None = ...,
        fatal: typing.Literal[True] = ...,
    ) -> typing.NoReturn: ...

    @typing.overload
    def _send_alert(
        self,
        description: AlertDescription,
        reason: typing.Any | None,
        fatal: typing.Literal[False],
    ) -> None: ...

    @typing.overload
    def _send_alert(
        self,
        description: AlertDescription,
        reason: typing.Any | None = ...,
        fatal: bool = ...,
    ) -> None: ...

    def _send_alert(
        self,
        description: AlertDescription,
        reason: typing.Any | None = None,
        fatal: bool = True,
    ) -> None:
        if self._write_shutdown == Shutdown.NONE:
            if not fatal:
                alert = Alert(description, AlertLevel.WARNING)
                self._write(alert.content_type, alert.serialize())
            else:
                alert = Alert(description, AlertLevel.FATAL)
                self._write(alert.content_type, alert.serialize())
                self._write_shutdown = Shutdown.ERROR

        if fatal:
            raise TLSLocalAlert(alert.description, reason)
        return None

    def _sni_callback(self, hostname: bytes) -> None:
        callback = self.context.sni_callback
        if callback is None:
            return

        sni = bytes_to_str(hostname)
        arg = self.context.sni_callback_arg
        result = callback(self, sni, arg)

        if result is not None:
            try:
                description = AlertDescription(result)
            except ValueError:
                self._send_alert(
                    AlertDescription.INTERNAL_ERROR,
                    f"Unknown alert description '{description}'",
                )
            else:
                self._send_alert(description)

    def _do_hs_callback(
        self,
        direction: typing.Literal["write", "read"],
        message: HandshakeMessage,
    ) -> None:
        cb = self.context.message_callback
        if cb is not None:
            version = self._handshake.version
            data = message.serialize()
            cb(self, direction, version, ContentType.HANDSHAKE, data)
        return None

    # Record layer
    def _setup_traffic(
        self, direction: Direction, epoch: Epoch, cipher: TLSCipher
    ) -> None:
        state = ConnectionState(epoch, cipher)
        version = self._handshake.protocol_version()
        max_seal_overhead = _HEADER_LENGTH
        max_seal_overhead += cipher.max_overhead()

        if version < TLSVersion.TLSv1_1 and cipher.is_block_cipher():
            state.record_splitting = True
            max_seal_overhead *= 2

        if version >= TLSVersion.TLSv1_3:
            state.hide_content_type = True
            max_seal_overhead += 1

        state.max_seal_overhead = max_seal_overhead

        if direction == Direction.ENCRYPT:
            self._write_states[epoch] = state
        else:
            self._read_states[epoch] = state

    def _update_traffic(self, direction: Direction, epoch: Epoch) -> None:
        if direction == Direction.ENCRYPT:
            assert len(self._handshake.pending_flight()) == 0
            self._current_write_epoch = epoch
        else:
            self._current_read_epoch = epoch

    def _add_ccs(self) -> None:
        record_version = self._record_version()
        css = ChangeCipherSpec(type=1)
        css_data = css.serialize()
        header = self._get_header(
            css.content_type, record_version, len(css_data)
        )
        self._pending_flight.extend(header)
        self._pending_flight.extend(css_data)

    def _read_ccs(self, epoch: Epoch) -> None:
        content_type, _ = self._open_record()
        if content_type != ContentType.CHANGE_CIPHER_SPEC:
            self._send_alert(AlertDescription.UNEXPECTED_MESSAGE)
        self._current_read_epoch = epoch

    def _read_handshake(self) -> None:
        content_type, data = self._open_record()
        if content_type != ContentType.HANDSHAKE:
            self._send_alert(
                AlertDescription.UNEXPECTED_MESSAGE,
                f"Unexpected content type '0x{content_type:02X}'",
            )
        self._handshake.add_hs_data(data)

    def _pack_handshake(self) -> None:
        pending_hs_data = self._handshake.pending_flight()
        if not pending_hs_data:
            return

        fragment = self._send_record_limit - 1
        content_type = ContentType.HANDSHAKE

        with memoryview(pending_hs_data) as view:
            for i in range(0, len(view), fragment):
                record_data = self._seal_record(
                    content_type, view[i : i + fragment]
                )
                self._pending_flight.extend(record_data)

        self._handshake.clear_flight()

    def _flush_handshake(self) -> None:
        self._pack_handshake()

        if not self._pending_flight:
            return

        if self._write_shutdown != Shutdown.NONE:
            return

        self._outbio.write(self._pending_flight)
        self._pending_flight.clear()

    def _write(self, content_type: int, data: ReadableBuffer) -> None:
        self._flush_handshake()

        if not data:
            return

        record_data = self._seal_record(content_type, data)
        self._outbio.write(record_data)

    def _seal_record(
        self,
        content_type: int,
        plaintext: ReadableBuffer,
    ) -> memoryview:
        epoch = self._current_write_epoch
        state = self._write_states[epoch]
        original_buf = self._write_buf
        buf = original_buf
        written = 0

        if (
            state.record_splitting
            and content_type == ContentType.APPLICATION_DATA
            and len(plaintext) > 1
        ):
            written = self._seal_record_internal(
                content_type, plaintext[:1], buf
            )
            plaintext = plaintext[1:]
            buf = buf[written:]

        written += self._seal_record_internal(content_type, plaintext, buf)
        return original_buf[:written]

    def _seal_record_internal(
        self,
        content_type: int,
        plaintext: ReadableBuffer,
        buf: WritableBuffer,
    ) -> int:
        assert len(plaintext) <= self._send_record_limit

        epoch = self._current_write_epoch
        state = self._write_states[epoch]

        data_buf = buf[_HEADER_LENGTH:]

        if state.hide_content_type:
            pt_len = len(plaintext)
            temp_view = self._temp_buf[0 : pt_len + 1]
            temp_view[0:pt_len] = plaintext
            temp_view[pt_len] = content_type
            plaintext = temp_view
            content_type = ContentType.APPLICATION_DATA

        cipher = state.cipher
        seq_num = state.sequence_number
        record_version = self._record_version()
        ciphertext_len = cipher.ciphertext_length(len(plaintext))
        header = self._get_header(content_type, record_version, ciphertext_len)

        ct_len = cipher.seal(
            content_type,
            record_version,
            plaintext,
            seq_num,
            header,
            data_buf,
        )
        assert ct_len == ciphertext_len

        state.sequence_number += 1

        buf[0:_HEADER_LENGTH] = header
        out_len = _HEADER_LENGTH + ct_len

        return out_len

    def _open_record(self) -> tuple[int, memoryview]:
        while True:
            try:
                return self._open_record_internal()
            except SkipDataException:
                pass

    def _open_record_internal(self) -> tuple[int, memoryview]:
        if self._read_shutdown != Shutdown.NONE:
            raise TLSEOFError()

        epoch = self._current_read_epoch
        state = self._read_states[epoch]
        out = self._read_buf
        inbio = self._inbio

        # Parse header: ContentType (1), Version (2), Length (2)
        if self._header is None:
            if inbio.pending < _HEADER_LENGTH:
                raise TLSWantReadError()
            self._header = inbio.read(_HEADER_LENGTH)

        header = self._header
        assert len(header) == _HEADER_LENGTH

        content_type, record_version, length = struct.unpack("!BHH", header)

        if isinstance(state.cipher, NullCipher):
            version_ok = record_version >> 8 == 0x03
        else:
            version_ok = record_version == self._record_version()

        if not version_ok:
            self._send_alert(
                AlertDescription.PROTOCOL_VERSION, "Wrong version number"
            )

        # Check the record header fields
        # 2**14 (default record size limit)
        # 1024 (maximum compression overhead)
        # 1024 (maximum encryption overhead)
        if length > self._recv_record_limit + 1024 + 1024:
            self._send_alert(
                AlertDescription.RECORD_OVERFLOW, "record too large"
            )

        # Extract full record
        if inbio.pending < length:
            raise TLSWantReadError()

        ciphertext = inbio.read(length)
        assert length == len(ciphertext)

        self._header = None

        if content_type == ContentType.CHANGE_CIPHER_SPEC:
            ccs = ChangeCipherSpec.from_bytes(ciphertext)
            # RFC 8446 section 5
            if ccs.type != 1:
                self._send_alert(
                    AlertDescription.UNEXPECTED_MESSAGE, "Invalid CCS message"
                )

            if (
                self._has_final_version()
                and self._handshake.protocol_version() >= TLSVersion.TLSv1_3
                and not self._handshake.done
            ):
                raise SkipDataException()

        if (
            self._handshake.skip_early_data
            and isinstance(state.cipher, NullCipher)
            and content_type == ContentType.APPLICATION_DATA
        ):
            self._skip_early_data(len(ciphertext))
            raise SkipDataException()

        # Check for cleartext alerts received during an encrypted epoch.
        # In TLS 1.3, encrypted records ALWAYS have an outer content_type
        # of 23. If it is 21, the peer aborted before/during key generation.
        if (
            content_type == ContentType.ALERT
            and state.hide_content_type
            and state.sequence_number == 0
        ):
            self._process_alert(ciphertext)

        seq_num = state.sequence_number
        try:
            pt_len = state.cipher.open(
                content_type,
                record_version,
                ciphertext,
                seq_num,
                header,
                out,
            )
        except InvalidTag as exc:
            if self._handshake.skip_early_data:
                self._skip_early_data(len(ciphertext))
                raise SkipDataException() from None

            self._send_alert(
                AlertDescription.BAD_RECORD_MAC,
                f"Invalid tag ({epoch}): {exc}",
            )
        else:
            state.sequence_number += 1

        self._handshake.skip_early_data = False

        if state.hide_content_type:
            if content_type != ContentType.APPLICATION_DATA:
                self._send_alert(AlertDescription.ILLEGAL_PARAMETER)
            pt_limit = self._recv_record_limit + 1
        else:
            pt_limit = self._recv_record_limit

        # RFC 5246 section 6.2.1
        # RFC 8446 section 5.4
        if pt_len > pt_limit:
            self._send_alert(AlertDescription.RECORD_OVERFLOW)

        if state.hide_content_type:
            content_type, pt_len = self._unpad_data_tlsv1_3(out[:pt_len])

        # RFC 8446 Section 5.1
        # Implementations MUST NOT send zero-length fragments of Handshake
        # types, even if those fragments contain padding.
        # RFC 5246 Section 6.2.1
        # Implementations MUST NOT send zero-length fragments of content
        # types other than Application Data.
        if content_type != ContentType.APPLICATION_DATA and pt_len == 0:
            self._send_alert(
                AlertDescription.UNEXPECTED_MESSAGE, "Empty handshake message"
            )

        if content_type == ContentType.ALERT:
            self._process_alert(out[:pt_len])

        # RFC 8446 Section 5.1
        # TLS 1.3 Handshake messages MUST NOT be interleaved with other
        # messages
        if (
            content_type != ContentType.HANDSHAKE
            and self._handshake.has_unprocessed_hs_data()
            and self._handshake.protocol_version() >= TLSVersion.TLSv1_3
        ):
            self._send_alert(
                AlertDescription.UNEXPECTED_MESSAGE,
                "Interleaved handshake message",
            )

        return content_type, out[:pt_len]

    def _skip_early_data(self, ciphertext_length: int) -> None:
        self._early_data_ignored += ciphertext_length
        if self._early_data_ignored >= _MAX_EARLY_DATA_SKIPPED:
            self._send_alert(AlertDescription.UNEXPECTED_MESSAGE)

    def _process_alert(self, data: ReadableBuffer) -> typing.NoReturn:
        alert = Alert.from_bytes(data)  # type: ignore

        if alert.level == AlertLevel.WARNING:
            if alert.description == AlertDescription.CLOSE_NOTIFY:
                self._read_shutdown = Shutdown.CLOSE_NOTIFY
                raise TLSEOFError()

            if (
                self._has_final_version()
                and self._handshake.protocol_version() >= TLSVersion.TLSv1_3
                and alert.description != AlertDescription.USER_CANCELLED
            ):
                self._send_alert(AlertDescription.DECODE_ERROR)

            raise SkipDataException()

        if alert.level == AlertLevel.FATAL:
            self._read_shutdown = Shutdown.ERROR
            raise TLSRemoteAlert(alert.description)

        self._send_alert(
            AlertDescription.UNEXPECTED_MESSAGE, "Unknown alert type"
        )

    def _record_version(self) -> int:
        if self._handshake.version == TLSVersion.UNSPECIFIED:
            return TLSVersion.TLSv1
        return min(TLSVersion.TLSv1_2, self._handshake.version)

    def _has_final_version(self) -> bool:
        if self._handshake.version == TLSVersion.UNSPECIFIED:
            return False
        if self._handshake.is_early_version:
            return False
        return True

    def _unpad_data_tlsv1_3(self, data: ReadableBuffer) -> tuple[int, int]:
        for pos in range(len(data) - 1, -1, -1):
            value = data[pos]
            if value != 0:
                break
        else:
            self._send_alert(
                AlertDescription.UNEXPECTED_MESSAGE, "Missing content type"
            )
        return value, pos

    @staticmethod
    def _get_header(
        content_type: int, record_version: int, length: int
    ) -> bytes:
        return struct.pack("!BHH", content_type, record_version, length)
