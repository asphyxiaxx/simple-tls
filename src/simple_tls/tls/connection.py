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
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Literal, NoReturn, overload

from cryptography import x509

from simple_tls.tls.alerts import AlertException
from simple_tls.tls.cipher import InvalidTag, TLSCipher, get_key_iv_lens
from simple_tls.tls.config import TLSConfiguration
from simple_tls.tls.constants import (
    UNSPECIFIED,
    AlertDescription,
    AlertLevel,
    CipherSuite,
    ContentType,
    KeyUpdateMessageType,
    TLSVersion,
)
from simple_tls.tls.enums import (
    Direction,
    EarlyDataStatus,
    ECHStatus,
    Epoch,
    Shutdown,
    Status,
)
from simple_tls.tls.exceptions import (
    TLSEOFError,
    TLSLocalAlert,
    TLSRemoteAlert,
    TLSWantReadError,
)
from simple_tls.tls.extensions import ECHConfig
from simple_tls.tls.handshake import TLSHandshake, TrafficContext
from simple_tls.tls.handshake_client import (
    NewSessionCallback,
    TLSHandshakeClient,
)
from simple_tls.tls.handshake_server import (
    ClientHelloCallback,
    TLSHandshakeServer,
)
from simple_tls.tls.messages import HandshakeMessage
from simple_tls.tls.utils import (
    Buffer,
    WritableBuffer,
    get_algorithm,
    hkdf_expand_label,
    version_to_wire,
)

MessageCallback = Callable[["TLSConnection", Direction, int, int, bytes], None]


HEADER_LENGTH = 5
MAX_PLAINTEXT_LENGTH = 2**14
MAX_WARNING_ALERTS = 5


class SkipDataException(Exception):
    pass


@dataclass(slots=True)
class ConnectionState:
    epoch: Epoch
    cipher: TLSCipher | None = None
    record_splitting: bool = False
    hide_content_type: bool = False
    sequence_number: int = 0


class TLSConnection:
    def __init__(
        self,
        *,
        configuration: TLSConfiguration,
        message_callback: MessageCallback | None = None,
        new_session_callback: NewSessionCallback | None = None,
        client_hello_callback: ClientHelloCallback | None = None,
    ) -> None:
        handshake: TLSHandshake
        if not configuration.is_server:
            handshake = TLSHandshakeClient(
                configuration=configuration,
                new_session_callback=new_session_callback,
            )
        else:
            handshake = TLSHandshakeServer(
                configuration=configuration,
                client_hello_callback=client_hello_callback,
            )
        handshake.message_cb = self._do_hs_callback
        handshake.setup_traffic_cb = self._setup_traffic

        self._handshake: TLSHandshake = handshake
        self._handshake_status: Status = Status.OK
        self._message_callback = message_callback

        self._send_record_limit: int = MAX_PLAINTEXT_LENGTH
        self._recv_record_limit: int = MAX_PLAINTEXT_LENGTH
        self._write_shutdown: Shutdown = Shutdown.NONE
        self._read_shutdown: Shutdown = Shutdown.NONE
        self._write_state: ConnectionState = ConnectionState(Epoch.INITIAL)
        self._read_state: ConnectionState = ConnectionState(Epoch.INITIAL)
        self._early_data_ignored: int = 0
        self._early_data_processed: int = 0
        self._warning_alert_received: int = 0
        self._header: tuple[int, int, int] | None = None
        self._header_data: bytearray | None = None
        self._pending_flight: bytearray = bytearray()

        self._in_buf_offset: int = 0
        self._pending_app_buf_offset: int = 0
        self._pending_app_buf_length: int = 0
        self._in_buf: bytearray = bytearray()
        self._out_buf: bytearray = bytearray()
        self._pending_app_buf: memoryview = memoryview(
            bytearray(MAX_PLAINTEXT_LENGTH + 2048)
        )
        self._open_buf: memoryview = memoryview(
            bytearray(MAX_PLAINTEXT_LENGTH + 2048)
        )
        self._seal_buf: memoryview = memoryview(
            bytearray(MAX_PLAINTEXT_LENGTH + 2 * (HEADER_LENGTH + 2048))
        )
        self._seal_single_buf: memoryview = memoryview(
            bytearray(MAX_PLAINTEXT_LENGTH + 2048)
        )

    @property
    def handshake_complete(self) -> bool:
        return self._handshake.session_established

    @property
    def server_name(self) -> bytes | None:
        return self._handshake.server_name

    @property
    def public_server_name(self) -> bytes | None:
        return self._handshake.public_server_name

    @property
    def ech_server_name(self) -> bytes | None:
        return self._handshake.ech_server_name

    @property
    def session_reused(self) -> bool:
        return self._handshake.session_reused

    @property
    def early_data_status(self) -> EarlyDataStatus:
        return self._handshake.early_data_status

    @property
    def ech_status(self) -> ECHStatus:
        return self._handshake.ech_status

    def bio_write(self, data: Buffer) -> None:
        """
        Data from the network
        """
        buf = self._in_buf
        offset = self._in_buf_offset
        buf_len = len(buf)

        if offset > 0:
            if offset == buf_len:
                buf.clear()
                self._in_buf_offset = 0
            elif offset >= buf_len // 2:
                del buf[:offset]
                self._in_buf_offset = 0

        buf.extend(data)

    def bio_read(self, length: int = -1) -> bytes:
        """
        Return data to send
        """
        if length == 0:
            return b""

        buf = self._out_buf

        if not buf:
            raise TLSWantReadError()
        if length < 0 or length >= len(buf):
            data = bytes(buf)
            buf.clear()
        else:
            data = bytes(buf[:length])
            del buf[:length]

        return data

    @overload
    def read(self, length: int = ..., buffer: None = ...) -> bytes: ...

    @overload
    def read(self, length: int = ..., buffer: WritableBuffer = ...) -> int: ...

    def read(
        self,
        length: int = -1,
        buffer: WritableBuffer | None = None,
    ) -> int | bytes:
        hs = self._handshake
        app_data = None
        app_data_len = 0

        while app_data is None:
            pending = self._pending_app_buf
            pending_offset = self._pending_app_buf_offset
            pending_length = self._pending_app_buf_length
            pending_remaining = pending_length - pending_offset

            if pending_remaining > 0:
                if length < 0 or length > pending_remaining:
                    app_data_len = pending_remaining
                else:
                    app_data_len = length

                if buffer is not None and len(buffer) < app_data_len:
                    raise ValueError("buffer too small")

                app_data = pending[
                    pending_offset : pending_offset + app_data_len
                ]
                self._pending_app_buf_offset += app_data_len
                break

            if not (hs.done or hs.can_early_read):
                self.do_handshake()

            content_type, data = self._open_record()

            if content_type != ContentType.APPLICATION_DATA:
                if content_type != ContentType.HANDSHAKE:
                    self._send_alert(
                        AlertDescription.UNEXPECTED_MESSAGE,
                        f"received unexpected record with content type "
                        f"'0x{content_type:02X}'",
                    )

                hs.feed_data(data)
                if not hs.done:
                    assert hs.can_early_read
                    hs.close_early_data()
                else:
                    hs.trigger_post_handshake()
                continue

            if hs.is_server and hs.can_early_read:
                self._early_data_processed += len(data)
                if self._early_data_processed > hs.max_early_data:
                    self._send_alert(
                        AlertDescription.UNEXPECTED_MESSAGE,
                        "received too much early data",
                    )

            buffer_too_small = buffer is not None and len(buffer) < len(data)
            if 0 <= length <= len(data) or buffer_too_small:
                assert pending_remaining == 0
                pending[0 : len(data)] = data
                self._pending_app_buf_offset = 0
                self._pending_app_buf_length = len(data)
            else:
                app_data = data
                app_data_len = len(data)

        if buffer is not None:
            assert len(buffer) >= app_data_len
            buffer[0:app_data_len] = app_data
            return app_data_len

        return app_data.tobytes()

    def write(self, data: Buffer) -> int:
        hs = self._handshake

        if not (hs.done or hs.can_early_write):
            self.do_handshake()

        if self._write_shutdown != Shutdown.NONE:
            raise TLSEOFError("protocol is shutdown")

        fragment_len = self._send_record_limit
        is_early_data_write = not hs.is_server and hs.can_early_write

        if is_early_data_write:
            fragment_len = min(
                fragment_len, hs.max_early_data - self._early_data_processed
            )

        if len(data) > fragment_len:
            data = data[:fragment_len]

        self._write(ContentType.APPLICATION_DATA, data)

        if is_early_data_write:
            self._early_data_processed += len(data)
            if self._early_data_processed >= hs.max_early_data:
                hs.close_early_data()

        return len(data)

    def pending(self) -> int:
        assert self._pending_app_buf_offset <= self._pending_app_buf_length
        return self._pending_app_buf_length - self._pending_app_buf_offset

    def do_handshake(self) -> None:
        while True:
            if self._handshake_status == Status.PACK_FLIGHT:
                self._pack_handshake()
            elif self._handshake_status == Status.FLUSH_HANDSHAKE:
                self._flush_handshake()
            elif self._handshake_status == Status.READ_HANDSHAKE:
                self._read_handshake()
            elif self._handshake_status == Status.READ_CHANGE_CIPHER_SPEC:
                self._read_ccs()
            elif self._handshake_status == Status.WRITE_CHANGE_CIPHER_SPEC:
                self._write_ccs()
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
                self._send_alert(exc.description, exc.message, exc.fatal)

            if self._handshake_status == Status.OK:
                assert self._handshake.done
                if isinstance(self._handshake, TLSHandshakeClient):
                    assert self._handshake.ech_status != ECHStatus.REJECTED
                break

    def shutdown(self) -> None:
        if self._write_shutdown == Shutdown.NONE:
            self._send_alert(AlertDescription.CLOSE_NOTIFY, fatal=False)
            self._write_shutdown = Shutdown.CLOSE_NOTIFY

    def update_key(self, request_receiver_update: bool = False) -> None:
        if request_receiver_update:
            message_type = KeyUpdateMessageType.UPDATE_REQUESTED
        else:
            message_type = KeyUpdateMessageType.UPDATE_NOT_REQUESTED

        self._handshake.send_key_update(message_type)

    def get_protocol_version(self) -> TLSVersion | None:
        if self._has_final_version():
            protocol = self._handshake.configuration.protocol
            version = self._handshake.protocol_version()
            wire_version = version_to_wire(protocol, version)
            return TLSVersion(wire_version)
        return None

    def get_peer_ciphers(self) -> list[CipherSuite] | None:
        if self._handshake.peer_cipher_suites is not None:
            out: list[CipherSuite] = []
            for cipher_suite in self._handshake.peer_cipher_suites:
                try:
                    out.append(CipherSuite(cipher_suite))
                except ValueError:
                    continue
            return out
        return None

    def get_peer_application_settings(self) -> bytes | None:
        return self._handshake.peer_application_settings

    def get_peer_ech_retry_configs(self) -> list[ECHConfig] | None:
        ech_retry_configs = self._handshake.peer_ech_retry_configs
        if ech_retry_configs is not None:
            return list(ech_retry_configs)
        return None

    def get_peer_certificate(self) -> x509.Certificate | None:
        return self._handshake.peer_certificate

    def get_peer_cert_chain(self) -> list[x509.Certificate]:
        return self._handshake.get_peer_cert_chain()

    def get_verified_chain(self) -> list[x509.Certificate]:
        return self._handshake.get_verified_chain()

    def get_npn_negotiated(self) -> bytes | None:
        return self._handshake.npn_protocol

    def get_alpn_negotiated(self) -> bytes | None:
        return self._handshake.alpn_protocol

    def get_cipher_negotitated(self) -> CipherSuite | None:
        return self._handshake.cipher_suite

    # Callbacks

    def _do_hs_callback(
        self,
        direction: Direction,
        message: HandshakeMessage,
    ) -> None:
        if self._message_callback is None:
            return
        version = self._handshake.version
        content_type = ContentType.HANDSHAKE
        data = message.to_bytes()
        self._message_callback(self, direction, version, content_type, data)

    # Record layer

    def _setup_traffic(
        self,
        direction: Direction,
        epoch: Epoch,
        context: TrafficContext | None,
    ) -> None:
        state = ConnectionState(epoch)

        if context is not None:
            version = context.version
            cipher_suite = context.cipher_suite

            if version >= TLSVersion.TLSv1_3:
                assert context.secret is not None

                algorithm = get_algorithm(cipher_suite.prf_hash)
                key_len, iv_len = get_key_iv_lens(cipher_suite)
                enc_key = hkdf_expand_label(
                    context.secret, b"key", b"", key_len, algorithm
                )
                fixed_iv = hkdf_expand_label(
                    context.secret, b"iv", b"", iv_len, algorithm
                )
                mac_key = b""
            else:
                assert context.enc_key is not None
                assert context.mac_key is not None
                assert context.fixed_iv is not None

                enc_key = context.enc_key
                fixed_iv = context.fixed_iv
                mac_key = context.mac_key

            state.cipher = TLSCipher(
                direction=direction,
                version=version,
                cipher_suite=cipher_suite,
                enc_key=enc_key,
                fixed_iv=fixed_iv,
                mac_key=mac_key,
                encrypt_then_mac=context.encrypt_then_mac,
            )

            if (
                context.version < TLSVersion.TLSv1_1
                and state.cipher.is_block_cipher()
            ):
                state.record_splitting = True

            if context.version >= TLSVersion.TLSv1_3:
                state.hide_content_type = True

        if direction == Direction.WRITE:
            assert len(self._handshake.pending_flight()) == 0
            self._write_state = state
        else:
            self._read_state = state

    def _write_ccs(self) -> None:
        header = self._get_header(
            content_type=ContentType.CHANGE_CIPHER_SPEC,
            record_version=self._record_version(),
            length=1,
        )
        self._pending_flight.extend(header)
        self._pending_flight.extend(b"\x01")

    def _read_ccs(self) -> None:
        content_type, data = self._open_record()
        if content_type != ContentType.CHANGE_CIPHER_SPEC:
            self._send_alert(
                AlertDescription.UNEXPECTED_MESSAGE,
                f"received unexpected record with content type "
                f"'0x{content_type:02X}'",
            )
        self._verify_ccs(data)
        self._current_read_epoch = Epoch.APPLICATION_DATA

    def _read_handshake(self) -> None:
        content_type, data = self._open_record()
        if content_type != ContentType.HANDSHAKE:
            self._send_alert(
                AlertDescription.UNEXPECTED_MESSAGE,
                f"received unexpected record with content type "
                f"'0x{content_type:02X}'",
            )
        self._handshake.feed_data(data)

    def _pack_handshake(self) -> None:
        pending_flight = self._handshake.pending_flight()
        if not pending_flight:
            return

        fragment_len = self._send_record_limit - 1
        content_type = ContentType.HANDSHAKE

        with memoryview(b"".join(pending_flight)) as view:
            for i in range(0, len(view), fragment_len):
                record_data = self._seal_record(
                    content_type, view[i : i + fragment_len]
                )
                self._pending_flight.extend(record_data)

        self._handshake.clear_flight()

    def _flush_handshake(self) -> None:
        self._pack_handshake()

        if not self._pending_flight:
            return
        if self._write_shutdown != Shutdown.NONE:
            return

        self._out_buf.extend(self._pending_flight)
        self._pending_flight.clear()

    def _write(self, content_type: int, data: Buffer) -> None:
        self._flush_handshake()

        if not data:
            return

        record_data = self._seal_record(content_type, data)
        self._out_buf.extend(record_data)

    def _seal_record(self, content_type: int, plaintext: Buffer) -> memoryview:
        state = self._write_state
        out_buf = self._seal_buf
        dest_view = out_buf  # Represents the remaining writable window/view
        total_written = 0

        if (
            state.record_splitting
            and content_type == ContentType.APPLICATION_DATA
            and len(plaintext) > 1
        ):
            written = self._seal_single(content_type, plaintext[:1], dest_view)
            plaintext = plaintext[1:]
            dest_view = dest_view[written:]
            total_written = written

        total_written += self._seal_single(content_type, plaintext, dest_view)
        return out_buf[:total_written]

    def _seal_single(
        self,
        content_type: int,
        plaintext: Buffer,
        out_buf: memoryview,
    ) -> int:
        assert len(plaintext) <= self._send_record_limit

        state = self._write_state
        out_data_buf = out_buf[HEADER_LENGTH:]

        if state.hide_content_type:
            pt_len = len(plaintext)
            temp_view = self._seal_single_buf[0 : pt_len + 1]
            temp_view[0:pt_len] = plaintext
            temp_view[pt_len] = content_type
            plaintext = temp_view
            content_type = ContentType.APPLICATION_DATA

        record_version = self._record_version()

        if state.cipher is not None:
            exp_ct_len = state.cipher.ciphertext_length(len(plaintext))
            header = self._get_header(content_type, record_version, exp_ct_len)
            ct_len = state.cipher.seal(
                content_type,
                record_version,
                plaintext,
                state.sequence_number,
                header,
                out_data_buf,
            )
            assert ct_len == exp_ct_len
            state.sequence_number += 1
        else:
            ct_len = len(plaintext)
            out_data_buf[0:ct_len] = plaintext
            header = self._get_header(content_type, record_version, ct_len)

        out_buf[0:HEADER_LENGTH] = header
        out_len = HEADER_LENGTH + ct_len

        return out_len

    def _open_record(self) -> tuple[int, memoryview]:
        while True:
            try:
                return self._open_record_internal()
            except SkipDataException:
                pass

    def _open_record_internal(self) -> tuple[int, memoryview]:
        if self._read_shutdown != Shutdown.NONE:
            raise TLSEOFError("protocol is shutdown")

        state = self._read_state
        in_buf = self._in_buf
        in_buf_offset = self._in_buf_offset
        out_buf = self._open_buf

        # Parse header: ContentType (1), Version (2), Length (2)
        if self._header is None:
            if len(in_buf) - in_buf_offset < HEADER_LENGTH:
                raise TLSWantReadError()

            header_data = in_buf[in_buf_offset : in_buf_offset + HEADER_LENGTH]
            in_buf_offset += HEADER_LENGTH
            header = struct.unpack("!BHH", header_data)
            content_type, record_version, length = header

            if state.cipher is None:
                version_ok = record_version >> 8 == 0x03
            else:
                version_ok = record_version == self._record_version()

            if not version_ok:
                self._send_alert(
                    AlertDescription.PROTOCOL_VERSION,
                    "received record with wrong version number",
                )
            if length > self._recv_record_limit + 2048:
                self._send_alert(
                    AlertDescription.RECORD_OVERFLOW,
                    "received record too large",
                )

            self._header = header
            self._header_data = header_data
            self._in_buf_offset = in_buf_offset
        else:
            assert self._header_data is not None
            content_type, record_version, length = self._header
            header_data = self._header_data

        if len(in_buf) - in_buf_offset < length:
            raise TLSWantReadError()

        ciphertext = in_buf[in_buf_offset : in_buf_offset + length]
        in_buf_offset += length

        self._header = None
        self._header_data = None
        self._in_buf_offset = in_buf_offset

        if (
            content_type == ContentType.CHANGE_CIPHER_SPEC
            and self._has_final_version()
            and self._handshake.protocol_version() >= TLSVersion.TLSv1_3
        ):
            self._verify_ccs(ciphertext)

            if self._handshake.session_established:
                self._send_alert(
                    AlertDescription.UNEXPECTED_MESSAGE,
                    "received unexpected change cipher spec message",
                )
            raise SkipDataException()

        if (
            self._handshake.skip_early_data
            and state.cipher is None
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

        if state.cipher is not None:
            try:
                pt_len = state.cipher.open(
                    content_type,
                    record_version,
                    ciphertext,
                    state.sequence_number,
                    header_data,
                    out_buf,
                )
            except InvalidTag:
                if self._handshake.skip_early_data:
                    self._skip_early_data(len(ciphertext))
                    raise SkipDataException() from None

                self._send_alert(
                    AlertDescription.BAD_RECORD_MAC,
                    "record payload decryption failed",
                )
            else:
                state.sequence_number += 1
        else:
            pt_len = len(ciphertext)
            out_buf[0:pt_len] = ciphertext

        if self._handshake.skip_early_data:
            self._handshake.close_early_data()

        if state.hide_content_type:
            if content_type != ContentType.APPLICATION_DATA:
                self._send_alert(
                    AlertDescription.ILLEGAL_PARAMETER,
                    "received record with outer content type is not "
                    "application data in TLSv1.3",
                )
            pt_limit = self._recv_record_limit + 1
        else:
            pt_limit = self._recv_record_limit

        # RFC 5246 section 6.2.1
        # RFC 8446 section 5.4
        if pt_len > pt_limit:
            self._send_alert(
                AlertDescription.RECORD_OVERFLOW,
                "received record too large",
            )

        if state.hide_content_type:
            content_type, pt_len = self._unpad_data_tlsv1_3(out_buf[:pt_len])

        # RFC 8446 Section 5.1
        # Implementations MUST NOT send zero-length fragments of Handshake
        # types, even if those fragments contain padding.
        # RFC 5246 Section 6.2.1
        # Implementations MUST NOT send zero-length fragments of content
        # types other than Application Data.
        if content_type != ContentType.APPLICATION_DATA and pt_len == 0:
            self._send_alert(
                AlertDescription.UNEXPECTED_MESSAGE,
                "received record with empty message",
            )

        if content_type == ContentType.ALERT:
            self._process_alert(out_buf[:pt_len])

        # RFC 8446 Section 5.1
        # TLS 1.3 Handshake messages MUST NOT be interleaved with other
        # messages
        if (
            content_type != ContentType.HANDSHAKE
            and self._handshake.has_unprocessed_data()
            and self._has_final_version()
            and self._handshake.protocol_version() >= TLSVersion.TLSv1_3
        ):
            self._send_alert(
                AlertDescription.UNEXPECTED_MESSAGE,
                "handshake messages interleaved with other record types",
            )

        return content_type, out_buf[:pt_len]

    def _skip_early_data(self, ciphertext_length: int) -> None:
        self._early_data_ignored += ciphertext_length
        if self._early_data_ignored > self._recv_record_limit:
            self._send_alert(
                AlertDescription.UNEXPECTED_MESSAGE,
                "received too many early data",
            )

    def _record_version(self) -> int:
        if self._handshake.version == UNSPECIFIED:
            return TLSVersion.TLSv1
        return min(TLSVersion.TLSv1_2, self._handshake.version)

    def _has_final_version(self) -> bool:
        if self._handshake.version == UNSPECIFIED:
            return False
        if self._handshake.is_early_version:
            return False
        return True

    def _unpad_data_tlsv1_3(self, data: Buffer) -> tuple[int, int]:
        for pos in range(len(data) - 1, -1, -1):
            value = data[pos]
            if value != 0:
                break
        else:
            self._send_alert(
                AlertDescription.UNEXPECTED_MESSAGE,
                "received record with missing content type",
            )
        return value, pos

    @overload
    def _send_alert(
        self,
        description: int,
        reason: Any | None = ...,
        fatal: Literal[True] = ...,
    ) -> NoReturn: ...

    @overload
    def _send_alert(
        self,
        description: int,
        reason: Any | None = ...,
        fatal: Literal[False] = ...,
    ) -> None: ...

    @overload
    def _send_alert(
        self,
        description: int,
        reason: Any | None = ...,
        fatal: bool = ...,
    ) -> None: ...

    def _send_alert(
        self,
        description: int,
        reason: Any | None = None,
        fatal: bool = True,
    ) -> None:
        if self._write_shutdown == Shutdown.NONE:
            if not fatal:
                self._write(
                    ContentType.ALERT,
                    bytes([AlertLevel.WARNING]) + bytes([description]),
                )
            else:
                self._write(
                    ContentType.ALERT,
                    bytes([AlertLevel.FATAL]) + bytes([description]),
                )
                self._write_shutdown = Shutdown.ERROR

        if fatal:
            raise TLSLocalAlert(description, reason)

    def _process_alert(self, data: Buffer) -> NoReturn:
        if len(data) != 2:
            self._send_alert(
                AlertDescription.DECODE_ERROR,
                "received invalid alert message",
            )

        level = data[0]
        description = data[1]

        if level == AlertLevel.WARNING:
            if description == AlertDescription.CLOSE_NOTIFY:
                self._read_shutdown = Shutdown.CLOSE_NOTIFY
                raise TLSEOFError()

            if (
                self._has_final_version()
                and self._handshake.protocol_version() >= TLSVersion.TLSv1_3
                and description != AlertDescription.USER_CANCELLED
            ):
                self._send_alert(
                    AlertDescription.DECODE_ERROR,
                    "received unexpected warning alert in TLSv1.3",
                )

            self._warning_alert_received += 1

            if self._warning_alert_received > MAX_WARNING_ALERTS:
                self._send_alert(
                    AlertDescription.UNEXPECTED_MESSAGE,
                    "received too many warning alerts",
                )

            raise SkipDataException()

        if level == AlertLevel.FATAL:
            self._read_shutdown = Shutdown.ERROR
            raise TLSRemoteAlert(description)

        self._send_alert(
            AlertDescription.UNEXPECTED_MESSAGE,
            "received unknown alert type",
        )

    def _verify_ccs(self, data: Buffer) -> None:
        if len(data) != 1:
            self._send_alert(
                AlertDescription.DECODE_ERROR,
                "received malformed CCS message type",
            )

        # RFC 8446 section 5
        if data != b"\x01":
            self._send_alert(
                AlertDescription.UNEXPECTED_MESSAGE,
                "received invalid CCS message",
            )

    @staticmethod
    def _get_header(
        content_type: int,
        record_version: int,
        length: int,
    ) -> bytes:
        return struct.pack("!BHH", content_type, record_version, length)
