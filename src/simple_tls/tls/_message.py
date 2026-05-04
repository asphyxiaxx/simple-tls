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

import typing
from dataclasses import dataclass, field

from ..utils.codec import ParseError, Parser, Writer
from ..utils.compression import ZLIB, ZSTD, Brotli
from ..utils.math import int_to_bytes
from ._alert import AlertUnexpectedMessage
from ._constant import (
    AlertDescription,
    AlertLevel,
    CertificateCompressionAlgorithm,
    CertificateStatusType,
    ContentType,
    HandshakeType,
)
from ._extension import (
    ExtensionsMessage,
    OptionalExtensionsMessage,
    SignatureAlgorithmsExtension,
)

_M = typing.TypeVar("_M", bound="Message")
_HM = typing.TypeVar("_HM", bound="HandshakeMessage")


class Message:
    content_type: typing.ClassVar[int]

    def __init__(self) -> None:
        raise NotImplementedError

    @classmethod
    def from_bytes(cls: type[_M], data: bytes) -> _M:
        raise NotImplementedError

    def serialize(self) -> bytes:
        raise NotImplementedError


@dataclass(repr=False)
class Alert(Message):
    content_type: typing.ClassVar[int] = ContentType.ALERT
    description: int
    level: int = AlertLevel.FATAL

    @classmethod
    def from_bytes(cls, data: bytes) -> Alert:
        if not len(data) == 2:
            raise ParseError("invalid structure")

        level = data[0]
        description = data[1]
        return Alert(description, level)

    def serialize(self) -> bytes:
        writer = Writer()
        writer.write_int(self.level, 1)
        writer.write_int(self.description, 1)
        return writer.tobytes()

    def __repr__(self) -> str:
        level: int | AlertLevel
        description: int | AlertDescription
        try:
            level = AlertLevel(self.level)
        except ValueError:
            level = self.level
        try:
            description = AlertDescription(self.description)
        except ValueError:
            description = self.description
        return f"<Alert(level={level}, description={description})>"


@dataclass
class ApplicationData(Message):
    content_type: typing.ClassVar[int] = ContentType.APPLICATION_DATA
    data: bytes = b""

    @classmethod
    def from_bytes(cls, data: bytes) -> ApplicationData:
        return ApplicationData(data)

    def serialize(self) -> bytes:
        return self.data


@dataclass
class ChangeCipherSpec(Message):
    content_type: typing.ClassVar[int] = ContentType.CHANGE_CIPHER_SPEC
    type: int = 1

    @classmethod
    def from_bytes(cls, data: bytes) -> ChangeCipherSpec:
        if len(data) != 1:
            raise ParseError("invalid payload")
        return ChangeCipherSpec(type=data[0])

    def serialize(self) -> bytes:
        return int_to_bytes(self.type, 1)


@dataclass
class Handshake(Message):
    content_type: typing.ClassVar[ContentType] = ContentType.HANDSHAKE
    handshake_type: int
    data: bytes

    _cache: typing.Any = field(
        default=None, init=False, repr=False, compare=False
    )

    @classmethod
    def from_bytes(cls, data: bytes) -> Handshake:
        parser = Parser(data)
        handshake_type = parser.read_int(1)
        data = parser.read_prefixed_bytes(3)

        if parser.remaining():
            raise ParseError("trailing data")

        return Handshake(handshake_type, data)

    def serialize(self) -> bytes:
        writer = Writer()
        writer.write_int(self.handshake_type, 1)
        writer.write_prefixed_bytes(self.data, 3)
        return writer.tobytes()

    def get_handshake(self, handshake_cls: type[_HM]) -> _HM:
        if handshake_cls.handshake_type != self.handshake_type:
            raise AlertUnexpectedMessage(
                f"Unexpected message '{self.handshake_type}' "
                f"(expected {handshake_cls.handshake_type})"
            )

        if self._cache is None or type(self._cache) is not handshake_cls:
            self._cache = handshake_cls.from_bytes(self.data)

        return typing.cast(_HM, self._cache)


class HandshakeMessage:
    handshake_type: typing.ClassVar[int]

    @classmethod
    def from_bytes(cls: type[_HM], data: bytes) -> _HM:
        raise NotImplementedError

    def serialize(self) -> bytes:
        raise NotImplementedError


@dataclass
class ClientHello(HandshakeMessage, OptionalExtensionsMessage):
    handshake_type: typing.ClassVar[int] = HandshakeType.CLIENT_HELLO
    version: int
    random: bytes
    session_id: bytes
    cipher_suites: typing.Sequence[int]
    compression_methods: typing.Sequence[int]
    extensions: list[tuple[int, bytes]] = field(default_factory=list)

    @classmethod
    def from_bytes(cls, data: bytes) -> ClientHello:
        parser = Parser(data)
        version = parser.read_int(2)
        random = parser.read_bytes(32)
        session_id = parser.read_prefixed_bytes(1)
        if len(session_id) > 32:
            raise ParseError("session_id not within 32 bytes")

        cipher_suites = parser.read_prefixed_int_list(2, 2)
        compression_methods = parser.read_prefixed_int_list(1, 1)
        extensions = cls._parse_exts(parser)

        return ClientHello(
            version=version,
            random=random,
            session_id=session_id,
            cipher_suites=cipher_suites,
            compression_methods=compression_methods,
            extensions=extensions,
        )

    def serialize(self) -> bytes:
        if len(self.session_id) > 32:
            raise ValueError("session_id not within 32 bytes")

        writer = Writer()
        writer.write_int(self.version, 2)
        writer.write_bytes(self.random)
        writer.write_prefixed_bytes(self.session_id, 1)
        writer.write_prefixed_int_list(self.cipher_suites, 2, 2)
        writer.write_prefixed_int_list(self.compression_methods, 1, 1)
        self._write_exts(writer)
        return writer.tobytes()


@dataclass
class HelloRequest(HandshakeMessage):
    handshake_type: typing.ClassVar[int] = HandshakeType.HELLO_REQUEST

    @classmethod
    def from_bytes(cls, data: bytes) -> HelloRequest:
        if data:
            raise ParseError("trailing data")
        return HelloRequest()

    def serialize(self) -> bytes:
        return b""


@dataclass
class ServerHello(HandshakeMessage, OptionalExtensionsMessage):
    handshake_type: typing.ClassVar[int] = HandshakeType.SERVER_HELLO
    version: int
    random: bytes
    session_id: bytes
    cipher_suite: int
    compression_method: int
    extensions: list[tuple[int, bytes]] = field(default_factory=list)

    @classmethod
    def from_bytes(cls, data: bytes) -> ServerHello:
        parser = Parser(data)
        version = parser.read_int(2)
        random = parser.read_bytes(32)
        session_id = parser.read_prefixed_bytes(1)
        if len(session_id) > 32:
            raise ParseError("session_id not within 32 bytes")

        cipher_suite = parser.read_int(2)
        compression_method = parser.read_int(1)
        extensions = cls._parse_exts(parser)

        return ServerHello(
            version=version,
            random=random,
            session_id=session_id,
            cipher_suite=cipher_suite,
            compression_method=compression_method,
            extensions=extensions,
        )

    def serialize(self) -> bytes:
        if len(self.session_id) > 32:
            raise ValueError("session_id not within 32 bytes")

        writer = Writer()
        writer.write_int(self.version, 2)
        writer.write_bytes(self.random)
        writer.write_prefixed_bytes(self.session_id, 1)
        writer.write_int(self.cipher_suite, 2)
        writer.write_int(self.compression_method, 1)
        self._write_exts(writer)
        return writer.tobytes()


@dataclass
class ClientKeyExchange(HandshakeMessage):
    handshake_type: typing.ClassVar[int] = HandshakeType.CLIENT_KEY_EXCHANGE
    data: bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> ClientKeyExchange:
        return ClientKeyExchange(data)

    def serialize(self) -> bytes:
        return self.data


@dataclass
class ServerKeyExchange(HandshakeMessage):
    handshake_type: typing.ClassVar[int] = HandshakeType.SERVER_KEY_EXCHANGE
    data: bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> ServerKeyExchange:
        return ServerKeyExchange(data)

    def serialize(self) -> bytes:
        return self.data


@dataclass
class ServerHelloDone(HandshakeMessage):
    handshake_type: typing.ClassVar[int] = HandshakeType.SERVER_HELLO_DONE

    @classmethod
    def from_bytes(cls, data: bytes) -> ServerHelloDone:
        if data:
            raise ParseError("Trailing Data")
        return ServerHelloDone()

    def serialize(self) -> bytes:
        return b""


@dataclass
class NextProtocol(HandshakeMessage):
    handshake_type: typing.ClassVar[int] = HandshakeType.NEXT_PROTO
    next_protocol: bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> NextProtocol:
        parser = Parser(data)
        next_proto = parser.read_prefixed_bytes(1)
        _ = parser.read_prefixed_bytes(1)  # padding

        if parser.remaining():
            raise ParseError("trailing data")

        return NextProtocol(next_proto)

    def serialize(self) -> bytes:
        writer = Writer()
        writer.write_prefixed_bytes(self.next_protocol, 1)
        padding_len = 32 - ((len(self.next_protocol) + 2) % 32)
        writer.write_prefixed_bytes(bytes(padding_len), 1)
        return writer.tobytes()


@dataclass
class EncryptedExtensions(HandshakeMessage, ExtensionsMessage):
    handshake_type: typing.ClassVar[int] = HandshakeType.ENCRYPTED_EXTENSIONS
    extensions: list[tuple[int, bytes]] = field(default_factory=list)

    @classmethod
    def from_bytes(cls, data: bytes) -> EncryptedExtensions:
        parser = Parser(data)
        extensions = cls._parse_exts(parser)
        return EncryptedExtensions(extensions)

    def serialize(self) -> bytes:
        writer = Writer()
        self._write_exts(writer)
        return writer.tobytes()


@dataclass
class EndOfEarlyData(HandshakeMessage):
    handshake_type: typing.ClassVar[int] = HandshakeType.END_OF_EARLY_DATA

    @classmethod
    def from_bytes(cls, data: bytes) -> EndOfEarlyData:
        if data:
            raise ParseError("trailing data")
        return EndOfEarlyData()

    def serialize(self) -> bytes:
        return b""


@dataclass
class Finished(HandshakeMessage):
    handshake_type: typing.ClassVar[int] = HandshakeType.FINISHED
    verify_data: bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> Finished:
        return Finished(data)

    def serialize(self) -> bytes:
        return self.verify_data


@dataclass
class NewSessionTicket(HandshakeMessage):
    handshake_type: typing.ClassVar[int] = HandshakeType.NEWSESSION_TICKET
    ticket_lifetime: int
    ticket: bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> NewSessionTicket:
        parser = Parser(data)
        ticket_lifetime = parser.read_int(4)
        ticket = parser.read_prefixed_bytes(2)

        if parser.remaining():
            raise ParseError("trailing data")

        return NewSessionTicket(ticket_lifetime, ticket)

    def serialize(self) -> bytes:
        writter = Writer()
        writter.write_int(self.ticket_lifetime, 4)
        writter.write_prefixed_bytes(self.ticket, 2)
        return writter.tobytes()


@dataclass
class NewSessionTicketTLS13(HandshakeMessage, ExtensionsMessage):
    handshake_type: typing.ClassVar[int] = HandshakeType.NEWSESSION_TICKET
    ticket_lifetime: int
    ticket_age_add: int
    ticket_nonce: bytes
    ticket: bytes
    extensions: list[tuple[int, bytes]] = field(default_factory=list)

    @classmethod
    def from_bytes(cls, data: bytes) -> NewSessionTicketTLS13:
        parser = Parser(data)
        ticket_lifetime = parser.read_int(4)
        ticket_age_add = parser.read_int(4)
        ticket_nonce = parser.read_prefixed_bytes(1)
        ticket = parser.read_prefixed_bytes(2)
        extensions = cls._parse_exts(parser)

        return NewSessionTicketTLS13(
            ticket_lifetime=ticket_lifetime,
            ticket_age_add=ticket_age_add,
            ticket_nonce=ticket_nonce,
            ticket=ticket,
            extensions=extensions,
        )

    def serialize(self) -> bytes:
        writer = Writer()
        writer.write_int(self.ticket_lifetime, 4)
        writer.write_int(self.ticket_age_add, 4)
        writer.write_prefixed_bytes(self.ticket_nonce, 1)
        writer.write_prefixed_bytes(self.ticket, 2)
        self._write_exts(writer)
        return writer.tobytes()


@dataclass
class KeyUpdate(HandshakeMessage):
    handshake_type: typing.ClassVar[int] = HandshakeType.KEY_UPDATE
    message_type: int

    @classmethod
    def from_bytes(cls, data: bytes) -> KeyUpdate:
        if not len(data) == 1:
            raise ParseError("invalid key update message")

        message_type = data[0]
        return KeyUpdate(message_type)

    def serialize(self) -> bytes:
        return int_to_bytes(self.message_type, 1)


# --- Certificate ---
@dataclass(frozen=True)
class CertificateEntry(ExtensionsMessage):
    certificate: bytes
    extensions: list[tuple[int, bytes]] = field(default_factory=list)

    @classmethod
    def parse(cls, parser: Parser[bytes]) -> CertificateEntry:
        certificate = parser.read_prefixed_bytes(3)
        extensions = cls._parse_exts(parser)
        return CertificateEntry(certificate, extensions)

    def write(self, writer: Writer) -> None:
        writer.write_prefixed_bytes(self.certificate, 3)
        self._write_exts(writer)


@dataclass
class CertificateStatus(HandshakeMessage):
    handshake_type: typing.ClassVar[int] = HandshakeType.CERTIFICATE_STATUS
    ocsp: bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> CertificateStatus:
        parser = Parser(data)
        status_type = parser.read_int(1)
        if not status_type == CertificateStatusType.OCSP:
            raise ParseError("unknown status_type")

        ocsp = parser.read_prefixed_bytes(3)

        if parser.remaining():
            raise ParseError("trailing data")

        return CertificateStatus(ocsp)

    def serialize(self) -> bytes:
        writer = Writer()
        writer.write_int(CertificateStatusType.OCSP, 1)
        writer.write_prefixed_bytes(self.ocsp, 3)
        return writer.tobytes()


@dataclass
class Certificate(HandshakeMessage):
    handshake_type: typing.ClassVar[int] = HandshakeType.CERTIFICATE
    certificates: typing.Sequence[bytes]

    @classmethod
    def from_bytes(cls, data: bytes) -> Certificate:
        parser = Parser(data)
        certificates: list[bytes] = []

        with parser.assert_length(3) as end:
            while parser.tell() < end:
                certificate = parser.read_prefixed_bytes(3)
                if not certificate:
                    raise ParseError("empty payload in certificate list")
                certificates.append(certificate)

        if parser.remaining():
            raise ParseError("trailing data")

        return Certificate(certificates)

    def serialize(self) -> bytes:
        cert_writer = Writer()
        for certificate in self.certificates:
            if not certificate:
                raise ParseError("empty payload in certificate list")
            cert_writer.write_prefixed_bytes(certificate, 3)

        writer = Writer()
        writer.write_prefixed_bytes(cert_writer, 3)
        return writer.tobytes()


@dataclass
class CertificateTLS13(HandshakeMessage):
    handshake_type: typing.ClassVar[int] = HandshakeType.CERTIFICATE
    context: bytes
    certificate_entries: typing.Sequence[CertificateEntry]

    @classmethod
    def from_bytes(cls, data: bytes) -> CertificateTLS13:
        parser = Parser(data)
        context = parser.read_prefixed_bytes(1)
        certificates: list[CertificateEntry] = []

        with parser.assert_length(3) as end:
            while parser.tell() < end:
                cert_entry = CertificateEntry.parse(parser)
                certificates.append(cert_entry)

        if parser.remaining():
            raise ParseError("trailing data")

        return CertificateTLS13(context, certificates)

    def serialize(self) -> bytes:
        cert_writer = Writer()
        for cert_entry in self.certificate_entries:
            cert_entry.write(cert_writer)

        writer = Writer()
        writer.write_prefixed_bytes(self.context, 1)
        writer.write_prefixed_bytes(cert_writer, 3)
        return writer.tobytes()


@dataclass
class CompressedCertificate(HandshakeMessage):
    handshake_type: typing.ClassVar[int] = HandshakeType.COMPRESSED_CERTIFICATE
    compression: int
    """compression algorihtm"""
    length: int
    """expected length after decompress"""
    compressed_data: bytes
    """compressed certificate bytes"""

    @classmethod
    def from_bytes(cls, data: bytes) -> CompressedCertificate:
        parser = Parser(data)
        compression = parser.read_int(2)
        length = parser.read_int(3)
        compressed_data = parser.read_prefixed_bytes(3)

        if not compressed_data:
            raise ParseError("empty payload in compressed certificate")
        if parser.remaining():
            raise ParseError("trailing data")

        return CompressedCertificate(compression, length, compressed_data)

    def serialize(self) -> bytes:
        writer = Writer()
        writer.write_int(self.compression, 2)
        writer.write_int(self.length, 3)
        writer.write_prefixed_bytes(self.compressed_data, 3)
        return writer.tobytes()

    @classmethod
    def from_certificate(
        cls,
        compression: int,
        certificate: CertificateTLS13,
    ) -> CompressedCertificate:
        data = certificate.serialize()

        if compression == CertificateCompressionAlgorithm.ZLIB:
            compressed_data = ZLIB.compress(data)
        elif compression == CertificateCompressionAlgorithm.BROTLI:
            compressed_data = Brotli.compress(data)
        elif compression == CertificateCompressionAlgorithm.ZSTD:
            compressed_data = ZSTD.compress(data)
        else:
            raise ValueError("invalid compression method")

        return CompressedCertificate(
            compression=compression,
            length=len(data),
            compressed_data=compressed_data,
        )

    def to_certificate(self) -> CertificateTLS13:
        compression = self.compression
        compress_data = self.compressed_data
        expected_len = self.length

        if compression == CertificateCompressionAlgorithm.ZLIB:
            cert_bytes = ZLIB.decompress(compress_data, expected_len)
        elif compression == CertificateCompressionAlgorithm.BROTLI:
            cert_bytes = Brotli.decompress(compress_data, expected_len)
        elif compression == CertificateCompressionAlgorithm.ZSTD:
            cert_bytes = ZSTD.decompress(compress_data, expected_len)
        else:
            raise ValueError("invalid compression method")

        if len(cert_bytes) != expected_len:
            raise ValueError("length mismatch")

        return CertificateTLS13.from_bytes(cert_bytes)


@dataclass
class CertificateRequest(HandshakeMessage):
    handshake_type: typing.ClassVar[int] = HandshakeType.CERTIFICATE_REQUEST
    certificate_types: typing.Sequence[int]
    certificate_authorities: typing.Sequence[bytes]

    @classmethod
    def from_bytes(cls, data: bytes) -> CertificateRequest:
        parser = Parser(data)
        types = parser.read_prefixed_int_list(1, 1)
        authorities: list[bytes] = []

        with parser.assert_length(2) as end:
            while parser.tell() < end:
                certificate_authority = parser.read_prefixed_bytes(2)
                authorities.append(certificate_authority)

        if parser.remaining():
            raise ParseError("trailing data")

        return CertificateRequest(types, authorities)

    def serialize(self) -> bytes:
        auth_writer = Writer()
        for auth in self.certificate_authorities:
            auth_writer.write_prefixed_bytes(auth, 2)

        writer = Writer()
        writer.write_prefixed_int_list(self.certificate_types, 1, 1)
        writer.write_prefixed_bytes(auth_writer, 2)
        return writer.tobytes()


@dataclass
class CertificateRequestTLS12(HandshakeMessage):
    handshake_type: typing.ClassVar[int] = HandshakeType.CERTIFICATE_REQUEST
    certificate_types: typing.Sequence[int]
    certificate_authorities: typing.Sequence[bytes]
    signature_algorithms: typing.Sequence[int]

    @classmethod
    def from_bytes(cls, data: bytes) -> CertificateRequestTLS12:
        parser = Parser(data)
        cert_types = parser.read_prefixed_int_list(1, 1)
        signature_algorithms = parser.read_prefixed_int_list(2, 2)
        cert_authorities: list[bytes] = []

        with parser.assert_length(2) as end:
            while parser.tell() < end:
                authority = parser.read_prefixed_bytes(2)
                cert_authorities.append(authority)

        if parser.remaining():
            raise ParseError("trailing data")

        return CertificateRequestTLS12(
            certificate_types=cert_types,
            certificate_authorities=cert_authorities,
            signature_algorithms=signature_algorithms,
        )

    def serialize(self) -> bytes:
        auth_writer = Writer()
        for auth in self.certificate_authorities:
            auth_writer.write_prefixed_bytes(auth, 2)

        writer = Writer()
        writer.write_prefixed_int_list(self.certificate_types, 1, 1)
        writer.write_prefixed_int_list(self.signature_algorithms, 2, 2)
        writer.write_prefixed_bytes(auth_writer, 2)
        return writer.tobytes()


@dataclass
class CertificateRequestTLS13(HandshakeMessage, ExtensionsMessage):
    handshake_type: typing.ClassVar[int] = HandshakeType.CERTIFICATE_REQUEST
    context: bytes
    extensions: list[tuple[int, bytes]] = field(default_factory=list)

    @property
    def signature_algorithms(self) -> typing.Sequence[int] | None:
        sigalg_ext = self.get_extension(SignatureAlgorithmsExtension)
        if sigalg_ext is not None:
            return sigalg_ext.data
        return None

    @classmethod
    def from_bytes(cls, data: bytes) -> CertificateRequestTLS13:
        parser = Parser(data)
        context = parser.read_prefixed_bytes(1)
        extensions = cls._parse_exts(parser)

        if parser.remaining():
            raise ParseError("trailing data")

        return CertificateRequestTLS13(context, extensions)

    def serialize(self) -> bytes:
        writer = Writer()
        writer.write_prefixed_bytes(self.context, 1)
        self._write_exts(writer)
        return writer.tobytes()


@dataclass
class CertificateVerify(HandshakeMessage):
    handshake_type: typing.ClassVar[int] = HandshakeType.CERTIFICATE_VERIFY
    signature: bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> CertificateVerify:
        parser = Parser(data)
        signature = parser.read_prefixed_bytes(2)

        if parser.remaining():
            raise ParseError("trailing data")

        return CertificateVerify(signature=signature)

    def serialize(self) -> bytes:
        writer = Writer()
        writer.write_prefixed_bytes(self.signature, 2)
        return writer.tobytes()


@dataclass
class CertificateVerifyTLS12(HandshakeMessage):
    handshake_type: typing.ClassVar[int] = HandshakeType.CERTIFICATE_VERIFY
    signature: bytes
    signature_algorithm: int

    @classmethod
    def from_bytes(cls, data: bytes) -> CertificateVerifyTLS12:
        parser = Parser(data)
        signature_algorithm = parser.read_int(2)
        signature = parser.read_prefixed_bytes(2)

        if parser.remaining():
            raise ParseError("trailing data")

        return CertificateVerifyTLS12(signature, signature_algorithm)

    def serialize(self) -> bytes:
        writer = Writer()
        writer.write_int(self.signature_algorithm, 2)
        writer.write_prefixed_bytes(self.signature, 2)
        return writer.tobytes()
