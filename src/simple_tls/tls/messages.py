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

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import ClassVar, TypeVar

from simple_tls.codec import ParseError, Parser, Writer
from simple_tls.compression import ZLIB, ZSTD, Brotli
from simple_tls.crypto.utils import int_to_bytes
from simple_tls.tls.constants import (
    CertificateCompressionAlgorithm,
    CertificateStatusType,
    HandshakeType,
)
from simple_tls.tls.extensions import Extensions

_M = TypeVar("_M", bound="HandshakeMessage")


class HandshakeMessage:
    handshake_type: ClassVar[int]

    @classmethod
    def from_bytes(cls: type[_M], data: bytes) -> _M:
        raise NotImplementedError

    def serialize(self) -> bytes:
        raise NotImplementedError


@dataclass
class ClientHello(HandshakeMessage):
    handshake_type: ClassVar[int] = HandshakeType.CLIENT_HELLO
    version: int
    random: bytes
    session_id: bytes
    cipher_suites: Sequence[int]
    compression_methods: Sequence[int]
    extensions: Extensions = field(default_factory=Extensions)

    @classmethod
    def from_bytes(cls, data: bytes) -> ClientHello:
        parser = Parser(data)
        version = parser.read_int(2)
        random = parser.read_bytes(32)
        session_id = parser.read_prefixed_bytes(1)
        cipher_suites = parser.read_prefixed_int_list(2, 2)
        compression_methods = parser.read_prefixed_int_list(1, 1)
        if parser.remaining():
            extensions = Extensions.parse(parser)
        else:
            extensions = Extensions()

        if len(session_id) > 32:
            raise ParseError("session_id not within 32 bytes")
        if parser.remaining():
            raise ParseError("trailing data in client hello")

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
        if len(self.extensions) > 0:
            self.extensions.write(writer)

        return writer.tobytes()


@dataclass
class HelloRequest(HandshakeMessage):
    handshake_type: ClassVar[int] = HandshakeType.HELLO_REQUEST

    @classmethod
    def from_bytes(cls, data: bytes) -> HelloRequest:
        if data:
            raise ParseError("trailing data in hello request")
        return HelloRequest()

    def serialize(self) -> bytes:
        return b""


@dataclass
class ServerHello(HandshakeMessage):
    handshake_type: ClassVar[int] = HandshakeType.SERVER_HELLO
    version: int
    random: bytes
    session_id: bytes
    cipher_suite: int
    compression_method: int
    extensions: Extensions = field(default_factory=Extensions)

    @classmethod
    def from_bytes(cls, data: bytes) -> ServerHello:
        parser = Parser(data)
        version = parser.read_int(2)
        random = parser.read_bytes(32)
        session_id = parser.read_prefixed_bytes(1)
        cipher_suite = parser.read_int(2)
        compression_method = parser.read_int(1)
        if parser.remaining():
            extensions = Extensions.parse(parser)
        else:
            extensions = Extensions()

        if len(session_id) > 32:
            raise ParseError("session_id not within 32 bytes")
        if parser.remaining():
            raise ParseError("trailing data in server hello")

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
        if len(self.extensions) > 0:
            self.extensions.write(writer)

        return writer.tobytes()


@dataclass
class ClientKeyExchange(HandshakeMessage):
    handshake_type: ClassVar[int] = HandshakeType.CLIENT_KEY_EXCHANGE
    data: bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> ClientKeyExchange:
        return ClientKeyExchange(data)

    def serialize(self) -> bytes:
        return self.data


@dataclass
class ServerKeyExchange(HandshakeMessage):
    handshake_type: ClassVar[int] = HandshakeType.SERVER_KEY_EXCHANGE
    data: bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> ServerKeyExchange:
        return ServerKeyExchange(data)

    def serialize(self) -> bytes:
        return self.data


@dataclass
class ServerHelloDone(HandshakeMessage):
    handshake_type: ClassVar[int] = HandshakeType.SERVER_HELLO_DONE

    @classmethod
    def from_bytes(cls, data: bytes) -> ServerHelloDone:
        if data:
            raise ParseError("trailing data in server hello done")
        return ServerHelloDone()

    def serialize(self) -> bytes:
        return b""


@dataclass
class NextProtocol(HandshakeMessage):
    handshake_type: ClassVar[int] = HandshakeType.NEXT_PROTO
    next_protocol: bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> NextProtocol:
        parser = Parser(data)
        next_proto = parser.read_prefixed_bytes(1)
        _ = parser.read_prefixed_bytes(1)  # padding

        if parser.remaining():
            raise ParseError("trailing data in next protocol")

        return NextProtocol(next_proto)

    def serialize(self) -> bytes:
        writer = Writer()
        writer.write_prefixed_bytes(self.next_protocol, 1)
        padding_len = 32 - ((len(self.next_protocol) + 2) % 32)
        writer.write_prefixed_bytes(bytes(padding_len), 1)
        return writer.tobytes()


@dataclass
class EncryptedExtensions(HandshakeMessage):
    handshake_type: ClassVar[int] = HandshakeType.ENCRYPTED_EXTENSIONS
    extensions: Extensions

    @classmethod
    def from_bytes(cls, data: bytes) -> EncryptedExtensions:
        extensions = Extensions.from_bytes(data)
        return EncryptedExtensions(extensions)

    def serialize(self) -> bytes:
        return self.extensions.serialize()


@dataclass
class EndOfEarlyData(HandshakeMessage):
    handshake_type: ClassVar[int] = HandshakeType.END_OF_EARLY_DATA

    @classmethod
    def from_bytes(cls, data: bytes) -> EndOfEarlyData:
        if data:
            raise ParseError("trailing data in end of early data")
        return EndOfEarlyData()

    def serialize(self) -> bytes:
        return b""


@dataclass
class Finished(HandshakeMessage):
    handshake_type: ClassVar[int] = HandshakeType.FINISHED
    verify_data: bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> Finished:
        return Finished(data)

    def serialize(self) -> bytes:
        return self.verify_data


@dataclass
class NewSessionTicket(HandshakeMessage):
    handshake_type: ClassVar[int] = HandshakeType.NEWSESSION_TICKET
    ticket_lifetime: int
    ticket: bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> NewSessionTicket:
        parser = Parser(data)
        ticket_lifetime = parser.read_int(4)
        ticket = parser.read_prefixed_bytes(2)

        if parser.remaining():
            raise ParseError("trailing data in new session ticket")

        return NewSessionTicket(ticket_lifetime, ticket)

    def serialize(self) -> bytes:
        writter = Writer()
        writter.write_int(self.ticket_lifetime, 4)
        writter.write_prefixed_bytes(self.ticket, 2)
        return writter.tobytes()


@dataclass
class NewSessionTicketTLS13(HandshakeMessage):
    handshake_type: ClassVar[int] = HandshakeType.NEWSESSION_TICKET
    ticket_lifetime: int
    ticket_age_add: int
    ticket_nonce: bytes
    ticket: bytes
    extensions: Extensions

    @classmethod
    def from_bytes(cls, data: bytes) -> NewSessionTicketTLS13:
        parser = Parser(data)
        ticket_lifetime = parser.read_int(4)
        ticket_age_add = parser.read_int(4)
        ticket_nonce = parser.read_prefixed_bytes(1)
        ticket = parser.read_prefixed_bytes(2)
        extensions = Extensions.parse(parser)

        if parser.remaining():
            raise ParseError("trailing data in new session ticket")

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
        self.extensions.write(writer)

        return writer.tobytes()


@dataclass
class KeyUpdate(HandshakeMessage):
    handshake_type: ClassVar[int] = HandshakeType.KEY_UPDATE
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
class CertificateEntry:
    certificate: bytes
    extensions: Extensions

    @classmethod
    def parse(cls, parser: Parser[bytes]) -> CertificateEntry:
        certificate = parser.read_prefixed_bytes(3)
        extensions = Extensions.parse(parser)
        return CertificateEntry(certificate, extensions)

    def write(self, writer: Writer) -> None:
        writer.write_prefixed_bytes(self.certificate, 3)
        self.extensions.write(writer)


@dataclass
class CertificateStatus(HandshakeMessage):
    handshake_type: ClassVar[int] = HandshakeType.CERTIFICATE_STATUS
    ocsp: bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> CertificateStatus:
        parser = Parser(data)
        status_type = parser.read_int(1)
        if not status_type == CertificateStatusType.OCSP:
            raise ParseError("unknown status_type")
        ocsp = parser.read_prefixed_bytes(3)

        if parser.remaining():
            raise ParseError("trailing data in certificate status")

        return CertificateStatus(ocsp)

    def serialize(self) -> bytes:
        writer = Writer()
        writer.write_int(CertificateStatusType.OCSP, 1)
        writer.write_prefixed_bytes(self.ocsp, 3)
        return writer.tobytes()


@dataclass
class Certificate(HandshakeMessage):
    handshake_type: ClassVar[int] = HandshakeType.CERTIFICATE
    certificates: Sequence[bytes]

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
            raise ParseError("trailing data in certificate")

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
    handshake_type: ClassVar[int] = HandshakeType.CERTIFICATE
    context: bytes
    certificate_entries: Sequence[CertificateEntry]

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
            raise ParseError("trailing data in certificate")

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
    handshake_type: ClassVar[int] = HandshakeType.COMPRESSED_CERTIFICATE
    compression: int
    length: int
    compressed_data: bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> CompressedCertificate:
        parser = Parser(data)
        compression = parser.read_int(2)
        length = parser.read_int(3)
        compressed_data = parser.read_prefixed_bytes(3)

        if not compressed_data:
            raise ParseError("empty payload in compressed certificate")
        if parser.remaining():
            raise ParseError("trailing data in compressed certificate")

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
    handshake_type: ClassVar[int] = HandshakeType.CERTIFICATE_REQUEST
    certificate_types: Sequence[int]
    certificate_authorities: Sequence[bytes]

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
            raise ParseError("trailing data in certificate request")

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
    handshake_type: ClassVar[int] = HandshakeType.CERTIFICATE_REQUEST
    certificate_types: Sequence[int]
    certificate_authorities: Sequence[bytes]
    signature_algorithms: Sequence[int]

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
            raise ParseError("trailing data in certificate request")

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
class CertificateRequestTLS13(HandshakeMessage):
    handshake_type: ClassVar[int] = HandshakeType.CERTIFICATE_REQUEST
    context: bytes
    extensions: Extensions

    @classmethod
    def from_bytes(cls, data: bytes) -> CertificateRequestTLS13:
        parser = Parser(data)
        context = parser.read_prefixed_bytes(1)
        extensions = Extensions.parse(parser)

        if parser.remaining():
            raise ParseError("trailing data in certificate request")

        return CertificateRequestTLS13(context, extensions)

    def serialize(self) -> bytes:
        writer = Writer()
        writer.write_prefixed_bytes(self.context, 1)
        self.extensions.write(writer)
        return writer.tobytes()


@dataclass
class CertificateVerify(HandshakeMessage):
    handshake_type: ClassVar[int] = HandshakeType.CERTIFICATE_VERIFY
    signature: bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> CertificateVerify:
        parser = Parser(data)
        signature = parser.read_prefixed_bytes(2)

        if parser.remaining():
            raise ParseError("trailing data in certificate verify")

        return CertificateVerify(signature=signature)

    def serialize(self) -> bytes:
        writer = Writer()
        writer.write_prefixed_bytes(self.signature, 2)
        return writer.tobytes()


@dataclass
class CertificateVerifyTLS12(HandshakeMessage):
    handshake_type: ClassVar[int] = HandshakeType.CERTIFICATE_VERIFY
    signature: bytes
    signature_algorithm: int

    @classmethod
    def from_bytes(cls, data: bytes) -> CertificateVerifyTLS12:
        parser = Parser(data)
        signature_algorithm = parser.read_int(2)
        signature = parser.read_prefixed_bytes(2)

        if parser.remaining():
            raise ParseError("trailing data in certificate verify")

        return CertificateVerifyTLS12(signature, signature_algorithm)

    def serialize(self) -> bytes:
        writer = Writer()
        writer.write_int(self.signature_algorithm, 2)
        writer.write_prefixed_bytes(self.signature, 2)
        return writer.tobytes()
