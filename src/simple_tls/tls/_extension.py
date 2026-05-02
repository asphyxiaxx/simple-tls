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

import enum
import typing
from dataclasses import dataclass, field

from ..utils.codec import ParseError, Parser, Writer
from ..utils.math import int_to_bytes
from ._constant import (
    CertificateStatusType,
    ECHClientHelloType,
    ExtensionType,
    NameType,
)

_E = typing.TypeVar("_E", bound="TLSExtension")
_PBE = typing.TypeVar("_PBE", bound="PrefixedBytesExtension")
_PILE = typing.TypeVar("_PILE", bound="PrefixedIntListExtension")
_IE = typing.TypeVar("_IE", bound="IntExtension")


class ExtensionSource(enum.IntEnum):
    NONE = enum.auto()
    CERT = enum.auto()
    CLIENT = enum.auto()
    SERVER = enum.auto()
    HRR = enum.auto()


@dataclass
class TLSExtension:
    extension_type: typing.ClassVar[int]

    @classmethod
    def from_bytes(cls: type[_E], data: bytes) -> _E:
        raise NotImplementedError()

    def serialize(self) -> bytes:
        raise NotImplementedError()


class ExtensionsMessage:
    extensions: list[tuple[int, bytes]]

    def find_extension(self, extension_type: int) -> tuple[int, bytes | None]:
        i = 0
        for i, (ext_type, ext_data) in enumerate(self.extensions):
            if ext_type == extension_type:
                return i, ext_data
        return i, None

    def get_extension(self, extclass: type[_E]) -> _E | None:
        if not issubclass(extclass, TLSExtension):
            raise TypeError("extclass must be type of TLSExtension")

        for ext_type, ext_data in self.extensions:
            if ext_type == extclass.extension_type:
                return extclass.from_bytes(ext_data)

        return None

    def extension_map(
        self, extension_source: ExtensionSource = ExtensionSource.NONE
    ) -> dict[int, TLSExtension]:
        ext_map: dict[int, TLSExtension] = {}
        source = _EXTENSION_SOUCES[extension_source]

        for ext_type, ext_data in self.extensions:
            try:
                ext_cls = source[ext_type]
            except KeyError:
                # Fallback: unknown or unsupported extension
                ext_map[ext_type] = GenericExtension(ext_type, ext_data)
            else:
                try:
                    ext_map[ext_type] = ext_cls.from_bytes(ext_data)
                except ParseError as exc:
                    raise ParseError(
                        f"Error in parsing extension data for "
                        f"'0x{ext_type:02X}': {exc}"
                    ) from exc

        return ext_map

    @classmethod
    def _parse_exts(cls, parser: Parser[bytes]) -> list[tuple[int, bytes]]:
        extensions: list[tuple[int, bytes]] = []
        seen: set[int] = set()

        with parser.assert_length(2) as end:
            while parser.tell() < end:
                ext_type = None
                try:
                    ext_type = parser.read_int(2)
                    ext_data = parser.read_prefixed_bytes(2)
                except ParseError as exc:
                    if ext_type is None:
                        raise ParseError("Not an extension") from None
                    raise ParseError(
                        f"Error in reading extension data for "
                        f"'0x{ext_type:02X}': {exc}"
                    ) from exc

                extensions.append((ext_type, ext_data))
                seen.add(ext_type)

        if len(extensions) != len(seen):
            raise ParseError("Duplicated extension")

        return extensions

    def _write_exts(self, writer: Writer) -> None:
        ext_writer = Writer()
        for ext_type, ext_data in self.extensions:
            ext_writer.write_int(ext_type, 2)
            ext_writer.write_prefixed_bytes(ext_data, 2)

        writer.write_prefixed_bytes(ext_writer, 2)


class OptionalExtensionsMessage(ExtensionsMessage):
    @classmethod
    def _parse_exts(cls, parser: Parser[bytes]) -> list[tuple[int, bytes]]:
        if parser.remaining():
            return super()._parse_exts(parser)
        return []

    def _write_exts(self, writer: Writer) -> None:
        if self.extensions:
            super()._write_exts(writer)


class EmptyExtension(TLSExtension):
    @classmethod
    def from_bytes(cls: type[_E], data: bytes) -> _E:
        if data:
            raise ParseError("trailing data")
        return cls()

    def serialize(self) -> bytes:
        return b""


@dataclass
class GenericExtension(TLSExtension):
    parsed_type: int
    data: bytes

    @property
    def extension_type(self) -> int:
        return self.parsed_type

    @extension_type.setter
    def extension_type(self, value: int) -> None:
        self.parsed_type = value

    def serialize(self) -> bytes:
        return self.data


@dataclass
class PrefixedBytesExtension(TLSExtension):
    extension_type: typing.ClassVar[int]
    data: bytes

    # Internal
    _prefix_size: typing.ClassVar[int] = 0

    @classmethod
    def from_bytes(cls: type[_PBE], data: bytes) -> _PBE:
        parser = Parser(data)
        value = parser.read_prefixed_bytes(cls._prefix_size)

        if parser.remaining():
            raise ParseError("trailing data")

        return cls(value)

    def serialize(self) -> bytes:
        writer = Writer()
        writer.write_prefixed_bytes(self.data, self._prefix_size)
        return writer.tobytes()


@dataclass
class PrefixedIntListExtension(TLSExtension):
    extension_type: typing.ClassVar[int]
    data: typing.Sequence[int]

    # Internal
    _item_size: typing.ClassVar[int] = 0
    _prefix_size: typing.ClassVar[int] = 0
    _min_length: typing.ClassVar[int] = 0
    _max_length: typing.ClassVar[int] = 0xFFFF

    @classmethod
    def from_bytes(cls: type[_PILE], data: bytes) -> _PILE:
        if not (cls._min_length <= len(data) <= cls._max_length):
            raise ParseError("data not within boundaries")

        parser = Parser(data)
        value = parser.read_prefixed_int_list(cls._item_size, cls._prefix_size)

        if parser.remaining():
            raise ParseError("trailing data")

        return cls(value)

    def serialize(self) -> bytes:
        writer = Writer()
        writer.write_prefixed_int_list(
            self.data, self._item_size, self._prefix_size
        )
        data = writer.tobytes()

        if not (self._min_length <= len(data) <= self._max_length):
            raise ParseError("data not within boundaries")

        return data


@dataclass
class IntExtension(TLSExtension):
    extension_type: typing.ClassVar[int]
    data: int

    # Internal
    _item_size: typing.ClassVar[int] = 0

    @classmethod
    def from_bytes(cls: type[_IE], data: bytes) -> _IE:
        parser = Parser(data)
        value = parser.read_int(cls._item_size)

        if parser.remaining():
            raise ParseError("trailing data")

        return cls(value)

    def serialize(self) -> bytes:
        try:
            return int_to_bytes(self.data, self._item_size)
        except OverflowError:
            raise ValueError("data too large") from None


@dataclass
class EncryptThenMacExtension(EmptyExtension):
    extension_type: typing.ClassVar[int] = ExtensionType.ENCRYPT_THEN_MAC


@dataclass
class ExtendedMasterSecretExtension(EmptyExtension):
    extension_type: typing.ClassVar[int] = ExtensionType.EXTENDED_MAIN_SECRET


@dataclass
class RenegotiationInfoExtension(PrefixedBytesExtension):
    extension_type: typing.ClassVar[int] = ExtensionType.RENEGOTIATION_INFO
    _prefix_size: typing.ClassVar[int] = 1


@dataclass
class SessionTicketExtension(TLSExtension):
    extension_type: typing.ClassVar[int] = ExtensionType.SESSION_TICKET
    ticket: bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> SessionTicketExtension:
        return SessionTicketExtension(data)

    def serialize(self) -> bytes:
        return self.ticket


@dataclass
class CompressedCertificateExtension(PrefixedIntListExtension):
    extension_type: typing.ClassVar[int] = ExtensionType.COMPRESS_CERTIFICATE
    _item_size: typing.ClassVar[int] = 2
    _prefix_size: typing.ClassVar[int] = 1
    _min_length: typing.ClassVar[int] = 2
    _max_length: typing.ClassVar[int] = 2**8 - 2


@dataclass
class ClientSupportedVersionsExtension(PrefixedIntListExtension):
    extension_type: typing.ClassVar[int] = ExtensionType.SUPPORTED_VERSIONS
    _item_size: typing.ClassVar[int] = 2
    _prefix_size: typing.ClassVar[int] = 1
    _min_length: typing.ClassVar[int] = 2
    _max_length: typing.ClassVar[int] = 254


@dataclass
class ServerSupportedVersionExtension(IntExtension):
    extension_type: typing.ClassVar[int] = ExtensionType.SUPPORTED_VERSIONS
    _item_size: typing.ClassVar[int] = 2


@dataclass
class ClientSupportedGroupsExtension(PrefixedIntListExtension):
    extension_type: typing.ClassVar[int] = ExtensionType.SUPPORTED_GROUPS
    _item_size: typing.ClassVar[int] = 2
    _prefix_size: typing.ClassVar[int] = 2
    _min_length = 2


@dataclass
class ECPointFormatsExtension(PrefixedIntListExtension):
    """
    RFC4492.
    """

    extension_type: typing.ClassVar[int] = ExtensionType.EC_POINT_FORMATS
    _item_size: typing.ClassVar[int] = 1
    _prefix_size: typing.ClassVar[int] = 1
    _min_length: typing.ClassVar[int] = 1
    _max_length: typing.ClassVar[int] = 2**8 - 1


@dataclass
class ClientHelloPaddingExtension(TLSExtension):
    extension_type: typing.ClassVar[int] = ExtensionType.CLIENT_HELLO_PADDING
    padding_length: int

    @classmethod
    def from_bytes(cls, data: bytes) -> ClientHelloPaddingExtension:
        return ClientHelloPaddingExtension(len(data))

    def serialize(self) -> bytes:
        return bytes(self.padding_length)


@dataclass
class SignatureAlgorithmsExtension(PrefixedIntListExtension):
    """
    RFC5246.
    """

    extension_type: typing.ClassVar[int] = ExtensionType.SIGNATURE_ALGORITHMS
    _item_size: typing.ClassVar[int] = 2
    _prefix_size: typing.ClassVar[int] = 2
    _min_length: typing.ClassVar[int] = 2
    _max_length: typing.ClassVar[int] = 2**16 - 2


@dataclass
class PSKKeyExchangeModesExtension(PrefixedIntListExtension):
    extension_type: typing.ClassVar[int] = ExtensionType.PSK_KEY_EXCHANGE_MODES
    _item_size: typing.ClassVar[int] = 1
    _prefix_size: typing.ClassVar[int] = 1
    _min_length: typing.ClassVar[int] = 1
    _max_length: typing.ClassVar[int] = 255


@dataclass
class ClientALPSExtension(TLSExtension):
    extension_type: typing.ClassVar[int] = ExtensionType.APPLICATION_SETTINGS
    protocols: typing.Sequence[bytes]

    @classmethod
    def from_bytes(cls, data: bytes) -> ClientALPSExtension:
        parser = Parser(data)
        protocols: list[bytes] = []

        with parser.assert_length(2) as end:
            while parser.tell() < end:
                protocol = parser.read_prefixed_bytes(1)
                protocols.append(protocol)

        if not protocols:
            raise ParseError("empty protocol list")
        if not all(bool(p) for p in protocols):
            raise ParseError("empty protocol in protocol list")
        if parser.remaining():
            raise ParseError("trailing data")

        return ClientALPSExtension(protocols)

    def serialize(self) -> bytes:
        if not self.protocols:
            raise ParseError("empty protocol list")
        if not all(bool(p) for p in self.protocols):
            raise ParseError("empty protocol in protocol list")

        p_writer = Writer()
        for protocol in self.protocols:
            p_writer.write_prefixed_bytes(protocol, 1)

        writer = Writer()
        writer.write_prefixed_bytes(p_writer, 2)
        return writer.tobytes()


@dataclass
class ServerALPSExtension(TLSExtension):
    extension_type: typing.ClassVar[int] = ExtensionType.APPLICATION_SETTINGS
    settings: bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> ServerALPSExtension:
        return ServerALPSExtension(data)

    def serialize(self) -> bytes:
        return self.settings


@dataclass
class CookieExtension(PrefixedBytesExtension):
    extension_type: typing.ClassVar[int] = ExtensionType.COOKIE
    _prefix_size: typing.ClassVar[int] = 2


@dataclass
class ECHOuterExtension(PrefixedIntListExtension):
    extension_type: typing.ClassVar[int] = ExtensionType.ECH_OUTER_EXTENSIONS
    _item_size = 2
    _prefix_size = 1


@dataclass
class ClientSNIExtension(TLSExtension):
    """
    RFC 4366. Server Name Indication extension
    """

    extension_type: typing.ClassVar[int] = ExtensionType.SERVER_NAME
    hostname: bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> ClientSNIExtension:
        parser = Parser(data)
        _ = parser.read_int(2)  # prefixed list size

        name_type = parser.read_int(1)
        if not name_type == NameType.HOSTNAME:
            raise ParseError("invalid name type")

        hostname = parser.read_prefixed_bytes(2)
        if not hostname:
            raise ParseError("empty hostname")

        if parser.remaining():
            raise ParseError("trailing data")

        return ClientSNIExtension(hostname)

    def serialize(self) -> bytes:
        sn_writer = Writer()
        sn_writer.write_int(NameType.HOSTNAME, 1)
        sn_writer.write_prefixed_bytes(self.hostname, 2)

        writer = Writer()
        writer.write_prefixed_bytes(sn_writer, 2)
        return writer.tobytes()


@dataclass
class ServerSNIExtension(EmptyExtension):
    """
    RFC 4366. Server Name Indication extension
    """

    extension_type: typing.ClassVar[int] = ExtensionType.SERVER_NAME


@dataclass
class ClientNPNExtension(EmptyExtension):
    extension_type: typing.ClassVar[int] = ExtensionType.SUPPORTS_NPN


@dataclass
class ServerNPNExtension(TLSExtension):
    extension_type: typing.ClassVar[int] = ExtensionType.SUPPORTS_NPN
    protocols: typing.Sequence[bytes]

    @classmethod
    def from_bytes(cls, data: bytes) -> ServerNPNExtension:
        parser = Parser(data)
        protocols: list[bytes] = []

        while parser.remaining():
            protocol = parser.read_prefixed_bytes(1)
            protocols.append(protocol)

        if not protocols:
            raise ParseError("empty protocol list")
        if not all(bool(p) for p in protocols):
            raise ParseError("empty protocol in protocol list")
        if parser.remaining():
            raise ParseError("trailing data")

        return ServerNPNExtension(protocols)

    def serialize(self) -> bytes:
        if not self.protocols:
            raise ParseError("empty protocol list")
        if not all(bool(p) for p in self.protocols):
            raise ParseError("empty protocol in protocol list")

        writer = Writer()
        for protocol in self.protocols:
            writer.write_prefixed_bytes(protocol, 1)

        return writer.tobytes()


@dataclass
class ClientALPNExtension(TLSExtension):
    extension_type: typing.ClassVar[int] = ExtensionType.ALPN
    protocols: typing.Sequence[bytes]

    @classmethod
    def from_bytes(cls, data: bytes) -> ClientALPNExtension:
        parser = Parser(data)
        protocols: list[bytes] = []

        with parser.assert_length(2) as end:
            while parser.tell() < end:
                protocol = parser.read_prefixed_bytes(1)
                protocols.append(protocol)

        if not protocols:
            raise ParseError("empty protocol list")
        if not all(bool(p) for p in protocols):
            raise ParseError("empty protocol in protocol list")
        if parser.remaining():
            raise ParseError("trailing data")

        return ClientALPNExtension(protocols=protocols)

    def serialize(self) -> bytes:
        if not self.protocols:
            raise ParseError("empty protocol list")
        if not all(bool(p) for p in self.protocols):
            raise ParseError("empty protocol in protocol list")

        p_writer = Writer()
        for protocol in self.protocols:
            p_writer.write_prefixed_bytes(protocol, 1)

        writer = Writer()
        writer.write_prefixed_bytes(p_writer, 2)
        return writer.tobytes()


@dataclass
class ServerALPNExtension(TLSExtension):
    extension_type: typing.ClassVar[int] = ExtensionType.ALPN
    protocol: bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> ServerALPNExtension:
        parser = Parser(data)
        _ = parser.read_int(2)  # prefixed list size
        protocol = parser.read_prefixed_bytes(1)
        if not protocol:
            raise ParseError("empty protocol")

        if parser.remaining():
            raise ParseError("trailing data")

        return ServerALPNExtension(protocol)

    def serialize(self) -> bytes:
        if not self.protocol:
            raise ValueError("empty protocol")

        p_writer = Writer()
        p_writer.write_prefixed_bytes(self.protocol, 1)

        writer = Writer()
        writer.write_prefixed_bytes(p_writer, 2)
        return writer.tobytes()


@dataclass
class ClientStatusRequestExtension(TLSExtension):
    extension_type: typing.ClassVar[int] = ExtensionType.STATUS_REQUEST
    responder_id_list: typing.Sequence[bytes] = ()
    request_extensions: bytes = b""

    @classmethod
    def from_bytes(cls, data: bytes) -> ClientStatusRequestExtension:
        parser = Parser(data)
        status_type = parser.read_int(1)
        if status_type != CertificateStatusType.OCSP:
            raise ParseError("Unknown certificate status type")

        responder_id_list: list[bytes] = []
        with parser.assert_length(2) as end:
            while parser.tell() < end:
                responder_id = parser.read_prefixed_bytes(2)
                responder_id_list.append(responder_id)

        request_extensions = parser.read_prefixed_bytes(2)

        if parser.remaining():
            raise ParseError("trailing data")

        return ClientStatusRequestExtension(
            responder_id_list, request_extensions
        )

    def serialize(self) -> bytes:
        rid_writer = Writer()
        if self.responder_id_list is not None:
            for i in self.responder_id_list:
                rid_writer.write_prefixed_bytes(i, 2)

        writer = Writer()
        writer.write_int(CertificateStatusType.OCSP, 1)
        writer.write_prefixed_bytes(rid_writer, 2)
        writer.write_prefixed_bytes(self.request_extensions, 2)
        return writer.tobytes()


@dataclass
class ServerStatusRequestExtension(EmptyExtension):
    extension_type: typing.ClassVar[int] = ExtensionType.STATUS_REQUEST


@dataclass
class CertStatusRequestExtension(TLSExtension):
    extension_type: typing.ClassVar[int] = ExtensionType.STATUS_REQUEST
    response: bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> CertStatusRequestExtension:
        parser = Parser(data)
        status_type = parser.read_int(1)
        if status_type != CertificateStatusType.OCSP:
            raise ParseError("invalid certificate status type")

        response = parser.read_prefixed_bytes(3)

        if parser.remaining():
            raise ParseError("trailing data")

        return CertStatusRequestExtension(response)

    def serialize(self) -> bytes:
        writer = Writer()
        writer.write_int(CertificateStatusType.OCSP, 1)
        writer.write_prefixed_bytes(self.response, 3)
        return writer.tobytes()


@dataclass(frozen=True)
class KeyShareEntry:
    group: int
    key_exchange: bytes

    @classmethod
    def parse(cls, parser: Parser[bytes]) -> KeyShareEntry:
        group = parser.read_int(2)
        key_exchange = parser.read_prefixed_bytes(2)
        if not key_exchange:
            raise ParseError("empty key_exchange")

        return KeyShareEntry(group, key_exchange)

    def write(self, writer: Writer) -> None:
        if not self.key_exchange:
            raise ValueError("empty key_exchange")

        writer.write_int(self.group, 2)
        writer.write_prefixed_bytes(self.key_exchange, 2)


@dataclass
class ClientKeyShareExtension(TLSExtension):
    extension_type: typing.ClassVar[int] = ExtensionType.KEY_SHARE
    key_shares: typing.Sequence[KeyShareEntry]

    @classmethod
    def from_bytes(cls, data: bytes) -> ClientKeyShareExtension:
        parser = Parser(data)
        key_shares: list[KeyShareEntry] = []

        with parser.assert_length(2) as end:
            while parser.tell() < end:
                key_share_entry = KeyShareEntry.parse(parser)
                key_shares.append(key_share_entry)

        if parser.remaining():
            raise ParseError("trailing data")

        return ClientKeyShareExtension(key_shares)

    def serialize(self) -> bytes:
        ks_writer = Writer()
        for key_share in self.key_shares:
            key_share.write(ks_writer)

        writer = Writer()
        writer.write_prefixed_bytes(ks_writer, 2)
        return writer.tobytes()


@dataclass
class ServerKeyShareExtension(TLSExtension):
    extension_type: typing.ClassVar[int] = ExtensionType.KEY_SHARE
    key_share: KeyShareEntry

    @classmethod
    def from_bytes(cls, data: bytes) -> ServerKeyShareExtension:
        parser = Parser(data)
        key_share = KeyShareEntry.parse(parser)

        if parser.remaining():
            raise ParseError("trailing data")

        return ServerKeyShareExtension(key_share)

    def serialize(self) -> bytes:
        writer = Writer()
        self.key_share.write(writer)
        return writer.tobytes()


@dataclass
class HRRKeyShareExtension(IntExtension):
    extension_type: typing.ClassVar[int] = ExtensionType.KEY_SHARE
    _item_size: typing.ClassVar[int] = 2


@dataclass(frozen=True)
class PSKIdentity:
    identity: bytes
    obfuscated_ticket_age: int

    @classmethod
    def parse(cls, parser: Parser[bytes]) -> PSKIdentity:
        identity = parser.read_prefixed_bytes(2)
        if not identity:
            raise ParseError("empty identity")

        obfuscated_ticket_age = parser.read_int(4)

        return PSKIdentity(identity, obfuscated_ticket_age)

    def write(self, writer: Writer) -> None:
        if not self.identity:
            raise ValueError("empty identity")

        writer.write_prefixed_bytes(self.identity, 2)
        writer.write_int(self.obfuscated_ticket_age, 4)


@dataclass
class ClientPSKExtension(TLSExtension):
    extension_type: typing.ClassVar[int] = ExtensionType.PRE_SHARED_KEY
    identities: typing.Sequence[PSKIdentity]
    binders: typing.Sequence[bytes]

    @classmethod
    def from_bytes(cls, data: bytes) -> ClientPSKExtension:
        parser = Parser(data)
        identities: list[PSKIdentity] = []
        binders: list[bytes] = []

        with parser.assert_length(2) as end:
            while parser.tell() < end:
                psk_identity = PSKIdentity.parse(parser)
                identities.append(psk_identity)

        with parser.assert_length(2) as end:
            while parser.tell() < end:
                binder = parser.read_prefixed_bytes(1)
                if not binder:
                    raise ParseError("empty binder")
                binders.append(binder)

        if len(identities) != len(binders):
            raise ParseError("invalid extension")
        if not identities:
            raise ParseError("empty identities")
        if parser.remaining():
            raise ParseError("trailing data")

        return ClientPSKExtension(identities, binders)

    def serialize(self) -> bytes:
        if len(self.identities) != len(self.binders):
            raise ValueError("invalid extension")
        if not self.identities:
            raise ValueError("empty identities")

        ids_writer = Writer()
        binder_writer = Writer()

        for psk_identity in self.identities:
            psk_identity.write(ids_writer)

        for binder in self.binders:
            if not binder:
                raise ValueError("empty binder")
            binder_writer.write_prefixed_bytes(binder, 1)

        writer = Writer()
        writer.write_prefixed_bytes(ids_writer, 2)
        writer.write_prefixed_bytes(binder_writer, 2)
        return writer.tobytes()


@dataclass
class ServerPSKExtension(IntExtension):
    extension_type: typing.ClassVar[int] = ExtensionType.PRE_SHARED_KEY
    _item_size: typing.ClassVar[int] = 2


@dataclass
class ClientPHAExtension(EmptyExtension):
    extension_type: typing.ClassVar[int] = ExtensionType.POST_HANDSHAKE_AUTH


@dataclass
class EarlyDataExtension(IntExtension):
    extension_type: typing.ClassVar[int] = ExtensionType.EARLY_DATA
    _item_size: typing.ClassVar[int] = 4


@dataclass
class ClientEarlyDataExtension(EmptyExtension):
    extension_type: typing.ClassVar[int] = ExtensionType.EARLY_DATA


@dataclass
class ServerEarlyDataExtension(EmptyExtension):
    extension_type: typing.ClassVar[int] = ExtensionType.EARLY_DATA


@dataclass
class ClientSCTExtension(EmptyExtension):
    extension_type: typing.ClassVar[int] = (
        ExtensionType.SIGNED_CERTIFICATE_TIMESTAMP
    )


@dataclass
class ServerSCTExtension(PrefixedBytesExtension):
    extension_type: typing.ClassVar[int] = (
        ExtensionType.SIGNED_CERTIFICATE_TIMESTAMP
    )
    _prefix_size = 2


@dataclass(frozen=True)
class ECHConfigContents(ExtensionsMessage):
    public_key: bytes
    public_name: bytes
    cipher_suites: typing.Sequence[tuple[int, int]]
    kem_id: int
    maximum_name_length: int
    config_id: int
    extensions: list[tuple[int, bytes]] = field(default_factory=list)

    @classmethod
    def parse(cls, parser: Parser[bytes]) -> ECHConfigContents:
        config_id = parser.read_int(1)
        kem_id = parser.read_int(2)
        public_key = parser.read_prefixed_bytes(2)
        cipher_suites: list[tuple[int, int]] = []

        with parser.assert_length(2) as end:
            while parser.tell() < end:
                kdf_id = parser.read_int(2)
                aead_id = parser.read_int(2)
                cipher_suites.append((kdf_id, aead_id))

        maximum_name_length = parser.read_int(1)
        public_name = parser.read_prefixed_bytes(1)
        extensions = cls._parse_exts(parser)

        if not (public_key and cipher_suites and public_name):
            raise ParseError("empty payload")

        return ECHConfigContents(
            public_key=public_key,
            public_name=public_name,
            cipher_suites=cipher_suites,
            kem_id=kem_id,
            maximum_name_length=maximum_name_length,
            config_id=config_id,
            extensions=extensions,
        )

    def write(self, writer: Writer) -> None:
        c_writer = Writer()
        for kdf_id, aead_id in self.cipher_suites:
            c_writer.write_int(kdf_id, 2)
            c_writer.write_int(aead_id, 2)

        writer.write_int(self.config_id, 1)
        writer.write_int(self.kem_id, 2)
        writer.write_prefixed_bytes(self.public_key, 2)
        writer.write_prefixed_bytes(c_writer, 2)
        writer.write_int(self.maximum_name_length, 1)
        writer.write_prefixed_bytes(self.public_name, 1)
        self._write_exts(writer)


@dataclass(frozen=True)
class ECHConfig:
    contents: ECHConfigContents

    def supported(self, all_extensions_mandatory: bool = False) -> bool:
        if not self.contents.extensions:
            return True

        has_unknown_mandatory_extension = False
        for ext_type, _ in self.contents.extensions:
            if ext_type & 0x8000 or all_extensions_mandatory:
                has_unknown_mandatory_extension = True
                break

        return not has_unknown_mandatory_extension

    @classmethod
    def parse(cls, parser: Parser[bytes]) -> ECHConfig:
        version = parser.read_int(2)
        if version != 65037:
            raise ParseError("Unsupported ECHConfig version")

        with parser.assert_length(2):
            contents = ECHConfigContents.parse(parser)

        return ECHConfig(contents)

    def write(self, writer: Writer) -> None:
        contents_writer = Writer()
        self.contents.write(contents_writer)

        writer.write_int(65037, 2)  # version fixed
        writer.write_prefixed_bytes(contents_writer, 2)

    def serialize(self) -> bytes:
        writer = Writer()
        self.write(writer)
        return writer.tobytes()


@dataclass
class ClientECHExtension(TLSExtension):
    extension_type: typing.ClassVar[int] = ExtensionType.ENCRYPTED_CLIENT_HELLO
    ech_client_hello_type: int
    hpke_kdf_id: int = 0
    hpke_aead_id: int = 0
    config_id: int = 0
    enc: bytes = b""
    payload: bytes = b""

    @classmethod
    def from_bytes(cls, data: bytes) -> ClientECHExtension:
        parser = Parser(data)
        ech_cl_type = parser.read_int(1)

        if ech_cl_type == ECHClientHelloType.OUTER:
            hpke_kem_id = parser.read_int(2)
            hpke_aead_id = parser.read_int(2)
            confid_id = parser.read_int(1)
            enc = parser.read_prefixed_bytes(2)
            payload = parser.read_prefixed_bytes(2)
            ret = ClientECHExtension(
                ech_client_hello_type=ech_cl_type,
                hpke_kdf_id=hpke_kem_id,
                hpke_aead_id=hpke_aead_id,
                config_id=confid_id,
                enc=enc,
                payload=payload,
            )
        elif ech_cl_type == ECHClientHelloType.INNER:
            ret = ClientECHExtension(ech_cl_type)
        else:
            raise ParseError("invalid encrypted client hello extension")

        if parser.remaining():
            raise ParseError("trailing data")

        return ret

    def serialize(self) -> bytes:
        writer = Writer()
        writer.write_int(self.ech_client_hello_type, 1)

        if self.ech_client_hello_type == ECHClientHelloType.OUTER:
            writer.write_int(self.hpke_kdf_id, 2)
            writer.write_int(self.hpke_aead_id, 2)
            writer.write_int(self.config_id, 1)
            writer.write_prefixed_bytes(self.enc, 2)
            writer.write_prefixed_bytes(self.payload, 2)

        return writer.tobytes()


@dataclass
class ServerECHExtensions(TLSExtension):
    extension_type: typing.ClassVar[int] = ExtensionType.ENCRYPTED_CLIENT_HELLO
    retry_configs: typing.Sequence[ECHConfig]

    @classmethod
    def from_bytes(cls, data: bytes) -> ServerECHExtensions:
        parser = Parser(data)
        configs: list[ECHConfig] = []

        with parser.assert_length(2) as end:
            while parser.tell() < end:
                ech_config = ECHConfig.parse(parser)
                configs.append(ech_config)

        if not configs:
            raise ValueError("empty retry config list")

        return ServerECHExtensions(configs)

    def serialize(self) -> bytes:
        if not self.retry_configs:
            raise ValueError("empty retry config list")

        config_writer = Writer()
        for c in self.retry_configs:
            c.write(config_writer)

        writer = Writer()
        writer.write_prefixed_bytes(config_writer, 2)
        return writer.tobytes()


@dataclass
class HRRECHExtension(TLSExtension):
    extension_type: typing.ClassVar[int] = ExtensionType.ENCRYPTED_CLIENT_HELLO
    data: bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> HRRECHExtension:
        if not len(data) == 8:
            raise ParseError("data must be exactly 8-bytes")
        return HRRECHExtension(data)

    def serialize(self) -> bytes:
        if not len(self.data) == 8:
            raise ValueError("data must be exactly 8-bytes")
        return self.data


COMPRESSIBLE_EXTENSIONS = (
    ExtensionType.SIGNATURE_ALGORITHMS,
    ExtensionType.STATUS_REQUEST,
    ExtensionType.SIGNED_CERTIFICATE_TIMESTAMP,
    ExtensionType.ALPN,
    ExtensionType.PSK_KEY_EXCHANGE_MODES,
    ExtensionType.EARLY_DATA,
    ExtensionType.KEY_SHARE,
    ExtensionType.COOKIE,
    ExtensionType.SUPPORTED_GROUPS,
    ExtensionType.COMPRESS_CERTIFICATE,
    ExtensionType.APPLICATION_SETTINGS,
    ExtensionType.POST_HANDSHAKE_AUTH,
)


_UNIVERSAL_EXTENSIONS: dict[int, type[TLSExtension]] = {
    e.extension_type: e
    for e in (
        CompressedCertificateExtension,
        EarlyDataExtension,
        SignatureAlgorithmsExtension,
    )
}


_CLIENT_EXTENSION: dict[int, type[TLSExtension]] = {
    e.extension_type: e
    for e in (
        ClientALPSExtension,
        ClientALPNExtension,
        ClientEarlyDataExtension,
        ClientECHExtension,
        ClientHelloPaddingExtension,
        ClientKeyShareExtension,
        ClientNPNExtension,
        ClientSCTExtension,
        ClientSNIExtension,
        ClientPSKExtension,
        ClientStatusRequestExtension,
        ClientSupportedGroupsExtension,
        ClientSupportedVersionsExtension,
        ClientPHAExtension,
        CompressedCertificateExtension,
        ECHOuterExtension,
        ECPointFormatsExtension,
        EncryptThenMacExtension,
        ExtendedMasterSecretExtension,
        RenegotiationInfoExtension,
        PSKKeyExchangeModesExtension,
        SessionTicketExtension,
        SignatureAlgorithmsExtension,
    )
}


_SERVER_EXTENSIONS: dict[int, type[TLSExtension]] = {
    e.extension_type: e
    for e in (
        ECPointFormatsExtension,
        EncryptThenMacExtension,
        ExtendedMasterSecretExtension,
        RenegotiationInfoExtension,
        ServerALPNExtension,
        ServerALPSExtension,
        ServerEarlyDataExtension,
        ServerECHExtensions,
        ServerKeyShareExtension,
        ServerNPNExtension,
        ServerPSKExtension,
        ServerSCTExtension,
        ServerStatusRequestExtension,
        ServerSNIExtension,
        ServerSupportedVersionExtension,
        SessionTicketExtension,
    )
}


_HRR_EXTENSIONS: dict[int, type[TLSExtension]] = {
    e.extension_type: e
    for e in (
        CookieExtension,
        HRRKeyShareExtension,
        HRRECHExtension,
        ServerSupportedVersionExtension,
    )
}


_CERTIFICATE_EXTENSIONS: dict[int, type[TLSExtension]] = {
    e.extension_type: e for e in (CertStatusRequestExtension,)
}


_EXTENSION_SOUCES: dict[ExtensionSource, dict[int, type[TLSExtension]]] = {
    ExtensionSource.NONE: _UNIVERSAL_EXTENSIONS,
    ExtensionSource.CERT: _CERTIFICATE_EXTENSIONS,
    ExtensionSource.CLIENT: _CLIENT_EXTENSION,
    ExtensionSource.SERVER: _SERVER_EXTENSIONS,
    ExtensionSource.HRR: _HRR_EXTENSIONS,
}
