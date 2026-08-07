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

import ipaddress
import typing
from typing import TypeAlias

from ..io import asn1

_IPAddressTypes: TypeAlias = typing.Union[
    ipaddress.IPv4Address,
    ipaddress.IPv6Address,
    ipaddress.IPv4Network,
    ipaddress.IPv6Network,
]


_AttributeValue: TypeAlias = typing.Union[
    # asn1.Variant[typing.Literal["octet_string"], asn1.OctetString],
    asn1.Variant[typing.Literal["utf8_string"], asn1.UTF8String],
    asn1.Variant[typing.Literal["numeric_string"], asn1.NumericString],
    asn1.Variant[typing.Literal["printable_string"], asn1.PrintableString],
    asn1.Variant[typing.Literal["teletex_string"], asn1.TeletexString],
    asn1.Variant[typing.Literal["videotex_string"], asn1.VideotexString],
    asn1.Variant[typing.Literal["ia5_string"], asn1.IA5String],
    asn1.Variant[typing.Literal["graphic_string"], asn1.GraphicString],
    asn1.Variant[typing.Literal["visible_string"], asn1.VisibleString],
    asn1.Variant[typing.Literal["general_string"], asn1.GeneralString],
    asn1.Variant[typing.Literal["bmp_string"], asn1.BMPString],
]


@asn1.sequence(frozen=True)
class NameAttribute:
    # AttributeTypeAndValue ::= SEQUENCE {
    #     type     AttributeType,
    #     value    AttributeValue
    # }
    # AttributeType ::= OBJECT IDENTIFIER
    # AttributeValue ::= ANY -- DEFINED BY AttributeType
    oid: asn1.ObjectIdentifier
    attribute_value: _AttributeValue

    def rfc4514_string(self) -> str:
        return f"{self.oid.name}={(self.value)}"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, NameAttribute):
            return NotImplemented
        return other.oid == self.oid and other.value == self.value

    def __hash__(self) -> int:
        return hash((self.oid, self.value))

    def __repr__(self) -> str:
        return f"<NameAttribute(type={self.oid}, value={self.value})>"

    @property
    def value(self) -> str:
        return self.attribute_value.value


@asn1.mapped(base_type=asn1.SetOf[NameAttribute])
class RelativeDistinguishedName:
    # RelativeDistinguishedName ::=
    #    SET SIZE (1..MAX) OF AttributeTypeAndValue

    def __init__(
        self,
        attributes: typing.Iterable[NameAttribute],
        *,
        _from_decoder: bool = False,
    ) -> None:
        if not _from_decoder:
            attributes = list(attributes)
        else:
            attributes = typing.cast(list[NameAttribute], attributes)

        attribute_set = frozenset(attributes)
        if len(attribute_set) != len(attributes):
            raise ValueError("duplicate NameAttribute in attributes")

        self._attributes = attribute_set

    def rfc4514_string(self) -> str:
        return "+".join(attr.rfc4514_string() for attr in self)

    def __iter__(self) -> typing.Iterator[NameAttribute]:
        return iter(self._attributes)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, RelativeDistinguishedName):
            return NotImplemented
        return self._attributes == other._attributes

    def __hash__(self) -> int:
        return hash(self._attributes)

    def __repr__(self) -> str:
        return f"<RelativeDistinguishedName({self.rfc4514_string()})>"

    def to_encoder(self) -> frozenset[NameAttribute]:
        return self._attributes

    @classmethod
    def from_decoder(
        cls, value: list[NameAttribute]
    ) -> RelativeDistinguishedName:
        return RelativeDistinguishedName(value, _from_decoder=True)


@asn1.mapped(base_type=asn1.SequenceOf[RelativeDistinguishedName])
class Name:
    # Name ::= CHOICE {
    #     rdnSequence  RDNSequence
    # }
    # RDNSequence ::= SEQUENCE OF RelativeDistinguishedName

    def __init__(
        self,
        rdns: typing.Iterable[RelativeDistinguishedName],
        *,
        _from_decoder: bool = False,
    ) -> None:
        if not _from_decoder:
            if not all(isinstance(a, RelativeDistinguishedName) for a in rdns):
                raise TypeError(
                    "rdns must be Iterable of RelativeDistinguishedName "
                    "objects"
                )
            rdns = list(rdns)
        else:
            rdns = typing.cast(list[RelativeDistinguishedName], rdns)

        self._rdns = rdns

    def get_attributes_for_oid(
        self, oid: asn1.ObjectIdentifier
    ) -> list[NameAttribute]:
        return [i for i in self if i.oid == oid]

    def rfc4514_string(self) -> str:
        return ",".join(reversed([attr.rfc4514_string() for attr in self]))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Name):
            return NotImplemented
        return self._rdns == other._rdns

    def __hash__(self) -> int:
        return hash(tuple(self._rdns))

    def __iter__(self) -> typing.Iterator[NameAttribute]:
        return iter(attribute for rdn in self._rdns for attribute in rdn)

    def __repr__(self) -> str:
        return f"<Name({self.rfc4514_string()})>"

    @property
    def rdns(self) -> list[RelativeDistinguishedName]:
        return self._rdns

    def to_encoder(self) -> list[RelativeDistinguishedName]:
        return self._rdns

    @classmethod
    def from_decoder(cls, value: list[RelativeDistinguishedName]) -> Name:
        return Name(value)


class GeneralName:
    pass


@asn1.mapped(base_type=asn1.IA5String)
class RFC822Name(GeneralName):
    def __init__(self, value: str) -> None:
        self._value = value

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, RFC822Name):
            return NotImplemented
        return self.value == other.value

    def __hash__(self) -> int:
        return hash(self.value)

    def __repr__(self) -> str:
        return f"RFC822Name({self.value})"

    @property
    def value(self) -> str:
        return self._value

    def to_encoder(self) -> str:
        return self._value

    @classmethod
    def from_decoder(cls, data: str) -> RFC822Name:
        return RFC822Name(data)


@asn1.mapped(base_type=asn1.IA5String)
class DNSName(GeneralName):
    def __init__(self, value: str) -> None:
        self._value = value

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, DNSName):
            return NotImplemented
        return self.value == other.value

    def __hash__(self) -> int:
        return hash(self.value)

    def __repr__(self) -> str:
        return f"DNSName({self.value})"

    @property
    def value(self) -> str:
        return self._value

    def to_encoder(self) -> str:
        return self._value

    @classmethod
    def from_decoder(cls, data: str) -> DNSName:
        return DNSName(data)


@asn1.mapped(base_type=asn1.IA5String)
class UniformResourceIdentifier(GeneralName):
    def __init__(self, value: str) -> None:
        self._value = value

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, UniformResourceIdentifier):
            return NotImplemented
        return self.value == other.value

    def __hash__(self) -> int:
        return hash(self.value)

    def __repr__(self) -> str:
        return f"UniformResourceIdentifier({self.value})"

    @property
    def value(self) -> str:
        return self._value

    def to_encoder(self) -> str:
        return self._value

    @classmethod
    def from_decoder(cls, data: str) -> UniformResourceIdentifier:
        return UniformResourceIdentifier(data)


@asn1.mapped(base_type=Name)
class DirectoryName(GeneralName):
    def __init__(self, value: Name) -> None:
        self._value = value

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, DirectoryName):
            return NotImplemented
        return self.value == other.value

    def __hash__(self) -> int:
        return hash(self.value)

    def __repr__(self) -> str:
        return f"DirectoryName({self.value})"

    @property
    def value(self) -> Name:
        return self._value

    def to_encoder(self) -> Name:
        return self._value

    @classmethod
    def from_decoder(cls, data: Name) -> DirectoryName:
        return DirectoryName(data)


@asn1.mapped(base_type=asn1.ObjectIdentifier)
class RegisteredID(GeneralName):
    def __init__(self, value: asn1.ObjectIdentifier) -> None:
        self._value = value

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, RegisteredID):
            return NotImplemented
        return self.value == other.value

    def __hash__(self) -> int:
        return hash(self.value)

    def __repr__(self) -> str:
        return f"RegisteredID({self.value})"

    @property
    def value(self) -> asn1.ObjectIdentifier:
        return self._value

    def to_encoder(self) -> asn1.ObjectIdentifier:
        return self._value

    @classmethod
    def from_decoder(cls, data: asn1.ObjectIdentifier) -> RegisteredID:
        return RegisteredID(data)


@asn1.mapped(base_type=asn1.OctetString)
class IPAddress(GeneralName):
    def __init__(self, value: _IPAddressTypes) -> None:
        self._value = value

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, IPAddress):
            return NotImplemented
        return self.value == other.value

    def __hash__(self) -> int:
        return hash(self.value)

    def __repr__(self) -> str:
        return f"IPAddress({self.value})"

    @property
    def value(self) -> _IPAddressTypes:
        return self._value

    def to_encoder(self) -> bytes:
        addr = self._value
        if isinstance(addr, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
            return addr.packed
        return addr.network_address.packed + addr.netmask.packed

    @classmethod
    def from_decoder(cls, data: bytes) -> IPAddress:
        length = len(data)
        value: _IPAddressTypes
        ip: ipaddress.IPv4Address | ipaddress.IPv6Address
        mask: ipaddress.IPv4Address | ipaddress.IPv6Address

        if length == 4:
            # IPv4 Host
            value = ipaddress.IPv4Address(data)

        elif length == 16:
            # IPv6 Host
            value = ipaddress.IPv6Address(data)

        elif length == 8:
            # IPv4 Network (4 bytes IP + 4 bytes Mask)
            ip_bytes = data[0:4]
            mask_bytes = data[4:8]

            ip = ipaddress.IPv4Address(ip_bytes)
            mask = ipaddress.IPv4Address(mask_bytes)
            value = ipaddress.IPv4Network(f"{ip}/{mask}")

        elif length == 32:
            # IPv6 Network (16 bytes IP + 16 bytes Mask)
            ip_bytes = data[0:16]
            mask_bytes = data[16:32]

            ip = ipaddress.IPv6Address(ip_bytes)
            mask = ipaddress.IPv6Address(mask_bytes)
            value = ipaddress.IPv6Network(f"{ip}/{mask}")

        else:
            raise ValueError("Unable to parse ipaddress")

        return IPAddress(value)


@asn1.sequence(frozen=True)
class OtherName(GeneralName):
    # AnotherName ::= SEQUENCE {
    #     type-id    OBJECT IDENTIFIER,
    #     value      [0] EXPLICIT ANY DEFINED BY type-id
    # }
    type_id: asn1.ObjectIdentifier
    value: asn1.Any


# GeneralName ::= CHOICE {
#     otherName                       [0]     OtherName,
#     rfc822Name                      [1]     IA5String,
#     dNSName                         [2]     IA5String,
#     x400Address                     [3]     ORAddress,
#     directoryName                   [4]     Name,
#     ediPartyName                    [5]     EDIPartyName,
#     uniformResourceIdentifier       [6]     IA5String,
#     iPAddress                       [7]     OCTET STRING,
#     registeredID                    [8]     OBJECT IDENTIFIER
# }
_GeneralName: TypeAlias = typing.Union[
    asn1.Annotated[RFC822Name, asn1.Implicit(1)],
    asn1.Annotated[DNSName, asn1.Implicit(2)],
    asn1.Annotated[UniformResourceIdentifier, asn1.Implicit(6)],
    asn1.Annotated[DirectoryName, asn1.Explicit(4)],
    asn1.Annotated[RegisteredID, asn1.Implicit(8)],
    asn1.Annotated[IPAddress, asn1.Implicit(7)],
    asn1.Annotated[OtherName, asn1.Implicit(0)],
]


@asn1.mapped(asn1.SequenceOf[_GeneralName])
class GeneralNames:
    # GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName

    def __init__(
        self,
        general_names: typing.Iterable[GeneralName],
        *,
        _from_decoder: bool = False,
    ) -> None:
        self._general_names = tuple(general_names)

    @typing.overload
    def get_values_for_type(
        self,
        type: type[DNSName]
        | type[UniformResourceIdentifier]
        | type[RFC822Name],
    ) -> list[str]: ...

    @typing.overload
    def get_values_for_type(
        self,
        type: type[DirectoryName],
    ) -> list[Name]: ...

    @typing.overload
    def get_values_for_type(
        self,
        type: type[RegisteredID],
    ) -> list[asn1.ObjectIdentifier]: ...

    @typing.overload
    def get_values_for_type(
        self,
        type: type[IPAddress],
    ) -> list[_IPAddressTypes]: ...

    @typing.overload
    def get_values_for_type(
        self,
        type: type[OtherName],
    ) -> list[OtherName]: ...

    def get_values_for_type(
        self,
        type: type[DNSName]
        | type[DirectoryName]
        | type[IPAddress]
        | type[OtherName]
        | type[RFC822Name]
        | type[RegisteredID]
        | type[UniformResourceIdentifier],
    ) -> (
        list[_IPAddressTypes]
        | list[str]
        | list[OtherName]
        | list[Name]
        | list[asn1.ObjectIdentifier]
    ):
        objs: typing.Generator[typing.Any] = (
            i for i in self if isinstance(i, type)
        )
        if type is OtherName:
            return list(objs)
        return [i.value for i in objs]

    def __iter__(self) -> typing.Iterator[GeneralName]:
        return iter(self._general_names)

    def __repr__(self) -> str:
        return f"GeneralNames({self._general_names}])"

    def to_encoder(self) -> tuple[GeneralName, ...]:
        return self._general_names

    @classmethod
    def from_decoder(cls, value: list[GeneralName]) -> GeneralNames:
        return GeneralNames(value, _from_decoder=True)
