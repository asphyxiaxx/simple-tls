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

import abc
import enum
import typing

from ..io import asn1
from ._name import (
    DirectoryName,
    DNSName,
    GeneralName,
    GeneralNames,
    IPAddress,
    Name,
    OtherName,
    RegisteredID,
    RelativeDistinguishedName,
    RFC822Name,
    UniformResourceIdentifier,
    _GeneralName,
    _IPAddressTypes,
)
from .certificate_transparent import (
    LogEntryType,
    SignedCertificateTimestamp,
    _parse_signed_certificate_timestamps,
    _serialize_signed_certificate_timestamps,
)
from .oid import CertificatePoliciesOID, ExtensionOID, ObjectIdentifier

_E = typing.TypeVar("_E", bound="ExtensionType", covariant=True)


class DuplicateExtension(Exception):
    def __init__(self, msg: str, oid: ObjectIdentifier) -> None:
        super().__init__(msg)
        self.oid = oid


class ExtensionNotFound(Exception):
    def __init__(self, msg: str, oid: ObjectIdentifier) -> None:
        super().__init__(msg)
        self.oid = oid


class ExtensionType(metaclass=abc.ABCMeta):
    @property
    @abc.abstractmethod
    def oid(self) -> ObjectIdentifier: ...


@asn1.sequence
class Extension(typing.Generic[_E]):
    oid: ObjectIdentifier
    critical: asn1.Boolean = False
    raw_value: asn1.OctetString

    def __post_init__(self) -> None:
        self._value: ExtensionType
        try:
            t = _EXTENSION_MAP[self.oid]
        except KeyError:
            self._value = UnrecognizedExtension(self.oid, self.raw_value)
        else:
            self._value, _ = asn1.decode(
                self.raw_value, t, root_name=self.oid.name
            )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Extension):
            return NotImplemented
        return (
            self.oid == other.oid
            and self.critical == other.critical
            and self.raw_value == other.raw_value
        )

    def __hash__(self) -> int:
        return hash((self.oid, self.critical, self.raw_value))

    def __repr__(self) -> str:
        return (
            f"<Extension(oid={self.oid}, "
            f"critical={self.critical}, "
            f"value={self.value})>"
        )

    @property
    def value(self) -> _E:
        return typing.cast(_E, self._value)


class UnrecognizedExtension(ExtensionType):
    def __init__(self, oid: ObjectIdentifier, value: bytes) -> None:
        self._oid = oid
        self._value = value

    def __repr__(self) -> str:
        return f"<UnrecognizedExtension(oid={self.oid}, value={self.value!r})>"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, UnrecognizedExtension):
            return NotImplemented
        return self.oid == other.oid and self.value == other.value

    @property
    def oid(self) -> ObjectIdentifier:
        return self._oid

    @property
    def value(self) -> bytes:
        return self._value


@asn1.mapped(base_type=asn1.SequenceOf[Extension])
class Extensions:
    def __init__(
        self,
        extensions: typing.Iterable[Extension[ExtensionType]],
        *,
        _from_decoder: bool = False,
    ) -> None:
        if not _from_decoder:
            extensions = list(extensions)
        else:
            extensions = typing.cast(
                list[Extension[ExtensionType]], extensions
            )

        for x in extensions:
            if extensions.count(x) > 1:
                raise DuplicateExtension("Dupicated extension found", x.oid)

        self._extensions = extensions

    def get_extension_for_oid(self, oid: ObjectIdentifier) -> Extension:
        for ext in self:
            if ext.oid == oid:
                return ext

        raise ExtensionNotFound(f"No '{oid}' extension was found", oid)

    def get_extension_for_class(self, ext_cls: type[_E]) -> Extension[_E]:
        if ext_cls is UnrecognizedExtension:
            raise TypeError(
                "UnrecognizedExtension can't be used with "
                "get_extension_for_class"
            )

        for ext in self:
            if isinstance(ext.value, ext_cls):
                return typing.cast(Extension[_E], ext)

        raise ExtensionNotFound(
            f"No '{ext_cls}'extension was found",
            ext_cls.oid,  # type: ignore
        )

    def __iter__(self) -> typing.Iterator[Extension[ExtensionType]]:
        return iter(self._extensions)

    def __repr__(self) -> str:
        return f"<Extensions({self._extensions})>"

    def to_encoder(self) -> list[Extension[ExtensionType]]:
        return self._extensions

    @classmethod
    def from_decoder(cls, value: list[Extension[ExtensionType]]) -> Extensions:
        return Extensions(value, _from_decoder=True)


@asn1.mapped(base_type=asn1.Integer)
class CRLNumber(ExtensionType):
    oid = ExtensionOID.CRL_NUMBER

    # CRLNumber ::= INTEGER (0..MAX)

    def __init__(self, crl_number: int) -> None:
        self._crl_number = crl_number

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, CRLNumber):
            return NotImplemented
        return self.crl_number == other.crl_number

    def __hash__(self) -> int:
        return hash(self.crl_number)

    def __repr__(self) -> str:
        return f"<CRLNumber({self.crl_number})>"

    @property
    def crl_number(self) -> int:
        return self._crl_number

    def to_encoder(self) -> int:
        return self.crl_number

    @classmethod
    def from_decoder(cls, value: int) -> CRLNumber:
        return CRLNumber(value)


@asn1.sequence(frozen=True)
class AuthorityKeyIdentifier(ExtensionType):
    oid = ExtensionOID.AUTHORITY_KEY_IDENTIFIER

    # AuthorityKeyIdentifier ::= SEQUENCE {
    #     keyIdentifier             [0] KeyIdentifier           OPTIONAL,
    #     authorityCertIssuer       [1] GeneralNames            OPTIONAL,
    #     authorityCertSerialNumber [2] CertificateSerialNumber OPTIONAL
    # }
    key_identifier: asn1.Annotated[asn1.OctetString, asn1.Implicit(0)] | None
    authority_cert_issuer: (
        asn1.Annotated[GeneralNames, asn1.Implicit(1)] | None
    )
    authority_cert_serial_number: (
        asn1.Annotated[asn1.Integer, asn1.Implicit(2)] | None
    )


@asn1.mapped(base_type=asn1.OctetString)
class SubjectKeyIdentifier(ExtensionType):
    oid = ExtensionOID.SUBJECT_KEY_IDENTIFIER

    # SubjectKeyIdentifier ::= OCTET STRING

    def __init__(self, key_identifier: bytes) -> None:
        self._key_identifier = key_identifier

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SubjectKeyIdentifier):
            return NotImplemented
        return self.key_identifier == other.key_identifier

    def __hash__(self) -> int:
        return hash(self.key_identifier)

    def __repr__(self) -> str:
        return f"<SubjectKeyIdentifier({self.key_identifier!r})>"

    @property
    def key_identifier(self) -> bytes:
        return self._key_identifier

    def to_encoder(self) -> bytes:
        return self._key_identifier

    @classmethod
    def from_decoder(cls, value: bytes) -> SubjectKeyIdentifier:
        return SubjectKeyIdentifier(value)


@asn1.sequence(frozen=True)
class BasicConstraints(ExtensionType):
    oid = ExtensionOID.BASIC_CONSTRAINTS

    # BasicConstraints ::= SEQUENCE {
    #     cA                      BOOLEAN DEFAULT FALSE,
    #     pathLenConstraint       INTEGER (0..MAX) OPTIONAL
    # }
    ca: asn1.Boolean = False
    path_length: int | None


@asn1.sequence(frozen=True)
class AccessDescription:
    # AccessDescription  ::=  SEQUENCE {
    #     accessMethod          OBJECT IDENTIFIER,
    #     accessLocation        GeneralName
    # }
    access_method: ObjectIdentifier
    access_location: _GeneralName


@asn1.mapped(base_type=asn1.SequenceOf[AccessDescription])
class AuthorityInformationAccess(ExtensionType):
    oid = ExtensionOID.AUTHORITY_INFORMATION_ACCESS

    # AuthorityInformationAccess  ::= SEQUENCE SIZE (1..MAX) OF
    #   AccessDescription

    def __init__(
        self,
        description: typing.Iterable[AccessDescription],
        *,
        _from_decoder: bool = False,
    ) -> None:
        if not _from_decoder:
            description = list(description)
        else:
            description = typing.cast(list[AccessDescription], description)

        self._description = description

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, AuthorityInformationAccess):
            return NotImplemented
        return self._description == other._description

    def __hash__(self) -> int:
        return hash(self._description)

    def __iter__(self) -> typing.Iterator[AccessDescription]:
        return iter(self._description)

    def __repr__(self) -> str:
        return f"AuthorityInformationAccess({self._description})"

    def to_encoder(self) -> list[AccessDescription]:
        return self._description

    @classmethod
    def from_decoder(
        cls, value: list[AccessDescription]
    ) -> AuthorityInformationAccess:
        return AuthorityInformationAccess(value, _from_decoder=True)


@asn1.mapped(base_type=asn1.SequenceOf[AccessDescription])
class SubjectInformationAccess(ExtensionType):
    oid = ExtensionOID.SUBJECT_INFORMATION_ACCESS

    # SubjectInfoAccessSyntax  ::= SEQUENCE SIZE (1..MAX) OF AccessDescription

    def __init__(
        self,
        description: typing.Iterable[AccessDescription],
        *,
        _from_decoder: bool = False,
    ) -> None:
        if not _from_decoder:
            description = list(description)
        else:
            description = typing.cast(list[AccessDescription], description)

        self._description = description

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SubjectInformationAccess):
            return NotImplemented
        return self.description == other.description

    def __hash__(self) -> int:
        return hash(self.description)

    def __repr__(self) -> str:
        return f"SubjectInformationAccess({self.description})"

    @property
    def description(self) -> list[AccessDescription]:
        return self._description

    def to_encoder(self) -> list[AccessDescription]:
        return self._description

    @classmethod
    def from_decoder(
        cls, value: list[AccessDescription]
    ) -> SubjectInformationAccess:
        return SubjectInformationAccess(value, _from_decoder=True)


class ReasonFlags(enum.Enum):
    # ReasonFlags ::= BIT STRING {
    #      unused                  (0),
    #      keyCompromise           (1),
    #      cACompromise            (2),
    #      affiliationChanged      (3),
    #      superseded              (4),
    #      cessationOfOperation    (5),
    #      certificateHold         (6),
    #      privilegeWithdrawn      (7),
    #      aACompromise            (8)
    # }
    unspecified = "unspecified"
    key_compromise = "keyCompromise"
    ca_compromise = "cACompromise"
    affiliation_changed = "affiliationChanged"
    superseded = "superseded"
    cessation_of_operation = "cessationOfOperation"
    certificate_hold = "certificateHold"
    privilege_withdrawn = "privilegeWithdrawn"
    aa_compromise = "aACompromise"
    remove_from_crl = "removeFromCRL"


_REASON_FLAGS = {
    1: ReasonFlags.key_compromise,
    2: ReasonFlags.ca_compromise,
    3: ReasonFlags.affiliation_changed,
    4: ReasonFlags.superseded,
    5: ReasonFlags.cessation_of_operation,
    6: ReasonFlags.certificate_hold,
    7: ReasonFlags.privilege_withdrawn,
    8: ReasonFlags.aa_compromise,
}
_CRLREASON_FLAGS = {v: k for k, v in _REASON_FLAGS.items()}


@asn1.mapped(base_type=asn1.BitString)
class Reasons:
    # ReasonFlags ::= BIT STRING {
    #      unused                  (0),
    #      keyCompromise           (1),
    #      cACompromise            (2),
    #      affiliationChanged      (3),
    #      superseded              (4),
    #      cessationOfOperation    (5),
    #      certificateHold         (6),
    #      privilegeWithdrawn      (7),
    #      aACompromise            (8)
    # }

    def __init__(self, flags: typing.Iterable[ReasonFlags]) -> None:
        if not isinstance(flags, typing.Sequence):
            flags = list(flags)

        flags_set = frozenset(flags)
        if len(flags_set) != len(flags):
            raise ValueError("Duplicated reasons flag")

        if (
            ReasonFlags.unspecified in flags_set
            or ReasonFlags.remove_from_crl in flags_set
        ):
            raise ValueError(
                "unspecified and remove_from_crl are not valid reasons "
                "in a DistributionPoint"
            )

        self._flags = flags_set

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Reasons):
            return NotImplemented
        return self.flags == other.flags

    def __hash__(self) -> int:
        return hash(self.flags)

    def __iter__(self) -> typing.Iterator[ReasonFlags]:
        return iter(self._flags)

    def __repr__(self) -> str:
        return f"Reasons({list(self.flags)})"

    @property
    def flags(self) -> frozenset[ReasonFlags]:
        return self._flags

    def to_encoder(self) -> asn1.BitString:
        bits = [True if f in self.flags else False for f in _CRLREASON_FLAGS]
        return asn1.BitString.from_bits(bits)

    @classmethod
    def from_decoder(cls, value: asn1.BitString) -> Reasons:
        bits = value.as_bits()
        flags = [_REASON_FLAGS[i] for i, b in enumerate(bits, start=1) if b]
        return Reasons(flags)


_DistributionPoint = typing.Union[
    asn1.Annotated[GeneralNames, asn1.Implicit(0)],
    asn1.Annotated[RelativeDistinguishedName, asn1.Implicit(1)],
]


@asn1.sequence(frozen=True)
class DistributionPoint:
    # distributionPoint ::= CHOICE {
    #      fullName                     [0]
    #      nameRelativeToCRLIssuer      [1]
    # }
    # reasons ::= BITSTRING
    # cRLIssuer ::= SEQUENCE SIZE (1..MAX) of GeneralName
    # DistributionPoint ::= SEQUENCE {
    #      distributionPoint    [0]
    #      reasons              [1]
    #      cRLIssuer            [2]
    # }
    distribution_point: (
        asn1.Annotated[_DistributionPoint, asn1.Explicit(0)] | None
    )
    reasons: asn1.Annotated[Reasons, asn1.Implicit(1)] | None
    crl_issuer: asn1.Annotated[GeneralNames, asn1.Implicit(2)] | None

    @property
    def full_name(self) -> GeneralNames | None:
        if isinstance(self.distribution_point, GeneralNames):
            return self.distribution_point
        return None

    @property
    def relative_name(self) -> RelativeDistinguishedName | None:
        if isinstance(self.distribution_point, RelativeDistinguishedName):
            return self.distribution_point
        return None


@asn1.mapped(base_type=asn1.SequenceOf[DistributionPoint])
class CRLDistributionPoints(ExtensionType):
    oid = ExtensionOID.CRL_DISTRIBUTION_POINTS

    # CRLDistributionPoints ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint

    def __init__(
        self,
        distribution_point: typing.Iterable[DistributionPoint],
        *,
        _from_decoder: bool = False,
    ) -> None:
        if not _from_decoder:
            distribution_point = list(distribution_point)
        else:
            distribution_point = typing.cast(
                list[DistributionPoint], distribution_point
            )

        self._distribution_point = distribution_point

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, CRLDistributionPoints):
            return NotImplemented
        return self._distribution_point == other._distribution_point

    def __hash__(self) -> int:
        return hash(tuple(self._distribution_point))

    def __iter__(self) -> typing.Iterator[DistributionPoint]:
        return iter(self._distribution_point)

    def __repr__(self) -> str:
        return f"CRLDistributionPoints({self._distribution_point})"

    def to_encoder(self) -> list[DistributionPoint]:
        return self._distribution_point

    @classmethod
    def from_decoder(
        cls, value: list[DistributionPoint]
    ) -> CRLDistributionPoints:
        return CRLDistributionPoints(value, _from_decoder=True)


@asn1.sequence(frozen=True)
class GeneralSubtree:
    # GeneralSubtree ::= SEQUENCE {
    #     base                    GeneralName,
    #     minimum         [0]     BaseDistance DEFAULT 0,
    #     maximum         [1]     BaseDistance OPTIONAL
    # }
    base: _GeneralName
    minimum: asn1.Annotated[asn1.Integer, asn1.Implicit(0)] = 0
    maximum: asn1.Annotated[asn1.Integer, asn1.Implicit(1)] | None = None


@asn1.mapped(base_type=asn1.SequenceOf[GeneralSubtree])
class GeneralSubtrees:
    # GeneralSubtrees ::= SEQUENCE SIZE (1..MAX) OF GeneralSubtree

    def __init__(
        self,
        names: typing.Iterable[GeneralName],
        *,
        _from_decoder: bool = False,
    ) -> None:
        self._general_names = GeneralNames(names)

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
    ) -> list[ObjectIdentifier]: ...

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
        | list[ObjectIdentifier]
    ):
        return self._general_names.get_values_for_type(type)

    def __iter__(self) -> typing.Iterator[GeneralName]:
        return iter(self._general_names)

    def __repr__(self) -> str:
        return f"<GeneralSubtree({self._general_names})>"

    def to_encoder(self) -> typing.Iterable[GeneralSubtree]:
        return (
            GeneralSubtree(base=typing.cast(_GeneralName, s))
            for s in self._general_names
        )

    @classmethod
    def from_decoder(cls, value: list[GeneralSubtree]) -> GeneralSubtrees:
        return GeneralSubtrees(s.base for s in value)


@asn1.sequence(frozen=True)
class NameConstraints(ExtensionType):
    oid = ExtensionOID.NAME_CONSTRAINTS

    # NameConstraints ::= SEQUENCE {
    #     permittedSubtrees       [0]     GeneralSubtrees OPTIONAL,
    #     excludedSubtrees        [1]     GeneralSubtrees OPTIONAL
    # }
    permitted_subtrees: (
        asn1.Annotated[GeneralSubtrees, asn1.Implicit(0)] | None
    )
    excluded_subtrees: asn1.Annotated[GeneralSubtrees, asn1.Implicit(1)] | None


@asn1.mapped(base_type=asn1.BitString)
class KeyUsage(ExtensionType):
    oid = ExtensionOID.KEY_USAGE

    # KeyUsage ::= BIT STRING {
    #     digitalSignature        (0),
    #     contentCommitment       (1),
    #     keyEncipherment         (2),
    #     dataEncipherment        (3),
    #     keyAgreement            (4),
    #     keyCertSign             (5),
    #     cRLSign                 (6),
    #     encipherOnly            (7),
    #     decipherOnly            (8)
    # }

    def __init__(
        self,
        digital_signature: bool,
        content_commitment: bool,
        key_encipherment: bool,
        data_encipherment: bool,
        key_agreement: bool,
        key_cert_sign: bool,
        crl_sign: bool,
        encipher_only: bool,
        decipher_only: bool,
    ) -> None:
        if not key_agreement and (encipher_only or decipher_only):
            raise ValueError(
                "encipher_only and decipher_only cannot be true unless "
                "key_agreement is true"
            )

        self._digital_signature = digital_signature
        self._content_commitment = content_commitment
        self._key_encipherment = key_encipherment
        self._data_encipherment = data_encipherment
        self._key_agreement = key_agreement
        self._key_cert_sign = key_cert_sign
        self._crl_sign = crl_sign
        self._encipher_only = encipher_only
        self._decipher_only = decipher_only

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, KeyUsage):
            return NotImplemented
        return (
            self.digital_signature == other.digital_signature
            and self.content_commitment == other.content_commitment
            and self.key_encipherment == other.key_encipherment
            and self.data_encipherment == other.data_encipherment
            and self.key_agreement == other.key_agreement
            and self.key_cert_sign == other.key_cert_sign
            and self.crl_sign == other.crl_sign
            and self._encipher_only == other._encipher_only
            and self._decipher_only == other._decipher_only
        )

    def __hash__(self) -> int:
        return hash(
            (
                self.digital_signature,
                self.content_commitment,
                self.key_encipherment,
                self.data_encipherment,
                self.key_agreement,
                self.key_cert_sign,
                self.crl_sign,
                self._encipher_only,
                self._decipher_only,
            )
        )

    def __repr__(self) -> str:
        try:
            encipher_only = self.encipher_only
            decipher_only = self.decipher_only
        except ValueError:
            encipher_only = False
            decipher_only = False

        return (
            f"<KeyUsage("
            f"digital_signature={self.digital_signature}, "
            f"content_commitment={self.content_commitment}, "
            f"key_encipherment={self.key_encipherment}, "
            f"data_encipherment={self.data_encipherment}, "
            f"key_agreement={self.key_agreement}, "
            f"key_cert_sign={self.key_cert_sign}, "
            f"crl_sign={self.crl_sign}, "
            f"encipher_only={encipher_only}, "
            f"decipher_only={decipher_only})>"
        )

    @property
    def digital_signature(self) -> bool:
        return self._digital_signature

    @property
    def content_commitment(self) -> bool:
        return self._content_commitment

    @property
    def key_encipherment(self) -> bool:
        return self._key_encipherment

    @property
    def data_encipherment(self) -> bool:
        return self._data_encipherment

    @property
    def key_agreement(self) -> bool:
        return self._key_agreement

    @property
    def key_cert_sign(self) -> bool:
        return self._key_cert_sign

    @property
    def crl_sign(self) -> bool:
        return self._crl_sign

    @property
    def encipher_only(self) -> bool:
        if not self.key_agreement:
            raise ValueError("encipher_only is undefined")
        return self._encipher_only

    @property
    def decipher_only(self) -> bool:
        if not self.key_agreement:
            raise ValueError("decipher_only is undefined")
        return self._decipher_only

    def to_encoder(self) -> asn1.BitString:
        bits = (
            self.digital_signature,
            self.content_commitment,
            self.key_encipherment,
            self.data_encipherment,
            self.key_agreement,
            self.key_cert_sign,
            self.crl_sign,
            self._encipher_only,
            self._decipher_only,
        )
        return asn1.BitString.from_bits(bits)

    @classmethod
    def from_decoder(cls, value: asn1.BitString) -> KeyUsage:
        bits = value.as_bits()
        bits.extend([False] * (9 - len(bits)))
        return KeyUsage(*bits)


@asn1.mapped(base_type=asn1.SequenceOf[ObjectIdentifier])
class ExtendedKeyUsage(ExtensionType):
    oid = ExtensionOID.EXTENDED_KEY_USAGE

    # ExtKeyUsageSyntax ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId
    # KeyPurposeId ::= OBJECT IDENTIFIER

    def __init__(
        self,
        usages: typing.Iterable[ObjectIdentifier],
        *,
        _from_decoder: bool = False,
    ) -> None:
        if not _from_decoder:
            usages = list(usages)
        else:
            usages = typing.cast(list[ObjectIdentifier], usages)

        self._usages = usages

    def __iter__(self) -> typing.Iterator[ObjectIdentifier]:
        return iter(self._usages)

    def __repr__(self) -> str:
        return f"<ExtendedKeyUsages({self._usages})>"

    def to_encoder(self) -> list[ObjectIdentifier]:
        return self._usages

    @classmethod
    def from_decoder(cls, value: list[ObjectIdentifier]) -> ExtendedKeyUsage:
        return ExtendedKeyUsage(value, _from_decoder=True)


@asn1.mapped(base_type=GeneralNames)
class SubjectAlternativeName(ExtensionType):
    oid = ExtensionOID.SUBJECT_ALTERNATIVE_NAME

    # SubjectAltName ::= GeneralNames

    def __init__(
        self,
        general_names: typing.Iterable[GeneralName],
        *,
        _from_decoder: bool = False,
    ) -> None:
        if not _from_decoder:
            general_names = GeneralNames(general_names)
        else:
            general_names = typing.cast(GeneralNames, general_names)

        self._general_names = general_names

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
    ) -> list[ObjectIdentifier]: ...

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
        | list[ObjectIdentifier]
    ):
        return self._general_names.get_values_for_type(type)

    def __iter__(self) -> typing.Iterator[GeneralName]:
        return iter(self._general_names)

    def __repr__(self) -> str:
        return f"<SubjectAlternativeName({self._general_names})>"

    def to_encoder(self) -> GeneralNames:
        return self._general_names

    @classmethod
    def from_decoder(cls, value: GeneralNames) -> SubjectAlternativeName:
        return SubjectAlternativeName(value, _from_decoder=True)


@asn1.mapped(base_type=GeneralNames)
class IssuerAlternativeName(ExtensionType):
    oid = ExtensionOID.ISSUER_ALTERNATIVE_NAME

    # IssuerAltName ::= GeneralNames

    def __init__(
        self,
        general_names: typing.Iterable[GeneralName],
        *,
        _from_decoder: bool = False,
    ) -> None:
        if not _from_decoder:
            general_names = GeneralNames(general_names)
        else:
            general_names = typing.cast(GeneralNames, general_names)

        self._general_names = general_names

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
    ) -> list[ObjectIdentifier]: ...

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
        | list[ObjectIdentifier]
    ):
        return self._general_names.get_values_for_type(type)

    def __iter__(self) -> typing.Iterator[GeneralName]:
        return iter(self._general_names)

    def __repr__(self) -> str:
        return f"<IssuerAlternativeName({self._general_names})>"

    def to_encoder(self) -> GeneralNames:
        return self._general_names

    @classmethod
    def from_decoder(cls, value: GeneralNames) -> IssuerAlternativeName:
        return IssuerAlternativeName(value, _from_decoder=True)


# DisplayText ::= CHOICE {
#     ia5String        IA5String      (SIZE (1..200)),
#     visibleString    VisibleString  (SIZE (1..200)),
#     bmpString        BMPString      (SIZE (1..200)),
#     utf8String       UTF8String     (SIZE (1..200))
# }
_DisplayText = typing.Union[
    asn1.Variant[typing.Literal["ia5_string"], asn1.IA5String],
    asn1.Variant[typing.Literal["visible_string"], asn1.VisibleString],
    asn1.Variant[typing.Literal["utf8_string"], asn1.UTF8String],
    asn1.Variant[typing.Literal["bmp_string"], asn1.BMPString],
]


@asn1.sequence(frozen=True)
class NoticeReference:
    # NoticeReference ::= SEQUENCE {
    #     organization     DisplayText,
    #     noticeNumbers    SEQUENCE OF INTEGER
    # }
    organization: _DisplayText
    notice_numbers: asn1.SequenceOf[int]


@asn1.sequence(frozen=True)
class UserNotice:
    # UserNotice ::= SEQUENCE {
    #     noticeRef        NoticeReference OPTIONAL,
    #     explicitText     DisplayText OPTIONAL
    # }
    notice_reference: NoticeReference | None
    explicit_text: _DisplayText | None


_QUALIFIER_OPENTYPE = asn1.OpenType(
    base_type=asn1.Any,
    defined_by="qualifier_id",
    typemap={
        CertificatePoliciesOID.CPS_QUALIFIER: asn1.IA5String,
        CertificatePoliciesOID.CPS_USER_NOTICE: UserNotice,
    },
)


@asn1.sequence(frozen=True)
class PolicyQualifier:
    # PolicyQualifierInfo ::= SEQUENCE {
    #     policyQualifierId  PolicyQualifierId,
    #     qualifier          ANY DEFINED BY policyQualifierId
    # }
    qualifier_id: ObjectIdentifier
    qualifier: asn1.Annotated[asn1.IA5String | UserNotice, _QUALIFIER_OPENTYPE]


@asn1.sequence(frozen=True)
class PolicyInformation:
    # PolicyInformation ::= SEQUENCE {
    #     policyIdentifier   CertPolicyId,
    #     policyQualifiers   SEQUENCE SIZE (1..MAX) OF
    #                        PolicyQualifierInfo OPTIONAL
    # }
    policy_identifier: ObjectIdentifier
    policy_qualifiers: asn1.SequenceOf[PolicyQualifier] | None


@asn1.mapped(base_type=asn1.SequenceOf[PolicyInformation])
class CertificatePolicies(ExtensionType):
    oid = ExtensionOID.CERTIFICATE_POLICIES

    # certificatePolicies ::= SEQUENCE SIZE (1..MAX) OF PolicyInformation

    def __init__(
        self,
        policies: typing.Iterable[PolicyInformation],
        *,
        _from_decoder: bool = False,
    ) -> None:
        if not _from_decoder:
            policies = list(policies)
        else:
            policies = typing.cast(list[PolicyInformation], policies)

        self._policies = policies

    def __iter__(self) -> typing.Iterator[PolicyInformation]:
        return iter(self._policies)

    def __repr__(self) -> str:
        return f"<CertificatePolicies({self._policies})>"

    def to_encoder(self) -> list[PolicyInformation]:
        return self._policies

    @classmethod
    def from_decoder(
        cls, value: list[PolicyInformation]
    ) -> CertificatePolicies:
        return CertificatePolicies(value, _from_decoder=True)


@asn1.sequence(frozen=True)
class PrivateKeyUsagePeriod(ExtensionType):
    oid = ExtensionOID.PRIVATE_KEY_USAGE_PERIOD

    # PrivateKeyUsagePeriod ::= SEQUENCE {
    #     notBefore [0] GeneralizedTime OPTIONAL,
    #     notAfter  [1] GeneralizedTime OPTIONAL
    # } (WITH COMPONENTS {..., notBefore PRESENT} |
    # WITH COMPONENTS {..., notAfter PRESENT} )
    not_before: asn1.Annotated[asn1.GeneralizedTime, asn1.Implicit(0)] | None
    not_after: asn1.Annotated[asn1.GeneralizedTime, asn1.Implicit(1)] | None


@asn1.sequence(frozen=True)
class PolicyMapping:
    issuer_domain_policy: ObjectIdentifier
    subject_domain_policy: ObjectIdentifier


@asn1.mapped(base_type=asn1.SequenceOf[PolicyMapping])
class PolicyMappings(ExtensionType):
    oid = ExtensionOID.POLICY_MAPPINGS

    # PolicyMappings ::= SEQUENCE SIZE (1..MAX) OF SEQUENCE {
    #     issuerDomainPolicy      CertPolicyId,
    #     subjectDomainPolicy     CertPolicyId
    # }

    def __init__(
        self,
        policy_mappings: typing.Iterable[PolicyMapping],
        *,
        _from_decoder: bool = False,
    ) -> None:
        if not _from_decoder:
            policy_mappings = list(policy_mappings)
        else:
            policy_mappings = typing.cast(list[PolicyMapping], policy_mappings)

        self._policy_mappings = policy_mappings

    def __iter__(self) -> typing.Iterator[PolicyMapping]:
        return iter(self._policy_mappings)

    def __repr__(self) -> str:
        return f"<PolicyMappings({self._policy_mappings})>"

    def to_encoder(self) -> list[PolicyMapping]:
        return self._policy_mappings

    @classmethod
    def from_decoder(cls, value: list[PolicyMapping]) -> PolicyMappings:
        return PolicyMappings(value, _from_decoder=True)


@asn1.mapped(base_type=asn1.OctetString)
class PrecertificateSignedCertificateTimestamps(ExtensionType):
    oid = ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS

    def __init__(
        self,
        signed_certificate_timestamps: typing.Iterable[
            SignedCertificateTimestamp
        ],
        *,
        _from_decoder: bool = False,
    ) -> None:
        if not _from_decoder:
            signed_certificate_timestamps = list(signed_certificate_timestamps)
        else:
            signed_certificate_timestamps = typing.cast(
                list[SignedCertificateTimestamp], signed_certificate_timestamps
            )

        self._scts = signed_certificate_timestamps

    def __iter__(self) -> typing.Iterator[SignedCertificateTimestamp]:
        return iter(self._scts)

    def __repr__(self) -> str:
        return (
            f"<PrecertificateSignedCertificateTimestamps({list(self._scts)})>"
        )

    def to_encoder(self) -> bytes:
        return _serialize_signed_certificate_timestamps(self._scts)

    @classmethod
    def from_decoder(
        cls, value: bytes
    ) -> PrecertificateSignedCertificateTimestamps:
        scts = _parse_signed_certificate_timestamps(
            value, LogEntryType.PRE_CERTIFICATE
        )
        return PrecertificateSignedCertificateTimestamps(
            scts, _from_decoder=True
        )


@asn1.mapped(base_type=asn1.OctetString)
class SignedCertificateTimestamps(ExtensionType):
    oid = ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS

    def __init__(
        self,
        signed_certificate_timestamps: typing.Iterable[
            SignedCertificateTimestamp
        ],
        *,
        _from_decoder: bool = False,
    ) -> None:
        if not _from_decoder:
            signed_certificate_timestamps = list(signed_certificate_timestamps)
        else:
            signed_certificate_timestamps = typing.cast(
                list[SignedCertificateTimestamp], signed_certificate_timestamps
            )

        self._scts = signed_certificate_timestamps

    def __iter__(self) -> typing.Iterator[SignedCertificateTimestamp]:
        return iter(self._scts)

    def __repr__(self) -> str:
        return f"<SignedCertificateTimestamps({list(self._scts)})>"

    def to_encoder(self) -> bytes:
        return _serialize_signed_certificate_timestamps(self._scts)

    @classmethod
    def from_decoder(cls, value: bytes) -> SignedCertificateTimestamps:
        scts = _parse_signed_certificate_timestamps(
            value, LogEntryType.X509_CERTIFICATE
        )
        return SignedCertificateTimestamps(scts, _from_decoder=True)


_NsComment = typing.Union[
    asn1.Variant[typing.Literal["ia5_string"], asn1.IA5String],
    asn1.Variant[typing.Literal["printable_string"], asn1.PrintableString],
]


@asn1.mapped(base_type=_NsComment)
class NetscapeComment(ExtensionType):
    oid = ExtensionOID.NS_COMMENT

    def __init__(self, comment: str, *, _type: str = "ia5_string") -> None:
        self._comment = comment
        self._type = _type

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, NetscapeComment):
            return NotImplemented
        return self.comment == other.comment

    def __hash__(self) -> int:
        return hash(self.comment)

    def __repr__(self) -> str:
        return f"<NsComment({self.comment})>"

    @property
    def comment(self) -> str:
        return self._comment

    def to_encoder(self) -> asn1.Variant:
        return asn1.Variant(self._type, self.comment)

    @classmethod
    def from_decoder(cls, value: _DisplayText) -> NetscapeComment:
        return NetscapeComment(value.value, _type=value.name)


_EXTENSION_MAP: dict[ObjectIdentifier, type] = {
    ExtensionOID.CRL_NUMBER: CRLNumber,
    ExtensionOID.NAME_CONSTRAINTS: NameConstraints,
    ExtensionOID.BASIC_CONSTRAINTS: BasicConstraints,
    ExtensionOID.AUTHORITY_INFORMATION_ACCESS: AuthorityInformationAccess,
    ExtensionOID.SUBJECT_ALTERNATIVE_NAME: SubjectAlternativeName,
    ExtensionOID.SUBJECT_KEY_IDENTIFIER: SubjectKeyIdentifier,
    ExtensionOID.SUBJECT_INFORMATION_ACCESS: SubjectInformationAccess,
    ExtensionOID.CRL_DISTRIBUTION_POINTS: CRLDistributionPoints,
    ExtensionOID.KEY_USAGE: KeyUsage,
    ExtensionOID.EXTENDED_KEY_USAGE: ExtendedKeyUsage,
    ExtensionOID.AUTHORITY_KEY_IDENTIFIER: AuthorityKeyIdentifier,
    ExtensionOID.CERTIFICATE_POLICIES: CertificatePolicies,
    ExtensionOID.PRIVATE_KEY_USAGE_PERIOD: PrivateKeyUsagePeriod,
    ExtensionOID.NS_COMMENT: NetscapeComment,
    ExtensionOID.POLICY_MAPPINGS: PolicyMappings,
    ExtensionOID.ISSUER_ALTERNATIVE_NAME: IssuerAlternativeName,
    ExtensionOID.SIGNED_CERTIFICATE_TIMESTAMPS: SignedCertificateTimestamps,
    ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS: (
        PrecertificateSignedCertificateTimestamps
    ),
}
