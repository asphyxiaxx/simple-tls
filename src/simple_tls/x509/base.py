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

import binascii
import datetime
import enum
import typing

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import (
    dsa,
    ec,
    ed448,
    ed25519,
    padding,
    rsa,
)
from cryptography.hazmat.primitives.asymmetric.types import (
    CertificatePublicKeyTypes,
)
from cryptography.hazmat.primitives.serialization import load_der_public_key

from ..io import asn1, asn1_module, pem
from ..io.oid import (
    AlgorithmIdentifier,
    ObjectIdentifier,
    PublicKeyAlgorithmOID,
    SignatureAlgorithmOID,
)
from .extensions import Extensions
from .name import Name


class InvalidVersion(Exception):
    pass


class Version(enum.IntEnum):
    v1 = 0
    v2 = 1
    v3 = 2


class Encoding(enum.Enum):
    DER = "DER"
    PEM = "PEM"


_Time = typing.Union[
    asn1.Variant[typing.Literal["utc_time"], asn1.UTCTime],
    asn1.Variant[typing.Literal["general_time"], asn1.GeneralizedTime],
]


@asn1.sequence(frozen=True)
class Validity:
    # Validity ::= SEQUENCE {
    #     notBefore      Time,
    #     notAfter       Time
    # }
    not_before: _Time
    not_after: _Time


@asn1.sequence
class TBSCertificate:
    # Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }
    #
    # CertificateSerialNumber  ::=  INTEGER
    #
    # Validity ::= SEQUENCE {
    #     notBefore      Time,
    #     notAfter       Time
    # }
    #
    # Time ::= CHOICE {
    #     utcTime        UTCTime,
    #     generalTime    GeneralizedTime
    # }
    #
    # UniqueIdentifier  ::=  BIT STRING
    #
    # SubjectPublicKeyInfo  ::=  SEQUENCE  {
    #     algorithm            AlgorithmIdentifier,
    #     subjectPublicKey     BIT STRING
    # }
    #
    # Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension
    #
    # TBSCertificate  ::=  SEQUENCE  {
    #    version         [0]  Version DEFAULT v1,
    #    serialNumber         CertificateSerialNumber,
    #    signature            AlgorithmIdentifier,
    #    issuer               Name,
    #    validity             Validity,
    #    subject              Name,
    #    subjectPublicKeyInfo SubjectPublicKeyInfo,
    #    issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
    #                        -- If present, version MUST be v2 or v3
    #    subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
    #                        -- If present, version MUST be v2 or v3
    #    extensions      [3]  Extensions OPTIONAL
    #                        -- If present, version MUST be v3 --
    # }
    version: asn1.Annotated[asn1.Integer, asn1.Explicit(0)] = Version.v1
    serial_number: asn1.Integer
    signature_algorithm: AlgorithmIdentifier
    issuer: Name
    validity: Validity
    subject: Name
    subject_public_key_info: asn1_module.SubjectPublicKeyInfo
    issuer_unique_id: asn1.Annotated[asn1.BitString, asn1.Implicit(1)] | None
    subject_unique_id: asn1.Annotated[asn1.BitString, asn1.Implicit(2)] | None
    extensions_bytes: asn1.Annotated[asn1.Any, asn1.Explicit(3)] | None

    def __post_init__(self) -> None:
        if self.version not in (Version.v1, Version.v2, Version.v3):
            raise InvalidVersion(self.version)

    def public_key(self) -> CertificatePublicKeyTypes:
        self._public_key: CertificatePublicKeyTypes
        try:
            return self._public_key
        except AttributeError:
            pass

        binary_data = asn1.encode(
            self.subject_public_key_info, asn1_module.SubjectPublicKeyInfo
        )
        self._public_key = typing.cast(
            CertificatePublicKeyTypes, load_der_public_key(binary_data)
        )
        return self._public_key

    @property
    def extensions(self) -> Extensions:
        self._extensions: Extensions
        try:
            return self._extensions
        except AttributeError:
            pass

        if self.extensions_bytes is None:
            self._extensions = Extensions([])
        else:
            self._extensions, _ = asn1.decode(
                self.extensions_bytes,
                Extensions,
                root_name=Extensions.__name__,
            )

        return self._extensions

    def __repr__(self) -> str:
        return (
            f"<TBSCertificate"
            f"(version={self.version!r}, "
            f"serial_number={self.serial_number!r}, "
            f"signature_algorithm={self.signature_algorithm!r}, "
            f"issuer={self.issuer!r}, "
            f"validity={self.validity!r}, "
            f"subject={self.subject!r}, "
            f"subject_public_key_info={self.subject_public_key_info!r}, "
            f"issuer_unique_id={self.issuer_unique_id!r}, "
            f"subject_unique_id={self.subject_unique_id!r}, "
            f"extensions={self.extensions})>"
        )


@asn1.sequence(frozen=True)
class Certificate:
    # Certificate  ::=  SEQUENCE  {
    #     tbsCertificate       TBSCertificate,
    #     signatureAlgorithm   AlgorithmIdentifier,
    #     signatureValue       BIT STRING
    # }
    tbs_certificate: TBSCertificate
    signature_algorithm: AlgorithmIdentifier
    signature_value: asn1.BitString

    def fingerprint(self, algorithm: hashes.HashAlgorithm) -> bytes:
        binary_data = asn1.encode(self, Certificate)
        msg_hash = hashes.Hash(algorithm)
        msg_hash.update(binary_data)
        return binascii.b2a_hex(msg_hash.finalize())

    def public_key(self) -> CertificatePublicKeyTypes:
        return self.tbs_certificate.public_key()

    @property
    def version(self) -> Version:
        return Version(self.tbs_certificate.version)

    @property
    def serial_number(self) -> int:
        return self.tbs_certificate.serial_number

    @property
    def public_key_algorithm_oid(self) -> ObjectIdentifier:
        return self.tbs_certificate.subject_public_key_info.algorithm.oid

    @property
    def not_valid_before_utc(self) -> datetime.datetime:
        return self.tbs_certificate.validity.not_before.value

    @property
    def not_valid_after_utc(self) -> datetime.datetime:
        return self.tbs_certificate.validity.not_after.value

    @property
    def issuer(self) -> Name:
        return self.tbs_certificate.issuer

    @property
    def subject(self) -> Name:
        return self.tbs_certificate.subject

    @property
    def signature_algorithm_oid(self) -> ObjectIdentifier:
        return self.tbs_certificate.signature_algorithm.oid

    @property
    def signature_algorithm_parameters(self) -> bytes | None:
        return self.tbs_certificate.signature_algorithm.parameters

    @property
    def signature(self) -> bytes:
        return self.signature_value.data

    @property
    def extensions(self) -> Extensions:
        return self.tbs_certificate.extensions

    @property
    def tbs_certificate_bytes(self) -> bytes:
        return asn1.encode(self.tbs_certificate, TBSCertificate)

    def public_bytes(self, encoding: Encoding) -> bytes:
        binary_data = asn1.encode(self, Certificate)
        if encoding == Encoding.DER:
            return binary_data
        elif encoding == Encoding.PEM:
            return pem.encode(binary_data, b"CERTIFICATE")
        raise TypeError("encoding must be Encoding.DER or Encoding.PEM")

    def verify_directly_issued_by(self, issuer: Certificate) -> None:
        if not isinstance(issuer, Certificate):
            raise TypeError("Not Certificate object")

        if (
            self.signature_algorithm
            != self.tbs_certificate.signature_algorithm
        ):
            raise ValueError("inner and outer signature_algorithm mismatch")

        if self.tbs_certificate.issuer != issuer.subject:
            raise ValueError("'issuer' doesn't match issuer 'subject'")

        issuer_public_key = issuer.public_key()
        public_key_algorithm_oid = issuer.public_key_algorithm_oid

        try:
            algorithm = _SIG_OIDS_TO_HASH[self.signature_algorithm_oid]
        except KeyError:
            raise ValueError(
                f"Certificate have unsupported signature algorihtm "
                f"{self.signature_algorithm_oid}"
            ) from None

        try:
            verifier_func = _PUBKEY_OIDS_TO_SIGSCHEME[public_key_algorithm_oid]
        except KeyError:
            raise ValueError(
                f"Certificate have unsupported public key "
                f"'{public_key_algorithm_oid}'"
            ) from None

        signature = self.signature
        msg = self.tbs_certificate_bytes

        try:
            verifier_func(issuer_public_key, signature, msg, algorithm)
        except TypeError:
            raise ValueError("Invalid key type") from None
        except InvalidSignature:
            raise

    def __repr__(self) -> str:
        return f"<Certificate(subject={self.subject}, ...)>"


def load_der_x509_certificate(data: bytes) -> Certificate:
    try:
        return asn1.decode(data, Certificate)[0]
    except asn1.ASN1Error as exc:
        raise ValueError(f"Error parsing Certificate: {exc}") from None


def load_der_x509_certificates(data: bytes) -> list[Certificate]:
    certs: list[Certificate] = []

    while data:
        try:
            x509, data = asn1.decode(data, Certificate)
        except asn1.ASN1Error as exc:
            raise ValueError(f"Error parsing Certificate: {exc}") from None
        certs.append(x509)

    return certs


def load_pem_x509_certificate(data: bytes) -> Certificate:
    endpos = 0

    while endpos < len(data):
        try:
            result = pem.decode(data, pos=endpos)
        except ValueError:
            break

        endpos = result.endpos

        if result.marker == b"CERTIFICATE":
            return load_der_x509_certificate(result.data)

    raise TypeError("Not a certificate PEM file")


def load_pem_x509_certificates(data: bytes) -> list[Certificate]:
    certificates: list[Certificate] = []
    endpos = 0

    while endpos < len(data):
        try:
            result = pem.decode(data, pos=endpos)
        except ValueError:
            break
        endpos = result.endpos
        if not result.marker == b"CERTIFICATE":
            continue
        certificate = load_der_x509_certificate(result.data)
        certificates.append(certificate)

    return certificates


# Internal


def _verify_dsa(
    key: CertificatePublicKeyTypes,
    signature: bytes,
    data: bytes,
    algorithm: hashes.HashAlgorithm | None,
) -> None:
    if not isinstance(key, dsa.DSAPublicKey):
        raise TypeError("Invalid key type")
    if algorithm is None:
        raise ValueError("Missing algorithm")

    key.verify(signature, data, algorithm)


def _verify_ec(
    key: CertificatePublicKeyTypes,
    signature: bytes,
    data: bytes,
    algorithm: hashes.HashAlgorithm | None,
) -> None:
    if not isinstance(key, ec.EllipticCurvePublicKey):
        raise TypeError("Invalid key type")
    if algorithm is None:
        raise ValueError("Missing algorithm")

    signature_algorithm = ec.ECDSA(algorithm)
    key.verify(signature, data, signature_algorithm)


def _verify_rsa_pkcs115(
    key: CertificatePublicKeyTypes,
    signature: bytes,
    data: bytes,
    algorithm: hashes.HashAlgorithm | None,
) -> None:
    if not isinstance(key, rsa.RSAPublicKey):
        raise TypeError("Invalid key type")
    if algorithm is None:
        raise ValueError("Missing algorithm")

    p = padding.PKCS1v15()
    key.verify(signature, data, p, algorithm)


def _verify_rsa_pss(
    key: CertificatePublicKeyTypes,
    signature: bytes,
    data: bytes,
    algorithm: hashes.HashAlgorithm | None,
) -> None:
    if not isinstance(key, rsa.RSAPublicKey):
        raise TypeError("Invalid key type")
    if algorithm is None:
        raise ValueError("Missing algorithm")

    p = padding.PSS(
        mgf=padding.MGF1(algorithm),
        salt_length=algorithm.digest_size,
    )
    key.verify(signature, data, p, algorithm)


def _verify_ed25519(
    key: CertificatePublicKeyTypes,
    signature: bytes,
    data: bytes,
    algorithm: hashes.HashAlgorithm | None,
) -> None:
    if not isinstance(key, ed25519.Ed25519PublicKey):
        raise TypeError("Invalid key type")
    if algorithm is not None:
        raise ValueError("algorithm not None")

    key.verify(signature, data)


def _verify_ed448(
    key: CertificatePublicKeyTypes,
    signature: bytes,
    data: bytes,
    algorithm: hashes.HashAlgorithm | None,
) -> None:
    if not isinstance(key, ed448.Ed448PublicKey):
        raise TypeError("Invalid key type")
    if algorithm is not None:
        raise ValueError("algorithm not None")

    key.verify(signature, data)


_SIG_OIDS_TO_HASH = {
    SignatureAlgorithmOID.RSA_WITH_MD5: hashes.MD5(),
    SignatureAlgorithmOID.RSA_WITH_SHA1: hashes.SHA1(),
    SignatureAlgorithmOID.RSA_WITH_SHA224: hashes.SHA224(),
    SignatureAlgorithmOID.RSA_WITH_SHA256: hashes.SHA256(),
    SignatureAlgorithmOID.RSA_WITH_SHA384: hashes.SHA384(),
    SignatureAlgorithmOID.RSA_WITH_SHA512: hashes.SHA512(),
    SignatureAlgorithmOID.DSA_WITH_SHA1: hashes.SHA1(),
    SignatureAlgorithmOID.DSA_WITH_SHA224: hashes.SHA224(),
    SignatureAlgorithmOID.DSA_WITH_SHA256: hashes.SHA256(),
    SignatureAlgorithmOID.ECDSA_WITH_SHA1: hashes.SHA1(),
    SignatureAlgorithmOID.ECDSA_WITH_SHA224: hashes.SHA224(),
    SignatureAlgorithmOID.ECDSA_WITH_SHA256: hashes.SHA256(),
    SignatureAlgorithmOID.ECDSA_WITH_SHA384: hashes.SHA384(),
    SignatureAlgorithmOID.ECDSA_WITH_SHA512: hashes.SHA512(),
    SignatureAlgorithmOID.ED25519: None,
    SignatureAlgorithmOID.ED448: None,
}

_PUBKEY_OIDS_TO_SIGSCHEME = {
    PublicKeyAlgorithmOID.DSA: _verify_dsa,
    PublicKeyAlgorithmOID.EC_PUBLIC_KEY: _verify_ec,
    PublicKeyAlgorithmOID.RSAES_PKCS1_v1_5: _verify_rsa_pkcs115,
    PublicKeyAlgorithmOID.RSASSA_PSS: _verify_rsa_pss,
    PublicKeyAlgorithmOID.ED25519: _verify_ed25519,
    PublicKeyAlgorithmOID.ED448: _verify_ed448,
}
