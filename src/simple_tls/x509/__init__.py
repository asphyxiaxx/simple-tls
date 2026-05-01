# Copyright (c) 2026 The simple-tls Contributors

# Permission is hereby granted, free of charge, to any person obtaining a copy of
# this software and associated documentation files (the “Software”), to deal in
# the Software without restriction, including without limitation the rights to
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
# the Software, and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
# FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
# COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
# IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

from __future__ import annotations

import typing

from cryptography.x509 import (
    AccessDescription,
    AuthorityInformationAccess,
    AuthorityKeyIdentifier,
    BasicConstraints,
    Certificate,
    CertificatePolicies,
    CRLDistributionPoints,
    CRLNumber,
    DirectoryName,
    DistributionPoint,
    DNSName,
    ExtendedKeyUsage,
    ExtendedKeyUsageOID,
    Extension,
    ExtensionNotFound,
    ExtensionOID,
    Extensions,
    ExtensionType,
    GeneralName,
    GeneralNames,
    InvalidVersion,
    IPAddress,
    KeyUsage,
    Name,
    NameAttribute,
    NameConstraints,
    NameOID,
    NoticeReference,
    ObjectIdentifier,
    OtherName,
    PolicyInformation,
    PublicKeyAlgorithmOID,
    ReasonFlags,
    RegisteredID,
    RelativeDistinguishedName,
    RFC822Name,
    SubjectAlternativeName,
    SubjectInformationAccess,
    SubjectKeyIdentifier,
    UniformResourceIdentifier,
    UnrecognizedExtension,
    UserNotice,
    Version,
    load_der_x509_certificate,
    load_pem_x509_certificate,
    load_pem_x509_certificates,
)

from ..utils.math import bytes_to_int
from .verification import (
    CertificateExpired,
    CertificateNotYetValid,
    ExtensionPolicy,
    PolicyViolationError,
    SignatureVerificationError,
    Store,
    UntrustedRoot,
    VerificationError,
    Verifier,
)

__all__ = [
    "AccessDescription",
    "AuthorityInformationAccess",
    "AuthorityKeyIdentifier",
    "BasicConstraints",
    "CRLDistributionPoints",
    "CRLNumber",
    "Certificate",
    "CertificateExpired",
    "CertificateNotYetValid",
    "CertificatePolicies",
    "DNSName",
    "DirectoryName",
    "DistributionPoint",
    "ExtendedKeyUsage",
    "ExtendedKeyUsageOID",
    "Extension",
    "ExtensionNotFound",
    "ExtensionOID",
    "ExtensionPolicy",
    "ExtensionType",
    "Extensions",
    "GeneralName",
    "GeneralNames",
    "IPAddress",
    "InvalidVersion",
    "KeyUsage",
    "Name",
    "NameAttribute",
    "NameConstraints",
    "NameOID",
    "NoticeReference",
    "ObjectIdentifier",
    "OtherName",
    "PolicyInformation",
    "PolicyViolationError",
    "PublicKeyAlgorithmOID",
    "RFC822Name",
    "ReasonFlags",
    "RegisteredID",
    "RelativeDistinguishedName",
    "SignatureVerificationError",
    "Store",
    "SubjectAlternativeName",
    "SubjectInformationAccess",
    "SubjectKeyIdentifier",
    "UniformResourceIdentifier",
    "UnrecognizedExtension",
    "UntrustedRoot",
    "UserNotice",
    "VerificationError",
    "Verifier",
    "Version",
    "load_der_x509_certificate",
    "load_der_x509_certificates",
    "load_pem_x509_certificate",
    "load_pem_x509_certificates",
]


def _decode_sequence_len(data: bytes, offset: int) -> tuple[int, int]:
    if offset >= len(data):
        raise ValueError("Truncated DER data while reading length header.")

    length_byte = data[offset]

    # Short form
    if (length_byte & 0x80) == 0:
        return length_byte, 1

    # Long form
    num_length_bytes = length_byte & 0x7F
    if num_length_bytes == 0:
        raise ValueError(
            "Indefinite length ASN.1 encoding is not supported for DER."
        )
    if offset + 1 + num_length_bytes > len(data):
        raise ValueError(
            "Truncated DER data while reading long form length bytes."
        )

    length = bytes_to_int(data[offset + 1 : offset + 1 + num_length_bytes])
    return length, 1 + num_length_bytes


def load_der_x509_certificates(
    data: bytes, backend: typing.Any | None = None
) -> list[Certificate]:
    certificates: list[Certificate] = []
    offset = 0
    data_len = len(data)

    while offset < data_len:
        # An X.509 certificate is always an ASN.1 SEQUENCE.
        if data[offset] != 0x30:
            raise ValueError(
                f"Invalid DER data at offset {offset}: Expected ASN.1 SEQUENCE tag "
                f"(0x30), got {hex(data[offset])}."
            )

        try:
            value_len, header_len = _decode_sequence_len(data, offset + 1)
        except IndexError:
            raise ValueError(f"Truncated DER data at offset {offset}.")

        total_cert_len = 1 + header_len + value_len

        if offset + total_cert_len > data_len:
            raise ValueError(
                f"Truncated DER data: Certificate at offset {offset} claims to be "
                f"{total_cert_len} bytes long, but only {data_len - offset} "
                f"bytes remain."
            )

        cert_bytes = data[offset : offset + total_cert_len]
        cert = load_der_x509_certificate(cert_bytes, backend)
        certificates.append(cert)

        offset += total_cert_len

    return certificates
