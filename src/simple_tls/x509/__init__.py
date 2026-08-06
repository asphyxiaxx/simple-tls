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

from ..io.oid import (
    AlgorithmIdentifier,
    AuthorityInformationAccessOID,
    CRLEntryExtensionOID,
    ExtendedKeyUsageOID,
    ExtensionOID,
    NameOID,
    ObjectIdentifier,
    PublicKeyAlgorithmOID,
)
from .base import (
    Certificate,
    Encoding,
    InvalidVersion,
    Version,
    load_der_x509_certificate,
    load_der_x509_certificates,
    load_pem_x509_certificate,
    load_pem_x509_certificates,
)
from .extensions import (
    AccessDescription,
    AuthorityInformationAccess,
    AuthorityKeyIdentifier,
    BasicConstraints,
    CertificatePolicies,
    CRLDistributionPoints,
    CRLNumber,
    DistributionPoint,
    ExtendedKeyUsage,
    Extension,
    ExtensionNotFound,
    Extensions,
    ExtensionType,
    IssuerAlternativeName,
    KeyUsage,
    NameConstraints,
    NoticeReference,
    PolicyInformation,
    ReasonFlags,
    SubjectAlternativeName,
    SubjectInformationAccess,
    SubjectKeyIdentifier,
    UnrecognizedExtension,
    UserNotice,
)
from .name import (
    DirectoryName,
    DNSName,
    GeneralName,
    GeneralNames,
    IPAddress,
    Name,
    NameAttribute,
    OtherName,
    RegisteredID,
    RelativeDistinguishedName,
    RFC822Name,
    UniformResourceIdentifier,
)
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
    "AlgorithmIdentifier",
    "AuthorityInformationAccess",
    "AuthorityInformationAccessOID",
    "AuthorityKeyIdentifier",
    "BasicConstraints",
    "CRLDistributionPoints",
    "CRLEntryExtensionOID",
    "CRLNumber",
    "Certificate",
    "CertificateExpired",
    "CertificateNotYetValid",
    "CertificatePolicies",
    "DNSName",
    "DirectoryName",
    "DistributionPoint",
    "Encoding",
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
    "IssuerAlternativeName",
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
