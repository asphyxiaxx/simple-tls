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

from .asn1 import ObjectIdentifier
from .asn1_module import AlgorithmIdentifier

__all__ = [
    "AlgorithmIdentifier",
    "CertificatePoliciesOID",
    "ExtendedKeyUsageOID",
    "ExtensionOID",
    "NameOID",
    "ObjectIdentifier",
    "PublicKeyAlgorithmOID",
    "SignatureAlgorithmOID",
]


class SignatureAlgorithmOID:
    RSA_WITH_MD5 = ObjectIdentifier("1.2.840.113549.1.1.4")
    RSA_WITH_SHA1 = ObjectIdentifier("1.2.840.113549.1.1.5")
    RSA_WITH_SHA224 = ObjectIdentifier("1.2.840.113549.1.1.14")
    RSA_WITH_SHA256 = ObjectIdentifier("1.2.840.113549.1.1.11")
    RSA_WITH_SHA384 = ObjectIdentifier("1.2.840.113549.1.1.12")
    RSA_WITH_SHA512 = ObjectIdentifier("1.2.840.113549.1.1.13")
    RSA_WITH_SHA3_224 = ObjectIdentifier("2.16.840.1.101.3.4.3.13")
    RSA_WITH_SHA3_256 = ObjectIdentifier("2.16.840.1.101.3.4.3.14")
    RSA_WITH_SHA3_384 = ObjectIdentifier("2.16.840.1.101.3.4.3.15")
    RSA_WITH_SHA3_512 = ObjectIdentifier("2.16.840.1.101.3.4.3.16")
    RSASSA_PSS = ObjectIdentifier("1.2.840.113549.1.1.10")
    DSA_WITH_SHA1 = ObjectIdentifier("1.2.840.10040.4.3")
    DSA_WITH_SHA224 = ObjectIdentifier("2.16.840.1.101.3.4.3.1")
    DSA_WITH_SHA256 = ObjectIdentifier("2.16.840.1.101.3.4.3.2")
    DSA_WITH_SHA384 = ObjectIdentifier("2.16.840.1.101.3.4.3.3")
    DSA_WITH_SHA512 = ObjectIdentifier("2.16.840.1.101.3.4.3.4")
    ECDSA_WITH_SHA1 = ObjectIdentifier("1.2.840.10045.4.1")
    ECDSA_WITH_SHA224 = ObjectIdentifier("1.2.840.10045.4.3.1")
    ECDSA_WITH_SHA256 = ObjectIdentifier("1.2.840.10045.4.3.2")
    ECDSA_WITH_SHA384 = ObjectIdentifier("1.2.840.10045.4.3.3")
    ECDSA_WITH_SHA512 = ObjectIdentifier("1.2.840.10045.4.3.4")
    ECDSA_WITH_SHA3_224 = ObjectIdentifier("2.16.840.1.101.3.4.3.9")
    ECDSA_WITH_SHA3_256 = ObjectIdentifier("2.16.840.1.101.3.4.3.10")
    ECDSA_WITH_SHA3_384 = ObjectIdentifier("2.16.840.1.101.3.4.3.11")
    ECDSA_WITH_SHA3_512 = ObjectIdentifier("2.16.840.1.101.3.4.3.12")
    ED25519 = ObjectIdentifier("1.3.101.112")
    ED448 = ObjectIdentifier("1.3.101.113")


class PublicKeyAlgorithmOID:
    DH = ObjectIdentifier("1.2.840.113549.1.3.1")
    DSA = ObjectIdentifier("1.2.840.10040.4.1")
    EC_PUBLIC_KEY = ObjectIdentifier("1.2.840.10045.2.1")
    ECDH = ObjectIdentifier("1.3.132.1.12")
    ECMQV = ObjectIdentifier("1.3.132.1.13")
    RSAES_PKCS1_v1_5 = ObjectIdentifier("1.2.840.113549.1.1.1")
    RSASSA_PSS = ObjectIdentifier("1.2.840.113549.1.1.10")
    X25519 = ObjectIdentifier("1.3.101.110")
    X448 = ObjectIdentifier("1.3.101.111")
    ED25519 = ObjectIdentifier("1.3.101.112")
    ED448 = ObjectIdentifier("1.3.101.113")


class ExtensionOID:
    SUBJECT_DIRECTORY_ATTRIBUTES = ObjectIdentifier("2.5.29.9")
    SUBJECT_KEY_IDENTIFIER = ObjectIdentifier("2.5.29.14")
    KEY_USAGE = ObjectIdentifier("2.5.29.15")
    PRIVATE_KEY_USAGE_PERIOD = ObjectIdentifier("2.5.29.16")
    SUBJECT_ALTERNATIVE_NAME = ObjectIdentifier("2.5.29.17")
    ISSUER_ALTERNATIVE_NAME = ObjectIdentifier("2.5.29.18")
    BASIC_CONSTRAINTS = ObjectIdentifier("2.5.29.19")
    NAME_CONSTRAINTS = ObjectIdentifier("2.5.29.30")
    CRL_DISTRIBUTION_POINTS = ObjectIdentifier("2.5.29.31")
    CERTIFICATE_POLICIES = ObjectIdentifier("2.5.29.32")
    POLICY_MAPPINGS = ObjectIdentifier("2.5.29.33")
    AUTHORITY_KEY_IDENTIFIER = ObjectIdentifier("2.5.29.35")
    POLICY_CONSTRAINTS = ObjectIdentifier("2.5.29.36")
    EXTENDED_KEY_USAGE = ObjectIdentifier("2.5.29.37")
    FRESHEST_CRL = ObjectIdentifier("2.5.29.46")
    INHIBIT_ANY_POLICY = ObjectIdentifier("2.5.29.54")
    ISSUING_DISTRIBUTION_POINT = ObjectIdentifier("2.5.29.28")
    AUTHORITY_INFORMATION_ACCESS = ObjectIdentifier("1.3.6.1.5.5.7.1.1")
    SUBJECT_INFORMATION_ACCESS = ObjectIdentifier("1.3.6.1.5.5.7.1.11")
    OCSP_NO_CHECK = ObjectIdentifier("1.3.6.1.5.5.7.48.1.5")
    TLS_FEATURE = ObjectIdentifier("1.3.6.1.5.5.7.1.24")
    CRL_NUMBER = ObjectIdentifier("2.5.29.20")
    DELTA_CRL_INDICATOR = ObjectIdentifier("2.5.29.27")
    PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS = ObjectIdentifier(
        "1.3.6.1.4.1.11129.2.4.2"
    )
    PRECERT_POISON = ObjectIdentifier("1.3.6.1.4.1.11129.2.4.3")
    SIGNED_CERTIFICATE_TIMESTAMPS = ObjectIdentifier("1.3.6.1.4.1.11129.2.4.5")
    MS_CERTIFICATE_TEMPLATE = ObjectIdentifier("1.3.6.1.4.1.311.21.7")
    ADMISSIONS = ObjectIdentifier("1.3.36.8.3.3")
    NS_COMMENT = ObjectIdentifier("2.16.840.1.113730.1.13")


class AuthorityInformationAccessOID:
    CA_ISSUERS = ObjectIdentifier("1.3.6.1.5.5.7.48.2")
    OCSP = ObjectIdentifier("1.3.6.1.5.5.7.48.1")


class CertificatePoliciesOID:
    CPS_QUALIFIER = ObjectIdentifier("1.3.6.1.5.5.7.2.1")
    CPS_USER_NOTICE = ObjectIdentifier("1.3.6.1.5.5.7.2.2")
    ANY_POLICY = ObjectIdentifier("2.5.29.32.0")


class ExtendedKeyUsageOID:
    SERVER_AUTH = ObjectIdentifier("1.3.6.1.5.5.7.3.1")
    CLIENT_AUTH = ObjectIdentifier("1.3.6.1.5.5.7.3.2")
    CODE_SIGNING = ObjectIdentifier("1.3.6.1.5.5.7.3.3")
    EMAIL_PROTECTION = ObjectIdentifier("1.3.6.1.5.5.7.3.4")
    TIME_STAMPING = ObjectIdentifier("1.3.6.1.5.5.7.3.8")
    OCSP_SIGNING = ObjectIdentifier("1.3.6.1.5.5.7.3.9")
    ANY_EXTENDED_KEY_USAGE = ObjectIdentifier("2.5.29.37.0")
    SMARTCARD_LOGON = ObjectIdentifier("1.3.6.1.4.1.311.20.2.2")
    KERBEROS_PKINIT_KDC = ObjectIdentifier("1.3.6.1.5.2.3.5")
    IPSEC_IKE = ObjectIdentifier("1.3.6.1.5.5.7.3.17")
    BUNDLE_SECURITY = ObjectIdentifier("1.3.6.1.5.5.7.3.35")
    CERTIFICATE_TRANSPARENCY = ObjectIdentifier("1.3.6.1.4.1.11129.2.4.4")


class CRLEntryExtensionOID:
    CERTIFICATE_ISSUER = ObjectIdentifier("2.5.29.29")
    CRL_REASON = ObjectIdentifier("2.5.29.21")
    INVALIDITY_DATE = ObjectIdentifier("2.5.29.24")


class NameOID:
    COMMON_NAME = ObjectIdentifier("2.5.4.3")
    COUNTRY_NAME = ObjectIdentifier("2.5.4.6")
    LOCALITY_NAME = ObjectIdentifier("2.5.4.7")
    STATE_OR_PROVINCE_NAME = ObjectIdentifier("2.5.4.8")
    STREET_ADDRESS = ObjectIdentifier("2.5.4.9")
    ORGANIZATION_IDENTIFIER = ObjectIdentifier("2.5.4.97")
    ORGANIZATION_NAME = ObjectIdentifier("2.5.4.10")
    ORGANIZATIONAL_UNIT_NAME = ObjectIdentifier("2.5.4.11")
    SERIAL_NUMBER = ObjectIdentifier("2.5.4.5")
    SURNAME = ObjectIdentifier("2.5.4.4")
    GIVEN_NAME = ObjectIdentifier("2.5.4.42")
    TITLE = ObjectIdentifier("2.5.4.12")
    INITIALS = ObjectIdentifier("2.5.4.43")
    GENERATION_QUALIFIER = ObjectIdentifier("2.5.4.44")
    X500_UNIQUE_IDENTIFIER = ObjectIdentifier("2.5.4.45")
    DN_QUALIFIER = ObjectIdentifier("2.5.4.46")
    PSEUDONYM = ObjectIdentifier("2.5.4.65")
    USER_ID = ObjectIdentifier("0.9.2342.19200300.100.1.1")
    DOMAIN_COMPONENT = ObjectIdentifier("0.9.2342.19200300.100.1.25")
    EMAIL_ADDRESS = ObjectIdentifier("1.2.840.113549.1.9.1")
    JURISDICTION_COUNTRY_NAME = ObjectIdentifier("1.3.6.1.4.1.311.60.2.1.3")
    JURISDICTION_LOCALITY_NAME = ObjectIdentifier("1.3.6.1.4.1.311.60.2.1.1")
    JURISDICTION_STATE_OR_PROVINCE_NAME = ObjectIdentifier(
        "1.3.6.1.4.1.311.60.2.1.2"
    )
    BUSINESS_CATEGORY = ObjectIdentifier("2.5.4.15")
    POSTAL_ADDRESS = ObjectIdentifier("2.5.4.16")
    POSTAL_CODE = ObjectIdentifier("2.5.4.17")
    INN = ObjectIdentifier("1.2.643.3.131.1.1")
    OGRN = ObjectIdentifier("1.2.643.100.1")
    SNILS = ObjectIdentifier("1.2.643.100.3")
    UNSTRUCTURED_NAME = ObjectIdentifier("1.2.840.113549.1.9.2")
