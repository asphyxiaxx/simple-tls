from __future__ import annotations

import ssl as _ssl
import sys
import typing
from collections.abc import Callable
from os import PathLike
from typing import TYPE_CHECKING, TypeAlias, Union

from cryptography import x509
from cryptography.x509.oid import AuthorityInformationAccessOID

from simple_tls import tls

from ._constants import (
    CERT_NONE,
    CERT_REQUIRED,
    PROTOCOL_TLS_CLIENT,
    PROTOCOL_TLS_SERVER,
    ASN1Object,
    Purpose,
    TLSVersion,
)

if TYPE_CHECKING:
    from ._context import SSLContext
    from ._object import SSLObject
    from ._socket import SSLSocket

if sys.version_info < (3, 12):
    from typing_extensions import Buffer
else:
    from collections.abc import Buffer


ReadableBuffer: TypeAlias = Buffer
WritableBuffer: TypeAlias = Buffer
StrOrBytesPath: TypeAlias = str | bytes | PathLike[str] | PathLike[bytes]

PCTRTT: TypeAlias = tuple[tuple[str, str], ...]
PCTRTTT: TypeAlias = tuple[PCTRTT, ...]
PeerCertRetDictType: TypeAlias = dict[str, str | PCTRTTT | PCTRTT]

PSKClientCbType: TypeAlias = Callable[
    [str | None],
    tuple[str | None, bytes],
]
PSKServerCbType: TypeAlias = Callable[
    [str | None],
    bytes,
]
SrvnmeCbType: TypeAlias = Callable[
    [Union["SSLSocket", "SSLObject"], str | None, "SSLContext"],
    int | None,
]


def _parse_name(name: x509.Name) -> tuple[tuple[tuple[str, str], ...], ...]:
    return tuple(
        tuple(
            (attribute.oid._name, attribute.value)
            for attribute in rdn
            if isinstance(attribute.value, str)
        )
        for rdn in name.rdns
    )


def _parse_general_names(
    general_names: typing.Iterable[x509.GeneralName],
) -> tuple[tuple[str, str], ...]:
    out: list[tuple[str, str]] = []
    value: typing.Any

    for general_name in general_names:
        if isinstance(general_name, x509.DNSName):
            name = "DNS"
            value = general_name.value

        elif isinstance(general_name, x509.IPAddress):
            name = "IP Address"
            value = str(general_name.value)

        elif isinstance(general_name, x509.RegisteredID):
            name = "Registered ID"
            value = general_name.value._name
            if value == "Unknown OID":
                value = general_name.value.dotted_string

        elif isinstance(general_name, x509.OtherName):
            continue

        elif isinstance(general_name, x509.DirectoryName):
            name = "DirName"
            value = _parse_name(general_name.value)

        elif isinstance(general_name, x509.UniformResourceIdentifier):
            name = "URI"
            value = general_name.value

        elif isinstance(general_name, x509.RFC822Name):
            name = "email"
            value = general_name.value

        else:
            continue

        out.append((name, value))

    return tuple(out)


def parse_certificate(certificate: x509.Certificate) -> dict[str, typing.Any]:
    gmt_fmt = "%a, %d %b %Y %H:%M:%S GMT"
    out = {
        "subject": _parse_name(certificate.subject),
        "issuer": _parse_name(certificate.issuer),
        "version": certificate.version.value + 1,
        "serialNumber": f"{certificate.serial_number:X}",
        "notBefore": certificate.not_valid_before_utc.strftime(gmt_fmt),
        "notAfter": certificate.not_valid_after_utc.strftime(gmt_fmt),
    }

    exts = certificate.extensions

    try:
        san_ext = exts.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        pass
    else:
        san = _parse_general_names(san_ext.value)
        if san:
            out["subjectAltName"] = san

    try:
        crl_ext = exts.get_extension_for_class(x509.CRLDistributionPoints)
    except x509.ExtensionNotFound:
        pass
    else:
        crls = tuple(
            name.value
            for x in crl_ext.value
            if x.full_name is not None
            for name in x.full_name
            if isinstance(name, x509.UniformResourceIdentifier)
        )
        if crls:
            out["crlDistributionPoints"] = crls

    try:
        aia_ext = exts.get_extension_for_class(x509.AuthorityInformationAccess)
    except x509.ExtensionNotFound:
        pass
    else:
        ocsp = tuple(
            ad.access_location.value
            for ad in aia_ext.value
            if (
                ad.access_method == AuthorityInformationAccessOID.OCSP
                and isinstance(
                    ad.access_location, x509.UniformResourceIdentifier
                )
            )
        )
        if ocsp:
            out["OCSP"] = ocsp

    return out


def get_cipher(cipher_suite: tls.CipherSuite) -> _ssl._Cipher | None:
    if cipher_suite in (
        tls.CipherSuite.TLS_FALLBACK_SCSV,
        tls.CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV,
    ):
        return None

    desc: list[str] = []

    name = _OPENSSL_CIPHER_NAMES[cipher_suite.name]
    desc.append(f"{name:<31}")

    protocol, ver = _OPENSSL_VERSION_NAMES[cipher_suite.minimum_version]
    desc.append(f"{ver:<8}")

    kea, kx = _OPENSSL_KEA_NAMES[cipher_suite.kea]
    desc.append(f"Kx={kx:<9}")

    auth, au = _OPENSSL_AUTH_NAMES[cipher_suite.auth]
    desc.append(f"Au={au:<6}")

    symmetric, enc = _OPENSSL_SYMMETRIC_NAMES[cipher_suite.symmetric]
    desc.append(f"Enc={enc:<23}")

    if cipher_suite.digest is not None:
        assert not cipher_suite.aead
        digest, mac = _OPENSSL_DIGEST_NAMES[cipher_suite.digest]
    else:
        assert cipher_suite.aead
        digest = None
        mac = "AEAD"

    desc.append(f"Mac={mac}")

    return {
        "id": (0x03000000 | cipher_suite.id),
        "name": name,
        "protocol": protocol,
        "description": "".join(desc),
        "strength_bits": cipher_suite.value.strength_bits,
        "alg_bits": cipher_suite.value.alg_bits,
        "aead": cipher_suite.aead,
        "symmetric": symmetric,  # type: ignore
        "digest": digest,
        "kea": kea,
        "auth": auth,
    }


def get_cipher_tuple(
    cipher_suite: tls.CipherSuite,
) -> tuple[str, str, int] | None:
    cipher = get_cipher(cipher_suite)
    if cipher is not None:
        return (cipher["name"], cipher["protocol"], cipher["alg_bits"])
    return None


def get_version_name(version: int) -> str:
    try:
        return _OPENSSL_VERSION_NAMES[version][1]
    except KeyError:
        return "Unknown version"


def parse_cipher_string(cipher_str: str) -> list[tls.CipherSuite]:
    """
    Passes the string to the underlying OpenSSL engine via Python's ssl module
    and returns the actual list of cryptographic suites that result from the
    rules.
    """
    ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_SERVER)
    ctx.set_ciphers(cipher_str)

    cipher_suites: list[tls.CipherSuite] = []
    for cipher in ctx.get_ciphers():
        cipher_iana_id = cipher["id"] & 0xFFFF
        try:
            cipher_suite = tls.CipherSuite(cipher_iana_id)
        except ValueError:
            continue
        cipher_suites.append(cipher_suite)
    return cipher_suites


def create_default_context(
    purpose: Purpose = Purpose.SERVER_AUTH,
    *,
    cafile: StrOrBytesPath | None = None,
    capath: StrOrBytesPath | None = None,
    cadata: str | ReadableBuffer | None = None,
) -> SSLContext:
    if not isinstance(purpose, ASN1Object):  # type: ignore[misc]
        raise TypeError(purpose)

    from ._context import SSLContext

    if purpose == Purpose.SERVER_AUTH:
        context = SSLContext(PROTOCOL_TLS_CLIENT)
        context.verify_mode = CERT_REQUIRED
        context.check_hostname = True
    elif purpose == Purpose.CLIENT_AUTH:
        context = SSLContext(PROTOCOL_TLS_SERVER)
    else:
        raise ValueError(purpose)

    if cafile or capath or cadata:
        context.load_verify_locations(cafile, capath, cadata)  # type: ignore
    elif context.verify_mode != CERT_NONE:
        # no explicit cafile, capath or cadata but the verify mode is
        # CERT_OPTIONAL or CERT_REQUIRED. Let's try to load default system
        # root CA certificates for the given purpose. This may fail silently.
        context.load_default_certs(purpose)

    return context


class SSLConnection(tls.TLSConnection):
    def selected_alpn_protocol(self) -> str | None:  # type: ignore
        protocol = super().selected_alpn_protocol()
        if protocol is not None:
            return protocol.decode()
        return None


_OPENSSL_VERSION_NAMES: dict[int, tuple[str, str]] = {
    TLSVersion.TLSv1: ("TLSv1.0", "TLSv1"),
    TLSVersion.TLSv1_1: ("TLSv1.1", "TLSv1.1"),
    TLSVersion.TLSv1_2: ("TLSv1.2", "TLSv1.2"),
    TLSVersion.TLSv1_3: ("TLSv1.3", "TLSv1.3"),
}

_OPENSSL_DIGEST_NAMES: dict[int, tuple[str, str]] = {
    tls.HashAlgorithm.MD5: ("md5", "MD5"),
    tls.HashAlgorithm.SHA1: ("sha1", "SHA1"),
    tls.HashAlgorithm.SHA256: ("sha256", "SHA256"),
    tls.HashAlgorithm.SHA384: ("sha384", "SHA384"),
}

_OPENSSL_SYMMETRIC_NAMES: dict[int, tuple[str | None, str]] = {
    tls.Symmetric.NULL: (None, "None"),
    tls.Symmetric.RC4_128: ("rc4", "RC4(128)"),
    tls.Symmetric.TRIPLE_DES_EDE_CBC: ("des-ede3-cbc", "3DES(168)"),
    tls.Symmetric.AES_128_CBC: ("aes-128-cbc", "AES(128)"),
    tls.Symmetric.AES_256_CBC: ("aes-256-cbc", "AES(256)"),
    tls.Symmetric.AES_128_GCM: ("aes-128-gcm", "AESGCM(128)"),
    tls.Symmetric.AES_256_GCM: ("aes-256-gcm", "AESGCM(256)"),
    tls.Symmetric.CHACHA20_POLY1305: (
        "chacha20-poly1305",
        "CHACHA20/POLY1305(256)",
    ),
    tls.Symmetric.AES_128_CCM: ("aes-128-ccm", "AESCCM(128)"),
    tls.Symmetric.AES_256_CCM: ("aes-256-ccm", "AESCCM(256)"),
    tls.Symmetric.AES_128_CCM_8: ("aes-128-ccm", "AESCCM8(128)"),
    tls.Symmetric.AES_256_CCM_8: ("aes-256-ccm", "AESCCM8(256)"),
}

_OPENSSL_KEA_NAMES: dict[int, tuple[str, str]] = {
    tls.KeyExchange.RSA: ("kx-rsa", "RSA"),
    tls.KeyExchange.DHE: ("kx-dhe", "DH"),
    tls.KeyExchange.ECDHE: ("kx-ecdhe", "ECDH"),
    tls.KeyExchange.NONE: ("kx-any", "any"),
}

_OPENSSL_AUTH_NAMES: dict[int, tuple[str, str]] = {
    tls.Authentication.ANON: ("auth-null", "None"),
    tls.Authentication.DSS: ("auth-dss", "DSS"),
    tls.Authentication.ECDSA: ("auth-ecdsa", "ECDSA"),
    tls.Authentication.RSA: ("auth-rsa", "RSA"),
    tls.Authentication.NONE: ("auth-any", "any"),
}

# ruff: disable[E501]

_OPENSSL_CIPHER_NAMES: dict[str, str] = {
    "TLS_RSA_WITH_NULL_MD5": "NULL-MD5",
    "TLS_RSA_WITH_NULL_SHA": "NULL-SHA",
    "TLS_RSA_WITH_NULL_SHA256": "NULL-SHA256",
    "TLS_RSA_WITH_RC4_128_MD5": "RC4-MD5",
    "TLS_RSA_WITH_RC4_128_SHA": "RC4-SHA",
    "TLS_RSA_WITH_3DES_EDE_CBC_SHA": "DES-CBC3-SHA",
    "TLS_RSA_WITH_AES_128_CBC_SHA": "AES128-SHA",
    "TLS_RSA_WITH_AES_256_CBC_SHA": "AES256-SHA",
    "TLS_RSA_WITH_AES_128_CBC_SHA256": "AES128-SHA256",
    "TLS_RSA_WITH_AES_256_CBC_SHA256": "AES256-SHA256",
    "TLS_RSA_WITH_AES_128_CCM": "AES128-CCM",
    "TLS_RSA_WITH_AES_256_CCM": "AES256-CCM",
    "TLS_RSA_WITH_AES_128_CCM_8": "AES128-CCM8",
    "TLS_RSA_WITH_AES_256_CCM_8": "AES256-CCM8",
    "TLS_RSA_WITH_AES_128_GCM_SHA256": "AES128-GCM-SHA256",
    "TLS_RSA_WITH_AES_256_GCM_SHA384": "AES256-GCM-SHA384",
    "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA": "DHE-DSS-DES-CBC3-SHA",
    "TLS_DHE_DSS_WITH_AES_128_CBC_SHA": "DHE-DSS-AES128-SHA",
    "TLS_DHE_DSS_WITH_AES_256_CBC_SHA": "DHE-DSS-AES256-SHA",
    "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256": "DHE-DSS-AES128-SHA256",
    "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256": "DHE-DSS-AES256-SHA256",
    "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256": "DHE-DSS-AES128-GCM-SHA256",
    "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384": "DHE-DSS-AES256-GCM-SHA384",
    "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA": "DHE-RSA-DES-CBC3-SHA",
    "TLS_DHE_RSA_WITH_AES_128_CBC_SHA": "DHE-RSA-AES128-SHA",
    "TLS_DHE_RSA_WITH_AES_256_CBC_SHA": "DHE-RSA-AES256-SHA",
    "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256": "DHE-RSA-AES128-SHA256",
    "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256": "DHE-RSA-AES256-SHA256",
    "TLS_DHE_RSA_WITH_AES_128_CCM": "DHE-RSA-AES128-CCM",
    "TLS_DHE_RSA_WITH_AES_256_CCM": "DHE-RSA-AES256-CCM",
    "TLS_DHE_RSA_WITH_AES_128_CCM_8": "DHE-RSA-AES128-CCM8",
    "TLS_DHE_RSA_WITH_AES_256_CCM_8": "DHE-RSA-AES256-CCM8",
    "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256": "DHE-RSA-AES128-GCM-SHA256",
    "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384": "DHE-RSA-AES256-GCM-SHA384",
    "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256": "DHE-RSA-CHACHA20-POLY1305",
    "TLS_ECDHE_RSA_WITH_NULL_SHA": "ECDHE-RSA-NULL-SHA",
    "TLS_ECDHE_RSA_WITH_RC4_128_SHA": "ECDHE-RSA-RC4-SHA",
    "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA": "ECDHE-RSA-DES-CBC3-SHA",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA": "ECDHE-RSA-AES128-SHA",
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA": "ECDHE-RSA-AES256-SHA",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256": "ECDHE-RSA-AES128-SHA256",
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384": "ECDHE-RSA-AES256-SHA384",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256": "ECDHE-RSA-AES128-GCM-SHA256",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384": "ECDHE-RSA-AES256-GCM-SHA384",
    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256": "ECDHE-RSA-CHACHA20-POLY1305",
    "TLS_ECDHE_ECDSA_WITH_NULL_SHA": "ECDHE-ECDSA-NULL-SHA",
    "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA": "ECDHE-ECDSA-RC4-SHA",
    "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA": "ECDHE-ECDSA-DES-CBC3-SHA",
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA": "ECDHE-ECDSA-AES128-SHA",
    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA": "ECDHE-ECDSA-AES256-SHA",
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256": "ECDHE-ECDSA-AES128-SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384": "ECDHE-ECDSA-AES256-SHA384",
    "TLS_ECDHE_ECDSA_WITH_AES_128_CCM": "ECDHE-ECDSA-AES128-CCM",
    "TLS_ECDHE_ECDSA_WITH_AES_256_CCM": "ECDHE-ECDSA-AES256-CCM",
    "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8": "ECDHE-ECDSA-AES128-CCM8",
    "TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8": "ECDHE-ECDSA-AES256-CCM8",
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256": "ECDHE-ECDSA-AES128-GCM-SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384": "ECDHE-ECDSA-AES256-GCM-SHA384",
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256": "ECDHE-ECDSA-CHACHA20-POLY1305",
    "TLS_AES_128_GCM_SHA256": "TLS_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384": "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256": "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_AES_128_CCM_SHA256": "TLS_AES_128_CCM_SHA256",
    "TLS_AES_128_CCM_8_SHA256": "TLS_AES_128_CCM_8_SHA256",
}

# ruff: enable[E501]
