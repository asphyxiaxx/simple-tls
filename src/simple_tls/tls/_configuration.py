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

import os
import typing
from dataclasses import dataclass, field
from pathlib import Path

from cryptography import x509

from simple_tls.crypto.utils import str_to_bytes
from simple_tls.crypto.verification import ExtensionPolicy, Store

from ._constant import CipherSuite, NamedGroup, SignatureScheme, TLSVersion
from ._enum import Protocol, VerifyMode
from ._key import BasePrivateKey, load_pem_private_key
from ._keyexchange import DHParameters
from ._session import TicketAEAD, TLSSession
from ._utils import Buffer, StrOrBytesPath


def _ensure_str_path(path_input: str | bytes | os.PathLike) -> str:
    if isinstance(path_input, bytes):
        return path_input.decode("utf-8")
    return os.fspath(path_input)


def load_castore(
    cafile: StrOrBytesPath | None = None,
    capath: StrOrBytesPath | None = None,
    cadata: Buffer | None = None,
) -> Store:
    certs: list[x509.Certificate] = []

    if cafile:
        with open(cafile, "rb") as fp:
            pem_data = fp.read()
        certs.extend(x509.load_pem_x509_certificates(pem_data))

    if capath:
        path = Path(_ensure_str_path(capath))
        if path.is_dir():
            for file_path in path.iterdir():
                if not file_path.is_file():
                    continue
                try:
                    with open(file_path, "rb") as fp:
                        pem_data = fp.read()
                    certs.extend(x509.load_pem_x509_certificates(pem_data))
                except Exception:
                    pass

    if cadata:
        if not isinstance(cadata, bytes):
            cadata = bytes(cadata)
        certs.append(x509.load_der_x509_certificate(cadata))

    return Store(certs)


@dataclass(frozen=True)
class TLSCredential:
    """Represents a TLS identity consisting of a private key and its associated
    certificate chain."""

    private_key: BasePrivateKey
    x509_certificates: typing.Sequence[x509.Certificate]

    @classmethod
    def from_certfile(
        cls,
        certfile: StrOrBytesPath,
        keyfile: StrOrBytesPath | None = None,
        password: Buffer | None = None,
    ) -> TLSCredential:
        """Loads TLS credential from PEM certificate and private key files."""

        with open(certfile, "rb") as fp:
            pem_data = fp.read()

        certificates = x509.load_pem_x509_certificates(pem_data)
        if not certificates:
            raise ValueError(f"No certificates found in {certfile!r}")

        password = str_to_bytes(password)

        if b"PRIVATE KEY" in pem_data:
            key = load_pem_private_key(pem_data, password)
        else:
            if keyfile is None:
                raise ValueError(
                    "No private key found in certfile, and no keyfile provided"
                )
            with open(keyfile, "rb") as fp:
                key = load_pem_private_key(fp.read(), password)

        return TLSCredential(key, tuple(certificates))


@dataclass(frozen=True)
class TLSConfiguration:
    """Configuration for TLS connection parameters and capabilities."""

    is_server: bool = False
    """"""

    protocol: Protocol = Protocol.TLS
    """"""

    minimum_version: TLSVersion = TLSVersion.TLSv1_2
    """Minimum supported TLS version."""

    maximum_version: TLSVersion = TLSVersion.TLSv1_3
    """Maximum supported TLS version."""

    cipher_suites: typing.Sequence[CipherSuite] = (
        CipherSuite.TLS_AES_128_GCM_SHA256,
        CipherSuite.TLS_AES_256_GCM_SHA384,
        CipherSuite.TLS_CHACHA20_POLY1305_SHA256,
        CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        CipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        CipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
        CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
        CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256,
        CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384,
        CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
        CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA,
    )
    """List of supported cipher suites in order of preference."""

    dh_parameters: DHParameters | None = None
    """Custom Diffie-Hellman parameters for DHE cipher suites."""

    supported_groups: typing.Sequence[int] | None = (
        NamedGroup.X25519MLKEM768,
        NamedGroup.X25519,
        NamedGroup.SECP256R1,
        NamedGroup.SECP384R1,
    )
    """Supported key exchange groups (ECC / PQ-hybrid curves) in order of
    preference."""

    signature_algorithms: typing.Sequence[int] | None = (
        SignatureScheme.ECDSA_SECP256R1_SHA256,
        SignatureScheme.RSA_PSS_RSAE_SHA256,
        SignatureScheme.RSA_PKCS1_SHA256,
        SignatureScheme.ECDSA_SECP384R1_SHA384,
        SignatureScheme.RSA_PSS_RSAE_SHA384,
        SignatureScheme.RSA_PKCS1_SHA384,
        SignatureScheme.RSA_PSS_RSAE_SHA512,
        SignatureScheme.RSA_PKCS1_SHA512,
    )
    """Supported signature and hash algorithms in order of preference."""

    certificate_compressions: typing.Sequence[int] | None = None
    """Supported algorithms for certificate compression
    (e.g., zlib, brotli, zstd)."""

    ech_configs: bytes | None = None
    """Encrypted ClientHello (ECH) configuration bytes."""

    encrypt_then_mac: bool = False
    """Enable Encrypt-then-MAC extension for block ciphers (RFC 7366)."""

    extended_master_secret: bool = True
    """Enable Extended Master Secret extension (RFC 7627)."""

    client_hello_padding: bool = True
    """Pad ClientHello messages to avoid known middlebox bugs."""

    permute_extensions: bool = True
    """Randomize the order of extensions in ClientHello to combat
    ossification."""

    grease: bool = True
    """Enable GREASE (Generate Random Extensions, RFC 8701)."""

    grease_ech: bool = True
    """Send synthetic GREASE ECH extensions when ECH is not explicitly
    configured."""

    status_request: bool = True
    """Request OCSP stapling during the handshake."""

    signed_certificate_timestamp: bool = True
    """Request Signed Certificate Timestamps (SCTs) for Certificate
    Transparency."""

    early_data: bool = False
    """Enable 0-RTT Early Data support in TLS 1.3."""

    max_early_data_size: int = 0xFFFF
    """Maximum permitted size in bytes for TLS 1.3 early data."""

    post_handshake_auth: bool = False
    """Advertise support for post-handshake client authentication in
    TLS 1.3."""

    middlebox_compat: bool = True
    """Enable TLS 1.3 middlebox compatibility mode
    (legacy session IDs and dummy ChangeCipherSpec)."""

    legacy_server_connect: bool = False
    """Allow connections to legacy servers that do not support secure
    renegotiation."""

    npn_protocols: typing.Sequence[bytes] | None = None
    """Next Protocol Negotiation (NPN) protocol list (legacy)."""

    alpn_protocols: typing.Sequence[bytes] | None = None
    """Application-Layer Protocol Negotiation (ALPN) protocol list in
    preference order."""

    alps: typing.Mapping[bytes, bytes] | None = None
    """Application-Layer Protocol Settings (ALPS) mapped by ALPN protocol name.
    """

    session: TLSSession | None = None
    """Session object to attempt session resumption during the handshake."""

    server_hostname: bytes | None = None
    """Target hostname used for Server Name Indication (SNI) and certificate
    verification."""

    credential: TLSCredential | None = None
    """Local TLS certificate identity presented to the peer."""

    castore: Store | None = None
    """Trusted Root Certificate Authority (CA) store used for peer
    verification."""

    verify_mode: VerifyMode = VerifyMode.CERT_NONE
    """Peer certificate verification policy mode."""

    check_hostname: bool = False
    """Whether to verify that the peer certificate matches `server_hostname`.
    """

    ee_policy: ExtensionPolicy | None = field(
        default_factory=ExtensionPolicy.defaults_ee
    )
    """Validation policy applied to End-Entity (leaf) certificate extensions.
    """

    ca_policy: ExtensionPolicy | None = field(
        default_factory=ExtensionPolicy.defaults_ca
    )
    """Validation policy applied to intermediate and root CA certificate
    extensions."""

    ticket_aead: TicketAEAD | None = None
    """"""
