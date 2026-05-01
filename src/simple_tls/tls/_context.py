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

from .. import x509
from ..io.serialization import load_pem_parameters, load_pem_private_key
from ..key import dh
from ..key.types import CertificateIssuerPrivateKeyTypes
from ..utils.math import str_to_bytes
from ._constant import (
    CertificateCompressionAlgorithm,
    CipherSuite,
    ECPointFormat,
    NamedGroup,
    SignatureScheme,
    TLSVersion,
)
from ._types import StrOrBytesPath, ReadableBuffer
from ._enum import TLSVerifyMode
from ._session import TLSSessionKeys, TLSSessionStorage

_ExtensionsOrderCallback = typing.Callable[
    [list[int]],
    list[int],
]
_SNICallback = typing.Callable[
    ["TLSContext", typing.Optional[str], typing.Optional[object]],
    typing.Optional[int],
]
_MessageCallback = typing.Callable[
    [typing.Optional[object], typing.Literal["write", "read"], int, bytes],
    None,
]


class TLSContext:
    """
    Configuration factory for TLS connections.
    """

    def __init__(self) -> None:
        # -------------------------------------------------------------------------
        # Identity & Credentials (The "Who am I?")
        # -------------------------------------------------------------------------
        self._private_key: CertificateIssuerPrivateKeyTypes | None = None
        self._x509_certs: tuple[x509.Certificate, ...] | None = None

        # Trust Store & Verification
        self._castore = x509.Store()
        self._verify_mode = TLSVerifyMode.CERT_NONE
        self._check_hostname = False

        # Certificate Policies
        self._ee_policy = x509.ExtensionPolicy.defaults_ee()
        self._ca_policy = x509.ExtensionPolicy.defaults_ca()

        # -------------------------------------------------------------------------
        # Protocol & Version Control (The "How do we talk?")
        # -------------------------------------------------------------------------
        self._minimum_version: TLSVersion = TLSVersion.TLSv1_2
        self._maximum_version: TLSVersion = TLSVersion.TLSv1_3

        # ALPN / NPN (Next Protocol Negotiation)
        self._alpn_protocols: tuple[bytes, ...] = ()
        self._npn_protocols: tuple[bytes, ...] = ()
        self._alps: dict[bytes, bytes] = {}

        # -------------------------------------------------------------------------
        # Cryptographic Parameters (The "Math")
        # -------------------------------------------------------------------------
        self._cipher_suites: tuple[CipherSuite, ...] = (
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

        # Key Exchange
        self._dh_params: dh.DHParameters | None = None
        """DH parameters for server side only"""
        self._supported_groups: tuple[int, ...] = (
            NamedGroup.X25519MLKEM768,
            NamedGroup.X25519,
            NamedGroup.SECP256R1,
            NamedGroup.SECP384R1,
        )
        """supported groups to send over in TLSv1.3"""
        self._key_share_groups: tuple[int, ...] = (
            NamedGroup.X25519MLKEM768,
            NamedGroup.X25519,
        )

        self._ec_point_formats: tuple[int, ...] = (ECPointFormat.UNCOMPRESSED,)
        """ec point compression format (default uncompressed)"""

        # Signature
        self._signature_algorithms: tuple[int, ...] = (
            SignatureScheme.ECDSA_SECP256R1_SHA256,
            SignatureScheme.RSA_PSS_RSAE_SHA256,
            SignatureScheme.RSA_PKCS1_SHA256,
            SignatureScheme.ECDSA_SECP384R1_SHA384,
            SignatureScheme.RSA_PSS_RSAE_SHA384,
            SignatureScheme.RSA_PKCS1_SHA384,
            SignatureScheme.RSA_PSS_RSAE_SHA512,
            SignatureScheme.RSA_PKCS1_SHA512,
        )
        """Signature algorithms"""

        # Certificate compression algorihtm
        self._certificate_compressions: tuple[int, ...] = (
            CertificateCompressionAlgorithm.ZLIB,
        )
        """Certificate compression algorithms (TLSv1.3 specific)"""

        # ECH Config
        self._ech_configs: bytes | None = None

        # Compatibilty
        self.middlebox_compat: bool = True
        self.legacy_server_connect: bool = False

        # Standard security features
        self.encrypt_then_mac: bool = False
        self.extended_master_secret: bool = True
        self.required_extended_master_secret: bool = False

        # Client-side Privacy & Obfuscation
        self.client_hello_padding: bool = True
        self.grease: bool = True
        self.grease_ech: bool = True

        # Client-side Extensions
        self.status_request: bool = True  # OCSP Stapling
        self.signed_certificate_timestamp: bool = True

        # Advanced / TLS 1.3 features
        self.early_data: bool = False
        self.max_early_data_size: int = 0xFFFF
        self.post_handshake_auth: bool = False

        # Session keys to decrypt ticket
        self._session_keys: TLSSessionKeys | None = TLSSessionKeys()

        # Session storage
        self._session_storage: TLSSessionStorage | None = TLSSessionStorage()

        # Message Callback
        self.owner: object | None = None
        """Owner of this object"""
        self.message_callback: _MessageCallback | None = None
        """
        Callback for Message Debugging/Tracing
        Signature: (owner, direction, version, message) -> None
        """

        # Client specific callback
        self.extensions_order_cb: _ExtensionsOrderCallback | None = None
        """
        Callback for Extension Reordering (for fingerprinting randomization)
        Signature: (list_of_ids) -> list_of_ids
        """

        # Server specific callback
        self.sni_callback: _SNICallback | None = None
        """
        Callback for SNI (Server Name Indication)
        Signature: (ctx, hostname, owner) -> int_result
        """

    @property
    def minimum_version(self) -> TLSVersion:
        return self._minimum_version

    @minimum_version.setter
    def minimum_version(self, value: TLSVersion) -> None:
        try:
            value = TLSVersion(value)
        except ValueError:
            raise ValueError(f"Unsupported TLS version '{value}'")
        if value > self._maximum_version:
            raise ValueError(
                f"Minimum version ({value}) cannot be greater than maximum "
                f"({self._maximum_version})"
            )
        self._minimum_version = value

    @property
    def maximum_version(self) -> TLSVersion:
        return self._maximum_version

    @maximum_version.setter
    def maximum_version(self, value: TLSVersion) -> None:
        try:
            value = TLSVersion(value)
        except ValueError:
            raise ValueError(f"Unsupported TLS version '{value}'")
        if value < self._minimum_version:
            raise ValueError(
                f"Maximum version ({value}) cannot be lesser than minimum "
                f"({self._minimum_version})"
            )
        self._maximum_version = value

    @property
    def verify_mode(self) -> TLSVerifyMode:
        return self._verify_mode

    @verify_mode.setter
    def verify_mode(self, value: TLSVerifyMode) -> None:
        try:
            self._verify_mode = TLSVerifyMode(value)
        except ValueError:
            raise ValueError(f"Unknown verify_mode '{value}'")

    @property
    def check_hostname(self) -> bool:
        return self._check_hostname

    @check_hostname.setter
    def check_hostname(self, value: bool) -> None:
        if value and self.verify_mode == TLSVerifyMode.CERT_NONE:
            self.verify_mode = TLSVerifyMode.CERT_REQUIRED
        self._check_hostname = value

    @property
    def castore(self) -> x509.Store:
        return self._castore

    @property
    def x509_certs(self) -> typing.Sequence[x509.Certificate] | None:
        """Returns the chain of X.509 certificate (including leaf)."""
        return self._x509_certs

    @property
    def private_key(self) -> CertificateIssuerPrivateKeyTypes | None:
        return self._private_key

    @property
    def session_keys(self) -> TLSSessionKeys | None:
        return self._session_keys

    @session_keys.setter
    def session_keys(self, value: TLSSessionKeys | None) -> None:
        if value is not None and not isinstance(value, TLSSessionKeys):
            raise TypeError(
                "session_storage must be TLSSessionKeysManager instance"
            )
        self._session_keys = value

    @property
    def session_storage(self) -> TLSSessionStorage | None:
        return self._session_storage

    @session_storage.setter
    def session_storage(self, value: TLSSessionStorage | None) -> None:
        if value is not None and not isinstance(value, TLSSessionStorage):
            raise TypeError(
                "session_storage must be TLSSessionStorage instance"
            )
        self._session_storage = value

    @property
    def cipher_suites(self) -> typing.Sequence[CipherSuite]:
        return self._cipher_suites

    @cipher_suites.setter
    def cipher_suites(self, value: typing.Sequence[CipherSuite]) -> None:
        self._cipher_suites = tuple(
            CipherSuite(v) if not isinstance(v, CipherSuite) else v
            for v in value
        )

    @property
    def signature_algorithms(self) -> typing.Sequence[int]:
        """signature algorithms used for signing"""
        return self._signature_algorithms

    @signature_algorithms.setter
    def signature_algorithms(self, value: typing.Sequence[int]) -> None:
        self._signature_algorithms = tuple(value)

    @property
    def ec_point_formats(self) -> typing.Sequence[int]:
        return self._ec_point_formats

    @ec_point_formats.setter
    def ec_point_formats(self, value: typing.Sequence[int]) -> None:
        self._ec_point_formats = tuple(value)

    @property
    def certificate_compressions(self) -> typing.Sequence[int]:
        return self._certificate_compressions

    @certificate_compressions.setter
    def certificate_compressions(self, value: typing.Sequence[int]) -> None:
        self._certificate_compressions = tuple(value)

    @property
    def supported_groups(self) -> typing.Sequence[int]:
        """"""
        return self._supported_groups

    @supported_groups.setter
    def supported_groups(self, value: typing.Sequence[int]) -> None:
        self._supported_groups = tuple(value)

    @property
    def key_share_groups(self) -> typing.Sequence[int]:
        """key share groups to send over in TLSv1.3 for client side"""
        return self._key_share_groups

    @key_share_groups.setter
    def key_share_groups(self, value: typing.Sequence[int]) -> None:
        self._key_share_groups = tuple(value)

    @property
    def ech_configs(self) -> bytes | None:
        return self._ech_configs

    @ech_configs.setter
    def ech_configs(self, value: bytes | None) -> None:
        if value is not None and not isinstance(value, bytes):
            raise TypeError("ech_configs must be bytes object")
        self._ech_configs = value

    @property
    def dh_params(self) -> dh.DHParameters | None:
        return self._dh_params

    @property
    def alps(self) -> dict[bytes, bytes]:
        return self._alps

    @property
    def alpn_protocols(self) -> typing.Sequence[bytes]:
        return self._alpn_protocols

    @alpn_protocols.setter
    def alpn_protocols(self, value: typing.Sequence[bytes]) -> None:
        if not all(isinstance(p, bytes) for p in value):
            raise TypeError("alpn_protocols must be Sequence of bytes object")
        self._alpn_protocols = tuple(value)

    @property
    def npn_protocols(self) -> typing.Sequence[bytes]:
        return self._npn_protocols

    @npn_protocols.setter
    def npn_protocols(self, value: typing.Sequence[bytes]) -> None:
        if not all(isinstance(p, bytes) for p in value):
            raise TypeError("npn_protocols must be Sequence of bytes object")
        self._npn_protocols = tuple(value)

    @property
    def ee_policy(self) -> x509.ExtensionPolicy:
        return self._ee_policy

    @ee_policy.setter
    def ee_policy(self, value: x509.ExtensionPolicy) -> None:
        if not isinstance(value, x509.ExtensionPolicy):
            raise TypeError("ee_policy must be x509.ExtensionPolicy instance")
        self._ee_policy = value

    @property
    def ca_policy(self) -> x509.ExtensionPolicy:
        return self._ca_policy

    @ca_policy.setter
    def ca_policy(self, value: x509.ExtensionPolicy) -> None:
        if not isinstance(value, x509.ExtensionPolicy):
            raise TypeError("ca_policy must be x509.ExtensionPolicy instance")
        self._ca_policy = value

    def load_dh_params(self, path: str) -> None:
        with open(path, "rb") as fp:
            pem_data = fp.read()
        self._dh_params = load_pem_parameters(pem_data)

    def load_cert_chain(
        self,
        certfile: str | bytes,
        keyfile: str | bytes | None = None,
        password: str | bytes | None = None,
    ) -> None:
        """
        Securely loads the chain and key, updating internal state atomically.
        """
        password = str_to_bytes(password)

        # Load Certificates
        with open(certfile, "rb") as fp:
            pem_data = fp.read()

        # load_pem_x509_certificates returns a LIST
        certs = x509.load_pem_x509_certificates(pem_data)

        if not certs:
            raise ValueError(f"No certificates found in {certfile!r}")

        # Try to find key in the same file if not provided
        key = None
        if b"PRIVATE KEY" in pem_data:
            key = load_pem_private_key(pem_data, password)

        # Load Key from separate file if needed
        if key is None:
            if keyfile is None:
                raise ValueError(
                    "No private key found in certfile, and no keyfile provided"
                )
            with open(keyfile, "rb") as fp:
                key = load_pem_private_key(fp.read(), password)

        # Update State Atomically
        self._x509_certs = tuple(certs)
        self._private_key = typing.cast(CertificateIssuerPrivateKeyTypes, key)

    def get_ca_certs(self) -> list[x509.Certificate]:
        return [c for c in self.castore]

    def load_verify_locations(
        self,
        cafile: StrOrBytesPath | None = None,
        capath: StrOrBytesPath | None = None,
        cadata: str | ReadableBuffer | None = None,
    ) -> None:
        if cafile:
            with open(cafile, "rb") as fp:
                pem_data = fp.read()
            certificates = x509.load_pem_x509_certificates(pem_data)
            self.castore.extend(certificates)
        if capath:
            with open(capath, "rb") as fp:
                pem_data = fp.read()
            certificates = x509.load_pem_x509_certificates(pem_data)
            self.castore.extend(certificates)
        if cadata:
            if isinstance(cadata, str):
                cadata = str_to_bytes(cadata)
                certificates = x509.load_pem_x509_certificates(cadata)
                self.castore.extend(certificates)
            else:
                certificates = x509.load_der_x509_certificates(cadata)
                self.castore.extend(certificates)
