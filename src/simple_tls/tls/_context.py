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

import typing

from simple_tls import x509
from simple_tls.utils.math import str_to_bytes
from simple_tls.x509.verification import ExtensionPolicy, Store

from ._constant import CipherSuite, NamedGroup, SignatureScheme, TLSVersion
from ._enum import Direction, Protocol, VerifyMode
from ._key import BasePrivateKey, load_pem_private_key
from ._keyexchange import DHParameters, load_pem_parameters
from ._session import TicketAEAD
from ._utils import Buffer, StrOrBytesPath, version_from_wire

_MsgCallback = typing.Callable[
    [typing.Any, Direction, int, int, bytes, typing.Any],
    None,
]
_SNICallback = typing.Callable[
    [typing.Any, str, typing.Any],
    int | None,
]


class TLSContext:
    """
    Context for TLS connections.
    """

    def __init__(
        self,
        protocol: Protocol = Protocol.TLS,
        is_server: bool = False,
    ) -> None:
        if protocol == Protocol.TLS:
            pass
        elif protocol == Protocol.QUIC:
            raise NotImplementedError("QUIC is not supported yet.")
        elif self._protocol == Protocol.DTLS:
            raise NotImplementedError("DTLS is not supported yet.")
        else:
            raise ValueError(f"Unknown protocol '{protocol}'")

        self._protocol: Protocol = protocol
        self._is_server: bool = is_server

        # ---------------------------------------------------------------------
        # Version
        # ---------------------------------------------------------------------
        self._minimum_version: TLSVersion = TLSVersion.TLSv1_2
        """Normalize minimum TLS version"""
        self._maximum_version: TLSVersion = TLSVersion.TLSv1_3
        """Normalize maximum TLS version"""

        # ---------------------------------------------------------------------
        # Identity & Credentials
        # ---------------------------------------------------------------------
        self._private_key: BasePrivateKey | None = None
        self._x509_certs: tuple[x509.Certificate, ...] | None = None

        # Trust Store & Verification
        self._castore = Store()
        self._verify_mode = VerifyMode.CERT_NONE
        self._check_hostname = False

        # Certificate policies
        self._ee_policy = ExtensionPolicy.defaults_ee()
        self._ca_policy = ExtensionPolicy.defaults_ca()

        # ---------------------------------------------------------------------
        # Protocol
        # ---------------------------------------------------------------------
        # ALPN / NPN
        self._npn_protocols: tuple[bytes, ...] | None = None
        self._alpn_protocols: tuple[bytes, ...] | None = None
        self._alps: tuple[tuple[bytes, bytes], ...] = ()

        # ---------------------------------------------------------------------
        # Cryptographic Parameters
        # ---------------------------------------------------------------------
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

        # Key exchange
        self._dh_parameters: DHParameters | None = None
        self._supported_groups: tuple[int, ...] | None = (
            NamedGroup.X25519MLKEM768,
            NamedGroup.X25519,
            NamedGroup.SECP256R1,
            NamedGroup.SECP384R1,
        )
        self._signature_algorithms: tuple[int, ...] | None = (
            SignatureScheme.ECDSA_SECP256R1_SHA256,
            SignatureScheme.RSA_PSS_RSAE_SHA256,
            SignatureScheme.RSA_PKCS1_SHA256,
            SignatureScheme.ECDSA_SECP384R1_SHA384,
            SignatureScheme.RSA_PSS_RSAE_SHA384,
            SignatureScheme.RSA_PKCS1_SHA384,
            SignatureScheme.RSA_PSS_RSAE_SHA512,
            SignatureScheme.RSA_PKCS1_SHA512,
        )
        self._certificate_compressions: tuple[int, ...] | None = None

        # ECH configurations
        self._ech_configs: bytes | None = None

        # Compatibilty
        self.middlebox_compat: bool = True
        self.legacy_server_connect: bool = False

        # Standard security features
        self.encrypt_then_mac: bool = False
        self.extended_master_secret: bool = True

        # Client-side Privacy & Obfuscation
        self.client_hello_padding: bool = True
        self.permute_extensions: bool = True
        self.grease: bool = True
        self.grease_ech: bool = True

        # Client-side Extensions
        self.status_request: bool = True  # OCSP Stapling
        self.signed_certificate_timestamp: bool = True

        # TLS 1.3 features
        self.early_data: bool = False
        self.max_early_data_size: int = 0xFFFF
        self.post_handshake_auth: bool = False

        # ---------------------------------------------------------------------
        # Callbacks
        # ---------------------------------------------------------------------
        self.callback_arg: typing.Any | None = None
        """Argument to be pass together during callback"""

        # Shared Callbacks
        self.msg_cb: _MsgCallback | None = None
        """Traces or logs raw TLS handshake messages."""

        # Server-Side Callbacks
        self.sni_cb: _SNICallback | None = None
        """Invoked during SNI extension processing to select dynamic context or
        certs."""

        # ---------------------------------------------------------------------
        # Others
        # ---------------------------------------------------------------------
        self.ticket_aead: TicketAEAD | None = None
        """"""

    @property
    def protocol(self) -> Protocol:
        return self._protocol

    @property
    def is_server(self) -> bool:
        return self._is_server

    @property
    def minimum_version(self) -> TLSVersion:
        return self._minimum_version

    @minimum_version.setter
    def minimum_version(self, value: TLSVersion) -> None:
        version = version_from_wire(self.protocol, value)
        if version > self._maximum_version:
            raise ValueError(
                f"minimum_version ({value}) cannot be greater than maximum"
            )
        self._minimum_version = value

    @property
    def maximum_version(self) -> TLSVersion:
        return self._maximum_version

    @maximum_version.setter
    def maximum_version(self, value: TLSVersion) -> None:
        version = version_from_wire(self.protocol, value)
        if version < self._minimum_version:
            raise ValueError(
                f"Maximum version ({value}) cannot be lesser than minimum "
            )
        self._maximum_version = value

    @property
    def verify_mode(self) -> VerifyMode:
        return self._verify_mode

    @verify_mode.setter
    def verify_mode(self, value: VerifyMode) -> None:
        try:
            self._verify_mode = VerifyMode(value)
        except ValueError as exc:
            raise ValueError(f"Invalid verify_mode '{value}'") from exc

    @property
    def check_hostname(self) -> bool:
        return self._check_hostname

    @check_hostname.setter
    def check_hostname(self, value: bool) -> None:
        if value and self.verify_mode == VerifyMode.CERT_NONE:
            self.verify_mode = VerifyMode.CERT_REQUIRED
        self._check_hostname = value

    @property
    def castore(self) -> Store:
        return self._castore

    @property
    def x509_certs(self) -> tuple[x509.Certificate, ...] | None:
        """Returns the chain of X.509 certificate (including leaf)."""
        return self._x509_certs

    @property
    def private_key(self) -> BasePrivateKey | None:
        return self._private_key

    @property
    def ee_policy(self) -> ExtensionPolicy:
        return self._ee_policy

    @ee_policy.setter
    def ee_policy(self, value: ExtensionPolicy) -> None:
        if not isinstance(value, ExtensionPolicy):
            raise TypeError("ee_policy must be x509.ExtensionPolicy instance")
        self._ee_policy = value

    @property
    def ca_policy(self) -> ExtensionPolicy:
        return self._ca_policy

    @ca_policy.setter
    def ca_policy(self, value: ExtensionPolicy) -> None:
        if not isinstance(value, ExtensionPolicy):
            raise TypeError("ca_policy must be x509.ExtensionPolicy instance")
        self._ca_policy = value

    @property
    def npn_protocols(self) -> tuple[bytes, ...] | None:
        return self._npn_protocols

    @property
    def alpn_protocols(self) -> tuple[bytes, ...] | None:
        return self._alpn_protocols

    @property
    def alps(self) -> tuple[tuple[bytes, bytes], ...]:
        return self._alps

    @property
    def cipher_suites(self) -> tuple[CipherSuite, ...]:
        return self._cipher_suites

    @property
    def dh_parameters(self) -> DHParameters | None:
        """Diffie-Hellman parameters (server-side only)"""
        return self._dh_parameters

    @property
    def supported_groups(self) -> tuple[int, ...] | None:
        """Supported groups (TLSv1.3)"""
        return self._supported_groups

    @property
    def signature_algorithms(self) -> tuple[int, ...] | None:
        """Signature algorithms (TLSv1.3)"""
        return self._signature_algorithms

    @property
    def certificate_compressions(self) -> tuple[int, ...] | None:
        """Certificate compression algorithms (TLSv1.3)"""
        return self._certificate_compressions

    @property
    def ech_configs(self) -> bytes | None:
        """ECH configurations (TLSv1.3)"""
        return self._ech_configs

    def set_cipher_suites(self, value: typing.Iterable[CipherSuite]) -> None:
        cipher_suites = tuple(value)
        if not cipher_suites:
            raise ValueError("Empty cipher suites")
        self._cipher_suites = cipher_suites

    def set_supported_groups(self, value: typing.Iterable[int]) -> None:
        self._supported_groups = tuple(value) or None

    def set_signature_algorithms(self, value: typing.Iterable[int]) -> None:
        self._signature_algorithms = tuple(value) or None

    def set_certificate_compressions(
        self, value: typing.Iterable[int]
    ) -> None:
        self._certificate_compressions = tuple(value) or None

    def set_ech_configs(self, value: Buffer | None) -> None:
        if isinstance(value, Buffer):
            value = bytes(value)
        elif value is not None:
            raise TypeError("ech_configs must be bytes object")
        self._ech_configs = value

    def set_alpn_protocols(self, protocols: typing.Iterable[Buffer]) -> None:
        self._alpn_protocols = tuple(bytes(p) for p in protocols) or None

    def add_alps(self, protocol: Buffer, settings: Buffer) -> None:
        self._alps = (*self._alps, (bytes(protocol), bytes(settings)))

    def remove_alps(self, protocol: Buffer) -> None:
        self._alps = tuple(x for x in self._alps if x[0] != protocol)

    def set_npn_protocols(self, protocols: typing.Iterable[Buffer]) -> None:
        self._npn_protocols = tuple(bytes(p) for p in protocols) or None

    def load_dh_params(self, path: StrOrBytesPath) -> None:
        with open(path, "rb") as fp:
            pem_data = fp.read()
        self._dh_parameters = load_pem_parameters(pem_data)

    def load_cert_chain(
        self,
        certfile: StrOrBytesPath,
        keyfile: StrOrBytesPath | None = None,
        password: Buffer | None = None,
    ) -> None:
        """
        Securely loads the chain and key, updating internal state atomically.
        """
        with open(certfile, "rb") as fp:
            pem_data = fp.read()

        certs = x509.load_pem_x509_certificates(pem_data)
        if not certs:
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

        self._x509_certs = tuple(certs)
        self._private_key = key

    def load_verify_locations(
        self,
        cafile: StrOrBytesPath | None = None,
        capath: StrOrBytesPath | None = None,
        cadata: Buffer | None = None,
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
            if not isinstance(cadata, bytes):
                cadata = bytes(cadata)
            certificates = x509.load_pem_x509_certificates(cadata)
            self.castore.extend(certificates)
