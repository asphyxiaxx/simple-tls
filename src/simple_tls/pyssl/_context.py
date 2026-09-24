from __future__ import annotations

import ssl as _ssl
import sys
import typing
import warnings
from socket import socket

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from simple_tls import tls
from simple_tls.crypto import verification
from simple_tls.crypto.utils import str_to_bytes

from ._constant import (
    PROTOCOL_TLS,
    PROTOCOL_TLS_CLIENT,
    PROTOCOL_TLS_SERVER,
    Options,
    Purpose,
    TLSVersion,
    VerifyFlags,
    VerifyMode,
)
from ._object import SSLObject
from ._session import SSLSession, TicketAEAD
from ._socket import SSLSocket
from ._utils import (
    PeerCertRetDictType,
    PSKClientCbType,
    PSKServerCbType,
    ReadableBuffer,
    SrvnmeCbType,
    StrOrBytesPath,
    parse_certificate,
    parse_cipher_string,
)


class SSLContext:
    """
    An SSLContext holds various SSL-related configuration options and
    data, such as certificates and possibly a private key.
    """

    _windows_cert_stores = ("CA", "ROOT")

    sslsocket_class: type[SSLSocket] = SSLSocket
    sslobject_class: type[SSLObject] = SSLObject

    def __init__(self, protocol: int = PROTOCOL_TLS_CLIENT):
        if protocol == PROTOCOL_TLS_CLIENT:
            verify_mode = VerifyMode.CERT_REQUIRED
            check_hostname = True
            ticket_aead = None
        elif protocol == PROTOCOL_TLS_SERVER:
            verify_mode = VerifyMode.CERT_NONE
            check_hostname = False
            ticket_aead = TicketAEAD()
        elif protocol == PROTOCOL_TLS:
            raise ValueError("PROTOCOL_TLS is unsupported.")
        else:
            raise ValueError(f"unsupported protocol {protocol}")

        self._config: dict[str, typing.Any] = {}
        self._protocol = protocol
        self._options: Options = (
            Options.OP_ENABLE_MIDDLEBOX_COMPAT
            | Options.OP_SINGLE_DH_USE
            | Options.OP_SINGLE_ECDH_USE
            | Options.OP_NO_COMPRESSION
            | Options.OP_NO_RENEGOTIATION
            | Options.OP_NO_SSLv2
            | Options.OP_NO_SSLv3
            | Options.OP_NO_TLSv1
            | Options.OP_NO_TLSv1_1
        )
        self._minimum_version = _ssl.TLSVersion.MINIMUM_SUPPORTED
        self._maximum_version = _ssl.TLSVersion.MAXIMUM_SUPPORTED
        self._castore = verification.Store()
        self._verify_mode: _ssl.VerifyMode = verify_mode
        self._check_hostname: bool = check_hostname
        self._post_handshake_auth: bool = False
        self._ticket_aead = ticket_aead
        self._sni_callback: SrvnmeCbType | None = None

    def wrap_socket(
        self,
        sock: socket,
        server_side: bool = False,
        do_handshake_on_connect: bool = True,
        suppress_ragged_eofs: bool = True,
        server_hostname: str | None = None,
        session: SSLSession | None = None,
    ) -> SSLSocket:
        return self.sslsocket_class._create(
            sock=sock,
            server_side=server_side,
            do_handshake_on_connect=do_handshake_on_connect,
            suppress_ragged_eofs=suppress_ragged_eofs,
            server_hostname=server_hostname,
            context=self,
            session=session,
        )

    def wrap_bio(
        self,
        incoming: _ssl.MemoryBIO,
        outgoing: _ssl.MemoryBIO,
        server_side: bool = False,
        server_hostname: str | None = None,
        session: SSLSession | None = None,
    ) -> SSLObject:
        return self.sslobject_class._create(
            incoming,
            outgoing,
            server_side=server_side,
            server_hostname=server_hostname,
            session=session,
            context=self,
        )

    def get_ciphers(self) -> list:
        raise NotImplementedError

    def session_stats(self) -> dict[str, int]:
        raise NotImplementedError

    def set_ciphers(self, cipherlist: str) -> None:
        cipher_suites = parse_cipher_string(cipherlist)
        self._config["cipher_suites"] = cipher_suites

    def set_npn_protocols(self, npn_protocols: typing.Iterable[str]) -> None:
        out: list[bytes] = []
        for protocol in npn_protocols:
            b = bytes(protocol, "ascii")
            if len(b) == 0 or len(b) > 255:
                raise ValueError("NPN protocols must be 1 to 255 in length")
            out.append(b)
        self._config["npn_protocols"] = out

    def set_alpn_protocols(self, alpn_protocols: typing.Iterable[str]) -> None:
        out: list[bytes] = []
        for protocol in alpn_protocols:
            b = bytes(protocol, "ascii")
            if len(b) == 0 or len(b) > 255:
                raise ValueError("NPN protocols must be 1 to 255 in length")
            out.append(b)
        self._config["alpn_protocols"] = out

    def set_servername_callback(self, callback: SrvnmeCbType | None) -> None:
        if callback is None:
            self._sni_callback = None
            return

        if not callable(callback):
            raise TypeError("not a callable object")

        self._sni_callback = callback

    def set_psk_client_callback(
        self, callback: PSKClientCbType | None
    ) -> None:
        raise NotImplementedError

    def set_psk_server_callback(
        self,
        callback: PSKServerCbType | None,
        identity_hint: str | None = None,
    ) -> None:
        raise NotImplementedError

    _ECDH_CURVES: typing.ClassVar[dict[str, int]] = {
        "prime256v1": tls.NamedGroup.SECP256R1,
        "secp256r1": tls.NamedGroup.SECP256R1,
        "secp384r1": tls.NamedGroup.SECP384R1,
        "x25519": tls.NamedGroup.X25519,
        "x448": tls.NamedGroup.X448,
        "x25519mlkem768": tls.NamedGroup.X25519MLKEM768,
    }

    def set_ecdh_curve(self, curve: str) -> None:
        groups: list[int] = []
        for c in curve.split(":"):
            if not c:
                continue
            try:
                group = self._ECDH_CURVES[c]
            except KeyError:
                raise ValueError(
                    f"Unknown elliptic curve name '{c}'"
                ) from None
            else:
                groups.append(group)

        if not groups:
            raise ValueError(f"Unknown elliptic curve name '{curve}'")

        self._config["supported_groups"] = groups

    def load_dh_params(self, path: StrOrBytesPath) -> None:
        with open(path, "rb") as fp:
            dh_parameters = tls.load_pem_parameters(fp.read())
        self._config["dh_parameters"] = dh_parameters

    def set_ech_configs(self, ech_configs: ReadableBuffer | None) -> None:
        self._config["ech_configs"] = ech_configs

    def _load_windows_store_certs(
        self, storename: str, purpose: Purpose
    ) -> None:
        if not hasattr(_ssl, "enum_certificates"):
            return

        enum_certificates = _ssl.enum_certificates
        try:
            for cert, encoding, trust in enum_certificates(storename):
                # CA certs are never PKCS#7 encoded
                if encoding == "x509_asn":
                    if trust is False:
                        continue
                    if trust is True or purpose.oid in trust:
                        self.load_verify_locations(cadata=cert)
        except PermissionError:
            warnings.warn(
                "unable to enumerate Windows certificate store",
                stacklevel=2,
            )

    def cert_store_stats(self) -> dict[str, int]:
        data = {"x509": 0, "crl": 0, "x509_ca": 0}

        for c in self._castore:
            data["x509"] += 1

            try:
                ba = c.extensions.get_extension_for_class(
                    x509.BasicConstraints
                )
            except x509.ExtensionNotFound:
                pass
            else:
                if ba.value.ca:
                    data["x509_ca"] += 1

        return data

    @typing.overload
    def get_ca_certs(
        self, binary_form: typing.Literal[False] = False
    ) -> list[PeerCertRetDictType]: ...

    @typing.overload
    def get_ca_certs(
        self, binary_form: typing.Literal[True]
    ) -> list[bytes]: ...

    @typing.overload
    def get_ca_certs(
        self, binary_form: bool = False
    ) -> list[PeerCertRetDictType] | list[bytes]: ...

    def get_ca_certs(self, binary_form: bool = False) -> typing.Any:
        castore = self._castore
        if not binary_form:
            return [parse_certificate(c) for c in castore]
        return [c.public_bytes(serialization.Encoding.DER) for c in castore]

    def load_cert_chain(
        self,
        certfile: StrOrBytesPath,
        keyfile: StrOrBytesPath | None = None,
        password: str | ReadableBuffer | None = None,
    ) -> None:
        credential = tls.TLSCredential.from_certfile(
            certfile=certfile,
            keyfile=keyfile,
            password=str_to_bytes(password),  # type: ignore
        )
        self._config["credential"] = credential

    def load_verify_locations(
        self,
        cafile: StrOrBytesPath | None = None,
        capath: StrOrBytesPath | None = None,
        cadata: ReadableBuffer | None = None,
    ) -> None:
        castore = tls.load_castore(
            cafile=cafile,
            capath=capath,
            cadata=cadata,  # type: ignore
        )
        self._castore.extend(castore)

    def load_default_certs(
        self, purpose: Purpose = Purpose.SERVER_AUTH
    ) -> None:
        if not isinstance(purpose, _ssl._ASN1Object):
            raise TypeError(purpose)

        if sys.platform == "win32":
            for storename in self._windows_cert_stores:
                self._load_windows_store_certs(storename, purpose)

        self.set_default_verify_paths()

    def set_default_verify_paths(self) -> None:
        try:
            import certifi
        except ImportError:
            pass
        else:
            self.load_verify_locations(cafile=certifi.where())

    @property
    def minimum_version(self) -> TLSVersion:
        return self._minimum_version

    @minimum_version.setter
    def minimum_version(self, value: TLSVersion) -> None:
        self._minimum_version = value

    @property
    def maximum_version(self) -> TLSVersion:
        return self._maximum_version

    @maximum_version.setter
    def maximum_version(self, value: TLSVersion) -> None:
        self._maximum_version = value

    @property
    def options(self) -> Options:
        return self._options

    @options.setter
    def options(self, value: Options) -> None:
        try:
            value = Options(value)
        except ValueError:
            raise ValueError(f"Unknown Options ({value})") from None
        self._options = value

    @property
    def check_hostname(self) -> bool:
        return self._check_hostname

    @check_hostname.setter
    def check_hostname(self, value: bool) -> None:
        self._check_hostname = value

    @property
    def hostname_checks_common_name(self) -> bool:
        return True

    @property
    def post_handshake_auth(self) -> bool:
        return self._post_handshake_auth

    @post_handshake_auth.setter
    def post_handshake_auth(self, value: bool) -> None:
        self._post_handshake_auth = value

    @property
    def _msg_callback(self) -> typing.Callable | None:
        return None

    @_msg_callback.setter
    def _msg_callback(self, callback: typing.Callable | None) -> None:
        raise NotImplementedError

    @property
    def protocol(self) -> _ssl._SSLMethod:
        return _ssl._SSLMethod(self._protocol)

    @property
    def verify_flags(self) -> VerifyFlags:
        return VerifyFlags.VERIFY_DEFAULT

    @verify_flags.setter
    def verify_flags(self, value: VerifyFlags) -> None:
        raise NotImplementedError

    @property
    def verify_mode(self) -> VerifyMode:
        return self._verify_mode

    @verify_mode.setter
    def verify_mode(self, value: VerifyMode) -> None:
        self._verify_mode = value

    @staticmethod
    def _get_version(value: TLSVersion) -> tls.TLSVersion | None:
        if value == TLSVersion.MAXIMUM_SUPPORTED:
            return tls.TLSVersion.TLSv1_3
        elif value == TLSVersion.MINIMUM_SUPPORTED:
            return tls.TLSVersion.TLSv1
        try:
            return tls.TLSVersion(value)
        except ValueError:
            return None

    def _config_data(self) -> dict[str, typing.Any]:
        config = self._config.copy()

        minimum_version = self._get_version(self._minimum_version)
        if minimum_version is not None:
            config["minimum_version"] = minimum_version

        maximum_version = self._get_version(self._maximum_version)
        if maximum_version is not None:
            config["maximum_version"] = maximum_version

        if self._verify_mode == VerifyMode.CERT_NONE:
            config["verify_mode"] = tls.VerifyMode.CERT_NONE
        elif self._verify_mode == VerifyMode.CERT_OPTIONAL:
            config["verify_mode"] = tls.VerifyMode.CERT_OPTIONAL
        elif self._verify_mode == VerifyMode.CERT_REQUIRED:
            config["verify_mode"] = tls.VerifyMode.CERT_REQUIRED
        else:
            raise ValueError(f"Unsupported verify_mode '{self._verify_mode}'")

        config["castore"] = self._castore
        config["check_hostname"] = self._check_hostname
        config["post_handshake_auth"] = self._post_handshake_auth
        config["ticket_aead"] = self._ticket_aead

        return config
