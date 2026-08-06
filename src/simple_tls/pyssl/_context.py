from __future__ import annotations

import ssl as _ssl
import sys
import typing
import warnings
from socket import socket

from simple_tls import tls, x509
from simple_tls.utils.math import str_to_bytes

from ._cipher import parse_cipher_string
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
from ._session import SSLSession
from ._socket import SSLSocket
from ._types import (
    ExtensionsCbType,
    PeerCertRetDictType,
    PSKClientCbType,
    PSKServerCbType,
    ReadableBuffer,
    SrvnmeCbType,
    StrOrBytesPath,
)
from ._util import parse_certificate


class SSLContext:
    """
    An SSLContext holds various SSL-related configuration options and
    data, such as certificates and possibly a private key.
    """

    _windows_cert_stores = ("CA", "ROOT")

    sslsocket_class: type[SSLSocket] = SSLSocket
    sslobject_class: type[SSLObject] = SSLObject

    def __init__(self, protocol: int = PROTOCOL_TLS):
        self._context = tls.TLSContext()
        self._options = (
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

        if protocol == PROTOCOL_TLS_CLIENT:
            self.verify_mode = VerifyMode.CERT_REQUIRED
            self.check_hostname = True
        elif protocol == PROTOCOL_TLS_SERVER:
            self.verify_mode = VerifyMode.CERT_NONE
            self.check_hostname = False

    def _set_options(self) -> None:
        if self._options & Options.OP_NO_TICKET:
            self._context.session_keys = None
            self._context.session_storage = None

        self._context.middlebox_compat = bool(
            self._options & Options.OP_ENABLE_MIDDLEBOX_COMPAT
        )

    def wrap_socket(
        self,
        sock: socket,
        server_side: bool = False,
        do_handshake_on_connect: bool = True,
        suppress_ragged_eofs: bool = True,
        server_hostname: bytes | str | None = None,
        session: SSLSession | None = None,
    ) -> SSLSocket:
        self._set_options()
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
        self._set_options()
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
        self._context.cipher_suites = cipher_suites

    def set_npn_protocols(self, npn_protocols: typing.Iterable[str]) -> None:
        out = []
        for protocol in npn_protocols:
            b = bytes(protocol, "ascii")
            if len(b) == 0 or len(b) > 255:
                raise ValueError("NPN protocols must be 1 to 255 in length")
            out.append(b)

        self._context.npn_protocols = out

    def set_alpn_protocols(self, alpn_protocols: typing.Iterable[str]) -> None:
        out = []
        for protocol in alpn_protocols:
            b = bytes(protocol, "ascii")
            if len(b) == 0 or len(b) > 255:
                raise ValueError("NPN protocols must be 1 to 255 in length")
            out.append(b)

        self._context.alpn_protocols = out

    def set_servername_callback(self, callback: SrvnmeCbType | None) -> None:
        if callback is None:
            self._context.sni_callback = None
        else:
            if not callable(callback):
                raise TypeError("not a callable object")

            def shim_cb(
                _: tls.TLSConnection,
                servername: str,
                arg: typing.Any,
            ) -> int | None:
                return callback(arg, servername, self)

            self._context.sni_callback = shim_cb

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

    def set_exts_order_callback(
        self, callback: ExtensionsCbType | None
    ) -> None:
        if callback is not None and not callable(callback):
            raise TypeError("Not a callback object")
        self._context.extensions_order_cb = callback

    def set_ecdh_curve(self, curve: str) -> None:
        lookup_map = {
            "prime256v1": tls.NamedGroup.SECP256R1,
            "secp384r1": tls.NamedGroup.SECP384R1,
            "x25519": tls.NamedGroup.X25519,
            "x448": tls.NamedGroup.X448,
            "x25519mlkem768": tls.NamedGroup.X25519MLKEM768,
        }
        groups = []
        for c in curve.split(":"):
            if not c:
                continue
            try:
                group = lookup_map[c]
            except KeyError:
                raise ValueError(
                    f"Unknown elliptic curve name '{c}'"
                ) from None
            else:
                groups.append(group)

        if not groups:
            raise ValueError(f"Unknown elliptic curve name '{curve}'")

        self._context.supported_groups = groups
        self._context.key_share_groups = groups[:2]

    def load_dh_params(self, path: str) -> None:
        return self._context.load_dh_params(path)

    def set_ech_configs(self, ech_config: bytes | None) -> None:
        self._context.ech_configs = str_to_bytes(ech_config)

    def _load_windows_store_certs(
        self, storename: str, purpose: Purpose
    ) -> None:
        if not hasattr(_ssl, "enum_certificates"):
            return

        enum_certificates = _ssl.enum_certificates
        certs = bytearray()

        try:
            for cert, encoding, trust in enum_certificates(storename):
                # CA certs are never PKCS#7 encoded
                if encoding == "x509_asn":
                    if trust is False:
                        continue
                    if trust is True or purpose.oid in trust:
                        certs.extend(cert)

        except PermissionError:
            warnings.warn(
                "unable to enumerate Windows certificate store",
                stacklevel=2,
            )

        if certs:
            self.load_verify_locations(cadata=bytes(certs))

    def cert_store_stats(self) -> dict[str, int]:
        data = {"x509": 0, "crl": 0, "x509_ca": 0}

        for c in self._context.castore:
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
        ca_certs = self._context.get_ca_certs()
        if not binary_form:
            return [parse_certificate(c) for c in ca_certs]
        return [c.public_bytes(x509.Encoding.DER) for c in ca_certs]

    def load_cert_chain(
        self,
        certfile: str | bytes,
        keyfile: str | bytes | None = None,
        password: str | bytes | None = None,
    ) -> None:
        return self._context.load_cert_chain(
            certfile=certfile, keyfile=keyfile, password=password
        )

    def load_verify_locations(
        self,
        cafile: StrOrBytesPath | None = None,
        capath: StrOrBytesPath | None = None,
        cadata: str | ReadableBuffer | None = None,
    ) -> None:
        self._context.load_verify_locations(
            cafile=cafile,  # type: ignore
            capath=capath,  # type: ignore
            cadata=cadata,  # type: ignore
        )

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

    @staticmethod
    def _get_version(
        value: TLSVersion, default: tls.TLSVersion
    ) -> tls.TLSVersion:
        if value == TLSVersion.MAXIMUM_SUPPORTED:
            return tls.TLSVersion.TLSv1_3
        elif value == TLSVersion.MINIMUM_SUPPORTED:
            return tls.TLSVersion.TLSv1
        try:
            return tls.TLSVersion(value)
        except ValueError:
            return default

    @property
    def minimum_version(self) -> TLSVersion:
        return TLSVersion(self._context.minimum_version)

    @minimum_version.setter
    def minimum_version(self, value: TLSVersion) -> None:
        ver = self._get_version(value, tls.TLSVersion.TLSv1)
        if value > self._context.maximum_version:
            self._context.maximum_version = ver
        self._context.minimum_version = ver

    @property
    def maximum_version(self) -> TLSVersion:
        return TLSVersion(self._context.maximum_version)

    @maximum_version.setter
    def maximum_version(self, value: TLSVersion) -> None:
        ver = self._get_version(value, tls.TLSVersion.TLSv1_3)
        if value < self._context.minimum_version:
            self._context.minimum_version = ver
        self._context.maximum_version = ver

    @property
    def application_settings(self) -> bool:
        return b"h2" in self._context.alps

    @application_settings.setter
    def application_settings(self, value: bool) -> None:
        if value:
            self._context.alps[b"h2"] = b""
        else:
            self._context.alps.clear()

    @property
    def grease(self) -> bool:
        return self._context.grease

    @grease.setter
    def grease(self, value: bool) -> None:
        self._context.grease = value

    @property
    def grease_ech(self) -> bool:
        return self._context.grease_ech

    @grease_ech.setter
    def grease_ech(self, value: bool) -> None:
        self._context.grease_ech = value

    @property
    def client_hello_padding(self) -> bool:
        return self._context.client_hello_padding

    @client_hello_padding.setter
    def client_hello_padding(self, value: bool) -> None:
        self._context.client_hello_padding = value

    @property
    def encrypt_then_mac(self) -> bool:
        return self._context.encrypt_then_mac

    @encrypt_then_mac.setter
    def encrypt_then_mac(self, value: bool) -> None:
        self._context.encrypt_then_mac = value

    @property
    def options(self) -> Options:
        return self._options

    @options.setter
    def options(self, value: Options | int) -> None:
        try:
            value = Options(value)
        except ValueError:
            raise ValueError(f"Unknown Options ({value})") from None
        self._options = value

    @property
    def check_hostname(self) -> bool:
        return self._context.check_hostname

    @check_hostname.setter
    def check_hostname(self, value: bool) -> None:
        self._context.check_hostname = value

    @property
    def hostname_checks_common_name(self) -> bool:
        return True

    @property
    def post_handshake_auth(self) -> bool:
        return self._context.post_handshake_auth

    @post_handshake_auth.setter
    def post_handshake_auth(self, value: bool) -> None:
        self._context.post_handshake_auth = value

    @property
    def _msg_callback(self) -> typing.Callable | None:
        return None

    @_msg_callback.setter
    def _msg_callback(self, callback: typing.Callable | None) -> None:
        raise NotImplementedError

    @property
    def protocol(self) -> _ssl._SSLMethod:
        return _ssl._SSLMethod(self.protocol)

    @property
    def verify_flags(self) -> VerifyFlags:
        return VerifyFlags.VERIFY_DEFAULT

    @verify_flags.setter
    def verify_flags(self, value: VerifyFlags) -> None:
        raise NotImplementedError

    @property
    def verify_mode(self) -> VerifyMode:
        value = self._context.verify_mode
        if value == tls.TLSVerifyMode.CERT_NONE:
            return VerifyMode.CERT_NONE
        elif value == tls.TLSVerifyMode.CERT_OPTIONAL:
            return VerifyMode.CERT_OPTIONAL
        else:
            return VerifyMode.CERT_REQUIRED

    @verify_mode.setter
    def verify_mode(self, value: VerifyMode) -> None:
        if value == VerifyMode.CERT_NONE:
            self._context.verify_mode = tls.TLSVerifyMode.CERT_NONE
        elif value == VerifyMode.CERT_OPTIONAL:
            self._context.verify_mode = tls.TLSVerifyMode.CERT_OPTIONAL
        elif value == VerifyMode.CERT_REQUIRED:
            self._context.verify_mode = tls.TLSVerifyMode.CERT_REQUIRED
        else:
            raise ValueError(f"Unsupported verify_mode '{value}'")
