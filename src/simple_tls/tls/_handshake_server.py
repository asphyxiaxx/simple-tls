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

from cryptography import x509
from cryptography.x509.oid import PublicKeyAlgorithmOID

from simple_tls.codec import Parser, Writer
from simple_tls.crypto.constant_time import compare_digest
from simple_tls.crypto.utils import (
    bytes_to_int,
    get_random_bytes,
    int_to_bytes,
)

from ._alert import (
    Alert,
    AlertDecodeError,
    AlertDecryptError,
    AlertHandshakeFailure,
    AlertIllegalParameter,
    AlertInappropriateFallback,
    AlertInternalError,
    AlertMissingExtension,
    AlertProtocolVersion,
    AlertUnexpectedMessage,
    AlertUnsupportedExtension,
)
from ._callback import ClientHelloInfo, HandshakeContext
from ._configuration import TLSConfiguration
from ._constant import (
    SERVER_CONTEXT_STRING,
    TLS11_DOWNGRADE_SENTINEL,
    TLS12_DOWNGRADE_SENTINEL,
    TLS13_HRR_SENTINEL,
    AlertDescription,
    Authentication,
    CipherSuite,
    ClientCertificateType,
    Compression,
    ECCurveType,
    ECPointFormat,
    ExtensionType,
    HandshakeType,
    KeyExchange,
    KeyUpdateMessageType,
    PSKKeyExchangeMode,
    Symmetric,
    TLSVersion,
)
from ._enum import Direction, Epoch, ServerState, Status, VerifyMode
from ._extension import (
    ClientALPNExtension,
    ClientALPSExtension,
    ClientKeyShareExtension,
    ClientNPNExtension,
    ClientPHAExtension,
    ClientPSKExtension,
    ClientSNIExtension,
    ClientSupportedGroupsExtension,
    ClientSupportedVersionsExtension,
    CompressedCertificateExtension,
    CookieExtension,
    EarlyDataExtension,
    ECPointFormatsExtension,
    EncryptThenMacExtension,
    ExtendedMasterSecretExtension,
    Extension,
    ExtensionSource,
    HRRKeyShareExtension,
    KeyShareEntry,
    PSKKeyExchangeModesExtension,
    RenegotiationInfoExtension,
    ServerALPNExtension,
    ServerALPSExtension,
    ServerEarlyDataExtension,
    ServerKeyShareExtension,
    ServerNPNExtension,
    ServerPSKExtension,
    ServerSupportedVersionExtension,
    SessionTicketExtension,
    SignatureAlgorithmsExtension,
)
from ._handshake import TLSHandshake
from ._key import BasePrivateKey, RSAPrivateKey, load_certificate_public_key
from ._keyexchange import ECDHKeyExchange, FFDHKeyExchange, KEMKeyExchange
from ._message import (
    CertificateRequest,
    CertificateRequestTLS12,
    CertificateRequestTLS13,
    CertificateVerify,
    CertificateVerifyTLS12,
    ClientHello,
    ClientKeyExchange,
    EncryptedExtensions,
    EndOfEarlyData,
    Finished,
    Handshake,
    KeyUpdate,
    NewSessionTicket,
    NewSessionTicketTLS13,
    NextProtocol,
    ServerHello,
    ServerHelloDone,
    ServerKeyExchange,
)
from ._session import TLSSession
from ._supported import (
    CERTIFICATE_COMPRESSIONS,
    DSA_SIGNATURE_ALGORITHMS,
    ECC_GROUPS,
    ECDSA_SIGNATURE_ALGORITHMS,
    EDDSA_SIGNATURE_ALGORITHMS,
    FFDHE_GROUPS,
    KEM_GROUPS,
    RSA_SIGNATURE_ALGORITHMS,
    SIGNATURE_ALGORITHMS,
    SUPPORTED_GROUPS,
)
from ._transcript import KeyDeriver, KeySchedule
from ._utils import filter, negotiate

SNICallback = typing.Callable[[ClientHelloInfo, HandshakeContext], None]


class TLSHandshakeServer(TLSHandshake):
    is_server = True

    def __init__(self, configuration: TLSConfiguration) -> None:
        self.sni_callback: SNICallback | None = None

        ## Initialization
        super().__init__(configuration)

        ## Dispatch function
        # ruff: disable[E501]
        self._handle_dispatch = {
            ServerState.START_ACCEPT: self._do_start_accept,
            ServerState.READ_CLIENT_HELLO: self._do_read_client_hello,
            ServerState.SELECT_PARAMETERS: self._do_select_parameters,
            ServerState.SEND_SERVER_HELLO: self._do_send_server_hello,
            ServerState.SEND_SERVER_CERTIFICATE: self._do_send_server_certificate,
            ServerState.SEND_SERVER_KEY_EXCHANGE: self._do_send_server_key_exchange,
            ServerState.SEND_SERVER_HELLO_DONE: self._do_send_server_hello_done,
            ServerState.READ_CLIENT_CERTIFICATE: self._do_read_client_certificate,
            ServerState.VERIFY_CLIENT_CERTIFICATE: self._do_verify_client_certificate,
            ServerState.READ_CLIENT_KEY_EXCHANGE: self._do_read_client_key_exchange,
            ServerState.READ_CLIENT_CERTIFICATE_VERIFY: self._do_read_client_certificate_verify,
            ServerState.READ_CHANGE_CIPHER_SPEC: self._do_read_change_cipher_spec,
            ServerState.PROCESS_CHANGE_CIPHER_SPEC: self._do_process_change_cipher_spec,
            ServerState.READ_NEXT_PROTO: self._do_read_next_proto,
            ServerState.READ_CLIENT_FINISHED: self._do_read_client_finished,
            ServerState.SEND_SESSION_TICKET: self._do_send_session_ticket,
            ServerState.SEND_SERVER_FINISHED: self._do_send_server_finished,
            # TLSv1.3
            ServerState.SELECT_PARAMETERS_TLS13: self._do_select_parameters_tls13,
            ServerState.SEND_HELLO_RETRY_REQUEST_TLS13: self._do_send_hello_retry_request_tls13,
            ServerState.READ_SECOND_CLIENT_HELLO_TLS13: self._do_read_second_client_hello_tls13,
            ServerState.SEND_SERVER_HELLO_TLS13: self._do_send_server_hello_tls13,
            ServerState.SEND_ENCRYPTED_EXTENSIONS_TLS13: self._do_send_encrypted_extensions_tls13,
            ServerState.SEND_SERVER_FINISHED_TLS13: self._do_send_server_finished_tls13,
            ServerState.READ_SECOND_CLIENT_FLIGHT_TLS13: self._do_read_second_client_flight_tls13,
            ServerState.PROCESS_END_OF_EARLY_DATA_TLS13: self._do_process_end_of_early_data_tls13,
            ServerState.READ_CLIENT_ENCRYPTED_EXTENSIONS_TLS13: self._do_read_client_encrypted_extensions_tls13,
            ServerState.READ_CLIENT_CERTIFICATE_TLS13: self._do_read_client_certificate_tls13,
            ServerState.READ_CLIENT_CERTIFICATE_VERIFY_TLS13: self._do_read_client_certificate_verify_tls13,
            ServerState.READ_CLIENT_FINISHED_TLS13: self._do_read_client_finished_tls13,
            ServerState.SEND_NEWSESSION_TICKET_TLS13: self._do_send_new_session_ticket_tls13,
            # Finish handshake
            ServerState.FINISHED_SERVER_HANDSHAKE: self._do_finish_server_handshake,
            # Post handshake
            ServerState.READ_POST_HANDSHAKE: self._do_read_post_handshake,
            ServerState.PROCESS_UPDATE_TRAFFIC: self._do_process_update_traffic,
            ServerState.COMPLETE_UPDATE_TRAFFIC: self._do_complete_update_traffic,
        }
        # ruff: enable[E501]

        ## Configurations
        # Cipher Suites
        self._cipher_suites: tuple[CipherSuite, ...] = tuple(
            configuration.cipher_suites
        )

        # Supported groups
        self._supported_groups: tuple[int, ...] = filter(
            configuration.supported_groups,
            SUPPORTED_GROUPS,
            SUPPORTED_GROUPS,
        )

        # Signature algorithms
        self._signature_algorithms: tuple[int, ...] = filter(
            configuration.signature_algorithms,
            SIGNATURE_ALGORITHMS,
            SIGNATURE_ALGORITHMS,
        )

        # Certificate Compression Algorithm
        self._certificate_compressions: tuple[int, ...] | None = filter(
            configuration.certificate_compressions, CERTIFICATE_COMPRESSIONS
        )

        # EC point formats
        self._ec_point_formats: tuple[int, ...] = (ECPointFormat.UNCOMPRESSED,)

        # PSK Key Exchange Mode
        self._psk_kex_modes: tuple[int, ...] = (PSKKeyExchangeMode.PSK_DHE_KE,)

        # Encrypt Then Mac
        self._enable_etm: bool = configuration.encrypt_then_mac

        # Extended Master Secret
        self._enable_ems: bool = configuration.extended_master_secret

        # Post Handshake Authentication
        self._enable_pha: bool = configuration.post_handshake_auth

        # Early data
        self._enable_early_data: bool = configuration.early_data

        # Max early data size
        self._max_early_data_size: int = configuration.max_early_data_size

        # ALPN protocols
        self._alpn_protocols: tuple[bytes, ...] | None = (
            tuple(configuration.alpn_protocols)
            if configuration.alpn_protocols
            else None
        )

        # NPN Protocols
        self._npn_protocols: tuple[bytes, ...] | None = (
            tuple(configuration.npn_protocols)
            if configuration.npn_protocols
            else None
        )

        # Application Settings
        self._alps: dict[bytes, bytes] = {}
        if self._alpn_protocols is not None and configuration.alps is not None:
            for protocol, settings in configuration.alps.items():
                if protocol in self._alpn_protocols:
                    self._alps[protocol] = settings

        # Cookie for HRR
        self._cookie: bytes | None = None

        ## Temporary State
        self._hs_state = ServerState.START_ACCEPT
        self._extensions_recv: set[int] = set()
        self._npn_expected: bool = False
        self._ticket_expected: bool = False
        self._certificate_requested: bool = False

        self._pre_shared_key: tuple[bytes, bytes] | None = None
        self._key_exchange: ECDHKeyExchange | FFDHKeyExchange | None = None

        # Identity
        self._private_key: BasePrivateKey | None = None
        self._x509_certificates: tuple[x509.Certificate, ...] | None = None

        # Peer item
        self._peer_cipher_suites: tuple[int, ...] | None = None
        self._peer_signature_algorithms: tuple[int, ...] | None = None
        self._peer_supported_groups: tuple[int, ...] | None = None
        self._peer_key: bytes | None = None

        # Negotiated variable
        self._psk_index: int | None = None
        """PSK index selected"""
        self._group_id: int | None = None
        """gorup id (TLSv1)"""
        self._group_id_tls13: int | None = None
        """gorup id for key share (TLSv1.3)"""
        self._signature_algorithm: int | None = None
        """signature algorithm to be used with signing"""
        self._post_handshake_auth: bool = False
        """True when PHA negotiated"""
        self._certificate_compression: int | None = None
        """Certificate compression algorithm negotiated"""

    @property
    def done(self) -> bool:
        return self._hs_state == ServerState.DONE

    @property
    def peer_cipher_suites(self) -> tuple[int, ...] | None:
        return self._peer_cipher_suites

    def trigger_post_handshake(self) -> None:
        if not self.done:
            raise ValueError("handshake not complete")
        self._set_state(ServerState.READ_POST_HANDSHAKE)

    def send_key_update(self, message_type: KeyUpdateMessageType) -> None:
        if not self.done:
            raise ValueError("KeyUpdate can only be sent after handshake done")

        self._write_key_update(message_type)
        self._set_state(ServerState.PROCESS_UPDATE_TRAFFIC)

    def _do_start_accept(self) -> Status:
        self._set_state(ServerState.READ_CLIENT_HELLO)
        return Status.OK

    def _do_read_client_hello(self) -> Status:
        message = self._get_message()
        if message is None:
            return Status.READ_MESSAGE

        client_hello = message.get_handshake(ClientHello)

        # Server random
        self._server_random = get_random_bytes(32)

        # Update client random
        self._client_random = client_hello.random

        # Version
        self._client_version = client_hello.version

        if not TLSVersion.TLSv1 <= self._client_version <= TLSVersion.TLSv1_2:
            raise AlertHandshakeFailure("Invalid version in ClientHello")

        ext_map = client_hello.extension_map(ExtensionSource.CLIENT)

        # Supported versions
        supported_versions = range(
            self._maximum_version, self._minimum_version - 1, -1
        )
        supported_version_ext = typing.cast(
            ClientSupportedVersionsExtension | None,
            ext_map.get(ExtensionType.SUPPORTED_VERSIONS),
        )
        if supported_version_ext is not None:
            if self._client_version != TLSVersion.TLSv1_2:
                raise AlertIllegalParameter("Invalid version in ClientHello")
            real_version = supported_version_ext.data
        else:
            real_version = [self._client_version]

        version = negotiate(
            supported_versions,
            real_version,
            AlertProtocolVersion("No supported version"),
        )
        self._version = version

        if (
            version < self._maximum_version
            and CipherSuite.TLS_FALLBACK_SCSV in client_hello.cipher_suites
        ):
            raise AlertInappropriateFallback()

        # Compression methods
        if version >= TLSVersion.TLSv1_3:
            if (
                len(client_hello.compression_methods) != 1
                and client_hello.compression_methods[0] != Compression.NULL
            ):
                raise AlertIllegalParameter("Invalid compression methods")

        elif Compression.NULL not in client_hello.compression_methods:
            AlertHandshakeFailure("No supported compression method")

        # Cipher suites
        self._peer_cipher_suites = tuple(client_hello.cipher_suites)

        # Signature algorithms
        sigalgs_ext = typing.cast(
            SignatureAlgorithmsExtension | None,
            ext_map.get(ExtensionType.SIGNATURE_ALGORITHMS),
        )
        if sigalgs_ext is not None:
            self._peer_signature_algorithms = tuple(sigalgs_ext.data)
        elif version >= TLSVersion.TLSv1_3:
            raise AlertMissingExtension(
                "Missing signature algorithms extension"
            )

        # Supported groups
        supported_groups_ext = typing.cast(
            ClientSupportedGroupsExtension | None,
            ext_map.get(ExtensionType.SUPPORTED_GROUPS),
        )
        if supported_groups_ext is not None:
            self._peer_supported_groups = tuple(supported_groups_ext.data)
        elif version >= TLSVersion.TLSv1_3:
            raise AlertMissingExtension("Missing supported groups extension")

        # SNI
        sni_ext = typing.cast(
            ClientSNIExtension | None, ext_map.get(ExtensionType.SERVER_NAME)
        )
        if sni_ext is not None:
            self._hostname = sni_ext.hostname

        if self.sni_callback is not None:
            client_hello_info = ClientHelloInfo(
                server_name=self._hostname,
                cipher_suites=self._peer_cipher_suites,
            )
            handshake_context = HandshakeContext(
                credential=self._credential,
                verify_mode=self._verify_mode,
            )
            self.sni_callback(client_hello_info, handshake_context)

            if handshake_context.alert_description is not None:
                try:
                    alert_description = AlertDescription(
                        handshake_context.alert_description
                    )
                except ValueError:
                    raise AlertInternalError()
                raise Alert(alert_description)

            # override current configuration
            self._credential = handshake_context.credential
            self._verify_mode = handshake_context.verify_mode

        credential = self._credential
        if credential is not None:
            self._private_key = credential.private_key
            self._x509_certificates = tuple(credential.x509_certificates)

        self._cipher_suite = self._negotiate_cipher_suite()
        self._process_extensions(ext_map)

        if version >= TLSVersion.TLSv1_3:
            self._set_state(ServerState.SELECT_PARAMETERS_TLS13)
        else:
            self._set_state(ServerState.SELECT_PARAMETERS)
        return Status.OK

    def _do_select_parameters(self) -> Status:
        message = self._get_message()
        if message is None:
            return Status.READ_MESSAGE

        client_hello = message.get_handshake(ClientHello)
        version = self.protocol_version()
        cipher_suite = self.cipher_suite()

        if self._x509_certificates is not None:
            x509_leaf = self._x509_certificates[0]
            try:
                public_key = load_certificate_public_key(x509_leaf)
            except ValueError as exc:
                raise AlertInternalError(str(exc)) from exc

            default_sigalg, supported_sigalgs = self._sigalgs_for_pubkey(
                version=version,
                public_key=public_key,
                public_key_oid=x509_leaf.public_key_algorithm_oid,
                supported_sigalgs=self._signature_algorithms,
            )

            if (
                version == TLSVersion.TLSv1_2
                and self._peer_signature_algorithms is not None
            ):
                self._signature_algorithm = negotiate(
                    supported_sigalgs,
                    self._peer_signature_algorithms,
                    AlertHandshakeFailure("No supported signature algorithm"),
                )
            else:
                if default_sigalg is None:
                    raise AlertHandshakeFailure("Unsupported certificate")
                self._signature_algorithm = default_sigalg

        elif cipher_suite.auth != Authentication.ANON:
            raise AlertHandshakeFailure(
                "No private key and certificates provided"
            )

        ticket_ext = client_hello.get_extension(SessionTicketExtension)

        if ticket_ext is not None:
            session = self._decrypt_session(ticket_ext.ticket)
        else:
            session = None

        if session is not None:
            if (
                session.extended_master_secret
                and not self._extended_master_secret
            ):
                raise AlertHandshakeFailure(
                    "Resumed EMS session without EMS extenison"
                )
            elif (
                self._extended_master_secret
                and not session.extended_master_secret
            ):
                session = None

        if session is not None:
            self._session_reused = True
            self._ticket_expected = False
            self._session_id = client_hello.session_id
        else:
            self._ticket_expected = (
                ticket_ext is not None
                and self.configuration.ticket_aead is not None
            )
            self._session_id = get_random_bytes(32)
            session = self._get_new_session()
            session.session_id = self._session_id

        if (
            version == TLSVersion.TLSv1_2
            and self._maximum_version >= TLSVersion.TLSv1_3
        ):
            self._server_random = (
                self._server_random[:24] + TLS12_DOWNGRADE_SENTINEL
            )
        elif (
            version <= TLSVersion.TLSv1_1
            and self._maximum_version >= TLSVersion.TLSv1_2
        ):
            self._server_random = (
                self._server_random[:24] + TLS11_DOWNGRADE_SENTINEL
            )

        self._key_deriver = KeyDeriver(
            version=version,
            cipher_suite=cipher_suite,
            client_random=self._client_random,
            server_random=self._server_random,
        )
        self._session = session

        if self._session_reused:
            self._setup_traffic_key(session)
        else:
            session.cipher_suite = cipher_suite
            self._certificate_requested = (
                self.configuration.verify_mode != VerifyMode.CERT_NONE
                and cipher_suite.auth != Authentication.ANON
            )

        self.message_cb(Direction.READ, client_hello)
        self._next_message()

        self._set_state(ServerState.SEND_SERVER_HELLO)
        return Status.OK

    def _do_send_server_hello(self) -> Status:
        extensions: list[Extension] = []

        if self._secure_renegotiation:
            extensions.append(RenegotiationInfoExtension(b""))

        if self._extended_master_secret:
            extensions.append(ExtendedMasterSecretExtension())

        if self._encrypt_then_mac:
            extensions.append(EncryptThenMacExtension())

        if ExtensionType.EC_POINT_FORMATS in self._extensions_recv:
            extensions.append(ECPointFormatsExtension(self._ec_point_formats))

        if self._npn_expected:
            if self._npn_protocols is None:
                raise AlertInternalError("npn_protocols not set")
            extensions.append(ServerNPNExtension(self._npn_protocols))

        if self._ticket_expected:
            extensions.append(SessionTicketExtension(b""))

        if self._alpn_selected is not None:
            if self._npn_expected:
                raise AlertInternalError("Unexpected npn selected")
            extensions.append(ServerALPNExtension(self._alpn_selected))

        server_hello = ServerHello(
            version=self.protocol_version(),
            random=self._server_random,
            session_id=self._session_id,
            cipher_suite=self.cipher_suite().id,
            compression_method=Compression.NULL,
            extensions=self._serialize_extensions(extensions),
        )

        self.message_cb(Direction.WRITE, server_hello)
        self._add_message(server_hello)

        if self._session_reused:
            self._set_state(ServerState.SEND_SESSION_TICKET)
        else:
            self._set_state(ServerState.SEND_SERVER_CERTIFICATE)
        return Status.OK

    def _do_send_server_certificate(self) -> Status:
        if self.cipher_suite().auth == Authentication.ANON:
            self._set_state(ServerState.SEND_SERVER_KEY_EXCHANGE)
            return Status.OK

        if self._x509_certificates is None:
            raise AlertInternalError("x509_certs not set")

        certificate = self._create_certificate(self._x509_certificates)
        self.message_cb(Direction.WRITE, certificate)
        self._add_message(certificate)

        self._set_state(ServerState.SEND_SERVER_KEY_EXCHANGE)
        return Status.OK

    def _do_send_server_key_exchange(self) -> Status:
        cipher_suite = self.cipher_suite()

        if cipher_suite.kea == KeyExchange.RSA:
            self._set_state(ServerState.SEND_SERVER_HELLO_DONE)
            return Status.OK

        version = self.protocol_version()
        writer = Writer()

        if cipher_suite.kea == KeyExchange.ECDHE:
            if self._group_id is None:
                raise AlertInternalError("group_id not set")

            self._key_exchange = ECDHKeyExchange(self._group_id)
            key_share = self._key_exchange.generate_key_share()

            writer.write_int(ECCurveType.NAMED_CURVE, 1)
            writer.write_int(self._group_id, 2)
            writer.write_prefixed_bytes(key_share, 1)

        elif cipher_suite.kea == KeyExchange.DHE:
            dh_params = self.configuration.dh_parameters
            self._key_exchange = FFDHKeyExchange(parameters=dh_params)

            writer.write_prefixed_bytes(int_to_bytes(self._key_exchange.p), 2)
            writer.write_prefixed_bytes(int_to_bytes(self._key_exchange.g), 2)
            writer.write_prefixed_bytes(int_to_bytes(self._key_exchange.y), 2)

        else:
            raise AlertInternalError("Unsupported cipher suite selected")

        if cipher_suite.auth != Authentication.ANON:
            if self._private_key is None:
                raise AlertInternalError("private_key not set")
            if self._signature_algorithm is None:
                raise AlertInternalError("signature_algorithm not set")

            ske_data = writer.tobytes()
            data = self._client_random + self._server_random + ske_data
            signature = self._private_key.sign(data, self._signature_algorithm)

            if version == TLSVersion.TLSv1_2:
                writer.write_int(self._signature_algorithm, 2)
            writer.write_prefixed_bytes(signature, 2)

        ske = ServerKeyExchange(writer.tobytes())
        self.message_cb(Direction.WRITE, ske)
        self._add_message(ske)

        self._set_state(ServerState.SEND_SERVER_HELLO_DONE)
        return Status.OK

    def _do_send_server_hello_done(self) -> Status:
        if self._certificate_requested:
            cert_request: CertificateRequestTLS12 | CertificateRequest
            cert_types: list[int] = []
            cert_authorities: tuple[bytes, ...] = ()
            supported_sigalgs = set(self._signature_algorithms)

            if supported_sigalgs.intersection(RSA_SIGNATURE_ALGORITHMS):
                cert_types.append(ClientCertificateType.RSA_SIGN)
            if supported_sigalgs.intersection(DSA_SIGNATURE_ALGORITHMS):
                cert_types.append(ClientCertificateType.DSS_SIGN)
            if supported_sigalgs.intersection(
                ECDSA_SIGNATURE_ALGORITHMS + EDDSA_SIGNATURE_ALGORITHMS
            ):
                cert_types.append(ClientCertificateType.ECDSA_SIGN)

            if not cert_types:
                raise AlertInternalError("No supported signature algorithms")

            if self.protocol_version() == TLSVersion.TLSv1_2:
                cert_request = CertificateRequestTLS12(
                    certificate_types=cert_types,
                    certificate_authorities=cert_authorities,
                    signature_algorithms=self._signature_algorithms,
                )
            else:
                cert_request = CertificateRequest(cert_types, cert_authorities)

            self.message_cb(Direction.WRITE, cert_request)
            self._add_message(cert_request)

        server_hello_done = ServerHelloDone()
        self.message_cb(Direction.WRITE, server_hello_done)
        self._add_message(server_hello_done)

        self._set_state(ServerState.READ_CLIENT_CERTIFICATE)
        return Status.FLUSH_MESSAGE

    def _do_read_client_certificate(self) -> Status:
        if not self._certificate_requested:
            self._set_state(ServerState.VERIFY_CLIENT_CERTIFICATE)
            return Status.OK

        message = self._get_message()
        if message is None:
            return Status.READ_MESSAGE

        if self._session is None:
            raise AlertInternalError("session not set")

        allow_anon = self.configuration.verify_mode != VerifyMode.CERT_REQUIRED
        certificate = self._process_certificate(
            message, self._session, allow_anon
        )
        self.message_cb(Direction.READ, certificate)
        self._next_message()

        self._set_state(ServerState.VERIFY_CLIENT_CERTIFICATE)
        return Status.OK

    def _do_verify_client_certificate(self) -> Status:
        if self._session is None:
            raise AlertInternalError("session not set")

        session = self._session
        if session.x509_peer is not None:
            self._verify_x509(session)

        self._set_state(ServerState.READ_CLIENT_KEY_EXCHANGE)
        return Status.OK

    def _do_read_client_key_exchange(self) -> Status:
        message = self._get_message()
        if message is None:
            return Status.READ_MESSAGE

        cke = message.get_handshake(ClientKeyExchange)

        version = self.protocol_version()
        cipher_suite = self.cipher_suite()
        parser = Parser(cke.data)

        # Derive premaster secret
        if cipher_suite.kea == KeyExchange.RSA:
            assert cipher_suite.auth == Authentication.RSA

            if not isinstance(self._private_key, RSAPrivateKey):
                raise AlertInternalError("Invalid key")

            enc_premaster_secret = parser.read_prefixed_bytes(2)
            premaster_secret = self._private_key.decrypt(enc_premaster_secret)

            if (
                premaster_secret is None
                or len(premaster_secret) != 48
                or bytes_to_int(premaster_secret[0:2]) != version
            ):
                premaster_secret = get_random_bytes(48)

        else:
            if self._key_exchange is None:
                raise AlertInternalError("key_exchange not set")
            if cipher_suite.kea == KeyExchange.ECDHE:
                peer_key = parser.read_prefixed_bytes(1)
            elif cipher_suite.kea == KeyExchange.DHE:
                peer_key = parser.read_prefixed_bytes(2)
            else:
                raise AlertInternalError("Unsupported cipher suite selected")

            if not peer_key:
                raise AlertDecodeError(
                    "Empty key share in client key exchange"
                )

            kea = self._key_exchange
            premaster_secret = kea.compute_shared_secret(peer_key)

        if parser.remaining():
            raise AlertDecodeError("Trailing data")

        # Update hash since extended master secret required transcript
        # until client key exchange
        self.message_cb(Direction.READ, cke)
        self._next_message()

        if self._session is None:
            raise AlertInternalError("session not set")
        if self._key_deriver is None:
            raise AlertInternalError("key_deriver not set")

        session = self._session
        session.extended_master_secret = self._extended_master_secret

        if self._extended_master_secret:
            label = b"extended master secret"
            transcript = self._transcript
        else:
            label = b"master secret"
            transcript = None

        master_secret = self._key_deriver.derive_master_secret(
            premaster_secret, label, transcript
        )
        session.secret = master_secret
        self._setup_traffic_key(session)

        self._set_state(ServerState.READ_CLIENT_CERTIFICATE_VERIFY)
        return Status.OK

    def _do_read_client_certificate_verify(self) -> Status:
        if self._session is None:
            raise AlertInternalError("session not set")

        if self._session.x509_peer is None:
            self._set_state(ServerState.READ_CHANGE_CIPHER_SPEC)
            return Status.OK

        message = self._get_message()
        if message is None:
            return Status.READ_MESSAGE

        cert_verify: CertificateVerifyTLS12 | CertificateVerify
        if self.protocol_version() >= TLSVersion.TLSv1_2:
            cert_verify = message.get_handshake(CertificateVerifyTLS12)
        else:
            cert_verify = message.get_handshake(CertificateVerify)

        self._process_certificate_verify(
            session=self._session,
            cert_verify=cert_verify,
            supported_sigalgs=self._signature_algorithms,
        )

        self.message_cb(Direction.READ, cert_verify)
        self._next_message()

        self._set_state(ServerState.READ_CHANGE_CIPHER_SPEC)
        return Status.OK

    def _do_read_change_cipher_spec(self) -> Status:
        self._set_state(ServerState.PROCESS_CHANGE_CIPHER_SPEC)
        return Status.READ_CHANGE_CIPHER_SPEC

    def _do_process_change_cipher_spec(self) -> Status:
        self.update_traffic_cb(Direction.READ, Epoch.APPLICATION_DATA)
        self._set_state(ServerState.READ_NEXT_PROTO)
        return Status.OK

    def _do_read_next_proto(self) -> Status:
        if not self._npn_expected:
            self._set_state(ServerState.READ_CLIENT_FINISHED)
            return Status.OK

        message = self._get_message()
        if message is None:
            return Status.READ_MESSAGE

        if self._npn_protocols is None:
            raise AlertInternalError("npn_protocols config not set")

        next_proto = message.get_handshake(NextProtocol)
        if next_proto.next_protocol not in self._npn_protocols:
            raise AlertIllegalParameter("Unexpected next_proto selected")

        self._npn_selected = next_proto.next_protocol

        self.message_cb(Direction.READ, next_proto)
        self._next_message()

        self._set_state(ServerState.READ_CLIENT_FINISHED)
        return Status.OK

    def _do_read_client_finished(self) -> Status:
        message = self._get_message()
        if message is None:
            return Status.READ_MESSAGE

        finished = message.get_handshake(Finished)

        if self._session is None:
            raise AlertInternalError("session not set")
        if self._key_deriver is None:
            raise AlertInternalError("key_deriver not set")

        master_secret = self._session.secret
        expected_verify_data = self._key_deriver.finished_verify_data(
            master_secret, b"client finished", self._transcript
        )
        if not compare_digest(finished.verify_data, expected_verify_data):
            raise AlertDecryptError("Incorect finished verify data")

        self.message_cb(Direction.READ, finished)
        self._next_message()

        if self._session_reused:
            self._set_state(ServerState.FINISHED_SERVER_HANDSHAKE)
        else:
            self._set_state(ServerState.SEND_SESSION_TICKET)
        return Status.OK

    def _do_send_session_ticket(self) -> Status:
        if self._ticket_expected:
            if self._session is None:
                raise AlertInternalError("session not set")

            session = self._session
            session.rebase_time()
            ticket = self._encrypt_session(session)
            if ticket:
                ticket_lifetime = int(session.timeout.total_seconds())
                new_session_ticket = NewSessionTicket(ticket_lifetime, ticket)
                self.message_cb(Direction.WRITE, new_session_ticket)
                self._add_message(new_session_ticket)

        self._set_state(ServerState.SEND_SERVER_FINISHED)
        return Status.PACK_FLIGHT

    def _do_send_server_finished(self) -> Status:
        self.update_traffic_cb(Direction.WRITE, Epoch.APPLICATION_DATA)
        self.add_ccs_cb()

        if self._session is None:
            raise AlertInternalError("session not set")
        if self._key_deriver is None:
            raise AlertInternalError("key_deriver not set")

        master_secret = self._session.secret
        verify_data = self._key_deriver.finished_verify_data(
            master_secret, b"server finished", self._transcript
        )
        finished = Finished(verify_data)
        self.message_cb(Direction.WRITE, finished)
        self._add_message(finished)

        if self._session_reused:
            self._set_state(ServerState.READ_CHANGE_CIPHER_SPEC)
        else:
            self._set_state(ServerState.FINISHED_SERVER_HANDSHAKE)
        return Status.FLUSH_MESSAGE

    def _do_select_parameters_tls13(self) -> Status:
        message = self._get_message()
        if message is None:
            return Status.READ_MESSAGE

        if self.has_unprocessed_hs_data():
            raise AlertUnexpectedMessage("Trailing handshake data")

        client_hello = message.get_handshake(ClientHello)

        # Update session id
        self._session_id = client_hello.session_id

        if self._private_key is None or self._x509_certificates is None:
            raise AlertHandshakeFailure(
                "certificate and private key not provided"
            )

        x509_leaf = self._x509_certificates[0]
        try:
            public_key = load_certificate_public_key(x509_leaf)
        except ValueError as exc:
            raise AlertInternalError(str(exc)) from exc

        _, supported_sigalgs = self._sigalgs_for_pubkey(
            version=self.protocol_version(),
            public_key=public_key,
            public_key_oid=x509_leaf.public_key_algorithm_oid,
            supported_sigalgs=self._signature_algorithms,
        )
        self._signature_algorithm = negotiate(
            supported_sigalgs,
            self._peer_signature_algorithms,
            AlertHandshakeFailure("No supported signature algorithm"),
        )

        key_share_ext = client_hello.get_extension(ClientKeyShareExtension)
        psk_ext = client_hello.get_extension(ClientPSKExtension)
        psk_kex_modes_ext = client_hello.get_extension(
            PSKKeyExchangeModesExtension
        )

        cipher_suite = self.cipher_suite()
        session = None
        key_schedule = None
        psk_kex_mode = None

        if psk_kex_modes_ext is not None:
            psk_kex_mode = negotiate(
                self._psk_kex_modes, psk_kex_modes_ext.data
            )

        if psk_ext is not None:
            # RFC 8446, section 4.2.9
            # servers MUST abort the handshake if the client pre_shared_key
            # without psk_key_exchange_modes.
            if psk_kex_modes_ext is None:
                raise AlertMissingExtension(
                    "Missing pre shared key modes extension"
                )

            if psk_kex_mode is not None:
                binders = psk_ext.binders
                transcript = self._transcript.copy()
                transcript.update_hash(
                    self._get_client_hello_without_binders(message, psk_ext)
                )

                for index, psk_identity in enumerate(psk_ext.identities):
                    identity = psk_identity.identity
                    session = self._decrypt_session(identity)
                    if session is None:
                        continue

                    key_schedule = KeySchedule(cipher_suite.prf_hash)
                    key_schedule.extract(session.secret)
                    binder_key = key_schedule.derive_secret(
                        b"res binder", self._transcript
                    )
                    expected_binder = key_schedule.finished_verify_data(
                        binder_key, transcript
                    )
                    if not compare_digest(binders[index], expected_binder):
                        raise AlertDecryptError("binder verify failed")

                    self._session_reused = True
                    self._psk_index = index
                    # Store in case of HRR
                    self._pre_shared_key = (identity, binder_key)
                    break

        if not self._session_reused:
            new_session = self._get_new_session()
            key_schedule = KeySchedule(cipher_suite.prf_hash)
            key_schedule.extract(None)
        else:
            assert session is not None
            assert key_schedule is not None
            new_session = session.copy()

        hrr = False

        if self._cookie is not None:
            hrr = True

        if psk_kex_mode != PSKKeyExchangeMode.PSK_KE:
            if self._peer_supported_groups is None:
                raise AlertInternalError("peer_supported_groups not set")
            if key_share_ext is None:
                raise AlertMissingExtension("Missing key share extension")

            shared_key_shares = {
                ks.group: ks.key_exchange for ks in key_share_ext.key_shares
            }
            if len(shared_key_shares) != len(key_share_ext.key_shares):
                raise AlertIllegalParameter(
                    "Duplicated group in key share extension"
                )

            for group in shared_key_shares:
                if group not in self._peer_supported_groups:
                    raise AlertIllegalParameter(
                        "Invalid supported groups extension"
                    )

            # Check if prefered key share in client key share. If not,
            # check if it is in client supported groups. If so, do a
            # Hello Retry Request else select key share from ecc curves
            # and dh groups
            for key_share_group in self._supported_groups:
                if key_share_group in shared_key_shares:
                    self._group_id_tls13 = key_share_group
                    self._peer_key = shared_key_shares[key_share_group]
                    break
                if key_share_group in self._peer_supported_groups:
                    self._group_id_tls13 = key_share_group
                    hrr = True
                    break
            else:
                raise AlertHandshakeFailure("No supported key shares group")

        new_session.cipher_suite = self._cipher_suite
        new_session.early_alpn = self._alpn_selected

        alps_ext = client_hello.get_extension(ClientALPSExtension)
        if (
            alps_ext is not None
            and self._alpn_selected is not None
            and self._alpn_selected in self._alps
            and self._alpn_selected in alps_ext.protocols
        ):
            new_session.has_alps = True
            new_session.local_alps = self._alps[self._alpn_selected]

        self._session = new_session
        self._key_schedule = key_schedule

        # Early data key required update client hello hash
        self.message_cb(Direction.READ, client_hello)
        self._next_message()

        if self._early_data_offered:
            if psk_ext is None:
                raise AlertIllegalParameter("Unexpected early data extension")

            if (
                self.configuration.early_data
                # RFC8446 Section 4.2.10
                # early data MUST be the first PSK listed in the client's
                # "pre_shared_key" extension
                and self._psk_index == 0
                and not hrr
                and session is not None
                and session.ticket_max_early_data > 0
                and (self._alpn_selected == session.early_alpn)
                and (
                    session.has_alps == new_session.has_alps
                    and session.local_alps == new_session.local_alps
                )
            ):
                self._early_data_accepted = True

                if new_session.has_alps:
                    new_session.peer_alps = session.peer_alps

                # Install the 0-RTT decryption key
                self._setup_traffic_key_tls13(
                    session=new_session,
                    direction=Direction.READ,
                    epoch=Epoch.ZERO_RTT,
                    label=b"c e traffic",
                )

            else:
                self._early_data_accepted = False
                self.skip_early_data = True

        if hrr:
            self._transcript.update_for_hello_retry_request(
                cipher_suite.prf_hash
            )
            self._set_state(ServerState.SEND_HELLO_RETRY_REQUEST_TLS13)
            return Status.OK

        self._set_state(ServerState.SEND_SERVER_HELLO_TLS13)
        return Status.OK

    def _do_send_hello_retry_request_tls13(self) -> Status:
        version = self.protocol_version()
        cipher_suite = self.cipher_suite()

        extensions: list[Extension] = []

        # Supported version extension
        extensions.append(ServerSupportedVersionExtension(version))

        if self._cookie is not None:
            extensions.append(CookieExtension(self._cookie))

        # Selected key share group extension
        if self._group_id_tls13 is not None:
            extensions.append(HRRKeyShareExtension(self._group_id_tls13))

        if not extensions:
            # Currently still not support send cookie extension
            raise AlertInternalError()

        hrr = ServerHello(
            version=TLSVersion.TLSv1_2,
            random=TLS13_HRR_SENTINEL,
            session_id=self._session_id,
            cipher_suite=cipher_suite.id,
            compression_method=Compression.NULL,
            extensions=self._serialize_extensions(extensions),
        )
        self.message_cb(Direction.WRITE, hrr)
        self._add_message(hrr)

        self._set_state(ServerState.READ_SECOND_CLIENT_HELLO_TLS13)
        return Status.FLUSH_MESSAGE

    def _do_read_second_client_hello_tls13(self) -> Status:
        message = self._get_message()
        if message is None:
            return Status.READ_MESSAGE

        client_hello = message.get_handshake(ClientHello)

        if self.has_unprocessed_hs_data():
            raise AlertUnexpectedMessage("Trailing handshake data")
        if self._key_schedule is None:
            raise AlertInternalError("key_schedule not set")

        cipher_suite = self.cipher_suite()

        supported_version_ext = client_hello.get_extension(
            ClientSupportedVersionsExtension
        )
        if (
            client_hello.version != self._client_version
            or supported_version_ext is None
            or self.protocol_version() not in supported_version_ext.data
        ):
            raise AlertProtocolVersion()

        if (
            client_hello.random != self._client_random
            or client_hello.session_id != self._session_id
            or Compression.NULL not in client_hello.compression_methods
            or cipher_suite not in client_hello.cipher_suites
        ):
            raise AlertIllegalParameter()

        if self._group_id_tls13 is None and self._cookie is None:
            raise AlertInternalError()

        key_share_ext = client_hello.get_extension(ClientKeyShareExtension)
        if self._group_id_tls13 is not None:
            selected_ks_group = self._group_id_tls13

            if key_share_ext is None:
                raise AlertMissingExtension("Missing key share extension")

            if len(key_share_ext.key_shares) != 1:
                raise AlertIllegalParameter()

            key_share_entry = key_share_ext.key_shares[0]
            if key_share_entry.group != selected_ks_group:
                raise AlertIllegalParameter("Unexpected key share group")

            self._peer_key = key_share_entry.key_exchange

        cookie_ext = client_hello.get_extension(CookieExtension)
        if self._cookie is not None:
            if cookie_ext is None:
                raise AlertMissingExtension("Missing cookie extension")
            if cookie_ext.data != self._cookie:
                raise AlertIllegalParameter("Malformed CookieExtension")
        elif cookie_ext is not None:
            raise AlertIllegalParameter("Unxpected cookie extension")

        psk_ext = client_hello.get_extension(ClientPSKExtension)
        if self._psk_index is not None:
            if self._pre_shared_key is None:
                raise AlertInternalError()
            if psk_ext is None:
                raise AlertIllegalParameter("Inconsistent client hello")

            binders = psk_ext.binders
            transcript = self._transcript.copy()
            transcript.update_hash(
                self._get_client_hello_without_binders(message, psk_ext)
            )

            for i, psk_identity in enumerate(psk_ext.identities):
                if psk_identity.identity != self._pre_shared_key[0]:
                    continue

                expected_binder = self._key_schedule.finished_verify_data(
                    self._pre_shared_key[1], transcript
                )
                if not compare_digest(binders[i], expected_binder):
                    raise AlertDecryptError("binder verify failed")

                self._psk_index = i
                break

            else:
                raise AlertDecryptError("Missing expected psk identity")

        self._next_message()
        self.message_cb(Direction.READ, client_hello)

        self._set_state(ServerState.SEND_SERVER_HELLO_TLS13)
        return Status.OK

    def _do_send_server_hello_tls13(self) -> Status:
        if self._key_schedule is None:
            raise AlertInternalError("key_schedule not set")
        if self._session is None:
            raise AlertInternalError("session not set")

        cipher_suite = self.cipher_suite()

        if not self._key_schedule.generation == 1:
            raise AlertInternalError()

        extensions: list[Extension] = []

        # Server supported version extension
        extensions.append(
            ServerSupportedVersionExtension(self.protocol_version())
        )

        if self._psk_index is not None:
            extensions.append(ServerPSKExtension(self._psk_index))

        if self._group_id_tls13 is not None:
            if self._peer_key is None:
                raise AlertInternalError("peer_key not set")

            kex: ECDHKeyExchange | FFDHKeyExchange | KEMKeyExchange
            ks_group = self._group_id_tls13
            if ks_group in ECC_GROUPS:
                kex = ECDHKeyExchange(ks_group)
            elif ks_group in FFDHE_GROUPS:
                kex = FFDHKeyExchange(ks_group)
            elif ks_group in KEM_GROUPS:
                kex = KEMKeyExchange(ks_group)
            else:
                raise AlertInternalError("Unsupported group selected")

            key_share, shared_secret = kex.generate_and_compute(self._peer_key)
            key_share_entry = KeyShareEntry(ks_group, key_share)
            extensions.append(ServerKeyShareExtension(key_share_entry))
            self._key_schedule.extract(shared_secret)
        else:
            self._key_schedule.extract(None)

        server_hello = ServerHello(
            version=TLSVersion.TLSv1_2,
            random=self._server_random,
            session_id=self._session_id,
            cipher_suite=cipher_suite.id,
            compression_method=Compression.NULL,
            extensions=self._serialize_extensions(extensions),
        )
        self.message_cb(Direction.WRITE, server_hello)
        self._add_message(server_hello)

        self._setup_traffic_key_tls13(
            session=self._session,
            direction=Direction.WRITE,
            epoch=Epoch.HANDSHAKE,
            label=b"s hs traffic",
        )
        self._setup_traffic_key_tls13(
            session=self._session,
            direction=Direction.READ,
            epoch=Epoch.HANDSHAKE,
            label=b"c hs traffic",
        )

        self._set_state(ServerState.SEND_ENCRYPTED_EXTENSIONS_TLS13)
        return Status.PACK_FLIGHT

    def _do_send_encrypted_extensions_tls13(self) -> Status:
        self.update_traffic_cb(Direction.WRITE, Epoch.HANDSHAKE)

        if self._key_schedule is None:
            raise AlertInternalError("key_schedule not set")
        if self._session is None:
            raise AlertInternalError("session not set")
        if (
            self._signature_algorithm is None
            or self._x509_certificates is None
            or self._private_key is None
        ):
            raise AlertInternalError("authentications not set")

        session = self._session
        enc_extensions: list[Extension] = []

        if self._early_data_accepted:
            enc_extensions.append(ServerEarlyDataExtension())

        if self._alpn_selected is not None:
            enc_extensions.append(ServerALPNExtension(self._alpn_selected))

        if session.has_alps and not self._early_data_accepted:
            enc_extensions.append(ServerALPSExtension(session.local_alps))

        enc_ext = EncryptedExtensions(
            self._serialize_extensions(enc_extensions)
        )
        self.message_cb(Direction.WRITE, enc_ext)
        self._add_message(enc_ext)

        if self._session_reused:
            self._set_state(ServerState.SEND_SERVER_FINISHED_TLS13)
            return Status.OK

        if self.configuration.verify_mode != VerifyMode.CERT_NONE:
            cert_extensions: list[Extension] = []

            cert_extensions.append(
                SignatureAlgorithmsExtension(self._signature_algorithms)
            )

            if self._certificate_compressions is not None:
                cert_extensions.append(
                    CompressedCertificateExtension(
                        self._certificate_compressions
                    )
                )

            cert_request = CertificateRequestTLS13(
                context=b"",
                extensions=self._serialize_extensions(cert_extensions),
            )
            self.message_cb(Direction.WRITE, cert_request)
            self._add_message(cert_request)

            self._certificate_requested = True

        certificate = self._create_certificate_tls13(
            x509_certs=self._x509_certificates,
            compression=self._certificate_compression,
        )
        self.message_cb(Direction.WRITE, certificate)
        self._add_message(certificate)

        data = self._key_schedule.certificate_verify_data(
            SERVER_CONTEXT_STRING, self._transcript
        )
        signature = self._private_key.sign(data, self._signature_algorithm)

        cert_verify = CertificateVerifyTLS12(
            signature, self._signature_algorithm
        )
        self.message_cb(Direction.WRITE, cert_verify)
        self._add_message(cert_verify)

        self._set_state(ServerState.SEND_SERVER_FINISHED_TLS13)
        return Status.OK

    def _do_send_server_finished_tls13(self) -> Status:
        if self._key_schedule is None:
            raise AlertInternalError("key_schedule not set")
        if self._session is None:
            raise AlertInternalError("session not set")

        verify_data = self._key_schedule.finished_verify_data(
            self._enc_secret[Epoch.HANDSHAKE], self._transcript
        )
        finished = Finished(verify_data)
        self.message_cb(Direction.WRITE, finished)
        self._add_message(finished)

        if not self._key_schedule.generation == 2:
            raise AlertInternalError()

        self._key_schedule.extract(None)
        self._setup_traffic_key_tls13(
            session=self._session,
            direction=Direction.WRITE,
            epoch=Epoch.APPLICATION_DATA,
            label=b"s ap traffic",
        )
        self._setup_traffic_key_tls13(
            session=self._session,
            direction=Direction.READ,
            epoch=Epoch.APPLICATION_DATA,
            label=b"c ap traffic",
        )

        self._set_state(ServerState.READ_SECOND_CLIENT_FLIGHT_TLS13)
        return Status.FLUSH_MESSAGE

    def _do_read_second_client_flight_tls13(self) -> Status:
        self.update_traffic_cb(Direction.WRITE, Epoch.APPLICATION_DATA)

        if self._early_data_accepted:
            self.update_traffic_cb(Direction.READ, Epoch.ZERO_RTT)
            self.can_early_write = True
            self.can_early_read = True
            self._in_early_data = True

            self._set_state(ServerState.PROCESS_END_OF_EARLY_DATA_TLS13)
            return Status.READ_END_OF_EARLY_DATA

        self._set_state(ServerState.PROCESS_END_OF_EARLY_DATA_TLS13)
        return Status.OK

    def _do_process_end_of_early_data_tls13(self) -> Status:
        if self._early_data_accepted:
            message = self._get_message()
            if message is None:
                return Status.READ_MESSAGE

            end_of_early_data = message.get_handshake(EndOfEarlyData)

            if self.has_unprocessed_hs_data():
                raise AlertUnexpectedMessage("Trailing handshake data")

            self._close_early_data()

            self.message_cb(Direction.READ, end_of_early_data)
            self._next_message()

        self.update_traffic_cb(Direction.READ, Epoch.HANDSHAKE)

        self._set_state(ServerState.READ_CLIENT_ENCRYPTED_EXTENSIONS_TLS13)
        return Status.OK

    def _do_read_client_encrypted_extensions_tls13(self) -> Status:
        if self._session is None:
            raise AlertInternalError("session not set")

        session = self._session

        if session.has_alps and not self._early_data_accepted:
            message = self._get_message()
            if message is None:
                return Status.READ_MESSAGE

            enc_ext = message.get_handshake(EncryptedExtensions)
            ext_map = enc_ext.extension_map(ExtensionSource.SERVER)
            alps_ext = typing.cast(
                ServerALPSExtension | None,
                ext_map.pop(ExtensionType.APPLICATION_SETTINGS, None),
            )
            if alps_ext is None:
                raise AlertMissingExtension("Missing ALPS extension")

            session.peer_alps = alps_ext.settings

            if ext_map:
                raise AlertUnsupportedExtension("Unexpected extension")

            self.message_cb(Direction.READ, enc_ext)
            self._next_message()

        self._set_state(ServerState.READ_CLIENT_CERTIFICATE_TLS13)
        return Status.OK

    def _do_read_client_certificate_tls13(self) -> Status:
        if not self._certificate_requested:
            self._set_state(ServerState.READ_CLIENT_FINISHED_TLS13)
            return Status.OK

        message = self._get_message()
        if message is None:
            return Status.READ_MESSAGE

        if self._session is None:
            raise AlertInternalError("session not set")

        if self.configuration.verify_mode == VerifyMode.CERT_REQUIRED:
            allow_anon = False
        else:
            allow_anon = True

        session = self._session
        configuration = self._configuration
        certificate = self._process_certificate_tls13(
            message=message,
            session=session,
            supported_compressions=self._certificate_compressions,
            allow_anon=allow_anon,
        )

        if (
            session.x509_peer is not None
            and configuration.verify_mode != VerifyMode.CERT_NONE
        ):
            self._verify_x509(session)

        self.message_cb(Direction.READ, certificate)
        self._next_message()

        self._set_state(ServerState.READ_CLIENT_CERTIFICATE_VERIFY_TLS13)
        return Status.OK

    def _do_read_client_certificate_verify_tls13(self) -> Status:
        if self._session is None:
            raise AlertInternalError("session not set")

        if self._session.x509_peer is None:
            self._set_state(ServerState.READ_CLIENT_FINISHED_TLS13)
            return Status.OK

        message = self._get_message()
        if message is None:
            return Status.READ_MESSAGE

        cert_verify = message.get_handshake(CertificateVerifyTLS12)

        self._process_certificate_verify(
            session=self._session,
            cert_verify=cert_verify,
            supported_sigalgs=self._signature_algorithms,
        )

        self.message_cb(Direction.READ, cert_verify)
        self._next_message()

        self._set_state(ServerState.READ_CLIENT_FINISHED_TLS13)
        return Status.OK

    def _do_read_client_finished_tls13(self) -> Status:
        message = self._get_message()
        if message is None:
            return Status.READ_MESSAGE

        finished = message.get_handshake(Finished)

        if self.has_unprocessed_hs_data():
            raise AlertUnexpectedMessage("Trailing handshake data")
        if self._key_schedule is None:
            raise AlertInternalError("key_schedule not set")

        verify_data = finished.verify_data
        expected_verify_data = self._key_schedule.finished_verify_data(
            self._dec_secret[Epoch.HANDSHAKE], self._transcript
        )
        if not compare_digest(verify_data, expected_verify_data):
            raise AlertDecryptError("Server finished verify data mismatch")

        self.message_cb(Direction.READ, finished)
        self._next_message()

        self.update_traffic_cb(Direction.READ, Epoch.APPLICATION_DATA)

        self._set_state(ServerState.SEND_NEWSESSION_TICKET_TLS13)
        return Status.OK

    def _do_send_new_session_ticket_tls13(self) -> Status:
        if self.configuration.ticket_aead is None:
            self._set_state(ServerState.FINISHED_SERVER_HANDSHAKE)
            return Status.OK

        if self._key_schedule is None:
            raise AlertInternalError("key_schedule not set")
        if self._session is None:
            raise AlertInternalError("session not set")
        if not self._key_schedule.generation == 3:
            raise AlertInternalError()

        # Resumption master secret
        master_secret = self._key_schedule.derive_secret(
            b"res master", self._transcript
        )
        session = self._session
        session.rebase_time()

        extensions: list[Extension] = []

        if self._enable_early_data and self._max_early_data_size > 0:
            extensions.append(EarlyDataExtension(self._max_early_data_size))
            session.ticket_max_early_data = self._max_early_data_size

        for i in range(2):
            new_session = session.copy(include_noauth=True)
            new_session.ticket = get_random_bytes(64)
            new_session.ticket_age_add = bytes_to_int(get_random_bytes(4))
            new_session.not_resumable = False

            ticket_nonce = int_to_bytes(i, 1)

            # Resumption secret
            new_session.secret = self._key_schedule.resumption_secret(
                master_secret, ticket_nonce
            )

            # Ticket
            ticket = self._encrypt_session(new_session)
            if ticket:
                new_session_ticket = NewSessionTicketTLS13(
                    ticket_lifetime=int(new_session.timeout.total_seconds()),
                    ticket_age_add=new_session.ticket_age_add,
                    ticket_nonce=ticket_nonce,
                    ticket=ticket,
                    extensions=self._serialize_extensions(extensions),
                )
                self.message_cb(Direction.WRITE, new_session_ticket)
                self._add_message(new_session_ticket, update_hash=False)

        self._set_state(ServerState.FINISHED_SERVER_HANDSHAKE)
        return Status.PACK_FLIGHT

    def _do_finish_server_handshake(self) -> Status:
        if self._session is None:
            raise AlertInternalError("session not set")

        if not self._session_reused:
            session = self._session
            session.not_resumable = False

        self._session_establish = True

        self._set_state(ServerState.DONE)
        return Status.OK

    def _do_read_post_handshake(self) -> Status:
        message = self._get_message()
        if message is None:
            self._set_state(ServerState.DONE)
            return Status.OK

        if self.protocol_version() >= TLSVersion.TLSv1_3:
            return self._post_handshake_tls13(message)
        else:
            return self._post_handshake(message)

    def _do_process_update_traffic(self) -> Status:
        self._set_state(ServerState.COMPLETE_UPDATE_TRAFFIC)
        return Status.PACK_FLIGHT

    def _do_complete_update_traffic(self) -> Status:
        self._update_traffic_key_tls13(Direction.WRITE)
        self._set_state(ServerState.DONE)
        return Status.OK

    def _post_handshake(self, message: Handshake) -> Status:
        raise AlertUnexpectedMessage()

    def _post_handshake_tls13(self, message: Handshake) -> Status:
        if message.handshake_type == HandshakeType.KEY_UPDATE:
            key_update = message.get_handshake(KeyUpdate)

            if self.has_unprocessed_hs_data():
                raise AlertUnexpectedMessage("Trailing handshake data")

            message_type = key_update.message_type
            if message_type not in (
                KeyUpdateMessageType.UPDATE_NOT_REQUESTED,
                KeyUpdateMessageType.UPDATE_REQUESTED,
            ):
                raise AlertIllegalParameter("Unknown key update message type")

            self.message_cb(Direction.READ, key_update)
            self._next_message(update_hash=False)

            self._update_traffic_key_tls13(Direction.READ)

            if message_type == KeyUpdateMessageType.UPDATE_REQUESTED:
                self._write_key_update(
                    KeyUpdateMessageType.UPDATE_NOT_REQUESTED
                )

                self._set_state(ServerState.COMPLETE_UPDATE_TRAFFIC)
                return Status.PACK_FLIGHT

            return Status.OK

        raise AlertUnexpectedMessage()

    def _get_client_hello_without_binders(
        self,
        message: Handshake,
        psk_ext: ClientPSKExtension,
    ) -> bytes:
        assert message.handshake_type == HandshakeType.CLIENT_HELLO
        message_data = message.serialize()

        binders = psk_ext.binders
        total_binders_length = sum(1 + len(binder) for binder in binders)
        total_length = 2 + total_binders_length
        return message_data[:-total_length]

    def _negotiate_cipher_suite(self) -> CipherSuite:
        if self._peer_cipher_suites is None:
            raise AlertInternalError("peer_cipher_suites not set")

        version = self.protocol_version()
        supported_cipher_suites = self._cipher_suites
        peer_cipher_suites = self._peer_cipher_suites
        peer_supported_groups = self._peer_supported_groups

        if self._x509_certificates:
            x509_leaf = self._x509_certificates[0]
            public_key_algorithm_oid = x509_leaf.public_key_algorithm_oid

            if public_key_algorithm_oid in (
                PublicKeyAlgorithmOID.RSASSA_PSS,
                PublicKeyAlgorithmOID.RSAES_PKCS1_v1_5,
            ):
                auth = Authentication.RSA
            elif public_key_algorithm_oid == PublicKeyAlgorithmOID.DSA:
                auth = Authentication.DSS
            elif public_key_algorithm_oid in (
                PublicKeyAlgorithmOID.EC_PUBLIC_KEY,
                PublicKeyAlgorithmOID.ED25519,
                PublicKeyAlgorithmOID.ED448,
            ):
                auth = Authentication.ECDSA
            else:
                raise AlertHandshakeFailure("Unsupported Certificate")
        else:
            auth = Authentication.ANON

        kea = set((KeyExchange.RSA, KeyExchange.DHE))
        group_id = negotiate(
            (g for g in self._supported_groups if g in ECC_GROUPS),
            peer_supported_groups,
        )
        if group_id is not None:
            self._group_id = group_id
            kea.add(KeyExchange.ECDHE)

        for suite in supported_cipher_suites:
            if not (suite.minimum_version <= version <= suite.maximum_version):
                continue
            if suite.id not in peer_cipher_suites:
                continue
            if version <= TLSVersion.TLSv1_2 and (
                suite.kea not in kea or suite.auth != auth
            ):
                continue
            return suite

        raise AlertHandshakeFailure("No supported cipher suite")

    def _process_extensions(self, ext_map: dict[int, Extension]) -> None:
        version = self.protocol_version()
        cipher_suite = self.cipher_suite()

        self._extensions_recv.update(ext_map)

        # Renegotiation info extension
        ri_ext = typing.cast(
            RenegotiationInfoExtension | None,
            ext_map.get(ExtensionType.RENEGOTIATION_INFO),
        )
        if ri_ext is not None:
            if ri_ext.data:
                raise AlertHandshakeFailure(
                    "Invalid renegotiation info extension"
                )
            secure_renegotiate = True
        elif CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV in typing.cast(
            tuple[int, ...], self._peer_cipher_suites
        ):
            secure_renegotiate = True
        else:
            secure_renegotiate = False

        if secure_renegotiate:
            self._secure_renegotiation = True

        alpn_ext = typing.cast(
            ClientALPNExtension | None, ext_map.get(ExtensionType.ALPN)
        )
        if self._alpn_protocols is not None and alpn_ext is not None:
            self._alpn_selected = negotiate(
                self._alpn_protocols,
                alpn_ext.protocols,
                AlertHandshakeFailure("No supported ALPN protocols"),
            )

        if version >= TLSVersion.TLSv1_3:
            comp_cert_ext = typing.cast(
                CompressedCertificateExtension | None,
                ext_map.get(ExtensionType.COMPRESS_CERTIFICATE),
            )
            if (
                self._certificate_compressions is not None
                and comp_cert_ext is not None
            ):
                self._certificate_compression = negotiate(
                    self._certificate_compressions, comp_cert_ext.data
                )

            pha_ext = typing.cast(
                ClientPHAExtension | None,
                ext_map.get(ExtensionType.POST_HANDSHAKE_AUTH),
            )
            if self._enable_pha and pha_ext is not None:
                self._post_handshake_auth = True

            early_data_ext = typing.cast(
                EarlyDataExtension | None,
                ext_map.get(ExtensionType.EARLY_DATA),
            )
            if early_data_ext is not None:
                self._early_data_offered = True

        else:
            # Extended master secret extension
            ems_ext = typing.cast(
                ExtendedMasterSecretExtension | None,
                ext_map.get(ExtensionType.EXTENDED_MAIN_SECRET),
            )
            if self._enable_ems is not None:
                if ems_ext is not None:
                    self._extended_master_secret = True

            # Encrypt-then-mac extension
            etm_ext = typing.cast(
                EncryptThenMacExtension | None,
                ext_map.get(ExtensionType.ENCRYPT_THEN_MAC),
            )
            is_block_cipher = cipher_suite.symmetric in (
                Symmetric.AES_128_CBC,
                Symmetric.AES_256_CBC,
                Symmetric.TRIPLE_DES_EDE_CBC,
            )
            if self._enable_etm and is_block_cipher and etm_ext is not None:
                self._encrypt_then_mac = True

            # EC point formats extension
            ecpfs_ext = typing.cast(
                ECPointFormatsExtension | None,
                ext_map.get(ExtensionType.EC_POINT_FORMATS),
            )
            if (
                ecpfs_ext is not None
                and ECPointFormat.UNCOMPRESSED not in ecpfs_ext.data
            ):
                raise AlertIllegalParameter(
                    "Invalid EC point formats extension"
                )

            # NPN extension
            npn_ext = typing.cast(
                ClientNPNExtension | None,
                ext_map.get(ExtensionType.SUPPORTS_NPN),
            )
            if (
                self._alpn_selected is None
                and npn_ext is not None
                and self._npn_protocols is not None
            ):
                self._npn_expected = True

    def _decrypt_session(self, ticket: bytes) -> TLSSession | None:
        ticket_aead = self.configuration.ticket_aead
        if ticket_aead is None or not ticket:
            return None

        session = None
        session_data = ticket_aead.open(ticket)

        if session_data is not None:
            session_data = bytes(session_data)
            try:
                session = TLSSession.from_bytes(session_data)
            except Exception:
                pass

        if (
            session is not None
            and session.time_valid()
            and session.is_server
            and session.protocol_version() == self.protocol_version()
            and session.cipher_suite == self._cipher_suite
            and not session.not_resumable
        ):
            return session

        return None

    def _encrypt_session(self, session: TLSSession) -> bytes | None:
        ticket_aead = self.configuration.ticket_aead
        if ticket_aead is None:
            return None

        ticket = ticket_aead.seal(session.serialize())
        if ticket is not None:
            return bytes(ticket)
        return None
