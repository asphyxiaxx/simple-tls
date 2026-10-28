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

import random
from collections.abc import Callable
from dataclasses import dataclass
from typing import cast

from simple_tls.codec import ParseError, Parser, Writer
from simple_tls.crypto import hpke
from simple_tls.crypto.constant_time import compare_digest
from simple_tls.crypto.utils import (
    bytes_to_int,
    get_random_bits,
    get_random_bytes,
    get_random_int,
    int_to_bytes,
)

from .alerts import (
    AlertDecodeError,
    AlertDecryptError,
    AlertECHRequired,
    AlertHandshakeFailure,
    AlertIllegalParameter,
    AlertInsufficientSecurity,
    AlertInternalError,
    AlertMissingExtension,
    AlertProtocolVersion,
    AlertUnexpectedMessage,
    AlertUnsupportedExtension,
)
from .configuration import TLSConfiguration
from .constants import (
    GREASES,
    TLS11_DOWNGRADE_SENTINEL,
    TLS12_DOWNGRADE_SENTINEL,
    TLS13_CLIENT_CONTEXT_STRING,
    TLS13_HRR_SENTINEL,
    Authentication,
    CipherSuite,
    Compression,
    ECCurveType,
    ECHClientHelloType,
    ExtensionType,
    HandshakeType,
    HpkeAeadId,
    HpkeKdfId,
    KeyExchange,
    KeyUpdateMessageType,
    PSKKeyExchangeMode,
    Symmetric,
    TLSVersion,
)
from .enums import (
    ClientHelloType,
    ClientState,
    Direction,
    ECHStatus,
    Epoch,
    Status,
    VerifyMode,
)
from .extensions import (
    COMPRESSIBLE_EXTENSIONS,
    EXTENSION_TYPES,
    ALPNClientExtension,
    ALPNServerExtension,
    ALPSClientExtension,
    ALPSExtension,
    ClientHelloPaddingExtension,
    CompressedCertificateExtension,
    CookieExtension,
    EarlyDataClientExtension,
    EarlyDataExtension,
    EarlyDataServerExtension,
    ECHClientExtension,
    ECHConfig,
    ECHHRRExtension,
    ECHOuterExtension,
    ECHServerExtension,
    ECPointFormatsExtension,
    EncryptThenMacExtension,
    ExtendedMasterSecretExtension,
    Extension,
    Extensions,
    GenericExtension,
    KeyShareClientExtension,
    KeyShareEntry,
    KeyShareHRRExtension,
    KeyShareServerExtension,
    NPNClientExtension,
    NPNServerExtension,
    PostHandshakeAuthExtension,
    PSKClientExtension,
    PSKIdentity,
    PSKKeyExchangeModesExtension,
    PSKServerExtension,
    RenegotiationInfoExtension,
    SCTClientExtension,
    SessionTicketExtension,
    SignatureAlgorithmsExtension,
    SNIClientExtension,
    StatusRequestClientExtension,
    SupportedGroupsClientExtension,
    SupportedVersionsClientExtension,
    SupportedVersionsServerExtension,
)
from .handshake import Handshake, TLSHandshake
from .key import (
    BasePrivateKey,
    InvalidSignature,
    RSAPublicKey,
    load_certificate_public_key,
)
from .keyexchange import (
    BaseKeyExchange,
    DHParameters,
    ECDHKeyExchange,
    FFDHKeyExchange,
)
from .messages import (
    CertificateRequest,
    CertificateRequestTLS12,
    CertificateRequestTLS13,
    CertificateStatus,
    CertificateVerify,
    CertificateVerifyTLS12,
    ClientHello,
    ClientKeyExchange,
    EncryptedExtensions,
    EndOfEarlyData,
    Finished,
    KeyUpdate,
    NewSessionTicket,
    NewSessionTicketTLS13,
    NextProtocol,
    ServerHello,
    ServerHelloDone,
    ServerKeyExchange,
)
from .session import TLSSession
from .utils import (
    KeySchedule,
    Transcript,
    check_server_hostname,
    is_ipaddress,
    negotiate,
)

NewSessionCallback = Callable[[TLSSession], None]


@dataclass(frozen=True)
class ECHConfigContext:
    kdf_id: int
    aead_id: int
    kem_id: int
    hpke_context: hpke.Context
    config_id: int
    public_name: bytes
    maximum_name_length: int
    enc: bytes
    extensions: Extensions


class TLSHandshakeClient(TLSHandshake):
    is_server = False

    def __init__(
        self,
        configuration: TLSConfiguration,
        new_session_callback: NewSessionCallback | None = None,
    ) -> None:
        server_hostname = configuration.server_hostname
        if server_hostname is not None:
            check_server_hostname(server_hostname)
        elif configuration.check_hostname:
            raise ValueError("check_hostname requires server_hostname")

        # Initialization
        super().__init__(configuration)

        self._offered_session = configuration.session
        self._hostname = server_hostname
        self._new_session_callback = new_session_callback

        # Compressions
        self._compresion_methods: tuple[int, ...] = (Compression.NULL,)

        # Encrypt Then Mac
        self._enable_etm: bool = configuration.encrypt_then_mac

        # Extended Master Secret
        self._enable_ems: bool = configuration.extended_master_secret

        # Post Handshake Authentication
        self._enable_pha: bool = configuration.post_handshake_auth

        # Early data
        self._enable_early_data: bool = configuration.early_data

        # Status Request
        self._enable_status_request: bool = configuration.status_request

        # Signed certificate timestamp
        self._enable_scts: bool = configuration.signed_certificate_timestamp

        # Client Hello Padding
        self._enable_client_hello_padding: bool = (
            configuration.client_hello_padding
        )

        # Permute extensions
        self._enable_permute_extensions: bool = (
            configuration.permute_extensions
        )

        # Grease
        self._enable_grease: bool = configuration.grease
        self._enable_grease_ech: bool = configuration.grease_ech

        # Temporary State
        self._state = ClientState.START_CONNECT
        self._extensions_sent: set[int] = set()
        self._session_ticket: bytes | None = None
        self._selected_ech_config: ECHConfigContext | None = None
        self._ech_client_outer: ECHClientExtension | None = None
        self._ticket_expected: bool = False
        self._pre_shared_keys: list[
            tuple[KeySchedule, PSKIdentity, bytes]
        ] = []
        self._key_exchange: BaseKeyExchange | None = None
        self._key_exchanges: dict[int, BaseKeyExchange] = {}

        greases = list(GREASES)
        random.shuffle(greases)
        self._greases: tuple[int, ...] = tuple(greases)

        extension_types = list(EXTENSION_TYPES)
        random.shuffle(extension_types)
        self._extension_order: tuple[int, ...] = tuple(extension_types)

        # Inner client hello variable, will replace actual when ech accepted
        self._inner_transcript: Transcript | None = None
        self._inner_client_random: bytes | None = None
        self._inner_extensions_sent: set[int] | None = None

        # Peer item
        self._peer_cookie: bytes | None = None
        self._peer_key: bytes | None = None
        self._peer_cert_request: (
            CertificateRequest
            | CertificateRequestTLS12
            | CertificateRequestTLS13
            | None
        ) = None
        self._peer_ech_retry_configs: bytes | None = None
        self._peer_quic_transport_parameters: bytes | None = None

        # Negotiated variable
        self._signing_signature_algorithm: int | None = None
        """signature algorithm to be used with signing"""

        # ruff: disable[E501]
        self._handle_dispatch = {
            ClientState.START_CONNECT: self._do_start_connect,
            ClientState.ENTER_EARLY_DATA: self._do_enter_early_data,
            ClientState.ENTER_EARLY_DATA_COMPAT: self._do_enter_early_data_compat_css,
            ClientState.READ_SERVER_HELLO: self._do_read_server_hello,
            ClientState.READ_SERVER_CERTIFICATE: self._do_read_server_certificate,
            ClientState.READ_CERTIFICATE_STATUS: self._do_read_certificate_status,
            ClientState.READ_SERVER_KEY_EXCHANGE: self._do_read_server_key_exchange,
            ClientState.READ_CERTIFICATE_REQUEST: self._do_read_certificate_request,
            ClientState.READ_SERVER_HELLO_DONE: self._do_read_server_hello_done,
            ClientState.SEND_CLIENT_CERTIFICATE: self._do_send_client_certificate,
            ClientState.SEND_CLIENT_KEY_EXCHANGE: self._do_send_client_key_exchange,
            ClientState.SEND_CLIENT_CERTIFICATE_VERIFY: self._do_send_client_certificate_verify,
            ClientState.SEND_CHANGE_CIPHER_SPEC: self._do_send_change_cipher_spec,
            ClientState.SEND_CLIENT_FINISHED: self._do_send_client_finished,
            ClientState.FINISH_FLIGHT: self._do_finish_flight,
            ClientState.READ_SESSION_TICKET: self._do_read_session_ticket,
            ClientState.PROCESS_CHANGE_CIPHER_SPEC: self._do_process_change_cipher_spec,
            ClientState.READ_SERVER_FINISHED: self._do_read_server_finished,
            # TLSv1.3
            ClientState.COMPAT_CSS_TLS13: self._do_compat_ccs_tls13,
            ClientState.READ_HRR_TLS13: self._do_read_hrr_tlsv13,
            ClientState.SEND_SECOND_CLIENT_HELLO_TLS13: self._do_send_second_client_hello_tls13,
            ClientState.READ_SERVER_HELLO_TLS13: self._do_read_server_hello_tls13,
            ClientState.READ_ENCRYPTED_EXTENSIONS_TLS13: self._do_read_encrypted_extensions_tls13,
            ClientState.READ_CERTIFICATE_REQUEST_TLS13: self._do_read_certificate_request_tls13,
            ClientState.READ_SERVER_CERTIFICATE_TLS13: self._do_read_server_certificate_tls13,
            ClientState.READ_SERVER_CERTIFICATE_VERIFY_TLS13: self._do_read_server_certificate_verify_tls13,
            ClientState.READ_SERVER_FINISHED_TLS13: self._do_read_server_finished_tls13,
            ClientState.SEND_END_OF_EARLY_DATA_TLS13: self._do_send_end_of_early_data_tls13,
            ClientState.SEND_CLIENT_ENCRYPTED_EXTENSIONS_TLS13: self._do_send_client_encrypted_extensions_tls13,
            ClientState.SEND_CLIENT_CERTIFICATE_TLS13: self._do_send_client_certificate_tls13,
            ClientState.SEND_CLIENT_FINISHED_TLS13: self._do_send_client_finished_tls13,
            ClientState.COMPLETE_SECOND_FLIGHT_TLS13: self._do_complete_second_flight_tls13,
            # Finish handshake
            ClientState.FINISH_CLIENT_HANDSHAKE: self._do_finish_client_handshake,
            # Post handshake
            ClientState.READ_POST_HANDSHAKE: self._do_read_post_handshake,
            ClientState.PROCESS_UPDATE_TRAFFIC: self._do_process_update_traffic,
            ClientState.COMPLETE_UPDATE_TRAFFIC: self._do_complete_update_traffic,
        }
        # ruff: enable[E501]

    @property
    def done(self) -> bool:
        return self._state == ClientState.DONE

    @property
    def peer_ech_retry_configs(self) -> bytes | None:
        return self._peer_ech_retry_configs

    def trigger_post_handshake(self) -> None:
        if not self.done:
            raise ValueError("handshake not complete")
        self._set_state(ClientState.READ_POST_HANDSHAKE)

    def send_key_update(self, message_type: KeyUpdateMessageType) -> None:
        if not self.done:
            raise ValueError("handshake not complete")
        self._write_key_update(message_type)
        self._set_state(ClientState.PROCESS_UPDATE_TRAFFIC)

    def _do_start_connect(self) -> Status:
        self._session_reused = False

        configuration = self.configuration
        self._client_random = get_random_bytes(32)
        self._client_version = min(self._maximum_version, TLSVersion.TLSv1_2)

        if self._maximum_version >= TLSVersion.TLSv1_3:
            # Fake session id
            if configuration.middlebox_compat:
                self._session_id = get_random_bytes(32)

            # Key shares
            for group in self._supported_groups[:2]:
                kex = self._get_key_exchange(group)
                if kex is not None:
                    self._key_exchanges[group] = kex

            # ECH
            if configuration.ech_configs is not None:
                try:
                    c = self._select_ech_config(configuration.ech_configs)
                except ParseError:
                    c = None
                if c is not None:
                    self._selected_ech_config = c
                    self._inner_transcript = Transcript()
                    self._inner_client_random = get_random_bytes(32)

            if self._selected_ech_config is None and self._enable_grease_ech:
                self._ech_client_outer = ECHClientExtension(
                    ech_client_hello_type=ECHClientHelloType.OUTER,
                    hpke_kdf_id=HpkeKdfId.HKDF_SHA256,
                    hpke_aead_id=HpkeAeadId.AES_128_GCM,
                    config_id=bytes_to_int(get_random_bytes(1)),
                    enc=get_random_bytes(32),
                    payload=get_random_bytes(get_random_int(180, 205)),
                )

        session = self._offered_session
        if (
            session is not None
            and not session.is_server
            and session.time_valid()
            and session.protocol_version() >= self._minimum_version
            and session.protocol_version() <= self._maximum_version
            and not (
                session.protocol_version() < TLSVersion.TLSv1_3
                and self._selected_ech_config is not None
            )
        ):
            assert session.cipher_suite is not None
            if session.protocol_version() <= TLSVersion.TLSv1_2:
                if session.ticket:
                    # Generate random session_id so it track
                    # the session is resumed
                    self._session_id = get_random_bytes(32)
                    self._session_ticket = session.ticket
                elif session.session_id:
                    self._session_id = session.session_id

            elif session.ticket:
                identity = PSKIdentity(
                    identity=session.ticket,
                    obfuscated_ticket_age=session.obfuscated_age(),
                )
                key_schedule = KeySchedule(session.cipher_suite.prf_hash)
                key_schedule.extract(session.secret)
                binder_key = key_schedule.derive_secret(
                    b"res binder", self._transcript
                )
                self._pre_shared_keys = [(key_schedule, identity, binder_key)]

                if self._should_offer_early_data():
                    self._early_data_offered = True

        if (
            self._new_session_callback is not None
            and self._session_ticket is None
        ):
            self._session_ticket = b""

        if self._selected_ech_config is not None:
            client_hello = self._build_encrypted_client_hello()
        else:
            client_hello = self._build_client_hello()

        self.message_cb(Direction.WRITE, client_hello)
        self._add_message(client_hello)

        self._set_state(ClientState.ENTER_EARLY_DATA)
        return Status.FLUSH_MESSAGE

    def _do_enter_early_data(self) -> Status:
        if not self._early_data_offered:
            self._set_state(ClientState.READ_SERVER_HELLO)
            return Status.OK

        assert self._offered_session is not None
        offered_session = self._offered_session
        assert offered_session.cipher_suite is not None
        self._session = offered_session.copy(include_noauth=True)
        self._version = offered_session.version
        self._is_early_version = True

        # Early data extension is included in ClientHello
        self._key_schedule, _, _ = self._pre_shared_keys[0]
        if self._selected_ech_config is not None:
            assert self._inner_transcript is not None
            transcript = self._inner_transcript
        else:
            transcript = self._transcript

        self._derive_secret_tls13(
            direction=Direction.WRITE,
            epoch=Epoch.ZERO_RTT,
            label=b"c e traffic",
            transcript=transcript,
        )
        self._setup_traffic_tls13(Direction.WRITE, Epoch.ZERO_RTT)
        self._in_early_data = True
        self._can_early_write = True

        if self._configuration.middlebox_compat:
            self._set_state(ClientState.ENTER_EARLY_DATA_COMPAT)
            return Status.WRITE_CHANGE_CIPHER_SPEC

        self._set_state(ClientState.READ_SERVER_HELLO)
        return Status.EARLY_RETURN

    def _do_enter_early_data_compat_css(self) -> Status:
        self._set_state(ClientState.READ_SERVER_HELLO)
        return Status.EARLY_RETURN

    def _do_read_server_hello(self) -> Status:
        message = self._get_message()
        if message is None:
            return Status.READ_MESSAGE

        server_hello = message.parse_as(ServerHello)

        # Update version
        server_version = server_hello.version
        if not TLSVersion.TLSv1 <= server_version <= TLSVersion.TLSv1_2:
            raise AlertProtocolVersion("received invalid protocol version")

        extensions = server_hello.extensions

        supported_vers_ext = extensions.get(SupportedVersionsServerExtension)
        if supported_vers_ext is not None:
            if not self._maximum_version > TLSVersion.TLSv1_2:
                raise AlertIllegalParameter(
                    "received unexpected supported version extension"
                )
            if not server_version == TLSVersion.TLSv1_2:
                raise AlertIllegalParameter(
                    "received invalid protocol version"
                )
            if not supported_vers_ext.data > TLSVersion.TLSv1_2:
                raise AlertIllegalParameter(
                    "received unknown protocol version"
                )
            server_version = supported_vers_ext.data

        if server_version < self._minimum_version:
            raise AlertProtocolVersion(
                "received protocol version older than specified"
            )
        if server_version > self._maximum_version:
            raise AlertProtocolVersion(
                "received protocol version newer than specified"
            )

        self._version = server_version
        self._is_early_version = False

        # Compression method
        if server_hello.compression_method not in self._compresion_methods:
            raise AlertIllegalParameter("received invalid compression method")

        if self._early_data_offered:
            assert self._offered_session is not None
            offered_session = self._offered_session

            if self._version != offered_session.version:
                assert self.protocol_version() <= TLSVersion.TLSv1_2
                assert offered_session.protocol_version() >= TLSVersion.TLSv1_3

                raise AlertProtocolVersion(
                    "cannot negotiate TLSv1.2 or below since early data "
                    "has been sent"
                )

        if self.protocol_version() >= TLSVersion.TLSv1_3:
            self._set_state(ClientState.COMPAT_CSS_TLS13)
            return Status.OK

        sentinel = server_hello.random[-8:]

        # RFC 8446 Section 4.1.3 (TLS 1.3 downgrade protection)
        if (
            sentinel in (TLS12_DOWNGRADE_SENTINEL, TLS11_DOWNGRADE_SENTINEL)
            and self._maximum_version >= TLSVersion.TLSv1_3
            and self.protocol_version() < TLSVersion.TLSv1_3
        ):
            raise AlertIllegalParameter("protocol downgrade detected")

        # RFC 8446 Section 4.1.3 (TLS 1.2 downgrade protection)
        if (
            sentinel == TLS11_DOWNGRADE_SENTINEL
            and self._maximum_version == TLSVersion.TLSv1_2
            and self.protocol_version() < TLSVersion.TLSv1_2
        ):
            raise AlertIllegalParameter("protocol downgrade detected")

        if self._selected_ech_config is not None:
            self._ech_status = ECHStatus.REJECTED

        # Update server random
        self._server_random = server_hello.random

        # Cipher Suites
        try:
            cipher_suite = CipherSuite(server_hello.cipher_suite)
        except ValueError:
            raise AlertIllegalParameter(
                "received invalid cipher suite"
            ) from None

        if cipher_suite not in self._cipher_suites:
            raise AlertIllegalParameter("received unexpected cipher suite")

        if not (
            cipher_suite.minimum_version
            <= self.protocol_version()
            <= cipher_suite.maximum_version
        ):
            raise AlertIllegalParameter("received invalid cipher suite")

        self._cipher_suite = cipher_suite

        # Session ID
        if self._session_id and server_hello.session_id == self._session_id:
            if (
                self._offered_session is None
                or self._ech_status == ECHStatus.REJECTED
            ):
                raise AlertIllegalParameter(
                    "received echoed invalid session id"
                )
            if self._offered_session.version != self._version:
                raise AlertIllegalParameter(
                    "received invalid protocol version"
                )
            if self._offered_session.cipher_suite != self._cipher_suite:
                raise AlertIllegalParameter("received invalid cipher suite")

            self._session_reused = True
            session = self._offered_session.copy(include_noauth=True)
        else:
            session = self._get_new_session()
            session.session_id = server_hello.session_id
            session.cipher_suite = self._cipher_suite

        self._session = session

        # Process extensions
        self._process_extensions(extensions)

        if self._session_reused:
            if session.extended_master_secret != self._extended_master_secret:
                if session.extended_master_secret:
                    raise AlertHandshakeFailure(
                        "EMS session resumed without EMS extension"
                    )
                else:
                    raise AlertHandshakeFailure(
                        "non EMS Session resumed with EMS extension"
                    )

            self._derive_key(session.secret)

        self.message_cb(Direction.READ, server_hello)
        self._next_message()

        self._set_state(ClientState.READ_SERVER_CERTIFICATE)
        return Status.OK

    def _do_read_server_certificate(self) -> Status:
        if self._session_reused:
            self._set_state(ClientState.READ_SESSION_TICKET)
            return Status.OK

        assert self._cipher_suite is not None
        if self._cipher_suite.auth == Authentication.ANON:
            self._set_state(ClientState.READ_SERVER_KEY_EXCHANGE)
            return Status.OK

        message = self._get_message()
        if message is None:
            return Status.READ_MESSAGE

        assert self._session is not None
        session = self._session
        certificate = self._process_certificate(
            message, session, allow_anon=False
        )
        if self._verify_mode != VerifyMode.CERT_NONE:
            self._verify_x509(session, self._hostname)

        self.message_cb(Direction.READ, certificate)
        self._next_message()

        self._set_state(ClientState.READ_CERTIFICATE_STATUS)
        return Status.OK

    def _do_read_certificate_status(self) -> Status:
        if not self._enable_status_request:
            self._set_state(ClientState.READ_SERVER_KEY_EXCHANGE)
            return Status.OK

        message = self._get_message()
        if message is None:
            return Status.READ_MESSAGE

        if message.handshake_type != HandshakeType.CERTIFICATE_STATUS:
            self._set_state(ClientState.READ_SERVER_KEY_EXCHANGE)
            return Status.OK

        certificate_status = message.parse_as(CertificateStatus)

        assert self._session is not None
        self._session.ocsp_response = certificate_status.ocsp

        self.message_cb(Direction.READ, certificate_status)
        self._next_message()

        self._set_state(ClientState.READ_SERVER_KEY_EXCHANGE)
        return Status.OK

    def _do_read_server_key_exchange(self) -> Status:
        assert self._cipher_suite is not None
        cipher_suite = self._cipher_suite

        if cipher_suite.kea == KeyExchange.RSA:
            self._set_state(ClientState.READ_CERTIFICATE_REQUEST)
            return Status.OK

        message = self._get_message()
        if message is None:
            return Status.READ_MESSAGE

        ske = message.parse_as(ServerKeyExchange)

        assert self._session is not None
        version = self.protocol_version()
        session = self._session

        parser = Parser(ske.data)
        parser.set_bookmark()

        if cipher_suite.kea == KeyExchange.ECDHE:
            curve_type = parser.read_int(1)
            if curve_type != ECCurveType.NAMED_CURVE:
                raise AlertIllegalParameter("received invalid curve type")

            group_id = parser.read_int(2)
            if group_id not in self._ecc_groups:
                raise AlertIllegalParameter("received invalid curve group")

            point = parser.read_prefixed_bytes(1)
            if not point:
                raise AlertDecodeError("received empty key share")

            self._key_exchange = ECDHKeyExchange(group_id)
            self._peer_key = point

        elif cipher_suite.kea == KeyExchange.DHE:
            dh_p_length = parser.read_int(2)
            dh_p = parser.read_int(dh_p_length)
            dh_g_length = parser.read_int(2)
            dh_g = parser.read_int(dh_g_length)
            dh_ys_bytes = parser.read_prefixed_bytes(2)

            # enforce minimum prime size to prevent Logjam attacks
            if dh_p.bit_length() < 2048:
                raise AlertInsufficientSecurity(
                    "received DH prime size is too small"
                )

            try:
                parameters = DHParameters(p=dh_p, g=dh_g)
                self._key_exchange = FFDHKeyExchange(parameters)
            except ValueError as exc:
                raise AlertIllegalParameter(str(exc)) from exc

            self._peer_key = dh_ys_bytes

        else:
            raise AlertInternalError("unsupported cipher suite selected")

        if cipher_suite.auth != Authentication.ANON:
            assert session.peer_cert is not None
            peer_cert = session.peer_cert
            try:
                peer_public_key = load_certificate_public_key(peer_cert)
            except ValueError as exc:
                raise AlertHandshakeFailure(str(exc)) from exc

            auth = self._get_pubkey_auth(peer_public_key)
            if auth != cipher_suite.auth:
                raise AlertIllegalParameter("received invalid public key type")

            ske_data = parser.data_since_bookmark()
            peer_public_key_oid = peer_cert.public_key_algorithm_oid

            if version == TLSVersion.TLSv1_2:
                verify_alg = parser.read_int(2)
                self._verify_sigalg_tls12(
                    version=version,
                    public_key=peer_public_key,
                    public_key_oid=peer_public_key_oid,
                    signature_algorihtm=verify_alg,
                    supported_sigalgs=self._signature_algorithms,
                )
            else:
                verify_alg = self._get_sigalg_tls1(
                    version=version,
                    public_key=peer_public_key,
                    public_key_oid=peer_public_key_oid,
                )

            signature = parser.read_prefixed_bytes(2)
            if not signature:
                raise AlertIllegalParameter("received empty signature")

            data = self._client_random + self._server_random + ske_data

            try:
                peer_public_key.verify(signature, data, verify_alg)
            except ValueError as exc:
                raise AlertIllegalParameter(str(exc)) from exc
            except InvalidSignature:
                raise AlertDecryptError("failed to verify signature") from None

        if parser.remaining():
            raise AlertDecodeError("trailing data in server key exchange")

        self.message_cb(Direction.READ, ske)
        self._next_message()

        self._set_state(ClientState.READ_CERTIFICATE_REQUEST)
        return Status.OK

    def _do_read_certificate_request(self) -> Status:
        assert self._cipher_suite is not None
        if self._cipher_suite.auth == Authentication.ANON:
            self._set_state(ClientState.READ_SERVER_HELLO_DONE)
            return Status.OK

        message = self._get_message()
        if message is None:
            return Status.READ_MESSAGE

        if message.handshake_type != HandshakeType.CERTIFICATE_REQUEST:
            self._set_state(ClientState.READ_SERVER_HELLO_DONE)
            return Status.OK

        cert_request: CertificateRequestTLS12 | CertificateRequest
        if self.protocol_version() == TLSVersion.TLSv1_2:
            cert_request = message.parse_as(CertificateRequestTLS12)
        else:
            cert_request = message.parse_as(CertificateRequest)

        self._peer_cert_request = cert_request

        self.message_cb(Direction.READ, cert_request)
        self._next_message()

        self._set_state(ClientState.READ_SERVER_HELLO_DONE)
        return Status.OK

    def _do_read_server_hello_done(self) -> Status:
        message = self._get_message()
        if message is None:
            return Status.READ_MESSAGE

        hello_done = message.parse_as(ServerHelloDone)
        self.message_cb(Direction.READ, hello_done)
        self._next_message()

        self._set_state(ClientState.SEND_CLIENT_CERTIFICATE)
        return Status.OK

    def _do_send_client_certificate(self) -> Status:
        if self._peer_cert_request is None:
            self._set_state(ClientState.SEND_CLIENT_KEY_EXCHANGE)
            return Status.OK

        version = self.protocol_version()
        signature_algorithm: int | None = None

        if self._credential is not None:
            x509_cert = self._credential.certificate
            try:
                public_key = load_certificate_public_key(x509_cert)
            except ValueError as exc:
                raise AlertInternalError(str(exc)) from exc

            cert_type = self._get_pubkey_cert_type(public_key)
            default_sigalg, supported_sigalgs = self._sigalgs_for_pubkey(
                version=version,
                public_key=public_key,
                public_key_oid=x509_cert.public_key_algorithm_oid,
                supported_sigalgs=self._signing_signature_algorithms,
            )
            cert_request = cast(
                CertificateRequest | CertificateRequestTLS12,
                self._peer_cert_request,
            )

            if cert_type in cert_request.certificate_types:
                if version == TLSVersion.TLSv1_2:
                    cert_request = cast(CertificateRequestTLS12, cert_request)
                    signature_algorithm = negotiate(
                        supported_sigalgs,
                        cert_request.signature_algorithms,
                    )
                else:
                    if default_sigalg is not None:
                        signature_algorithm = default_sigalg

        if signature_algorithm is not None:
            assert self._credential is not None
            self._signing_signature_algorithm = signature_algorithm
            certificate = self._create_certificate(self._credential)
        else:
            certificate = self._create_certificate()

        self.message_cb(Direction.WRITE, certificate)
        self._add_message(certificate)

        self._set_state(ClientState.SEND_CLIENT_KEY_EXCHANGE)
        return Status.OK

    def _do_send_client_key_exchange(self) -> Status:
        assert self._cipher_suite is not None
        assert self._session is not None
        version = self.protocol_version()
        cipher_suite = self._cipher_suite
        session = self._session

        writer = Writer()

        if cipher_suite.kea == KeyExchange.RSA:
            assert cipher_suite.auth == Authentication.RSA
            assert session.peer_cert is not None
            peer_cert = session.peer_cert
            try:
                peer_public_key = load_certificate_public_key(peer_cert)
            except ValueError as exc:
                raise AlertHandshakeFailure(str(exc)) from exc
            if not isinstance(peer_public_key, RSAPublicKey):
                raise AlertIllegalParameter("received invalid public key type")

            premaster_secret = int_to_bytes(version, 2) + get_random_bytes(46)
            enc_premaster_secret = peer_public_key.encrypt(premaster_secret)
            writer.write_prefixed_bytes(enc_premaster_secret, 2)
        else:
            assert self._key_exchange is not None
            assert self._peer_key is not None
            try:
                key_share, premaster_secret = (
                    self._key_exchange.generate_and_exchange(self._peer_key)
                )
            except ValueError as exc:
                raise AlertIllegalParameter(
                    "failed to generate key share and exchange key"
                ) from exc

            if cipher_suite.kea == KeyExchange.ECDHE:
                writer.write_prefixed_bytes(key_share, 1)
            elif cipher_suite.kea == KeyExchange.DHE:
                writer.write_prefixed_bytes(key_share, 2)
            else:
                raise AlertInternalError("unsupported cipher suite selected")

        cke = ClientKeyExchange(writer.tobytes())
        self.message_cb(Direction.WRITE, cke)
        self._add_message(cke)

        if self._extended_master_secret:
            label = b"extended master secret"
            transcript = self._transcript
        else:
            label = b"master secret"
            transcript = None

        # RFC 5246 section 8.1.2
        # Remove leading zeroes from premaster secret for DHE key exchange
        if cipher_suite.kea == KeyExchange.DHE:
            premaster_secret = premaster_secret.lstrip(b"\x00")

        session.extended_master_secret = self._extended_master_secret
        session.secret = self._derive_secret(
            premaster_secret, label, transcript
        )
        self._derive_key(session.secret)

        self._set_state(ClientState.SEND_CLIENT_CERTIFICATE_VERIFY)
        return Status.OK

    def _do_send_client_certificate_verify(self) -> Status:
        if (
            self._peer_cert_request is not None
            and self._signing_signature_algorithm is not None
        ):
            assert self._credential is not None
            priv_key = self._credential.private_key
            signature_algorithm = self._signing_signature_algorithm
            transcript = self._transcript.get()
            signature = priv_key.sign(transcript, signature_algorithm)

            cert_verify: CertificateVerifyTLS12 | CertificateVerify
            if self.protocol_version() == TLSVersion.TLSv1_2:
                cert_verify = CertificateVerifyTLS12(
                    signature, signature_algorithm
                )
            else:
                cert_verify = CertificateVerify(signature)

            self.message_cb(Direction.WRITE, cert_verify)
            self._add_message(cert_verify)

        self._set_state(ClientState.SEND_CHANGE_CIPHER_SPEC)
        return Status.PACK_FLIGHT

    def _do_send_change_cipher_spec(self) -> Status:
        self._setup_traffic(Direction.WRITE)

        self._set_state(ClientState.SEND_CLIENT_FINISHED)
        return Status.WRITE_CHANGE_CIPHER_SPEC

    def _do_send_client_finished(self) -> Status:
        assert self._session is not None

        self._setup_traffic(Direction.WRITE)

        if self._npn_protocol is not None:
            npn = NextProtocol(self._npn_protocol)
            self.message_cb(Direction.WRITE, npn)
            self._add_message(npn)

        master_secret = self._session.secret
        verify_data = self._derive_finished_verify_data(
            master_secret, b"client finished"
        )
        finished = Finished(verify_data)
        self.message_cb(Direction.WRITE, finished)
        self._add_message(finished)

        self._set_state(ClientState.FINISH_FLIGHT)
        return Status.FLUSH_MESSAGE

    def _do_finish_flight(self) -> Status:
        if self._session_reused:
            # If it is resumed session, Finished is sent after read the
            # server Finshed
            self._set_state(ClientState.FINISH_CLIENT_HANDSHAKE)
            return Status.OK

        self._set_state(ClientState.READ_SESSION_TICKET)
        return Status.OK

    def _do_read_session_ticket(self) -> Status:
        if not self._ticket_expected:
            self._set_state(ClientState.PROCESS_CHANGE_CIPHER_SPEC)
            return Status.READ_CHANGE_CIPHER_SPEC

        message = self._get_message()
        if message is None:
            return Status.READ_MESSAGE

        new_session_ticket = message.parse_as(NewSessionTicket)
        if not new_session_ticket.ticket:
            self._ticket_expected = False
        else:
            assert self._session is not None
            session = self._session
            session.rebase_time()
            session.ticket = new_session_ticket.ticket

        self.message_cb(Direction.READ, new_session_ticket)
        self._next_message()

        self._set_state(ClientState.PROCESS_CHANGE_CIPHER_SPEC)
        return Status.READ_CHANGE_CIPHER_SPEC

    def _do_process_change_cipher_spec(self) -> Status:
        self._setup_traffic(Direction.READ)

        self._set_state(ClientState.READ_SERVER_FINISHED)
        return Status.OK

    def _do_read_server_finished(self) -> Status:
        message = self._get_message()
        if message is None:
            return Status.READ_MESSAGE

        finished = message.parse_as(Finished)

        assert self._session is not None
        master_secret = self._session.secret
        expected_verify_data = self._derive_finished_verify_data(
            master_secret, b"server finished"
        )
        if not compare_digest(finished.verify_data, expected_verify_data):
            raise AlertDecryptError("finished verify data mismatch")

        self.message_cb(Direction.READ, finished)
        self._next_message()

        if self._session_reused:
            self._set_state(ClientState.SEND_CHANGE_CIPHER_SPEC)
        else:
            self._set_state(ClientState.FINISH_CLIENT_HANDSHAKE)

        return Status.OK

    def _do_compat_ccs_tls13(self) -> Status:
        self._set_state(ClientState.READ_HRR_TLS13)
        if (
            self._configuration.middlebox_compat
            and not self._early_data_offered
        ):
            return Status.WRITE_CHANGE_CIPHER_SPEC
        return Status.OK

    def _do_read_hrr_tlsv13(self) -> Status:
        message = self._get_message()
        if message is None:
            return Status.READ_MESSAGE

        server_hello = message.parse_as(ServerHello)

        if self.has_unprocessed_data():
            raise AlertUnexpectedMessage("trailing handshake data")

        # Cipher Suites
        try:
            cipher_suite = CipherSuite(server_hello.cipher_suite)
        except ValueError as exc:
            raise AlertIllegalParameter(
                "received invalid cipher suite"
            ) from exc

        if cipher_suite not in self._cipher_suites:
            raise AlertIllegalParameter("received invalid cipher suite")

        if not (
            cipher_suite.minimum_version
            <= self.protocol_version()
            <= cipher_suite.maximum_version
        ):
            raise AlertIllegalParameter("received invalid cipher suite")

        self._cipher_suite = cipher_suite
        self._key_schedule = KeySchedule(cipher_suite.prf_hash)

        if server_hello.random != TLS13_HRR_SENTINEL:
            self._set_state(ClientState.READ_SERVER_HELLO_TLS13)
            return Status.OK

        self._hello_retry_request_used = True

        if server_hello.session_id != self._session_id:
            raise AlertIllegalParameter("received session ID mismatch")

        self._transcript.update_for_hello_retry_request(cipher_suite.prf_hash)

        # Process extensions
        extensions = server_hello.extensions
        allowed_extensions = set(
            (
                ExtensionType.SUPPORTED_VERSIONS,
                ExtensionType.KEY_SHARE,
                ExtensionType.COOKIE,
            )
        )

        if self._selected_ech_config is not None:
            assert self._inner_transcript is not None
            allowed_extensions.add(ExtensionType.ENCRYPTED_CLIENT_HELLO)
            self._inner_transcript.update_for_hello_retry_request(
                cipher_suite.prf_hash
            )
            if self._check_ech_confirmation(
                server_hello, self._inner_transcript.copy(), is_hrr=True
            ):
                self._ech_status = ECHStatus.ACCEPTED
                self._inner_transcript.update_hash(message.tobytes())
            else:
                self._ech_status = ECHStatus.REJECTED

        cookie_ext = extensions.get(CookieExtension)
        if cookie_ext is not None:
            self._peer_cookie = cookie_ext.data

        key_share_ext = extensions.get(KeyShareHRRExtension)
        if key_share_ext is not None:
            selected_group = key_share_ext.data
            if (
                selected_group not in self._supported_groups
                or selected_group in self._key_exchanges
            ):
                raise AlertIllegalParameter("received unexpected group")

            kex = self._get_key_exchange(selected_group)
            if kex is None:
                raise AlertIllegalParameter("received invalid group")

            self._key_exchanges.clear()
            self._key_exchanges[selected_group] = kex

        if not extensions.has_allowed(allowed_extensions):
            raise AlertUnsupportedExtension("received unexpected extensions")

        if cookie_ext is None and key_share_ext is None:
            raise AlertIllegalParameter(
                "received hello retry request did not cause update"
            )

        self.message_cb(Direction.READ, server_hello)
        self._next_message()

        if self._in_early_data:
            self._close_early_data()
            self._setup_traffic_tls13(Direction.WRITE, Epoch.INITIAL)

        self._set_state(ClientState.SEND_SECOND_CLIENT_HELLO_TLS13)
        return Status.OK

    def _do_send_second_client_hello_tls13(self) -> Status:
        if self._ech_status == ECHStatus.ACCEPTED:
            client_hello = self._build_encrypted_client_hello(is_hrr=True)
        else:
            client_hello = self._build_client_hello(is_hrr=True)

        self.message_cb(Direction.WRITE, client_hello)
        self._add_message(client_hello)

        self._set_state(ClientState.READ_SERVER_HELLO_TLS13)
        return Status.FLUSH_MESSAGE

    def _do_read_server_hello_tls13(self) -> Status:
        message = self._get_message()
        if message is None:
            return Status.READ_MESSAGE

        server_hello = message.parse_as(ServerHello)

        if self.has_unprocessed_data():
            raise AlertUnexpectedMessage("trailing handshake data")

        assert self._cipher_suite is not None
        cipher_suite = self._cipher_suite

        if server_hello.random == TLS13_HRR_SENTINEL:
            raise AlertUnexpectedMessage("received second hello retry request")
        if server_hello.session_id != self._session_id:
            raise AlertIllegalParameter("received session ID mismatch")
        if server_hello.cipher_suite != cipher_suite:
            raise AlertIllegalParameter("received cipher suite mismatch")

        # Update server random
        self._server_random = server_hello.random

        # Check if ECH accepted
        if (
            self._selected_ech_config is not None
            and self._ech_status != ECHStatus.REJECTED
        ):
            assert self._inner_transcript is not None
            ech_accepted = self._check_ech_confirmation(
                server_hello, self._inner_transcript.copy(), is_hrr=False
            )
            if ech_accepted:
                assert self._inner_client_random is not None
                assert self._inner_extensions_sent is not None
                self._ech_status = ECHStatus.ACCEPTED
                self._client_random = self._inner_client_random
                self._transcript = self._inner_transcript
                self._extensions_sent = self._inner_extensions_sent
                self._inner_transcript = None
                self._inner_client_random = None
                self._inner_extensions_sent = None
            else:
                if (
                    self._hello_retry_request_used
                    and self._ech_status == ECHStatus.ACCEPTED
                ):
                    raise AlertIllegalParameter(
                        "ECH not accepted after hello retry request"
                    )

                self._ech_status = ECHStatus.REJECTED

        # Process extensions
        extensions = server_hello.extensions
        allowed_extensions = set((ExtensionType.SUPPORTED_VERSIONS,))

        psk_ext = extensions.get(PSKServerExtension)
        if psk_ext is not None:
            if (
                not self._pre_shared_keys
                or self._ech_status == ECHStatus.REJECTED
            ):
                raise AlertUnsupportedExtension(
                    "received unexpected PSK extension"
                )

            allowed_extensions.add(ExtensionType.PRE_SHARED_KEY)

            assert self._offered_session is not None
            offered_session = self._offered_session
            assert offered_session.cipher_suite is not None

            if offered_session.version != self._version:
                raise AlertIllegalParameter(
                    "received protocol version mismatch"
                )
            if offered_session.cipher_suite.prf_hash != cipher_suite.prf_hash:
                raise AlertIllegalParameter("received invalid cipher suite")

            # Selected index
            selected_index = psk_ext.data
            if selected_index >= len(self._pre_shared_keys):
                raise AlertIllegalParameter(
                    "received invalid PSK selected index"
                )

            key_schedule, _, _ = self._pre_shared_keys[selected_index]
            self._key_schedule = key_schedule
            self._pre_shared_keys.clear()

            session = offered_session.copy()
            session.renew_timeout(100)
            self._session_reused = True
        else:
            assert self._key_schedule is not None
            key_schedule = self._key_schedule
            key_schedule.extract(None)
            session = self._get_new_session()

        session.cipher_suite = self._cipher_suite
        self._session = session

        kex_ext = extensions.get(KeyShareServerExtension)
        if kex_ext is not None:
            if (
                self._session_reused
                and PSKKeyExchangeMode.PSK_DHE_KE not in self._psk_kex_modes
            ):
                raise AlertIllegalParameter(
                    "received unexpected key share extension"
                )

            allowed_extensions.add(ExtensionType.KEY_SHARE)

            key_share = kex_ext.key_share
            if key_share.group not in self._key_exchanges:
                raise AlertIllegalParameter(
                    "received unexpected key share group"
                )

            kex = self._key_exchanges[key_share.group]
            try:
                shared_secret = kex.exchange(key_share.key_exchange)
            except ValueError as exc:
                raise AlertIllegalParameter(
                    "failed to compute shared secret"
                ) from exc
        else:
            if (
                not self._session_reused
                or PSKKeyExchangeMode.PSK_KE not in self._psk_kex_modes
            ):
                raise AlertMissingExtension("missing key share extension")

            shared_secret = None

        key_schedule.extract(shared_secret)

        if not extensions.has_allowed(allowed_extensions):
            raise AlertUnsupportedExtension("received unexpected extensions")

        self.message_cb(Direction.READ, server_hello)
        self._next_message()

        self._derive_secret_tls13(
            direction=Direction.READ,
            epoch=Epoch.HANDSHAKE,
            label=b"s hs traffic",
            transcript=self._transcript,
        )
        self._derive_secret_tls13(
            direction=Direction.WRITE,
            epoch=Epoch.HANDSHAKE,
            label=b"c hs traffic",
            transcript=self._transcript,
        )
        self._setup_traffic_tls13(Direction.READ, Epoch.HANDSHAKE)

        if not self._early_data_offered:
            self._setup_traffic_tls13(Direction.WRITE, Epoch.HANDSHAKE)

        self._set_state(ClientState.READ_ENCRYPTED_EXTENSIONS_TLS13)
        return Status.OK

    def _do_read_encrypted_extensions_tls13(self) -> Status:
        message = self._get_message()
        if message is None:
            return Status.READ_MESSAGE

        encrypted_extensions = message.parse_as(EncryptedExtensions)

        # Process extensions
        extensions = encrypted_extensions.extensions
        self._process_extensions(extensions)

        self.message_cb(Direction.READ, encrypted_extensions)
        self._next_message()

        assert self._session is not None
        session = self._session

        if self._early_data_accepted:
            assert self._offered_session is not None
            assert self._session_reused

            if self._ech_status == ECHStatus.REJECTED:
                raise AlertIllegalParameter(
                    "early data accepted on rejected ECH"
                )

            offered_session = self._offered_session

            if offered_session.cipher_suite != session.cipher_suite:
                raise AlertIllegalParameter("received cipher suite mismatch")
            if offered_session.early_alpn != self._alpn_protocol:
                raise AlertIllegalParameter("received ALPN mismatch")

            session.has_alps = offered_session.has_alps
            session.local_alps = offered_session.local_alps
            session.peer_alps = offered_session.peer_alps

        elif self._early_data_offered:
            self._setup_traffic_tls13(Direction.WRITE, Epoch.HANDSHAKE)

        alps_ext = extensions.get(ALPSExtension)
        if alps_ext is not None:
            if self._alpn_protocol is None:
                raise AlertIllegalParameter(
                    "received unexpected ALPS extension"
                )
            if self._alpn_protocol not in self._alps:
                raise AlertIllegalParameter(
                    "received ALPS extension for unsupported ALPN"
                )

            session.has_alps = True
            session.local_alps = self._alps[self._alpn_protocol]
            session.peer_alps = alps_ext.settings

        session.early_alpn = self._alpn_protocol

        self._set_state(ClientState.READ_CERTIFICATE_REQUEST_TLS13)
        return Status.OK

    def _do_read_certificate_request_tls13(self) -> Status:
        if self._session_reused:
            self._set_state(ClientState.READ_SERVER_FINISHED_TLS13)
            return Status.OK

        message = self._get_message()
        if message is None:
            return Status.READ_MESSAGE

        if message.handshake_type != HandshakeType.CERTIFICATE_REQUEST:
            self._set_state(ClientState.READ_SERVER_CERTIFICATE_TLS13)
            return Status.OK

        cert_request = message.parse_as(CertificateRequestTLS13)

        # RFC 8446 Section 4.3.2
        # certificate_request_context field SHALL be zero length unless used
        # for the post-handshake authentication exchanges described in Section
        # 4.6.2
        if cert_request.context:
            raise AlertIllegalParameter(
                "received unexpected certificate request context"
            )

        self._peer_cert_request = cert_request

        self.message_cb(Direction.READ, cert_request)
        self._next_message()

        self._set_state(ClientState.READ_SERVER_CERTIFICATE_TLS13)
        return Status.OK

    def _do_read_server_certificate_tls13(self) -> Status:
        message = self._get_message()
        if message is None:
            return Status.READ_MESSAGE

        assert self._session is not None
        certificate = self._process_certificate_tls13(
            message=message,
            session=self._session,
            allow_anon=False,
            compression_supported=(
                ExtensionType.COMPRESS_CERTIFICATE in self._extensions_sent
            ),
        )
        if self._verify_mode != VerifyMode.CERT_NONE:
            hostname = self._hostname
            if self._ech_status == ECHStatus.REJECTED:
                assert self._selected_ech_config is not None
                hostname = self._selected_ech_config.public_name

            self._verify_x509(self._session, hostname)

        self.message_cb(Direction.READ, certificate)
        self._next_message()

        self._set_state(ClientState.READ_SERVER_CERTIFICATE_VERIFY_TLS13)
        return Status.OK

    def _do_read_server_certificate_verify_tls13(self) -> Status:
        message = self._get_message()
        if message is None:
            return Status.READ_MESSAGE

        cert_verify = message.parse_as(CertificateVerifyTLS12)

        assert self._session is not None
        self._process_certificate_verify(
            session=self._session,
            cert_verify=cert_verify,
            supported_sigalgs=self._signature_algorithms,
        )
        self.message_cb(Direction.READ, cert_verify)
        self._next_message()

        self._set_state(ClientState.READ_SERVER_FINISHED_TLS13)
        return Status.OK

    def _do_read_server_finished_tls13(self) -> Status:
        message = self._get_message()
        if message is None:
            return Status.READ_MESSAGE

        finished = message.parse_as(Finished)

        if self.has_unprocessed_data():
            raise AlertUnexpectedMessage("trailing handshake data")

        assert self._key_schedule is not None
        expected_verify_data = self._key_schedule.finished_verify_data(
            self._dec_secret[Epoch.HANDSHAKE], self._transcript
        )
        if not compare_digest(finished.verify_data, expected_verify_data):
            raise AlertDecryptError("finished verify data mismatch")

        self.message_cb(Direction.READ, finished)
        self._next_message()

        # prepare traffic keys
        assert self._key_schedule.generation == 2
        self._key_schedule.extract(None)

        self._derive_secret_tls13(
            direction=Direction.READ,
            epoch=Epoch.APPLICATION_DATA,
            label=b"s ap traffic",
            transcript=self._transcript,
        )
        self._derive_secret_tls13(
            direction=Direction.WRITE,
            epoch=Epoch.APPLICATION_DATA,
            label=b"c ap traffic",
            transcript=self._transcript,
        )

        self._set_state(ClientState.SEND_END_OF_EARLY_DATA_TLS13)
        return Status.OK

    def _do_send_end_of_early_data_tls13(self) -> Status:
        if self._early_data_accepted:
            end_of_early_data = EndOfEarlyData()
            self.message_cb(Direction.WRITE, end_of_early_data)
            self._add_message(end_of_early_data)

            self._close_early_data()

        self._set_state(ClientState.SEND_CLIENT_ENCRYPTED_EXTENSIONS_TLS13)
        return Status.PACK_FLIGHT

    def _do_send_client_encrypted_extensions_tls13(self) -> Status:
        if self._early_data_accepted:
            self._setup_traffic_tls13(Direction.WRITE, Epoch.HANDSHAKE)

        assert self._session is not None

        extensions = Extensions()

        if self._session.has_alps and not self._early_data_accepted:
            alps = ALPSExtension(self._session.local_alps)
            extensions.append(alps)

        if len(extensions) > 0:
            enc_ext = EncryptedExtensions(extensions)
            self.message_cb(Direction.WRITE, enc_ext)
            self._add_message(enc_ext)

        self._set_state(ClientState.SEND_CLIENT_CERTIFICATE_TLS13)
        return Status.OK

    def _do_send_client_certificate_tls13(self) -> Status:
        if self._peer_cert_request is not None:
            peer_cert_request = cast(
                CertificateRequestTLS13, self._peer_cert_request
            )
            self._send_certificate_tls13(peer_cert_request)

        self._set_state(ClientState.SEND_CLIENT_FINISHED_TLS13)
        return Status.OK

    def _do_send_client_finished_tls13(self) -> Status:
        assert self._key_schedule is not None
        verify_data = self._key_schedule.finished_verify_data(
            self._enc_secret[Epoch.HANDSHAKE], self._transcript
        )
        finished = Finished(verify_data)
        self.message_cb(Direction.WRITE, finished)
        self._add_message(finished)

        self._set_state(ClientState.COMPLETE_SECOND_FLIGHT_TLS13)
        return Status.FLUSH_MESSAGE

    def _do_complete_second_flight_tls13(self) -> Status:
        self._setup_traffic_tls13(Direction.READ, Epoch.APPLICATION_DATA)
        self._setup_traffic_tls13(Direction.WRITE, Epoch.APPLICATION_DATA)

        self._set_state(ClientState.FINISH_CLIENT_HANDSHAKE)
        return Status.OK

    def _do_finish_client_handshake(self) -> Status:
        if self._ech_status == ECHStatus.REJECTED:
            raise AlertECHRequired("ECH not negotiated")

        if not self._session_reused:
            assert self._session is not None
            session = self._session
            session.not_resumable = False

            if (
                self._new_session_callback is not None
                and session.protocol_version() <= TLSVersion.TLSv1_2
                and (session.ticket or session.session_id)
            ):
                session = session.copy(
                    include_noauth=True, include_ticket=True
                )
                session.not_resumable = False
                self._new_session_callback(session)

        self._session_establish = True

        self._set_state(ClientState.DONE)
        return Status.OK

    def _do_read_post_handshake(self) -> Status:
        message = self._get_message()
        if message is None:
            self._set_state(ClientState.DONE)
            return Status.OK

        if self.protocol_version() >= TLSVersion.TLSv1_3:
            return self._post_handshake_tls13(message)
        else:
            return self._post_handshake(message)

    def _do_process_update_traffic(self) -> Status:
        self._set_state(ClientState.COMPLETE_UPDATE_TRAFFIC)
        return Status.PACK_FLIGHT

    def _do_complete_update_traffic(self) -> Status:
        self._derive_upd_secret_tls13(Direction.WRITE)
        self._set_state(ClientState.DONE)
        return Status.OK

    def _post_handshake(self, message: Handshake) -> Status:
        raise AlertUnexpectedMessage(
            "received unexpected post handshake message"
        )

    def _post_handshake_tls13(self, message: Handshake) -> Status:
        assert self._session is not None
        assert self._key_schedule is not None
        assert self._key_schedule.generation == 3
        session = self._session
        key_schedule = self._key_schedule

        if message.handshake_type == HandshakeType.NEWSESSION_TICKET:
            new_session_ticket = message.parse_as(NewSessionTicketTLS13)

            if self._new_session_callback is not None:
                extensions = new_session_ticket.extensions
                early_data_ext = extensions.get(EarlyDataExtension)
                if early_data_ext is not None:
                    max_early_data = early_data_ext.data
                else:
                    max_early_data = 0

                session = session.copy(include_noauth=True)
                session.rebase_time()
                session.set_timeout(new_session_ticket.ticket_lifetime)
                session.ticket = new_session_ticket.ticket
                session.ticket_age_add = new_session_ticket.ticket_age_add
                session.ticket_max_early_data = max_early_data

                # Resumption master secret
                master_secret = key_schedule.derive_secret(
                    b"res master", self._transcript
                )
                # Resumption secret
                session.secret = key_schedule.resumption_secret(
                    master_secret, new_session_ticket.ticket_nonce
                )
                session.not_resumable = False

                # Callback to user
                self._new_session_callback(session)

            self.message_cb(Direction.READ, new_session_ticket)
            self._next_message(update_hash=False)

            return Status.OK

        if message.handshake_type == HandshakeType.CERTIFICATE_REQUEST:
            if not self._enable_pha:
                raise AlertUnexpectedMessage(
                    "received unexpected certificate request"
                )

            cert_request = message.parse_as(CertificateRequestTLS13)
            self.message_cb(Direction.READ, cert_request)
            self._next_message()

            self._send_certificate_tls13(cert_request)
            cl_finished_key = key_schedule.finished_verify_data(
                self._enc_secret[Epoch.APPLICATION_DATA], self._transcript
            )
            finished = Finished(cl_finished_key)
            self.message_cb(Direction.WRITE, finished)
            self._add_message(finished)

            return Status.PACK_FLIGHT

        if message.handshake_type == HandshakeType.KEY_UPDATE:
            key_update = message.parse_as(KeyUpdate)

            if self.has_unprocessed_data():
                raise AlertUnexpectedMessage("trailing handshake data")

            message_type = key_update.message_type
            if message_type not in (
                KeyUpdateMessageType.UPDATE_NOT_REQUESTED,
                KeyUpdateMessageType.UPDATE_REQUESTED,
            ):
                raise AlertIllegalParameter(
                    "received invalid key update message type"
                )

            self.message_cb(Direction.READ, key_update)
            self._next_message(update_hash=False)

            self._derive_upd_secret_tls13(Direction.READ)

            if message_type == KeyUpdateMessageType.UPDATE_REQUESTED:
                self._write_key_update(
                    KeyUpdateMessageType.UPDATE_NOT_REQUESTED
                )

                self._set_state(ClientState.COMPLETE_UPDATE_TRAFFIC)
                return Status.PACK_FLIGHT

            return Status.OK

        raise AlertUnexpectedMessage(
            "received unexpected post handshake message"
        )

    def _build_client_hello(self, is_hrr: bool = False) -> ClientHello:
        client_hello = ClientHello(
            version=self._client_version,
            random=self._client_random,
            session_id=self._session_id,
            cipher_suites=self._get_cipher_suites(),
            compression_methods=self._compresion_methods,
        )
        header_len = len(client_hello.serialize())

        if self._selected_ech_config is not None:
            hello_type = ClientHelloType.OUTER
        else:
            hello_type = ClientHelloType.UNENCRYPTED

        client_hello.extensions = self._get_extensions(
            hello_type, header_len, is_hrr
        )

        if self._pre_shared_keys:
            transcript = self._transcript.copy()
            self._update_binders(
                self._pre_shared_keys, transcript, client_hello
            )

        return client_hello

    def _build_encrypted_client_hello(
        self, is_hrr: bool = False
    ) -> ClientHello:
        assert self._selected_ech_config is not None
        assert self._inner_transcript is not None
        assert self._inner_client_random is not None
        ech_config = self._selected_ech_config
        inner_transcript = self._inner_transcript
        inner_client_random = self._inner_client_random

        # Add Extension
        compressed: list[tuple[int, bytes]] = []
        extensions: list[tuple[int, bytes]] = []
        extensions_encoded: list[tuple[int, bytes]] = []
        psk_ext: tuple[int, bytes] | None = None

        inner_extensions = self._get_extensions(
            hello_type=ClientHelloType.INNER,
            header_len=0,
            is_hrr=is_hrr,
        )

        compressible_ext = COMPRESSIBLE_EXTENSIONS + GREASES
        for extension in inner_extensions:
            ext_type = extension[0]
            if ext_type == ExtensionType.PRE_SHARED_KEY:
                psk_ext = extension
            elif ext_type in compressible_ext:
                compressed.append(extension)
            else:
                extensions.append(extension)

        extensions_encoded.extend(extensions)

        if compressed:
            extensions.extend(compressed)
            ech_outer_ext = ECHOuterExtension([t for t, _ in compressed])
            extensions_encoded.append(
                (ech_outer_ext.extension_type, ech_outer_ext.serialize())
            )

        if psk_ext is not None:
            extensions.append(psk_ext)

        hello_inner = ClientHello(
            version=self._client_version,
            random=inner_client_random,
            session_id=self._session_id,
            cipher_suites=self._get_cipher_suites(),
            compression_methods=self._compresion_methods,
            extensions=Extensions(extensions),
        )
        encoded_hello_inner = ClientHello(
            version=self._client_version,
            random=inner_client_random,
            session_id=b"",
            cipher_suites=self._get_cipher_suites(),
            compression_methods=self._compresion_methods,
            extensions=Extensions(extensions_encoded),
        )

        if psk_ext is not None:
            assert self._pre_shared_keys
            self._update_binders(
                self._pre_shared_keys,
                inner_transcript.copy(),
                hello_inner,
                encoded_hello_inner,
            )

        self.message_cb(Direction.WRITE, hello_inner)
        inner_transcript.update_hash(self._pack_handshake(hello_inner))

        # draft-ietf-tls-esni-13, section 6.1.3.
        # Pad the EncodedClientHelloInner
        padding_len = 0
        maximum_name_length = ech_config.maximum_name_length
        if self._hostname is not None:
            server_name_len = len(self._hostname)
            if server_name_len <= maximum_name_length:
                padding_len = maximum_name_length - server_name_len
        else:
            padding_len = 9 + maximum_name_length
        encoded_hello_inner_data = encoded_hello_inner.serialize()
        padding_len += 31 - (
            (len(encoded_hello_inner_data) + padding_len - 1) % 32
        )
        encoded_hello_inner_data += bytes(padding_len)

        hpke_context = cast(hpke.SenderContext, ech_config.hpke_context)
        aead_overhead = hpke_context.aead_overhead
        payload_len = len(encoded_hello_inner_data) + aead_overhead
        if not is_hrr:
            self._ech_client_outer = ECHClientExtension(
                ECHClientHelloType.OUTER,
                ech_config.kdf_id,
                ech_config.aead_id,
                ech_config.config_id,
                ech_config.enc,
                bytes(payload_len),
            )
        else:
            self._ech_client_outer = ECHClientExtension(
                ECHClientHelloType.OUTER,
                ech_config.kdf_id,
                ech_config.aead_id,
                ech_config.config_id,
                b"",
                bytes(payload_len),
            )

        hello_outer = ClientHello(
            version=self._client_version,
            random=self._client_random,
            session_id=self._session_id,
            cipher_suites=self._get_cipher_suites(),
            compression_methods=self._compresion_methods,
        )
        extensions_outer = self._get_extensions(
            hello_type=ClientHelloType.OUTER,
            header_len=len(hello_outer.serialize()),
            is_hrr=is_hrr,
        )
        hello_outer.extensions = extensions_outer

        aad = hello_outer.serialize()
        payload = hpke_context.seal(encoded_hello_inner_data, aad)
        assert len(payload) == payload_len

        self._ech_client_outer.payload = payload
        hello_outer.extensions.replace(self._ech_client_outer)

        return hello_outer

    def _get_extensions(
        self, hello_type: ClientHelloType, header_len: int, is_hrr: bool
    ) -> Extensions:
        extensions = self._get_extensions_internal(hello_type, is_hrr)
        if len(extensions) > 0:
            last_was_empty = len(extensions[-1][1]) == 0
        else:
            last_was_empty = True

        psk_ext: PSKClientExtension | None = None

        if self._pre_shared_keys:
            identities: list[PSKIdentity] = []
            binders: list[bytes] = []

            if hello_type == ClientHelloType.OUTER:
                # GREASE
                for k, i, _ in self._pre_shared_keys:
                    identity = PSKIdentity(
                        identity=get_random_bytes(len(i.identity)),
                        obfuscated_ticket_age=get_random_bits(32),
                    )
                    identities.append(identity)
                    binders.append(get_random_bytes(k.digest_size))
            else:
                # Add dummy binders for now (will be updated later)
                for k, i, _ in self._pre_shared_keys:
                    identities.append(i)
                    binders.append(bytes(k.digest_size))

            psk_ext = PSKClientExtension(identities, binders)

        if (
            self._enable_client_hello_padding
            and hello_type != ClientHelloType.INNER
        ):
            header_len += 4 + 2
            padding_len = 0
            psk_ext_len = 0

            header_len += sum(len(e) for _, e in extensions)

            if psk_ext is not None:
                psk_ext_len = len(psk_ext.serialize())
                header_len += psk_ext_len

            if last_was_empty and psk_ext_len == 0:
                padding_len = 1
                header_len += 4 + padding_len

            if header_len > 0xFF and header_len < 0x200:
                if padding_len != 0:
                    header_len -= 4 + padding_len
                padding_len = 0x200 - header_len
                if padding_len >= 4 + 1:
                    padding_len -= 4
                else:
                    padding_len = 1

            if padding_len != 0:
                extensions.append(ClientHelloPaddingExtension(padding_len))

        if psk_ext is not None:
            extensions.append(psk_ext)

        extension_sent = set(extensions.get_types())
        if hello_type == ClientHelloType.INNER:
            self._inner_extensions_sent = extension_sent
        else:
            self._extensions_sent = extension_sent

        return extensions

    def _get_extensions_internal(
        self, hello_type: ClientHelloType, is_hrr: bool
    ) -> Extensions:
        extensions: list[Extension] = []

        # Server Name Indicator
        if hello_type == ClientHelloType.OUTER:
            assert self._selected_ech_config is not None
            hostname = self._selected_ech_config.public_name
            extensions.append(SNIClientExtension(hostname))
        else:
            # RFC 6066 explicitly forbids literal IP addresses in SNI
            if self._hostname is not None and not is_ipaddress(self._hostname):
                extensions.append(SNIClientExtension(self._hostname))

        # Status Request
        if self._enable_status_request:
            status_request_ext = StatusRequestClientExtension()
            extensions.append(status_request_ext)

        # Signed Certificate Timstamp
        if self._enable_scts:
            extensions.append(SCTClientExtension())

        # ALPN
        if self._alpn_protocols:
            extensions.append(ALPNClientExtension(self._alpn_protocols))

        # Supported Groups
        if self._maximum_version >= TLSVersion.TLSv1_3:
            supported_groups = list(self._supported_groups)
        else:
            if self._ecc_groups and any(
                c.kea == KeyExchange.ECDHE for c in self._cipher_suites
            ):
                supported_groups = list(self._ecc_groups)
            else:
                supported_groups = None

        if supported_groups is not None:
            if self._enable_grease:
                supported_groups.insert(0, self._get_grease(3))
            extensions.append(SupportedGroupsClientExtension(supported_groups))

        # Signature Algorithms
        if self._maximum_version >= TLSVersion.TLSv1_2:
            extensions.append(
                SignatureAlgorithmsExtension(self._signature_algorithms)
            )

        if (
            self._minimum_version <= TLSVersion.TLSv1_2
            and hello_type != ClientHelloType.INNER
        ):
            # Renegotiation Info
            if (
                CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV
                not in self._cipher_suites
            ):
                extensions.append(RenegotiationInfoExtension(b""))

            # NPN Protocols
            if self._npn_protocols:
                extensions.append(NPNClientExtension())

            # Encrypt Then Mac
            if self._enable_etm:
                extensions.append(EncryptThenMacExtension())

            # Extended Master Secret
            if self._enable_ems:
                extensions.append(ExtendedMasterSecretExtension())

            # EC Point Formats
            if self._ec_point_formats:
                extensions.append(
                    ECPointFormatsExtension(self._ec_point_formats)
                )

            # Session
            if self._session_ticket is not None:
                ticket = self._session_ticket
                extensions.append(SessionTicketExtension(ticket))

        if self._maximum_version >= TLSVersion.TLSv1_3:
            # Supported Versions
            minimum_version = self._minimum_version
            if hello_type == ClientHelloType.INNER:
                minimum_version = TLSVersion.TLSv1_3
            supported_versions = list(
                range(self._maximum_version, minimum_version - 1, -1)
            )
            if self._enable_grease:
                supported_versions.insert(0, self._get_grease(2))
            extensions.append(
                SupportedVersionsClientExtension(supported_versions)
            )

            # Supported PSK Key Exchange Mode
            if self._psk_kex_modes:
                extensions.append(
                    PSKKeyExchangeModesExtension(self._psk_kex_modes)
                )

            # Certificate compression algorithm
            if self._certificate_compressions:
                extensions.append(
                    CompressedCertificateExtension(
                        self._certificate_compressions
                    )
                )

            # ALPS
            if self._alps:
                alps_protocol = list(self._alps)
                extensions.append(ALPSClientExtension(alps_protocol))

            if hello_type == ClientHelloType.INNER:
                # When offering the encrypted_client_hello extension in
                # ClientHelloOuter,　the client MUST also offer an empty
                # encrypted_client_hello extension in the ClientHelloInner
                extensions.append(ECHClientExtension(ECHClientHelloType.INNER))
            elif self._ech_client_outer is not None:
                extensions.append(self._ech_client_outer)

            # Supported Key Share Exchange mode
            # RFC 8446, section 4.2.8
            # Put the groups used for key shares first, and in order
            # can be empty
            keyshare_entries: list[KeyShareEntry] = []
            for key_share_group, kex in self._key_exchanges.items():
                keyshare = kex.generate_share()
                keyshare_entry = KeyShareEntry(key_share_group, keyshare)
                keyshare_entries.append(keyshare_entry)

            if self._enable_grease and not is_hrr:
                keyshare_entries.insert(
                    0, KeyShareEntry(self._get_grease(3), b"\x00")
                )
            extensions.append(KeyShareClientExtension(keyshare_entries))

            if self._peer_cookie is not None:
                extensions.append(CookieExtension(self._peer_cookie))

            # Post Handshake Authentication
            if self._enable_pha:
                extensions.append(PostHandshakeAuthExtension())

            # Early Data
            if self._early_data_offered and not is_hrr:
                extensions.append(EarlyDataClientExtension())

        # Reorder extensions
        if self._enable_permute_extensions:
            order_index = {e: i for i, e in enumerate(self._extension_order)}
            extensions.sort(
                key=lambda e: order_index.get(e.extension_type, float("inf"))
            )

        # Insert GREASE
        if extensions and self._enable_grease:
            extensions.insert(0, GenericExtension(self._get_grease(1), b""))
            extensions.append(GenericExtension(self._get_grease(4), b"\x00"))

        return Extensions.from_extensions(extensions)

    def _get_grease(self, index: int) -> int:
        return self._greases[index]

    def _get_cipher_suites(self) -> list[int]:
        cipher_suites = []
        if self._enable_grease:
            cipher_suites.append(self._get_grease(0))
        cipher_suites.extend(c.id for c in self._cipher_suites)
        return cipher_suites

    def _check_ech_confirmation(
        self,
        server_hello: ServerHello,
        transcript: Transcript,
        is_hrr: bool,
    ) -> bool:
        assert self._key_schedule is not None
        assert self._inner_client_random is not None

        if is_hrr:
            ech_ext = server_hello.extensions.get(ECHHRRExtension)
            if ech_ext is None:
                return False

            label = b"hrr ech accept confirmation"

            ori = expected = ech_ext.data
            ech_ext.data = bytes(8)
            server_hello.extensions.replace(ech_ext)
            transcript.update_hash(self._pack_handshake(server_hello))
            ech_ext.data = ori
            server_hello.extensions.replace(ech_ext)
        else:
            label = b"ech accept confirmation"

            ori = server_hello.random
            expected = server_hello.random[-8:]
            server_hello.random = server_hello.random[:-8] + bytes(8)
            transcript.update_hash(self._pack_handshake(server_hello))
            server_hello.random = ori

        accept_confirmation = self._key_schedule.ech_accept_confirmation(
            self._inner_client_random, label, transcript
        )
        if compare_digest(accept_confirmation, expected):
            return True

        return False

    def _process_extensions(self, extensions: Extensions) -> None:
        extensions_recv = extensions.get_types()
        self._extensions_recv = set(extensions_recv)

        try:
            extensions_recv.remove(ExtensionType.RENEGOTIATION_INFO)
        except ValueError:
            pass

        if not self._extensions_sent.issuperset(extensions_recv):
            raise AlertUnsupportedExtension("received unexpected extensions")

        assert self._cipher_suite is not None
        version = self.protocol_version()
        cipher_suite = self._cipher_suite
        allowed_extensions: set[int] = set(
            (
                ExtensionType.SERVER_NAME,
                ExtensionType.ALPN,
            )
        )

        # ALPN extension
        alpn_ext = extensions.get(ALPNServerExtension)
        if alpn_ext is not None:
            if alpn_ext.protocol not in self._alpn_protocols:
                raise AlertIllegalParameter(
                    "received unexpected protocol in ALPN extension"
                )

            self._alpn_protocol = alpn_ext.protocol

        if version >= TLSVersion.TLSv1_3:
            allowed_extensions.update(
                (
                    ExtensionType.SUPPORTED_GROUPS,
                    ExtensionType.APPLICATION_SETTINGS,
                    ExtensionType.ENCRYPTED_CLIENT_HELLO,
                    ExtensionType.EARLY_DATA,
                )
            )

            # Encrypted client hello extension
            ech_ext = extensions.get(ECHServerExtension)
            if ech_ext is not None:
                self._peer_ech_retry_configs = ech_ext.serialize()

            # Early data extension
            early_data_ext = extensions.get(EarlyDataServerExtension)
            if early_data_ext is not None:
                if self._hello_retry_request_used:
                    raise AlertUnsupportedExtension(
                        "received unexpected early data extension"
                    )

                self._early_data_accepted = True
        else:
            allowed_extensions.update(
                (
                    ExtensionType.RENEGOTIATION_INFO,
                    ExtensionType.STATUS_REQUEST,
                    ExtensionType.EXTENDED_MAIN_SECRET,
                    ExtensionType.SUPPORTS_NPN,
                    ExtensionType.SESSION_TICKET,
                    ExtensionType.ENCRYPT_THEN_MAC,
                    ExtensionType.EC_POINT_FORMATS,
                )
            )

            # Renegotiation info extension
            ri_ext = extensions.get(RenegotiationInfoExtension)
            if ri_ext is not None:
                if ri_ext.data:
                    raise AlertIllegalParameter("invalid renegotation data")
                self._secure_renegotiation = True
            elif not self.configuration.legacy_server_connect:
                raise AlertInsufficientSecurity(
                    "peer does not support secure renegotiation"
                )

            # Session ticket extension
            session_ticket_ext = extensions.get(SessionTicketExtension)
            if session_ticket_ext is not None:
                self._ticket_expected = True

            # Extended master secret extension
            ems_ext = extensions.get(ExtendedMasterSecretExtension)
            if ems_ext is not None:
                self._extended_master_secret = True

            # Encrypt-then-mac extension
            etm_ext = extensions.get(EncryptThenMacExtension)
            if etm_ext is not None:
                if cipher_suite.symmetric not in (
                    Symmetric.AES_128_CBC,
                    Symmetric.AES_256_CBC,
                    Symmetric.TRIPLE_DES_EDE_CBC,
                ):
                    # This cipher suite doesnt support encrypt-then-mac
                    raise AlertIllegalParameter(
                        "received unexpected encrypt-then-mac extension"
                    )

                self._encrypt_then_mac = True

            # EC point formats extension
            ecpfs_ext = extensions.get(ECPointFormatsExtension)
            if ecpfs_ext is not None:
                negotiate(
                    self._ec_point_formats,
                    ecpfs_ext.data,
                    AlertIllegalParameter(
                        "received unexpected EC point format"
                    ),
                )

            # NPN extension
            npn_ext = extensions.get(NPNServerExtension)
            if npn_ext is not None:
                npn_protocol = negotiate(
                    self._npn_protocols, npn_ext.protocols
                )
                if npn_protocol is None:
                    npn_protocol = npn_ext.protocols[0]

                self._npn_protocol = npn_protocol

        if not extensions.has_allowed(allowed_extensions):
            raise AlertUnsupportedExtension("received unsupported extensions")

    def _send_certificate_tls13(
        self, cert_request: CertificateRequestTLS13
    ) -> None:
        extensions = cert_request.extensions

        sigalg_ext = extensions.get(SignatureAlgorithmsExtension)
        if sigalg_ext is None:
            raise AlertMissingExtension(
                "missing signature algorithms extension"
            )

        comp_cert_ext = extensions.get(CompressedCertificateExtension)
        if comp_cert_ext:
            compression = negotiate(
                self._certificate_compressions, comp_cert_ext.data
            )
        else:
            compression = None

        private_key: BasePrivateKey | None = None
        signature_algorithm: int | None = None

        # draft-ietf-tls-esni 25 Section 6.1.7
        # If the server requests a client certificate, the client MUST
        # respond with an empty Certificate message, denoting no client
        # certificate.
        if self._ech_status == ECHStatus.REJECTED:
            pass
        elif self._credential is not None:
            private_key = self._credential.private_key
            x509_cert = self._credential.certificate
            try:
                public_key = load_certificate_public_key(x509_cert)
            except ValueError as exc:
                raise AlertInternalError(str(exc)) from exc

            _, supported_sigalgs = self._sigalgs_for_pubkey(
                version=self.protocol_version(),
                public_key=public_key,
                public_key_oid=x509_cert.public_key_algorithm_oid,
                supported_sigalgs=self._signing_signature_algorithms,
            )
            signature_algorithm = negotiate(supported_sigalgs, sigalg_ext.data)

        if signature_algorithm is not None:
            credential = self._credential
        else:
            credential = None

        certificate = self._create_certificate_tls13(
            credential=credential,
            context=cert_request.context,
            compression=compression,
        )
        self.message_cb(Direction.WRITE, certificate)
        self._add_message(certificate)

        if signature_algorithm is None:
            return

        assert self._key_schedule is not None
        private_key = cast(BasePrivateKey, private_key)
        data = self._key_schedule.certificate_verify_data(
            TLS13_CLIENT_CONTEXT_STRING, self._transcript
        )
        signature = private_key.sign(data, signature_algorithm)

        c_verify = CertificateVerifyTLS12(signature, signature_algorithm)
        self.message_cb(Direction.WRITE, c_verify)
        self._add_message(c_verify)

    def _should_offer_early_data(self) -> bool:
        if not self._enable_early_data:
            return False
        if self._maximum_version < TLSVersion.TLSv1_3:
            return False
        if len(self._pre_shared_keys) != 1:
            return False

        offered_session = self._offered_session

        if offered_session is None:
            return False
        if offered_session.protocol_version() < TLSVersion.TLSv1_3:
            return False
        if offered_session.ticket_max_early_data == 0:
            return False
        if (
            offered_session.early_alpn is not None
            and offered_session.early_alpn not in self._alpn_protocols
        ):
            return False

        return True

    @staticmethod
    def _select_ech_config(ech_configs: bytes) -> ECHConfigContext | None:
        parser = Parser(ech_configs)

        length = parser.read_int(2)
        end = parser.tell() + length

        while parser.tell() < end:
            ech_config = ECHConfig.parse(parser)
            if not ech_config.supported():
                continue

            info = b"tls ech" + b"\x00" + ech_config.serialize()
            for cipher_suite in ech_config.contents.cipher_suites:
                kem_id = ech_config.contents.kem_id
                kdf_id, aead_id = cipher_suite
                try:
                    suite = hpke.create_suite(kem_id, kdf_id, aead_id)
                    peer_public_key = suite.kem.deserialize_public_key(
                        ech_config.contents.public_key
                    )
                except ValueError:
                    continue

                enc, ctx = suite.setup_send(peer_public_key, info=info)
                config_id = ech_config.contents.config_id
                public_name = ech_config.contents.public_name
                maximum_name_length = ech_config.contents.maximum_name_length
                extensions = ech_config.contents.extensions

                return ECHConfigContext(
                    kdf_id=kdf_id,
                    aead_id=aead_id,
                    kem_id=kem_id,
                    hpke_context=ctx,
                    config_id=config_id,
                    public_name=public_name,
                    maximum_name_length=maximum_name_length,
                    enc=enc,
                    extensions=extensions,
                )

        return None

    @classmethod
    def _update_binders(
        cls,
        pre_shared_keys: list[tuple[KeySchedule, PSKIdentity, bytes]],
        transcript: Transcript,
        client_hello: ClientHello,
        encoded_client_hello: ClientHello | None = None,
    ) -> None:
        assert client_hello.extensions
        assert client_hello.extensions[-1][0] == ExtensionType.PRE_SHARED_KEY

        handshake_data = cls._pack_handshake(client_hello)
        total_binders_length = sum(
            1 + i[0].digest_size for i in pre_shared_keys
        )
        total_length = 2 + total_binders_length
        transcript.update_hash(handshake_data[:-total_length])

        identities: list[PSKIdentity] = []
        binders: list[bytes] = []
        for key_schedule, identity, binder_key in pre_shared_keys:
            binder = key_schedule.finished_verify_data(binder_key, transcript)
            identities.append(identity)
            binders.append(binder)

        psk_ext = PSKClientExtension(identities, binders)
        client_hello.extensions.replace(psk_ext)
        if encoded_client_hello is not None:
            encoded_client_hello.extensions.append(psk_ext)
