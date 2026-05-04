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
import typing

from .. import x509
from ..key import InvalidSignature, dh, padding, rsa
from ..key.types import CertificateIssuerPrivateKeyTypes
from ..protocol.hpke import SenderContext, create_suite
from ..utils.codec import ParseError, Parser, Writer
from ..utils.constant_time import compare_digest
from ..utils.math import bytes_to_int, bytes_to_str, int_to_bytes
from ..utils.misc import is_valid_sni, negotiate
from ..utils.random import get_random_bits, get_random_bytes, get_random_int
from ._alert import (
    AlertDecodeError,
    AlertDecryptError,
    AlertECHRequired,
    AlertException,
    AlertHandshakeFailure,
    AlertIllegalParameter,
    AlertInsufficientSecurity,
    AlertInternalError,
    AlertMissingExtension,
    AlertProtocolVersion,
    AlertUnexpectedMessage,
    AlertUnsupportedExtension,
)
from ._common import create_signature, verify_signature
from ._constant import (
    CLIENT_CONTEXT_STRING,
    ECC_GROUPS,
    FFDHE_GROUPS,
    GREASES,
    KEM_GROUPS,
    SIGNATURE_ALGORITHMS,
    TLS11_DOWNGRADE_SENTINEL,
    TLS12_DOWNGRADE_SENTINEL,
    TLS13_HRR_SENTINEL,
    Authentication,
    CipherSuite,
    Compression,
    ECCurveType,
    ECHClientHelloType,
    ECPointFormat,
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
from ._context import TLSContext
from ._enum import (
    ClientHelloType,
    ClientState,
    Direction,
    ECHStatus,
    Epoch,
    Status,
    TLSSessionType,
    TLSVerifyMode,
)
from ._extension import (
    COMPRESSIBLE_EXTENSIONS,
    ClientALPNExtension,
    ClientALPSExtension,
    ClientEarlyDataExtension,
    ClientECHExtension,
    ClientHelloPaddingExtension,
    ClientKeyShareExtension,
    ClientNPNExtension,
    ClientPHAExtension,
    ClientPSKExtension,
    ClientSCTExtension,
    ClientSNIExtension,
    ClientStatusRequestExtension,
    ClientSupportedGroupsExtension,
    ClientSupportedVersionsExtension,
    CompressedCertificateExtension,
    CookieExtension,
    EarlyDataExtension,
    ECHConfig,
    ECHOuterExtension,
    ECPointFormatsExtension,
    EncryptThenMacExtension,
    ExtendedMasterSecretExtension,
    ExtensionSource,
    GenericExtension,
    HRRKeyShareExtension,
    KeyShareEntry,
    PSKIdentity,
    PSKKeyExchangeModesExtension,
    RenegotiationInfoExtension,
    ServerALPNExtension,
    ServerALPSExtension,
    ServerEarlyDataExtension,
    ServerECHExtensions,
    ServerKeyShareExtension,
    ServerNPNExtension,
    ServerPSKExtension,
    ServerSupportedVersionExtension,
    SessionTicketExtension,
    SignatureAlgorithmsExtension,
    TLSExtension,
)
from ._handshake import ECHConfigContent, TLSHandshake
from ._keyexchange import ECDHKeyExchange, FFDHKeyExchange, KEMKeyExchange
from ._message import (
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
from ._transcript import KeyDeriver, KeySchedule, Transcript

SessionTicketHandler = typing.Callable[[TLSSession], None]


class TLSHandshakeClient(TLSHandshake):
    server_side = False

    def __init__(
        self,
        context: TLSContext,
        hostname: bytes | None = None,
        session: TLSSession | None = None,
        session_ticket_handler: SessionTicketHandler | None = None,
    ) -> None:
        ## Initialization
        super().__init__(context)

        if hostname and not is_valid_sni(bytes_to_str(hostname)):
            self._hostname = None
        else:
            self._hostname = hostname

        self._session = session

        ## Callback
        self.session_ticket_handler = session_ticket_handler

        ## Dispatch function
        # ruff: disable[E501]
        self._handle_dispatch = {
            ClientState.START_CONNECT: self._do_start_connect,
            ClientState.ENTER_EARLY_DATA: self._do_enter_early_data,
            ClientState.READ_SERVER_HELLO: self._do_read_server_hello,
            ClientState.READ_SERVER_CERTIFICATE: self._do_read_server_certificate,
            ClientState.READ_CERTIFICATE_STATUS: self._do_read_certificate_status,
            ClientState.READ_SERVER_KEY_EXCHANGE: self._do_read_server_key_exchange,
            ClientState.READ_CERTIFICATE_REQUEST: self._do_read_certificate_request,
            ClientState.READ_SERVER_HELLO_DONE: self._do_read_server_hello_done,
            ClientState.SEND_CLIENT_CERTIFICATE: self._do_send_client_certificate,
            ClientState.SEND_CLIENT_KEY_EXCHANGE: self._do_send_client_key_exchange,
            ClientState.SEND_CLIENT_CERTIFICATE_VERIFY: self._do_send_client_certificate_verify,
            ClientState.SEND_CLIENT_FINISHED: self._do_send_client_finished,
            ClientState.FINISH_FLIGHT: self._do_finish_flight,
            ClientState.READ_SESSION_TICKET: self._do_read_session_ticket,
            ClientState.PROCESS_CHANGE_CIPHER_SPEC: self._do_process_change_cipher_spec,
            ClientState.READ_SERVER_FINISHED: self._do_read_server_finished,
            # TLSv1.3
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

        ## Configurations
        # Compression methods
        self._conf_compresion_methods: tuple[int, ...] = (Compression.NULL,)

        # Cipher Suites
        self._conf_cipher_suites: tuple[CipherSuite, ...] = tuple(
            cipher
            for cipher in context.cipher_suites
            if (
                cipher.minimum_version <= self._maximum_version
                and cipher.maximum_version >= self._minimum_version
            )
        )

        # Grease
        self._conf_grease = context.grease
        self._conf_grease_ech = context.grease_ech
        greases = list(GREASES)
        random.shuffle(greases)
        self._greases: tuple[int, ...] = tuple(greases)

        # Status Request
        self._conf_status_request: bool = context.status_request

        # Signed certificate timestamp
        self._conf_signed_cert_timestamp: bool = (
            context.signed_certificate_timestamp
        )

        # Client Hello Padding
        self._conf_client_hello_padding: bool = context.client_hello_padding

        # Signature Algorithms
        signature_algorithms = tuple(
            signature_algorithm
            for signature_algorithm in context.signature_algorithms
            if signature_algorithm in SIGNATURE_ALGORITHMS
        )
        self._conf_signature_algorithms: tuple[int, ...] | None = (
            signature_algorithms or None
        )

        # ALPN Protocols
        self._conf_alpn_protocols: tuple[bytes, ...] | None = (
            tuple(context.alpn_protocols) or None
        )

        # Supported groups
        valid_groups: set[int] = set()
        if self._maximum_version >= TLSVersion.TLSv1_3:
            valid_groups.update(ECC_GROUPS, FFDHE_GROUPS, KEM_GROUPS)
        elif any(c.kea == KeyExchange.ECDHE for c in self._conf_cipher_suites):
            valid_groups.update(ECC_GROUPS)

        supported_groups = tuple(
            g for g in context.supported_groups if g in valid_groups
        )
        self._conf_supported_groups: tuple[int, ...] | None = (
            supported_groups or None
        )

        # TLSv1.2 below configs
        # Encrypt Then Mac
        self._conf_encrypt_then_mac: bool = context.encrypt_then_mac

        # Extended Master Secret
        self._conf_extended_master_secret: bool = (
            context.extended_master_secret
        )

        # NPN Protocols
        self._conf_npn_protocols: tuple[bytes, ...] | None = (
            tuple(context.npn_protocols) or None
        )

        # EC point formats
        ec_point_formats = tuple(context.ec_point_formats)
        if ECPointFormat.UNCOMPRESSED not in ec_point_formats:
            ec_point_formats = (ECPointFormat.UNCOMPRESSED, *ec_point_formats)
        self._conf_ec_point_formats: tuple[int, ...] = ec_point_formats

        # TLSv1.3 above configs
        # Application Settings
        self._conf_alps: dict[bytes, bytes]
        if self._conf_alpn_protocols is not None:
            self._conf_alps = {
                p: context.alps[p]
                for p in self._conf_alpn_protocols
                if p in context.alps
            }
        else:
            self._conf_alps = {}

        # Post Handshake Authentication
        self._conf_post_handshake_auth: bool = context.post_handshake_auth

        # PSK Key Exchange Mode
        self._conf_psk_kex_modes: tuple[int, ...] | None = (
            PSKKeyExchangeMode.PSK_DHE_KE,
        )

        # Certificate Compression Algorithm
        self._conf_cert_comp_algs: tuple[int, ...] | None = (
            tuple(context.certificate_compressions) or None
        )

        ## Temporary State
        self._hs_state = ClientState.START_CONNECT
        self._extension_order: list[int] | None = None
        """Extensions type that was recevied from server hello or encrpypted
        extensions"""
        self._extensions_sent: set[int] = set()
        """Extensions type that was sent in client hello"""
        self._session_ticket: bytes | None = None
        """Session ticket to be sent"""
        self._cookie: bytes | None = None
        """Cookie from hello retry request"""
        self._selected_ech_config: ECHConfigContent | None = None
        """Selected ech config"""
        self._ech_client_outer: ClientECHExtension | None = None
        """Outer ECH to be sent in client hello extension"""
        self._hello_retry_request_used: bool = False
        """True if hello retry request received from server (TLSv1.3)"""
        self._ticket_expected: bool = False
        """True if server sent session ticket extension in ServerHello"""
        self._early_data_offered: bool = False
        """True if found early data extension in client hello"""

        # Peer item
        self._peer_key: bytes | None = None
        self._peer_cert_request: (
            CertificateRequest
            | CertificateRequestTLS12
            | CertificateRequestTLS13
            | None
        ) = None

        # Identity
        self._private_key: CertificateIssuerPrivateKeyTypes | None = None
        self._x509_certs: tuple[x509.Certificate, ...] | None = None

        # Inner client hello variable, will replace actual when ech accepted
        self._inner_transcript: Transcript | None = None
        self._inner_client_random: bytes | None = None
        self._inner_extensions_sent: set[int] | None = None

        self._pre_shared_keys: list[
            tuple[KeySchedule, PSKIdentity, bytes]
        ] = []

        self._key_exchange: ECDHKeyExchange | FFDHKeyExchange | None = None
        self._key_exchanges: dict[
            int, ECDHKeyExchange | FFDHKeyExchange | KEMKeyExchange
        ] = {}

        ## Negotiated variable
        self._ech_retry_configs: list[ECHConfig] | None = None
        """Retry configurations from encrypted extension"""
        self._ech_status: ECHStatus = ECHStatus.NONE
        """Encrypted Client Hello status"""
        self._signature_algorithm: int | None = None
        """signature algorithm to be used with signing"""
        self._secure_renegotiation: bool = False
        """True when secure renegotiation accepted"""
        self._extended_master_secret: bool = False
        """True when extended master secret is negotiated"""
        self._encrypt_then_mac: bool = False
        """True when extended master secret is negotiated"""

    @property
    def done(self) -> bool:
        return self._hs_state == ClientState.DONE

    @property
    def ech_retry_configs(self) -> list[ECHConfig] | None:
        return self._ech_retry_configs

    @property
    def ech_status(self) -> ECHStatus:
        return self._ech_status

    def trigger_post_handshake(self) -> None:
        if not self.done:
            raise ValueError("handshake not complete")
        self._set_state(ClientState.READ_POST_HANDSHAKE)

    def send_key_update(self, message_type: KeyUpdateMessageType) -> None:
        if not self.done:
            raise ValueError("KeyUpdate can only be sent after handshake done")

        self._write_key_update(message_type)
        self._set_state(ClientState.PROCESS_UPDATE_TRAFFIC)

    def _do_start_connect(self) -> Status:
        self._session_reused = False

        context = self.context

        # Client Random
        self._client_random = get_random_bytes(32)

        # Version to send in client hello
        self._client_version = min(self._maximum_version, TLSVersion.TLSv1_2)

        if self._maximum_version >= TLSVersion.TLSv1_3:
            if self._conf_supported_groups is None:
                raise ValueError("No supported groups")

            # Fake session id
            if context.middlebox_compat:
                self._session_id = get_random_bytes(32)

            # Key Shares
            key_share_groups = context.key_share_groups
            for key_share_group in key_share_groups:
                if key_share_group not in self._conf_supported_groups:
                    continue

                kex: ECDHKeyExchange | FFDHKeyExchange | KEMKeyExchange
                try:
                    if key_share_group in ECC_GROUPS:
                        kex = ECDHKeyExchange(key_share_group)
                    elif key_share_group in KEM_GROUPS:
                        kex = KEMKeyExchange(key_share_group)
                    elif key_share_group in FFDHE_GROUPS:
                        kex = FFDHKeyExchange(key_share_group)
                    else:
                        continue
                except AlertException as exc:
                    raise ValueError(str(exc)) from None

                self._key_exchanges[key_share_group] = kex

            if context.ech_configs is not None:
                c = None
                try:
                    c = self._select_ech_config(context.ech_configs)
                except ParseError:
                    pass
                if c is not None:
                    self._selected_ech_config = c
                    self._inner_transcript = Transcript()
                    self._inner_client_random = get_random_bytes(32)

        if self._session is not None:
            session = self._session
            if (
                not session.time_valid()
                or session.server_side
                or session.protocol_version() > self._maximum_version
                or session.protocol_version() < self._minimum_version
                or (
                    session.protocol_version() < TLSVersion.TLSv1_3
                    and self._selected_ech_config is not None
                )
            ):
                session_type = TLSSessionType.not_resumable
            else:
                session_type = session.session_type()

            if session_type == TLSSessionType.session_id:
                self._session_id = session.session_id
            elif session_type == TLSSessionType.session_ticket:
                # Generate random session_id so it track
                # the session is resumed
                self._session_id = get_random_bytes(32)
                self._session_ticket = session.ticket
            elif session_type == TLSSessionType.pre_shared_key:
                assert session.cipher_suite is not None
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
            self.session_ticket_handler is not None
            and self._session_ticket is None
        ):
            self._session_ticket = b""

        client_hello = ClientHello(
            version=self._client_version,
            random=self._client_random,
            session_id=self._session_id,
            cipher_suites=self._get_cipher_suites(),
            compression_methods=self._conf_compresion_methods,
        )
        result = False

        # If maximum version above TLSv1.3 try to build an EncryptedClientHello
        if self._maximum_version >= TLSVersion.TLSv1_3:
            result = self._build_ech(client_hello)

        # Proceed to plain ClientHello if build_ech return False
        if not result:
            self._build_client_hello(client_hello)

        self.do_message_cb("write", client_hello)
        self._add_message(client_hello)

        self._set_state(ClientState.ENTER_EARLY_DATA)
        return Status.FLUSH_MESSAGE

    def _do_enter_early_data(self) -> Status:
        if not self._early_data_offered:
            self._set_state(ClientState.READ_SERVER_HELLO)
            return Status.OK

        if self._session is None:
            raise AlertInternalError("Missing session")

        self._early_session = self._session
        self._version = self._early_session.version
        self._is_early_version = True

        # Early data extension is included in ClientHello
        self._key_schedule, _, _ = self._pre_shared_keys[0]
        if self._selected_ech_config is not None:
            assert self._inner_transcript is not None
            transcript = self._inner_transcript
        else:
            transcript = self._transcript

        self._setup_traffic_key_tls13(
            session=self._early_session,
            direction=Direction.ENCRYPT,
            epoch=Epoch.ZERO_RTT,
            label=b"c e traffic",
            transcript=transcript,
        )
        self.update_traffic_cb(Direction.ENCRYPT, Epoch.ZERO_RTT)
        self._in_early_data = True
        self.can_early_write = True

        if self.context.middlebox_compat:
            self.add_ccs_cb()

        self._set_state(ClientState.READ_SERVER_HELLO)
        return Status.EARLY_RETURN

    def _do_read_server_hello(self) -> Status:
        message = self._get_message()
        if message is None:
            return Status.READ_MESSAGE

        server_hello = message.get_handshake(ServerHello)

        # Update version
        server_version = server_hello.version
        if not TLSVersion.TLSv1 <= server_version <= TLSVersion.TLSv1_2:
            raise AlertProtocolVersion("Unknown protocol version")

        supported_versions_ext = server_hello.get_extension(
            ServerSupportedVersionExtension
        )
        if supported_versions_ext is not None:
            if not self._maximum_version > TLSVersion.TLSv1_2:
                raise AlertIllegalParameter(
                    "Unexpected supported version extension"
                )
            if not server_version == TLSVersion.TLSv1_2:
                raise AlertIllegalParameter("Invalid server version")
            if not supported_versions_ext.data > TLSVersion.TLSv1_2:
                raise AlertIllegalParameter("Unknown protocol version")
            server_version = supported_versions_ext.data

        if server_version < self._minimum_version:
            raise AlertProtocolVersion("Version older than specified")
        if server_version > self._maximum_version:
            raise AlertProtocolVersion("Version newer than specified")

        self._version = server_version
        self._is_early_version = False

        # Compression method
        if (
            server_hello.compression_method
            not in self._conf_compresion_methods
        ):
            raise AlertIllegalParameter("Invalid compression method")

        if self._early_data_offered:
            if self._early_session is None:
                self.can_early_write = False
                raise AlertInternalError("Missing early_session")

            if self._version != self._early_session.version:
                if (
                    self.protocol_version() >= TLSVersion.TLSv1_3
                    or self._early_session.protocol_version()
                    < TLSVersion.TLSv1_3
                ):
                    raise AlertInternalError("Version mistmatch")

                self.can_early_write = False

                # Termintate early since TLSv1.2 cannot handle early data
                raise AlertProtocolVersion(
                    "Unable to negotiate TLSv1.2 or below since early data "
                    "has been sent"
                )

        if self.protocol_version() >= TLSVersion.TLSv1_3:
            self._set_state(ClientState.READ_HRR_TLS13)
            return Status.OK

        # RFC8446 section 4.1.3
        if (
            (
                server_hello.random[-8:] == TLS12_DOWNGRADE_SENTINEL
                or server_hello.random[-8:] == TLS11_DOWNGRADE_SENTINEL
            )
            and self._maximum_version >= TLSVersion.TLSv1_3
            and self.protocol_version() < TLSVersion.TLSv1_3
        ):
            raise AlertIllegalParameter(
                "Connection terminated due to downgrade protection."
            )

        # RFC8446 section 4.1.3
        if (
            server_hello.random[-8:] == TLS11_DOWNGRADE_SENTINEL
            and self._maximum_version == TLSVersion.TLSv1_2
            and self.protocol_version() < TLSVersion.TLSv1_2
        ):
            raise AlertIllegalParameter(
                "Connection terminated due to downgrade protection."
            )

        if self._selected_ech_config is not None:
            self._ech_status = ECHStatus.REJECTED

        # Update server random
        self._server_random = server_hello.random

        # Cipher Suites
        try:
            cipher_suite = CipherSuite(server_hello.cipher_suite)
        except ValueError as exc:
            raise AlertIllegalParameter("Invalid cipher suite") from exc
        if cipher_suite not in self._conf_cipher_suites:
            raise AlertIllegalParameter("Cipher suite mismatch")
        if not (
            cipher_suite.minimum_version
            <= self.protocol_version()
            <= cipher_suite.maximum_version
        ):
            raise AlertIllegalParameter("Invalid cipher suite")

        self._cipher_suite = cipher_suite

        # Session ID
        if self._session_id and server_hello.session_id == self._session_id:
            session = self._session
            if session is None or self._ech_status == ECHStatus.REJECTED:
                raise AlertIllegalParameter("Echoed invalid session id")
            if session.version != self._version:
                raise AlertIllegalParameter("Invalid version")
            if session.cipher_suite != self._cipher_suite:
                raise AlertIllegalParameter("Invalid cipher suite")
            self._session_reused = True
        else:
            self._session = None
            self._new_session = self._get_new_session()
            self._new_session.session_id = server_hello.session_id
            self._new_session.cipher_suite = self._cipher_suite

        # Process extensions
        ext_map = server_hello.extension_map(ExtensionSource.SERVER)
        self._process_extensions(ext_map)

        if self._session is not None:
            if (
                self._session.extended_master_secret
                != self._extended_master_secret
            ):
                if self._session.extended_master_secret:
                    raise AlertHandshakeFailure(
                        "EMS Session resumed without EMS extension"
                    )
                else:
                    raise AlertHandshakeFailure(
                        "Non EMS Session resumed with EMS extension"
                    )

            self._key_deriver = KeyDeriver(
                version=self.protocol_version(),
                cipher_suite=self._cipher_suite,
                client_random=self._client_random,
                server_random=self._server_random,
            )
            self._setup_traffic_key(self._session)

        self.do_message_cb("read", server_hello)
        self._next_message()

        self._set_state(ClientState.READ_SERVER_CERTIFICATE)
        return Status.OK

    def _do_read_server_certificate(self) -> Status:
        if self._session is not None:
            self._set_state(ClientState.READ_SESSION_TICKET)
            return Status.OK

        if self.cipher().auth == Authentication.ANON:
            self._set_state(ClientState.READ_SERVER_KEY_EXCHANGE)
            return Status.OK

        message = self._get_message()
        if message is None:
            return Status.READ_MESSAGE

        if self._new_session is None:
            raise AlertInternalError("Missing new_session")

        session = self._new_session
        certificate = self._process_certificate(
            message, session, allow_anon=False
        )
        if self.context.verify_mode != TLSVerifyMode.CERT_NONE:
            if self.context.check_hostname:
                hostname = self._hostname
            else:
                hostname = None
            self._verify_x509(self.context, session, hostname)

        self.do_message_cb("read", certificate)
        self._next_message()

        self._set_state(ClientState.READ_CERTIFICATE_STATUS)
        return Status.OK

    def _do_read_certificate_status(self) -> Status:
        if not self._conf_status_request:
            self._set_state(ClientState.READ_SERVER_KEY_EXCHANGE)
            return Status.OK

        message = self._get_message()
        if message is None:
            return Status.READ_MESSAGE

        if message.handshake_type != HandshakeType.CERTIFICATE_STATUS:
            self._set_state(ClientState.READ_SERVER_KEY_EXCHANGE)
            return Status.OK

        certificate_status = message.get_handshake(CertificateStatus)

        if self._new_session is None:
            raise AlertInternalError("Missing new_session")

        self._new_session.ocsp_response = certificate_status.ocsp

        self.do_message_cb("read", certificate_status)
        self._next_message()

        self._set_state(ClientState.READ_SERVER_KEY_EXCHANGE)
        return Status.OK

    def _do_read_server_key_exchange(self) -> Status:
        cipher_suite = self.cipher()
        if cipher_suite.kea == KeyExchange.RSA:
            self._set_state(ClientState.READ_CERTIFICATE_REQUEST)
            return Status.OK

        message = self._get_message()
        if message is None:
            return Status.READ_MESSAGE

        ske = message.get_handshake(ServerKeyExchange)

        if self._new_session is None:
            raise AlertInternalError("Missing new_session")

        version = self.protocol_version()
        new_session = self._new_session
        parser = Parser(ske.data)
        parser.set_bookmark()

        if cipher_suite.kea == KeyExchange.ECDHE:
            curve_type = parser.read_int(1)
            group_id = parser.read_int(2)
            point = parser.read_prefixed_bytes(1)

            if curve_type != ECCurveType.NAMED_CURVE:
                raise AlertIllegalParameter(
                    "Unexpected curve_type in server key exchange"
                )
            if (
                self._conf_supported_groups is not None
                and group_id not in self._conf_supported_groups
            ):
                raise AlertIllegalParameter(
                    "Unexpected curve in server key exchange"
                )
            if not point:
                raise AlertDecodeError(
                    "Empty key share in server key exchange"
                )

            new_session.group_id = group_id
            self._key_exchange = ECDHKeyExchange(group_id)
            self._peer_key = point

        elif cipher_suite.kea == KeyExchange.DHE:
            dh_p_length = parser.read_int(2)
            dh_p = parser.read_int(dh_p_length)
            dh_g_length = parser.read_int(2)
            dh_g = parser.read_int(dh_g_length)
            dh_ys_bytes = parser.read_prefixed_bytes(2)

            # Enforce minimum prime size to prevent Logjam attacks!
            if dh_p.bit_length() < 2048:
                raise AlertInsufficientSecurity(
                    f"DHE prime too small: {dh_p.bit_length()} bits."
                )

            try:
                parameters_numbers = dh.DHParameterNumbers(p=dh_p, g=dh_g)
                parameters = parameters_numbers.parameters()
                self._key_exchange = FFDHKeyExchange(parameters=parameters)
            except ValueError as exc:
                raise AlertIllegalParameter(str(exc)) from exc

            self._peer_key = dh_ys_bytes

        else:
            raise AlertInternalError("Unsupported cipher suite selected")

        if cipher_suite.auth != Authentication.ANON:
            if new_session.x509_peer is None:
                raise AlertInternalError("Missing x509_peer in new_session")

            x509_peer = new_session.x509_peer
            try:
                peer_public_key = x509_peer.public_key()
            except ValueError as exc:
                raise AlertHandshakeFailure(
                    "Unsupported public key format"
                ) from exc

            ske_data = parser.data_since_bookmark()
            peer_public_key_oid = x509_peer.public_key_algorithm_oid

            if version == TLSVersion.TLSv1_2:
                verify_alg = parser.read_int(2)
                self._verify_sigalg_tls12(
                    version=version,
                    public_key=peer_public_key,
                    public_key_oid=peer_public_key_oid,
                    signature_algorihtm=verify_alg,
                    supported_sigalgs=self._conf_signature_algorithms,
                )
                new_session.peer_signature_algorithm = verify_alg
            else:
                verify_alg = self._get_sigalg_tls1(
                    version=version,
                    public_key=peer_public_key,
                    public_key_oid=peer_public_key_oid,
                )

            self._check_pubkey(version, peer_public_key, cipher_suite)

            signature = parser.read_prefixed_bytes(2)
            if not signature:
                raise AlertIllegalParameter("Empty signature")

            data = self._client_random + self._server_random + ske_data

            try:
                verify_signature(peer_public_key, signature, data, verify_alg)
            except ValueError as exc:
                raise AlertIllegalParameter(str(exc)) from exc
            except InvalidSignature:
                raise AlertDecryptError(
                    "Server key exchange signature verify failed"
                ) from None

        if parser.remaining():
            raise AlertDecodeError("Trailing data")

        self.do_message_cb("read", ske)
        self._next_message()

        self._set_state(ClientState.READ_CERTIFICATE_REQUEST)
        return Status.OK

    def _do_read_certificate_request(self) -> Status:
        if self.cipher().auth == Authentication.ANON:
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
            cert_request = message.get_handshake(CertificateRequestTLS12)
        else:
            cert_request = message.get_handshake(CertificateRequest)

        self._peer_cert_request = cert_request

        self.do_message_cb("read", cert_request)
        self._next_message()

        self._set_state(ClientState.READ_SERVER_HELLO_DONE)
        return Status.OK

    def _do_read_server_hello_done(self) -> Status:
        message = self._get_message()
        if message is None:
            return Status.READ_MESSAGE

        hello_done = message.get_handshake(ServerHelloDone)
        self.do_message_cb("read", hello_done)
        self._next_message()

        self._set_state(ClientState.SEND_CLIENT_CERTIFICATE)
        return Status.OK

    def _do_send_client_certificate(self) -> Status:
        if self._peer_cert_request is None:
            self._set_state(ClientState.SEND_CLIENT_KEY_EXCHANGE)
            return Status.OK

        version = self.protocol_version()
        priv_key = self.context.private_key
        x509_certs = self.context.x509_certs
        signature_algorithm: int | None = None
        cert_request = typing.cast(
            CertificateRequest | CertificateRequestTLS12,
            self._peer_cert_request,
        )

        if priv_key is not None and x509_certs is not None:
            x509_leaf = x509_certs[0]
            try:
                public_key = x509_leaf.public_key()
            except ValueError as exc:
                raise AlertInternalError(
                    "Unsupported public key format"
                ) from exc

            public_key_oid = x509_leaf.public_key_algorithm_oid
            default_sigalg, supported_sigalgs = self._sigalgs_for_pubkey(
                version=version,
                public_key=public_key,
                public_key_oid=public_key_oid,
                supported_sigalgs=self._conf_signature_algorithms,
            )
            cert_type = self._certificate_type(public_key_oid)
            supported_cert_types = cert_request.certificate_types

            if version == TLSVersion.TLSv1_2:
                cert_request = typing.cast(
                    CertificateRequestTLS12, cert_request
                )
                if cert_type in supported_cert_types:
                    signature_algorithm = negotiate(
                        supported_sigalgs,
                        cert_request.signature_algorithms,
                    )

            elif (
                default_sigalg is not None
                and cert_type in supported_cert_types
            ):
                signature_algorithm = default_sigalg

        if signature_algorithm is not None:
            x509_certs = typing.cast(tuple[x509.Certificate, ...], x509_certs)
            certificate = self._create_certificate(x509_certs)
            self._private_key = priv_key
            self._x509_certs = x509_certs
            self._signature_algorithm = signature_algorithm
        else:
            certificate = self._create_certificate(())

        self.do_message_cb("write", certificate)
        self._add_message(certificate)

        self._set_state(ClientState.SEND_CLIENT_KEY_EXCHANGE)
        return Status.OK

    def _do_send_client_key_exchange(self) -> Status:
        if self._new_session is None:
            raise AlertInternalError("Missing new_session")

        version = self.protocol_version()
        cipher_suite = self.cipher()
        new_session = self._new_session
        writer = Writer()

        if cipher_suite.kea == KeyExchange.RSA:
            assert cipher_suite.auth == Authentication.RSA

            if new_session.x509_peer is None:
                raise AlertInternalError("Missing x509_peer in new_session")
            try:
                peer_public_key = new_session.x509_peer.public_key()
            except ValueError as exc:
                raise AlertHandshakeFailure(
                    "Unsupported public key format"
                ) from exc

            self._check_pubkey(version, peer_public_key, cipher_suite)

            peer_public_key = typing.cast(rsa.RSAPublicKey, peer_public_key)
            premaster_secret = int_to_bytes(version, 2) + get_random_bytes(46)
            encrypted_premaster_secret = peer_public_key.encrypt(
                premaster_secret, padding.PKCS1v15()
            )
            writer.write_prefixed_bytes(encrypted_premaster_secret, 2)
        else:
            if self._key_exchange is None:
                raise AlertInternalError("Missing key_exchange")
            if self._peer_key is None:
                raise AlertInternalError("Missing peer_key")

            key_share, premaster_secret = (
                self._key_exchange.generate_and_compute(self._peer_key)
            )
            if cipher_suite.kea == KeyExchange.ECDHE:
                writer.write_prefixed_bytes(key_share, 1)
            elif cipher_suite.kea == KeyExchange.DHE:
                writer.write_prefixed_bytes(key_share, 2)
            else:
                raise AlertInternalError("Unsupported cipher suite selected")

        cke = ClientKeyExchange(writer.tobytes())
        self.do_message_cb("write", cke)
        self._add_message(cke)

        if self._extended_master_secret:
            label = b"extended master secret"
            transcript = self._transcript
        else:
            label = b"master secret"
            transcript = None

        self._key_deriver = KeyDeriver(
            version=version,
            cipher_suite=cipher_suite,
            client_random=self._client_random,
            server_random=self._server_random,
        )
        master_secret = self._key_deriver.derive_master_secret(
            premaster_secret, label, transcript
        )
        new_session.secret = master_secret
        new_session.extended_master_secret = self._extended_master_secret
        new_session.encrypt_then_mac = self._encrypt_then_mac

        self._setup_traffic_key(new_session)

        self._set_state(ClientState.SEND_CLIENT_CERTIFICATE_VERIFY)
        return Status.OK

    def _do_send_client_certificate_verify(self) -> Status:
        if self._peer_cert_request is None or self._x509_certs is None:
            self._set_state(ClientState.SEND_CLIENT_FINISHED)
            return Status.PACK_FLIGHT

        if self._private_key is None:
            raise AlertInternalError("Missing private_key")
        if self._signature_algorithm is None:
            raise AlertInternalError("Missing signature_algorithm")

        priv_key = self._private_key
        signature_algorithm = self._signature_algorithm
        transcript = self._transcript.get()
        signature = create_signature(priv_key, transcript, signature_algorithm)

        cert_verify: CertificateVerifyTLS12 | CertificateVerify
        if self.protocol_version() == TLSVersion.TLSv1_2:
            cert_verify = CertificateVerifyTLS12(
                signature, signature_algorithm
            )
        else:
            cert_verify = CertificateVerify(signature)

        self.do_message_cb("write", cert_verify)
        self._add_message(cert_verify)

        self._set_state(ClientState.SEND_CLIENT_FINISHED)
        return Status.PACK_FLIGHT

    def _do_send_client_finished(self) -> Status:
        self.update_traffic_cb(Direction.ENCRYPT, Epoch.APPLICATION_DATA)
        self.add_ccs_cb()

        if self._npn_selected is not None:
            npn = NextProtocol(self._npn_selected)
            self.do_message_cb("write", npn)
            self._add_message(npn)

        if self._new_session is not None:
            session = self._new_session
        else:
            if self._session is None:
                raise AlertInternalError("Missing session")
            session = self._session

        if self._key_deriver is None:
            raise AlertInternalError("key_deriver not set")

        verify_data = self._key_deriver.finished_verify_data(
            session.secret, b"client finished", self._transcript
        )
        finished = Finished(verify_data)
        self.do_message_cb("write", finished)
        self._add_message(finished)

        self._set_state(ClientState.FINISH_FLIGHT)
        return Status.FLUSH_MESSAGE

    def _do_finish_flight(self) -> Status:
        if self._session is not None:
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

        new_session_ticket = message.get_handshake(NewSessionTicket)
        if not new_session_ticket.ticket:
            self._ticket_expected = False
        else:
            if self._session is not None:
                if self._new_session is not None:
                    raise AlertInternalError("Unexpected new_session set")
                self._new_session = self._session.copy(include_noauth=True)
            elif self._new_session is None:
                raise AlertInternalError("Missing new_session")

            self._new_session.rebase_time()
            self._new_session.ticket = new_session_ticket.ticket

        self.do_message_cb("read", new_session_ticket)
        self._next_message()

        self._set_state(ClientState.PROCESS_CHANGE_CIPHER_SPEC)
        return Status.READ_CHANGE_CIPHER_SPEC

    def _do_process_change_cipher_spec(self) -> Status:
        self.update_traffic_cb(Direction.DECRYPT, Epoch.APPLICATION_DATA)
        self._set_state(ClientState.READ_SERVER_FINISHED)
        return Status.OK

    def _do_read_server_finished(self) -> Status:
        message = self._get_message()
        if message is None:
            return Status.READ_MESSAGE

        server_finished = message.get_handshake(Finished)

        if self._new_session is not None:
            session = self._new_session
        else:
            if self._session is None:
                raise AlertInternalError("Missing session")
            session = self._session

        if self._key_deriver is None:
            raise AlertInternalError("key_deriver not set")

        verify_data = server_finished.verify_data
        expected_verify_data = self._key_deriver.finished_verify_data(
            session.secret, b"server finished", self._transcript
        )
        if not compare_digest(verify_data, expected_verify_data):
            raise AlertDecryptError("Server finished verify_data mismatch")

        self.do_message_cb("read", server_finished)
        self._next_message()

        if self._session is not None:
            self._set_state(ClientState.SEND_CLIENT_FINISHED)
        else:
            self._set_state(ClientState.FINISH_CLIENT_HANDSHAKE)
        return Status.OK

    def _do_finish_client_handshake(self) -> Status:
        if self._ech_status == ECHStatus.REJECTED:
            raise AlertECHRequired("ECH not negotiated")

        if self._new_session is not None:
            has_new_session = True
            self._established_session = self._new_session
            self._established_session.not_resumable = False
        else:
            if self._session is None:
                raise AlertInternalError("Missing session")
            has_new_session = False
            self._established_session = self._session

        session = self._established_session
        if (
            has_new_session
            and self.session_ticket_handler is not None
            and session.session_type() != TLSSessionType.not_resumable
        ):
            self.session_ticket_handler(session)

        self._set_state(ClientState.DONE)
        return Status.OK

    def _do_read_hrr_tlsv13(self) -> Status:
        message = self._get_message()
        if message is None:
            return Status.READ_MESSAGE

        server_hello = message.get_handshake(ServerHello)

        if self.has_unprocessed_hs_data():
            raise AlertUnexpectedMessage("Trailing handshake data")

        # Cipher Suites
        try:
            cipher_suite = CipherSuite(server_hello.cipher_suite)
        except ValueError as exc:
            raise AlertIllegalParameter("Invalid cipher suite") from exc
        if cipher_suite not in self._conf_cipher_suites:
            raise AlertIllegalParameter("Cipher suite mismatch")
        if not (
            cipher_suite.minimum_version
            <= self.protocol_version()
            <= cipher_suite.maximum_version
        ):
            raise AlertIllegalParameter("Invalid cipher suite")

        self._cipher_suite = cipher_suite
        self._key_schedule = KeySchedule(cipher_suite.prf_hash)

        if server_hello.random != TLS13_HRR_SENTINEL:
            self._set_state(ClientState.READ_SERVER_HELLO_TLS13)
            return Status.OK

        self._hello_retry_request_used = True

        if server_hello.session_id != self._session_id:
            raise AlertIllegalParameter("Session ID mismatch")

        self._transcript.update_for_hello_retry_request(cipher_suite.prf_hash)

        ext_map = server_hello.extension_map(ExtensionSource.HRR)
        ext_map.pop(ExtensionType.SUPPORTED_VERSIONS)

        if self._selected_ech_config is not None:
            if self._inner_transcript is None:
                raise AlertInternalError("Missing inner_transcript")

            ext_map.pop(ExtensionType.ENCRYPTED_CLIENT_HELLO, None)
            self._inner_transcript.update_for_hello_retry_request(
                cipher_suite.prf_hash
            )
            if self._check_ech_confirmation(
                server_hello, self._inner_transcript.copy(), is_hrr=True
            ):
                self._ech_status = ECHStatus.ACCEPTED
                self._inner_transcript.update_hash(message.serialize())
            else:
                self._ech_status = ECHStatus.REJECTED

        cookie_ext = typing.cast(
            CookieExtension | None, ext_map.pop(ExtensionType.COOKIE, None)
        )
        key_share_ext = typing.cast(
            HRRKeyShareExtension | None,
            ext_map.pop(ExtensionType.KEY_SHARE, None),
        )

        if ext_map:
            raise AlertUnsupportedExtension(
                "Unexpected extension in hello retry request"
            )

        if cookie_ext is None and key_share_ext is None:
            raise AlertIllegalParameter(
                "Received hello retry request did not cause update to client "
                "hello"
            )

        if cookie_ext is not None:
            self._cookie = cookie_ext.data

        if key_share_ext is not None:
            selected_group = key_share_ext.data
            if self._conf_supported_groups is None:
                raise AlertInternalError()

            if selected_group not in self._conf_supported_groups:
                raise AlertIllegalParameter(
                    "Unexpected group in key share extension"
                )

            if self._key_exchanges.get(selected_group):
                raise AlertIllegalParameter(
                    "Unexpected group in key share extension"
                )

            kex: KEMKeyExchange | FFDHKeyExchange | ECDHKeyExchange
            if selected_group in KEM_GROUPS:
                kex = KEMKeyExchange(selected_group)
            elif selected_group in FFDHE_GROUPS:
                kex = FFDHKeyExchange(selected_group)
            elif selected_group in ECC_GROUPS:
                kex = ECDHKeyExchange(selected_group)
            else:
                raise AlertIllegalParameter()

            self._key_exchanges.clear()
            self._key_exchanges[selected_group] = kex

        self.do_message_cb("read", server_hello)
        self._next_message()

        if self._in_early_data:
            self._close_early_data()
            self.update_traffic_cb(Direction.ENCRYPT, Epoch.INITIAL)

        self._set_state(ClientState.SEND_SECOND_CLIENT_HELLO_TLS13)
        return Status.OK

    def _do_send_second_client_hello_tls13(self) -> Status:
        client_hello = ClientHello(
            version=self._client_version,
            random=self._client_random,
            session_id=self._session_id,
            cipher_suites=self._get_cipher_suites(),
            compression_methods=self._conf_compresion_methods,
        )
        if self._ech_status == ECHStatus.ACCEPTED:
            result = self._encrypt_client_hello(client_hello, is_hrr=True)
            if not result:
                raise AlertInternalError("Error encrypting client hello")
        else:
            self._build_client_hello(client_hello, is_hrr=True)

        self.do_message_cb("write", client_hello)
        self._add_message(client_hello)

        self._set_state(ClientState.READ_SERVER_HELLO_TLS13)
        return Status.FLUSH_MESSAGE

    def _do_read_server_hello_tls13(self) -> Status:
        message = self._get_message()
        if message is None:
            return Status.READ_MESSAGE

        server_hello = message.get_handshake(ServerHello)

        if self.has_unprocessed_hs_data():
            raise AlertUnexpectedMessage("Trailing handshake data")
        if self._key_schedule is None:
            raise AlertInternalError("key_schedule not set")

        cipher_suite = self.cipher()
        key_schedule = self._key_schedule

        if server_hello.random == TLS13_HRR_SENTINEL:
            raise AlertUnexpectedMessage("Second hello retry request")

        if server_hello.session_id != self._session_id:
            raise AlertIllegalParameter("session_id mismatch")

        # Saniry check if hello retry request used
        if server_hello.cipher_suite != cipher_suite:
            raise AlertIllegalParameter("cipher_suite mismatch")

        # Update server random
        self._server_random = server_hello.random

        # Check if ECH accepted
        if (
            self._selected_ech_config is not None
            and self._ech_status != ECHStatus.REJECTED
        ):
            if self._inner_transcript is None:
                raise AlertInternalError("Missing inner_transcript")

            ech_accepted = self._check_ech_confirmation(
                server_hello, self._inner_transcript.copy(), is_hrr=False
            )
            if ech_accepted:
                if self._inner_client_random is None:
                    raise AlertInternalError("Missing inner_client_random")
                if self._inner_extensions_sent is None:
                    raise AlertInternalError("Missing inner_extensions_sent")

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
                    raise AlertIllegalParameter()

                self._ech_status = ECHStatus.REJECTED

        ext_map = server_hello.extension_map(ExtensionSource.SERVER)
        ext_map.pop(ExtensionType.SUPPORTED_VERSIONS, None)
        kex_ext = typing.cast(
            ServerKeyShareExtension | None,
            ext_map.pop(ExtensionType.KEY_SHARE, None),
        )
        psk_ext = typing.cast(
            ServerPSKExtension | None,
            ext_map.pop(ExtensionType.PRE_SHARED_KEY, None),
        )
        if kex_ext is None and psk_ext is None:
            raise AlertMissingExtension("Missing extension")
        if ext_map:
            raise AlertUnsupportedExtension("Unsupported extension")

        if psk_ext is not None:
            if (
                not self._pre_shared_keys
                or self._ech_status == ECHStatus.REJECTED
            ):
                raise AlertUnsupportedExtension("Unexpected PSK extension")

            if self._session is None or self._session.cipher_suite is None:
                raise AlertInternalError(
                    "Missing session or session cipher_suite"
                )
            if self._session.version != self._version:
                raise AlertIllegalParameter("version mismatch")
            if self._session.cipher_suite.prf_hash != cipher_suite.prf_hash:
                raise AlertIllegalParameter("prf hash mismatch")

            # Selected index
            sel_idx = psk_ext.data
            try:
                key_schedule, _, _ = self._pre_shared_keys[sel_idx]
            except IndexError:
                raise AlertIllegalParameter(
                    f"Unexpected index '{sel_idx}' in Invalid pre shared key "
                    f"extension"
                ) from None

            self._key_schedule = key_schedule
            self._pre_shared_keys.clear()

            new_session = self._session.copy()
            new_session.renew_timeout(100)
            self._session = None
            self._session_reused = True
        else:
            if key_schedule.generation != 0:
                raise AlertInternalError()

            key_schedule.extract(None)
            new_session = self._get_new_session()

        self._new_session = new_session
        self._new_session.cipher_suite = self._cipher_suite

        shared_secret = None
        if kex_ext is not None:
            if (
                self._conf_psk_kex_modes is not None
                and PSKKeyExchangeMode.PSK_DHE_KE
                not in self._conf_psk_kex_modes
            ):
                raise AlertIllegalParameter(
                    "Unexpected PSK key exchange modes extension"
                )

            if self._key_exchanges is None:
                raise AlertInternalError()

            key_share = kex_ext.key_share
            try:
                kex = self._key_exchanges[key_share.group]
            except KeyError:
                raise AlertIllegalParameter(
                    f"Unexpected group '{key_share.group}' in key share "
                    f"extension"
                ) from None

            try:
                shared_secret = kex.compute_shared_secret(
                    key_share.key_exchange
                )
            except ValueError as exc:
                raise AlertIllegalParameter(str(exc)) from None

            new_session.group_id = key_share.group

        elif (
            self._conf_psk_kex_modes is not None
            and PSKKeyExchangeMode.PSK_KE not in self._conf_psk_kex_modes
        ):
            raise AlertIllegalParameter()

        key_schedule.extract(shared_secret)

        self.do_message_cb("read", server_hello)
        self._next_message()

        self._setup_traffic_key_tls13(
            session=self._new_session,
            direction=Direction.DECRYPT,
            epoch=Epoch.HANDSHAKE,
            label=b"s hs traffic",
        )
        self._setup_traffic_key_tls13(
            session=self._new_session,
            direction=Direction.ENCRYPT,
            epoch=Epoch.HANDSHAKE,
            label=b"c hs traffic",
        )
        self.update_traffic_cb(Direction.DECRYPT, Epoch.HANDSHAKE)

        if not self._early_data_offered:
            self.update_traffic_cb(Direction.ENCRYPT, Epoch.HANDSHAKE)
            if self.context.middlebox_compat:
                self.add_ccs_cb()

        self._set_state(ClientState.READ_ENCRYPTED_EXTENSIONS_TLS13)
        return Status.OK

    def _do_read_encrypted_extensions_tls13(self) -> Status:
        message = self._get_message()
        if message is None:
            return Status.READ_MESSAGE

        enc_ext = message.get_handshake(EncryptedExtensions)

        ext_map = enc_ext.extension_map(ExtensionSource.SERVER)
        self._process_extensions(ext_map)

        self.do_message_cb("read", enc_ext)
        self._next_message()

        if self._new_session is None:
            raise AlertInternalError("Missing new_session")

        new_session = self._new_session

        if self._early_data_accepted:
            if not self._session_reused:
                raise AlertInternalError("Session not reused")
            if self._ech_status == ECHStatus.REJECTED:
                raise AlertIllegalParameter(
                    "Early data accepted on rejected ECH"
                )
            if self._early_session is None:
                raise AlertInternalError("Missing early_session")
            if self._early_session.cipher_suite != new_session.cipher_suite:
                raise AlertIllegalParameter("Cipher suite mismatch")
            if self._early_session.early_alpn != self._alpn_selected:
                raise AlertIllegalParameter("ALPN mismatch")

            new_session.has_alps = self._early_session.has_alps
            new_session.local_alps = self._early_session.local_alps
            new_session.peer_alps = self._early_session.peer_alps

        elif self._early_data_offered:
            self.update_traffic_cb(Direction.ENCRYPT, Epoch.HANDSHAKE)

        new_session.early_alpn = self._alpn_selected

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

        cert_request = message.get_handshake(CertificateRequestTLS13)

        # RFC 8446 Section 4.3.2
        # certificate_request_context field SHALL be zero length unless used
        # for the post-handshake authentication exchanges described in Section
        # 4.6.2
        if cert_request.context:
            raise AlertIllegalParameter("Invalid certificate request context")

        self._peer_cert_request = cert_request

        self.do_message_cb("read", cert_request)
        self._next_message()

        self._set_state(ClientState.READ_SERVER_CERTIFICATE_TLS13)
        return Status.OK

    def _do_read_server_certificate_tls13(self) -> Status:
        message = self._get_message()
        if message is None:
            return Status.READ_MESSAGE

        if self._new_session is None:
            raise AlertInternalError("Missing new_session")

        certificate = self._process_certificate_tls13(
            message=message,
            session=self._new_session,
            supported_compressions=self._conf_cert_comp_algs,
            allow_anon=False,
        )
        if self.context.verify_mode != TLSVerifyMode.CERT_NONE:
            if not self.context.check_hostname:
                hostname = None
            elif (
                self._selected_ech_config is not None
                and self._ech_status == ECHStatus.REJECTED
            ):
                hostname = self._selected_ech_config.public_name
            else:
                hostname = self._hostname

            self._verify_x509(self.context, self._new_session, hostname)

        self.do_message_cb("read", certificate)
        self._next_message()

        self._set_state(ClientState.READ_SERVER_CERTIFICATE_VERIFY_TLS13)
        return Status.OK

    def _do_read_server_certificate_verify_tls13(self) -> Status:
        message = self._get_message()
        if message is None:
            return Status.READ_MESSAGE

        cert_verify = message.get_handshake(CertificateVerifyTLS12)

        if self._new_session is None:
            raise AlertInternalError("Missing new_session")

        self._process_certificate_verify(
            session=self._new_session,
            cert_verify=cert_verify,
            supported_sigalgs=self._conf_signature_algorithms,
        )

        self.do_message_cb("read", cert_verify)
        self._next_message()

        self._set_state(ClientState.READ_SERVER_FINISHED_TLS13)
        return Status.OK

    def _do_read_server_finished_tls13(self) -> Status:
        message = self._get_message()
        if message is None:
            return Status.READ_MESSAGE

        finished = message.get_handshake(Finished)

        if self.has_unprocessed_hs_data():
            raise AlertUnexpectedMessage("Trailing handshake data")
        if self._key_schedule is None:
            raise AlertInternalError("key_schedule not set")
        if self._new_session is None:
            raise AlertInternalError("Missing new_session")

        verify_data = finished.verify_data
        expected_verify_data = self._key_schedule.finished_verify_data(
            self._dec_secret[Epoch.HANDSHAKE], self._transcript
        )
        if not compare_digest(verify_data, expected_verify_data):
            raise AlertDecryptError("Server finished verify data mismatch")

        self.do_message_cb("read", finished)
        self._next_message()

        # prepare traffic keys
        if not self._key_schedule.generation == 2:
            raise AlertInternalError()

        self._key_schedule.extract(None)

        self._setup_traffic_key_tls13(
            session=self._new_session,
            direction=Direction.DECRYPT,
            epoch=Epoch.APPLICATION_DATA,
            label=b"s ap traffic",
        )
        self._setup_traffic_key_tls13(
            session=self._new_session,
            direction=Direction.ENCRYPT,
            epoch=Epoch.APPLICATION_DATA,
            label=b"c ap traffic",
        )

        self._set_state(ClientState.SEND_END_OF_EARLY_DATA_TLS13)
        return Status.OK

    def _do_send_end_of_early_data_tls13(self) -> Status:
        if not self._early_data_accepted:
            self._set_state(ClientState.SEND_CLIENT_ENCRYPTED_EXTENSIONS_TLS13)
            return Status.OK

        end_of_early_data = EndOfEarlyData()
        self.do_message_cb("write", end_of_early_data)
        self._add_message(end_of_early_data)

        self._close_early_data()

        self._set_state(ClientState.SEND_CLIENT_ENCRYPTED_EXTENSIONS_TLS13)
        return Status.PACK_FLIGHT

    def _do_send_client_encrypted_extensions_tls13(self) -> Status:
        if self._early_data_accepted:
            self.update_traffic_cb(Direction.ENCRYPT, Epoch.HANDSHAKE)

        if self._new_session is None:
            raise AlertInternalError("Missing new_session")

        extensions: list[TLSExtension] = []

        if self._new_session.has_alps and not self._early_data_accepted:
            alps = ServerALPSExtension(self._new_session.local_alps)
            extensions.append(alps)

        if extensions:
            raw_extensions = self._serialize_extensions(extensions)
            enc_ext = EncryptedExtensions(raw_extensions)
            self.do_message_cb("write", enc_ext)
            self._add_message(enc_ext)

        self._set_state(ClientState.SEND_CLIENT_CERTIFICATE_TLS13)
        return Status.OK

    def _do_send_client_certificate_tls13(self) -> Status:
        if self._peer_cert_request is not None:
            peer_cert_request = typing.cast(
                CertificateRequestTLS13, self._peer_cert_request
            )
            self._send_certificate_tlsv13(peer_cert_request)

        self._set_state(ClientState.SEND_CLIENT_FINISHED_TLS13)
        return Status.OK

    def _do_send_client_finished_tls13(self) -> Status:
        if self._key_schedule is None:
            raise AlertInternalError("key_schedule not set")

        verify_data = self._key_schedule.finished_verify_data(
            self._enc_secret[Epoch.HANDSHAKE], self._transcript
        )
        finished = Finished(verify_data)
        self.do_message_cb("write", finished)
        self._add_message(finished)

        self._set_state(ClientState.COMPLETE_SECOND_FLIGHT_TLS13)
        return Status.FLUSH_MESSAGE

    def _do_complete_second_flight_tls13(self) -> Status:
        self.update_traffic_cb(Direction.DECRYPT, Epoch.APPLICATION_DATA)
        self.update_traffic_cb(Direction.ENCRYPT, Epoch.APPLICATION_DATA)

        self._set_state(ClientState.FINISH_CLIENT_HANDSHAKE)
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
        self._update_traffic_key_tls13(Direction.ENCRYPT)
        self._set_state(ClientState.DONE)
        return Status.OK

    def _post_handshake(self, message: Handshake) -> Status:
        raise AlertUnexpectedMessage()

    def _post_handshake_tls13(self, message: Handshake) -> Status:
        if self._established_session is None:
            raise AlertInternalError("session not establish")
        if self._key_schedule is None:
            raise AlertInternalError("key_schedule not set")

        established_session = self._established_session
        key_schedule = self._key_schedule

        if message.handshake_type == HandshakeType.NEWSESSION_TICKET:
            new_session_ticket = message.get_handshake(NewSessionTicketTLS13)
            if self.session_ticket_handler is not None:
                early_data_ext = new_session_ticket.get_extension(
                    EarlyDataExtension
                )
                if early_data_ext is not None:
                    max_early_data = early_data_ext.data
                else:
                    max_early_data = 0

                session = established_session.copy(include_noauth=True)
                session.rebase_time()
                session.set_timeout(new_session_ticket.ticket_lifetime)
                session.ticket = new_session_ticket.ticket
                session.ticket_age_add = new_session_ticket.ticket_age_add
                session.ticket_max_early_data = max_early_data

                # Resumption master secret
                if not key_schedule.generation == 3:
                    raise AlertInternalError()

                master_secret = key_schedule.derive_secret(
                    b"res master", self._transcript
                )
                # Resumption secret
                session.secret = key_schedule.resumption_secret(
                    master_secret, new_session_ticket.ticket_nonce
                )
                session.not_resumable = False
                self.session_ticket_handler(session)

            self.do_message_cb("read", new_session_ticket)
            self._next_message(update_hash=False)

            return Status.OK

        if message.handshake_type == HandshakeType.CERTIFICATE_REQUEST:
            if not self._conf_post_handshake_auth:
                raise AlertUnexpectedMessage("Unexpected certificate request")

            cert_request = message.get_handshake(CertificateRequestTLS13)
            self.do_message_cb("read", cert_request)
            self._next_message()

            self._send_certificate_tlsv13(cert_request)
            cl_finished_key = key_schedule.finished_verify_data(
                self._enc_secret[Epoch.APPLICATION_DATA], self._transcript
            )
            finished = Finished(cl_finished_key)
            self.do_message_cb("write", finished)
            self._add_message(finished)

            return Status.PACK_FLIGHT

        if message.handshake_type == HandshakeType.KEY_UPDATE:
            key_update = message.get_handshake(KeyUpdate)

            if self.has_unprocessed_hs_data():
                raise AlertUnexpectedMessage("Trailing handshake data")

            message_type = key_update.message_type
            if message_type not in (
                KeyUpdateMessageType.UPDATE_NOT_REQUESTED,
                KeyUpdateMessageType.UPDATE_REQUESTED,
            ):
                raise AlertIllegalParameter("Invalid key update message type")

            self.do_message_cb("read", key_update)
            self._next_message(update_hash=False)

            self._update_traffic_key_tls13(Direction.DECRYPT)

            if message_type == KeyUpdateMessageType.UPDATE_REQUESTED:
                self._write_key_update(
                    KeyUpdateMessageType.UPDATE_NOT_REQUESTED
                )

                self._set_state(ClientState.COMPLETE_UPDATE_TRAFFIC)
                return Status.PACK_FLIGHT

            return Status.OK

        raise AlertUnexpectedMessage()

    def _build_client_hello(
        self, client_hello: ClientHello, is_hrr: bool = False
    ) -> None:
        assert not client_hello.extensions

        client_hello.extensions = self._construct_extensions(
            hello_type=ClientHelloType.UNENCRYPTED,
            header_len=len(client_hello.serialize()),
            is_hrr=is_hrr,
        )
        if self._pre_shared_keys:
            transcript = self._transcript.copy()
            self._update_binders(
                self._pre_shared_keys, transcript, client_hello
            )

    def _build_ech(self, hello_outer: ClientHello) -> bool:
        if self._selected_ech_config is None:
            if self._conf_grease_ech:
                self._ech_client_outer = ClientECHExtension(
                    ech_client_hello_type=ECHClientHelloType.OUTER,
                    hpke_kdf_id=HpkeKdfId.HKDF_SHA256,
                    hpke_aead_id=HpkeAeadId.AES_128_GCM,
                    config_id=bytes_to_int(get_random_bytes(1)),
                    enc=get_random_bytes(32),
                    payload=get_random_bytes(get_random_int(180, 205)),
                )
            return False

        result = self._encrypt_client_hello(hello_outer, is_hrr=False)
        if not result:
            self._selected_ech_config = None
            self._inner_transcript = None
            self._inner_client_random = None
            return False

        return True

    def _encrypt_client_hello(
        self, hello_outer: ClientHello, is_hrr: bool
    ) -> bool:
        assert not hello_outer.extensions
        assert self._selected_ech_config is not None
        assert self._inner_transcript is not None
        assert self._inner_client_random is not None

        content = self._selected_ech_config
        inner_transcript = self._inner_transcript
        inner_client_random = self._inner_client_random

        # Add Extension
        compressed: list[tuple[int, bytes]] = []
        extensions: list[tuple[int, bytes]] = []
        extensions_encoded: list[tuple[int, bytes]] = []
        psk_ext: tuple[int, bytes] | None = None

        inner_extensions = self._construct_extensions(
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
            compression_methods=self._conf_compresion_methods,
            extensions=extensions,
        )
        encoded_hello_inner = ClientHello(
            version=self._client_version,
            random=inner_client_random,
            session_id=b"",
            cipher_suites=self._get_cipher_suites(),
            compression_methods=self._conf_compresion_methods,
            extensions=extensions_encoded,
        )

        if self._pre_shared_keys:
            self._update_binders(
                self._pre_shared_keys,
                inner_transcript.copy(),
                hello_inner,
                encoded_hello_inner,
            )

        self.do_message_cb("write", hello_inner)
        self._update_hash(hello_inner, inner_transcript)

        # draft-ietf-tls-esni-13, section 6.1.3.
        # Pad the EncodedClientHelloInner
        padding_len = 0
        maximum_name_length = content.maximum_name_length
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

        hpke_context = typing.cast(SenderContext, content.hpke_context)
        aead_overhead = hpke_context.aead_overhead
        payload_len = len(encoded_hello_inner_data) + aead_overhead
        if not is_hrr:
            self._ech_client_outer = ClientECHExtension(
                ECHClientHelloType.OUTER,
                content.kdf_id,
                content.aead_id,
                content.config_id,
                content.enc,
                bytes(payload_len),
            )
        else:
            self._ech_client_outer = ClientECHExtension(
                ECHClientHelloType.OUTER,
                content.kdf_id,
                content.aead_id,
                content.config_id,
                b"",
                bytes(payload_len),
            )

        extensions_outer = self._construct_extensions(
            hello_type=ClientHelloType.OUTER,
            header_len=len(hello_outer.serialize()),
            is_hrr=is_hrr,
        )
        hello_outer.extensions = extensions_outer

        aad = hello_outer.serialize()
        payload = hpke_context.seal(encoded_hello_inner_data, aad)

        if len(payload) != payload_len:
            self._ech_client_outer = None
            self._inner_extensions_sent = None
            return False

        ext_type = ExtensionType.ENCRYPTED_CLIENT_HELLO
        idx, ext_data = hello_outer.find_extension(ext_type)
        if ext_data is None:
            raise AlertInternalError()

        self._ech_client_outer.payload = payload
        # new_ext_data = self._ech_client_outer.serialize()
        new_ext_data = ext_data[: -len(payload)] + payload
        hello_outer.extensions[idx] = (ext_type, new_ext_data)
        return True

    def _construct_extensions(
        self,
        hello_type: ClientHelloType,
        header_len: int,
        is_hrr: bool,
    ) -> list[tuple[int, bytes]]:
        extensions = self._get_extensions(hello_type, is_hrr)
        if extensions:
            last_was_empty = len(extensions[-1].serialize()) == 0
        else:
            last_was_empty = True

        psk_ext: ClientPSKExtension | None = None

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

            psk_ext = ClientPSKExtension(identities, binders)

        raw_extensions = self._serialize_extensions(extensions)

        if (
            self._conf_client_hello_padding
            and hello_type != ClientHelloType.INNER
        ):
            header_len += 4 + 2
            padding_len = 0
            psk_ext_len = 0

            header_len += sum(len(e) for _, e in raw_extensions)

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
                padding_ext = ClientHelloPaddingExtension(padding_len)
                raw_extensions.append(
                    (padding_ext.extension_type, padding_ext.serialize())
                )

        if psk_ext is not None:
            raw_extensions.append(
                (psk_ext.extension_type, psk_ext.serialize())
            )

        extension_sent = set((t for t, _ in raw_extensions))
        if hello_type == ClientHelloType.INNER:
            self._inner_extensions_sent = extension_sent
        else:
            self._extensions_sent = extension_sent

        return raw_extensions

    def _get_extensions(
        self,
        hello_type: ClientHelloType = ClientHelloType.UNENCRYPTED,
        is_hrr: bool = False,
    ) -> list[TLSExtension]:
        extensions: list[TLSExtension] = []

        # Server Name Indicator Extension
        if hello_type == ClientHelloType.OUTER:
            assert self._selected_ech_config is not None
            hostname = self._selected_ech_config.public_name
            extensions.append(ClientSNIExtension(hostname))
        elif self._hostname is not None:
            extensions.append(ClientSNIExtension(self._hostname))

        # Status Request
        if self._conf_status_request:
            status_request_ext = ClientStatusRequestExtension()
            extensions.append(status_request_ext)

        # Signed Certificate Timstamp
        if self._conf_signed_cert_timestamp:
            extensions.append(ClientSCTExtension())

        # ALPN
        if self._conf_alpn_protocols is not None:
            extensions.append(ClientALPNExtension(self._conf_alpn_protocols))

        # Signature Algorithms
        if self._conf_signature_algorithms is not None:
            extensions.append(
                SignatureAlgorithmsExtension(self._conf_signature_algorithms)
            )

        # Supported Groups
        if self._conf_supported_groups is not None:
            supported_groups = []
            if self._conf_grease:
                supported_groups.append(self._get_grease(3))
            supported_groups.extend(self._conf_supported_groups)
            extensions.append(ClientSupportedGroupsExtension(supported_groups))

        if not (
            self._minimum_version >= TLSVersion.TLSv1_3
            or hello_type == ClientHelloType.INNER
        ):
            # Renegotiation info
            if (
                CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV
                not in self._conf_cipher_suites
            ):
                extensions.append(RenegotiationInfoExtension(b""))

            # NPN protocols
            if self._conf_npn_protocols is not None:
                extensions.append(ClientNPNExtension())

            # Encrypt Then Mac
            if self._conf_encrypt_then_mac:
                extensions.append(EncryptThenMacExtension())

            # Extended Master Secret
            if self._conf_extended_master_secret:
                extensions.append(ExtendedMasterSecretExtension())

            # EC point format
            if self._conf_ec_point_formats is not None:
                extensions.append(
                    ECPointFormatsExtension(self._conf_ec_point_formats)
                )

            # Session
            if self._session_ticket is not None:
                ticket = self._session_ticket
                extensions.append(SessionTicketExtension(ticket))

        if self._maximum_version >= TLSVersion.TLSv1_3:
            # Supported versions
            minimum_version = self._minimum_version
            if hello_type == ClientHelloType.INNER:
                minimum_version = TLSVersion.TLSv1_3
            supported_versions = list(
                range(self._maximum_version, minimum_version - 1, -1)
            )
            if self._conf_grease:
                supported_versions.insert(0, self._get_grease(2))
            extensions.append(
                ClientSupportedVersionsExtension(supported_versions)
            )

            # Supported PSK Key Exchange mode
            if self._conf_psk_kex_modes is not None:
                extensions.append(
                    PSKKeyExchangeModesExtension(self._conf_psk_kex_modes)
                )

            # ALPS
            if self._conf_alps:
                alps_protocol = list(self._conf_alps)
                extensions.append(ClientALPSExtension(alps_protocol))

            # Post Handshake Authentication
            if self._conf_post_handshake_auth:
                extensions.append(ClientPHAExtension())

            # Certificate compression algorithm
            if self._conf_cert_comp_algs is not None:
                extensions.append(
                    CompressedCertificateExtension(self._conf_cert_comp_algs)
                )

            if hello_type == ClientHelloType.INNER:
                # When offering the encrypted_client_hello extension in
                # ClientHelloOuter,　the client MUST also offer an empty
                # encrypted_client_hello extension in the ClientHelloInner
                extensions.append(ClientECHExtension(ECHClientHelloType.INNER))
            elif self._ech_client_outer is not None:
                extensions.append(self._ech_client_outer)

            # Supported Key Share Exchange mode
            # RFC 8446, section 4.2.8
            # Put the groups used for key shares first, and in order
            # can be empty
            keyshare_entries: list[KeyShareEntry] = []
            for key_share_group, kex in self._key_exchanges.items():
                keyshare = kex.generate_key_share()
                keyshare_entry = KeyShareEntry(key_share_group, keyshare)
                keyshare_entries.append(keyshare_entry)

            if self._conf_grease and not is_hrr:
                keyshare_entries.insert(
                    0, KeyShareEntry(self._get_grease(3), b"\x00")
                )
            extensions.append(ClientKeyShareExtension(keyshare_entries))

            if self._cookie is not None:
                extensions.append(CookieExtension(self._cookie))

            # Early Data
            if self._early_data_offered and not is_hrr:
                extensions.append(ClientEarlyDataExtension())

        # Reorder extensions
        if self._extension_order is None:
            self._extension_order = [ext.extension_type for ext in extensions]
            if self.context.extensions_order_cb is not None:
                self._extension_order = self.context.extensions_order_cb(
                    self._extension_order
                )

        order_index = {
            ext_type: i for i, ext_type in enumerate(self._extension_order)
        }
        extensions.sort(
            key=lambda ext: order_index.get(ext.extension_type, float("inf"))
        )

        # Insert GREASE
        if extensions and self._conf_grease:
            extensions.insert(0, GenericExtension(self._get_grease(1), b""))
            extensions.append(GenericExtension(self._get_grease(4), b"\x00"))

        return extensions

    def _get_grease(self, index: int) -> int:
        return self._greases[index]

    def _get_cipher_suites(self) -> list[int]:
        cipher_suites = []
        if self._conf_grease:
            cipher_suites.append(self._get_grease(0))
        cipher_suites.extend(c.id for c in self._conf_cipher_suites)
        return cipher_suites

    def _check_ech_confirmation(
        self,
        server_hello: ServerHello,
        transcript: Transcript,
        is_hrr: bool,
    ) -> bool:
        if self._key_schedule is None:
            raise AlertInternalError("Missing key_schedule")
        if self._inner_client_random is None:
            raise AlertInternalError("Missing inner_client_random")

        if is_hrr:
            ext_type = ExtensionType.ENCRYPTED_CLIENT_HELLO
            i, ext_data = server_hello.find_extension(ext_type)
            if ext_data is None:
                return False
            if len(ext_data) != 8:
                raise AlertIllegalParameter("")

            label = b"hrr ech accept confirmation"

            ori = expected = ext_data
            server_hello.extensions[i] = (ext_type, bytes(8))
            self._update_hash(server_hello, transcript)
            server_hello.extensions[i] = (ext_type, ori)
        else:
            label = b"ech accept confirmation"

            ori = server_hello.random
            expected = server_hello.random[-8:]
            server_hello.random = server_hello.random[:-8] + bytes(8)
            self._update_hash(server_hello, transcript)
            server_hello.random = ori

        accept_confirmation = self._key_schedule.ech_accept_confirmation(
            self._inner_client_random, label, transcript
        )
        if compare_digest(accept_confirmation, expected):
            return True

        return False

    def _process_extensions(self, ext_map: dict[int, TLSExtension]) -> None:
        version = self.protocol_version()
        cipher_suite = self.cipher()

        # Renegotiation info extension
        ri_ext = typing.cast(
            RenegotiationInfoExtension | None,
            ext_map.pop(ExtensionType.RENEGOTIATION_INFO, None),
        )
        if ri_ext is not None:
            if version >= TLSVersion.TLSv1_3:
                raise AlertUnsupportedExtension(
                    "Unexpected renegotiation info extension"
                )

            self._secure_renegotiation = True

        elif (
            version <= TLSVersion.TLSv1_2
            and not self.context.legacy_server_connect
        ):
            raise AlertInsufficientSecurity(
                "Peer doesn't support secure renegotiation"
            )

        # Check all extension received was sent by client hello
        if not self._extensions_sent.issuperset(ext_map):
            raise AlertUnsupportedExtension("Unexpected extensions")

        forbid_extensions = set(
            (
                ExtensionType.SIGNATURE_ALGORITHMS,
                ExtensionType.KEY_SHARE,
                ExtensionType.PSK_KEY_EXCHANGE_MODES,
                ExtensionType.SUPPORTED_VERSIONS,
                ExtensionType.COOKIE,
            )
        )

        # SNI extension
        pass

        # ALPN extension
        alpn_ext = typing.cast(
            ServerALPNExtension | None, ext_map.get(ExtensionType.ALPN)
        )
        if alpn_ext is not None:
            if self._conf_alpn_protocols is None:
                raise AlertInternalError("Missing alpn protocols")
            if alpn_ext.protocol not in self._conf_alpn_protocols:
                raise AlertIllegalParameter(
                    "Unexpected protocol in ALPN extension"
                )

            self._alpn_selected = alpn_ext.protocol

        if version >= TLSVersion.TLSv1_3:
            if self._new_session is None:
                raise AlertInternalError("Missing new_session")

            forbid_extensions.add(ExtensionType.EXTENDED_MAIN_SECRET)
            forbid_extensions.add(ExtensionType.SUPPORTS_NPN)
            forbid_extensions.add(ExtensionType.SESSION_TICKET)
            forbid_extensions.add(ExtensionType.ENCRYPT_THEN_MAC)
            forbid_extensions.add(ExtensionType.EC_POINT_FORMATS)

            # Status request is sent in certificate extension
            forbid_extensions.add(ExtensionType.STATUS_REQUEST)

            # application settings extension
            apls_ext = typing.cast(
                ServerALPSExtension | None,
                ext_map.get(ExtensionType.APPLICATION_SETTINGS),
            )
            if apls_ext is not None:
                if self._alpn_selected is None:
                    raise AlertIllegalParameter("Unexected ALPS extension")

                try:
                    settings = self._conf_alps[self._alpn_selected]
                except KeyError:
                    raise AlertIllegalParameter(
                        f"Invalid ALPS extension with ALPN "
                        f"'{self._alpn_selected!r}'"
                    ) from None

                self._new_session.has_alps = True
                self._new_session.local_alps = settings
                self._new_session.peer_alps = apls_ext.settings

            # Encrypted client hello extension
            ech_ext = typing.cast(
                ServerECHExtensions | None,
                ext_map.get(ExtensionType.ENCRYPTED_CLIENT_HELLO),
            )
            if ech_ext is not None:
                self._ech_retry_configs = list(ech_ext.retry_configs)

            # Early data extension
            early_data_ext = typing.cast(
                ServerEarlyDataExtension | None,
                ext_map.get(ExtensionType.EARLY_DATA),
            )
            if early_data_ext is not None:
                if not self._early_data_offered:
                    raise AlertInternalError()
                if self._hello_retry_request_used:
                    AlertIllegalParameter(
                        "Unexpected early data extension after hello retry "
                        "requested"
                    )

                self._early_data_accepted = True

        else:
            forbid_extensions.add(ExtensionType.APPLICATION_SETTINGS)
            forbid_extensions.add(ExtensionType.ENCRYPTED_CLIENT_HELLO)
            forbid_extensions.add(ExtensionType.EARLY_DATA)

            # Extended master secret extension
            ems_ext = typing.cast(
                ExtendedMasterSecretExtension | None,
                ext_map.get(ExtensionType.EXTENDED_MAIN_SECRET),
            )
            if ems_ext is not None:
                self._extended_master_secret = True

            elif (
                self._conf_extended_master_secret
                and self.context.required_extended_master_secret
            ):
                raise AlertInsufficientSecurity(
                    "Peer doesn't support extended master secret"
                )

            # NPN extension
            npn_ext = typing.cast(
                ServerNPNExtension | None,
                ext_map.get(ExtensionType.SUPPORTS_NPN),
            )
            if npn_ext is not None:
                if self._conf_npn_protocols is None:
                    raise AlertInternalError()

                npn_selected = negotiate(
                    self._conf_npn_protocols, npn_ext.protocols
                )
                if npn_selected is None:
                    npn_selected = npn_ext.protocols[0]

                self._npn_selected = npn_selected

            # Session ticket extension
            session_ticket_ext = typing.cast(
                TLSSession | None, ext_map.get(ExtensionType.SESSION_TICKET)
            )
            if session_ticket_ext is not None:
                self._ticket_expected = True

            # Encrypt-then-mac extension
            etm_ext = typing.cast(
                EncryptThenMacExtension | None,
                ext_map.get(ExtensionType.ENCRYPT_THEN_MAC),
            )
            if etm_ext is not None:
                if cipher_suite.symmetric not in (
                    Symmetric.AES_128_CBC,
                    Symmetric.AES_256_CBC,
                    Symmetric.TRIPLE_DES_EDE_CBC,
                ):
                    # This cipher suite doesnt support encrypt-then-mac
                    raise AlertIllegalParameter(
                        "Unexpected encrypt-then-mac extension"
                    )

                self._encrypt_then_mac = True

            # EC point formats extension
            ecpfs_ext = typing.cast(
                ECPointFormatsExtension | None,
                ext_map.get(ExtensionType.EC_POINT_FORMATS),
            )
            if ecpfs_ext is not None:
                if self._conf_ec_point_formats is None:
                    raise AlertInternalError()

                _ = negotiate(
                    self._conf_ec_point_formats,
                    ecpfs_ext.data,
                    AlertIllegalParameter("Unexpected ec point format"),
                )

        if forbid_extensions.intersection(ext_map):
            raise AlertUnsupportedExtension("Unexpected extensions")

    def _send_certificate_tlsv13(
        self, cert_request: CertificateRequestTLS13
    ) -> None:
        comp_cert_ext = cert_request.get_extension(
            CompressedCertificateExtension
        )
        if comp_cert_ext and self._conf_cert_comp_algs is not None:
            comp_alg = negotiate(self._conf_cert_comp_algs, comp_cert_ext.data)
        else:
            comp_alg = None

        signature_algorithms = cert_request.signature_algorithms
        if not signature_algorithms:
            raise AlertMissingExtension(
                "Missing signature algorithms extension in certificate request"
            )

        private_key = self.context.private_key
        x509_certs = self.context.x509_certs

        signature_algorithm = None

        # draft-ietf-tls-esni 25 Section 6.1.7
        # If the server requests a client certificate, the client MUST
        # respond with an empty Certificate message, denoting no client
        # certificate.
        if self._ech_status == ECHStatus.REJECTED:
            pass

        elif private_key is not None and x509_certs is not None:
            if self._conf_signature_algorithms is None:
                raise AlertInternalError("Missing signature algorithms")

            x509_leaf = x509_certs[0]
            try:
                public_key = x509_leaf.public_key()
            except ValueError as exc:
                raise AlertInternalError(
                    "Unsupported public key format"
                ) from exc

            _, supported_sigalgs = self._sigalgs_for_pubkey(
                version=self.protocol_version(),
                public_key=public_key,
                public_key_oid=x509_leaf.public_key_algorithm_oid,
                supported_sigalgs=self._conf_signature_algorithms,
            )
            signature_algorithm = negotiate(
                supported_sigalgs, signature_algorithms
            )

        if signature_algorithm is not None:
            x509_certs = typing.cast(
                typing.Sequence[x509.Certificate], x509_certs
            )
        else:
            x509_certs = typing.cast(typing.Sequence[x509.Certificate], ())

        certificate = self._create_certificate_tls13(
            x509_certs, cert_request.context, comp_alg
        )

        self.do_message_cb("write", certificate)
        self._add_message(certificate)

        if signature_algorithm is None:
            return

        if self._key_schedule is None:
            raise AlertInternalError("key_schedule not set")

        private_key = typing.cast(
            CertificateIssuerPrivateKeyTypes, private_key
        )
        data = self._key_schedule.certificate_verify_data(
            CLIENT_CONTEXT_STRING, self._transcript
        )
        signature = create_signature(private_key, data, signature_algorithm)

        c_verify = CertificateVerifyTLS12(signature, signature_algorithm)
        self.do_message_cb("write", c_verify)
        self._add_message(c_verify)

    def _should_offer_early_data(self) -> bool:
        if not self.context.early_data:
            return False

        if self._maximum_version < TLSVersion.TLSv1_3:
            return False

        if self._session is None:
            return False

        if self._session.protocol_version() < TLSVersion.TLSv1_3:
            return False

        if self._session.ticket_max_early_data == 0:
            return False

        if self._session.early_alpn and self._conf_alpn_protocols is not None:
            if self._session.early_alpn not in self._conf_alpn_protocols:
                return False

        if len(self._pre_shared_keys) != 1:
            return False

        return True

    @staticmethod
    def _select_ech_config(ech_configs: bytes) -> ECHConfigContent | None:
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
                    suite = create_suite(kem_id, kdf_id, aead_id)
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

                return ECHConfigContent(
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

    @staticmethod
    def _update_binders(
        pre_shared_keys: list[tuple[KeySchedule, PSKIdentity, bytes]],
        transcript: Transcript,
        client_hello: ClientHello,
        encoded_client_hello: ClientHello | None = None,
    ) -> None:
        assert client_hello.extensions

        psk_ext_type, psk_ext_data = client_hello.extensions[-1]
        assert psk_ext_type == ExtensionType.PRE_SHARED_KEY

        handshake = Handshake(
            client_hello.handshake_type, client_hello.serialize()
        )
        handshake_data = handshake.serialize()

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

        psk_ext = ClientPSKExtension(identities, binders)
        psk_ext_data = psk_ext.serialize()
        psk_raw_ext = (psk_ext.extension_type, psk_ext_data)

        client_hello.extensions[-1] = psk_raw_ext
        if encoded_client_hello is not None:
            encoded_client_hello.extensions.append(psk_raw_ext)
