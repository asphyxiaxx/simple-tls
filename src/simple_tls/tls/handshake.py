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

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any, ClassVar, Optional, TypeVar, cast

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import ExtendedKeyUsageOID, PublicKeyAlgorithmOID

from simple_tls.codec import ParseError, Parser
from simple_tls.compression import UnsupportedCompression
from simple_tls.crypto.utils import bytes_to_int, int_to_bytes
from simple_tls.crypto.verification import (
    CertificateExpired,
    CertificateNotYetValid,
    ExtensionPolicy,
    UntrustedRoot,
    VerificationError,
    Verifier,
)

from .alerts import (
    AlertBadCertificate,
    AlertCertificateExpired,
    AlertCertificateRequired,
    AlertDecodeError,
    AlertDecryptError,
    AlertHandshakeFailure,
    AlertIllegalParameter,
    AlertInternalError,
    AlertUnexpectedMessage,
    AlertUnknownCA,
)
from .cipher import get_key_iv_lens
from .configuration import TLSConfiguration, TLSCredential
from .constants import (
    CERTIFICATE_COMPRESSIONS,
    DSA_SIGNATURE_ALGORITHMS,
    ECC_GROUPS,
    ECDSA_SIGNATURE_ALGORITHMS,
    FFDHE_GROUPS,
    KEM_GROUPS,
    RSA_PKCS1_SIGNATURE_ALGORITHMS,
    RSA_PSS_PSS_SIGNATURE_ALGORITHMS,
    RSA_PSS_RSAE_SIGNATURE_ALGORITHMS,
    SIGNATURE_ALGORITHMS,
    SUPPORTED_GROUPS,
    TLS13_CLIENT_CONTEXT_STRING,
    TLS13_SERVER_CONTEXT_STRING,
    UNSPECIFIED,
    Authentication,
    CipherSuite,
    ClientCertificateType,
    ECPointFormat,
    HandshakeType,
    KeyUpdateMessageType,
    NamedGroup,
    PSKKeyExchangeMode,
    SignatureScheme,
    TLSVersion,
)
from .enums import Direction, ECHStatus, Epoch, Protocol, Status, VerifyMode
from .extensions import Extensions, StatusRequestCertificateExtension
from .key import (
    BasePublicKey,
    DSAPublicKey,
    ECPublicKey,
    Ed448PublicKey,
    Ed25519PublicKey,
    InvalidSignature,
    RSAPublicKey,
    load_certificate_public_key,
)
from .keyexchange import (
    BaseKeyExchange,
    ECDHKeyExchange,
    FFDHKeyExchange,
    KEMKeyExchange,
    get_dh_parameters,
)
from .messages import (
    Certificate,
    CertificateEntry,
    CertificateTLS13,
    CertificateVerify,
    CertificateVerifyTLS12,
    CompressedCertificate,
    HandshakeMessage,
    KeyUpdate,
)
from .session import TLSSession
from .utils import (
    Buffer,
    EKUValidator,
    KeySchedule,
    SANValidator,
    Transcript,
    filter,
    get_algorithm,
    prf,
    version_from_wire,
)

_M = TypeVar("_M", bound="HandshakeMessage")

MessageCallback = Callable[[Direction, HandshakeMessage], None]
SetupTrafficCallback = Callable[
    [Direction, Epoch, Optional["TrafficContext"]], None
]


@dataclass(frozen=True, slots=True)
class TrafficContext:
    version: int
    cipher_suite: CipherSuite
    client_random: bytes
    server_random: bytes
    secret: bytes

    # --- Used for TLS 1.2 and below ---
    enc_key: bytes | None = None
    mac_key: bytes | None = None
    fixed_iv: bytes | None = None
    encrypt_then_mac: bool = False


@dataclass
class Handshake:
    handshake_type: int
    data: bytes

    _cache: Any = field(default=None, init=False)

    def tobytes(self) -> bytes:
        return (
            bytes([self.handshake_type])
            + int_to_bytes(len(self.data), 3)
            + self.data
        )

    def parse_as(self, message_cls: type[_M]) -> _M:
        if message_cls.handshake_type != self.handshake_type:
            raise AlertUnexpectedMessage(
                f"received unexpected message '{hex(self.handshake_type)}', "
                f"expected '{hex(message_cls.handshake_type)}'"
            )

        if self._cache is None or type(self._cache) is not message_cls:
            self._cache = message_cls.from_bytes(self.data)

        return cast(_M, self._cache)


class TLSHandshake:
    is_server: ClassVar[bool]

    def __init__(self, configuration: TLSConfiguration) -> None:
        # Callbacks
        self.message_cb: MessageCallback = lambda rw, m: None
        self.setup_traffic_cb: SetupTrafficCallback = lambda d, e, c: None

        # Configurations
        self._configuration: TLSConfiguration = configuration
        self._protocol: Protocol = configuration.protocol

        # Protocol versions
        self._minimum_version: int = version_from_wire(
            self._protocol, configuration.minimum_version
        )
        self._maximum_version: int = version_from_wire(
            self._protocol, configuration.maximum_version
        )
        if self._minimum_version > self._maximum_version:
            raise ValueError(
                "minimum_version cannot be larger then maximum_version"
            )

        # Identity
        self._credential: TLSCredential | None = configuration.credential
        self._verify_mode: VerifyMode = configuration.verify_mode

        # Cipher suites
        self._cipher_suites: tuple[CipherSuite, ...] = tuple(
            cipher_suite
            for cipher_suite in configuration.cipher_suites
            if (
                cipher_suite.minimum_version <= self._maximum_version
                and cipher_suite.maximum_version >= self._minimum_version
            )
        )
        if not self._cipher_suites:
            raise ValueError("None of the cipher_suites are supported")

        # Supported groups
        if configuration.supported_groups is not None:
            supported_groups = filter(
                configuration.supported_groups,
                SUPPORTED_GROUPS,
                ValueError("None of the supported_groups are supported"),
            )
        else:
            supported_groups = SUPPORTED_GROUPS

        self._supported_groups: tuple[int, ...] = supported_groups

        # ECC groups
        self._ecc_groups: tuple[int, ...] = tuple(
            g for g in self._supported_groups if g in ECC_GROUPS
        )

        # Signature algorithms
        if configuration.signature_algorithms is not None:
            signature_algorithms = filter(
                configuration.signature_algorithms,
                SIGNATURE_ALGORITHMS,
                ValueError("None of the signature_algorithms are supported"),
            )
        else:
            signature_algorithms = SIGNATURE_ALGORITHMS

        self._signature_algorithms: tuple[int, ...] = signature_algorithms

        # Signing signature algorithms
        if configuration.signing_signature_algorithms is not None:
            signing_signature_algorithms = filter(
                configuration.signing_signature_algorithms,
                SIGNATURE_ALGORITHMS,
                ValueError(
                    "None of the signing_signature_algorithms are supported"
                ),
            )
        else:
            signing_signature_algorithms = SIGNATURE_ALGORITHMS

        self._signing_signature_algorithms: tuple[int, ...] = (
            signing_signature_algorithms
        )

        # Certificate compressions algorithms
        if configuration.certificate_compressions is not None:
            certificate_compressions = filter(
                configuration.certificate_compressions,
                CERTIFICATE_COMPRESSIONS,
            )
        else:
            certificate_compressions = ()

        self._certificate_compressions: tuple[int, ...] = (
            certificate_compressions
        )

        # EC point formats
        self._ec_point_formats: tuple[int, ...] = (ECPointFormat.UNCOMPRESSED,)

        # PSK key exchange modes
        self._psk_kex_modes: tuple[int, ...] = (PSKKeyExchangeMode.PSK_DHE_KE,)

        # NPN Protocols
        self._npn_protocols: tuple[bytes, ...] = (
            tuple(configuration.npn_protocols)
            if configuration.npn_protocols is not None
            else ()
        )

        # ALPN protocols
        self._alpn_protocols: tuple[bytes, ...] = (
            tuple(configuration.alpn_protocols)
            if configuration.alpn_protocols is not None
            else ()
        )

        # Application Settings
        self._alps: dict[bytes, bytes] = {}
        if configuration.alps is not None:
            for protocol, settings in configuration.alps.items():
                if protocol in self._alpn_protocols:
                    self._alps[protocol] = settings

        # Dispatch function
        self._handle_dispatch: dict[int, Callable[[], Status]] = {}

        # Temporary State
        self._state: int = 0
        self._hostname: bytes | None = None
        self._version: int = UNSPECIFIED
        self._is_early_version: bool = False
        self._client_version: int = UNSPECIFIED
        self._session: TLSSession | None = None
        self._session_establish: bool = False
        self._session_reused: bool = False
        self._session_id: bytes = b""
        self._cipher_suite: CipherSuite | None = None
        self._in_early_data: bool = False
        self._skip_early_data: bool = False
        self._can_early_write: bool = False
        self._can_early_read: bool = False
        self._early_data_offered: bool = False
        self._early_data_accepted: bool = False
        self._hello_retry_request_used: bool = False
        self._extended_master_secret: bool = False
        self._encrypt_then_mac: bool = False
        self._secure_renegotiation: bool = False
        self._npn_protocol: bytes | None = None
        self._alpn_protocol: bytes | None = None
        self._ech_status: ECHStatus = ECHStatus.NONE

        # Buffer
        self._incoming_data: bytearray = bytearray()
        self._outgoing_messages: list[bytes] = []
        self._cache: Handshake | None = None

        # Transcript and secrets
        self._client_random: bytes = b""
        self._server_random: bytes = b""
        self._write_traffic: TrafficContext | None = None
        self._read_traffic: TrafficContext | None = None
        self._enc_secret: dict[Epoch, bytes] = {}
        self._dec_secret: dict[Epoch, bytes] = {}
        self._transcript: Transcript = Transcript()
        self._key_schedule: KeySchedule | None = None

    @property
    def done(self) -> bool:
        raise NotImplementedError

    @property
    def state(self) -> int:
        return self._state

    @property
    def configuration(self) -> TLSConfiguration:
        return self._configuration

    @property
    def session(self) -> TLSSession | None:
        if self._session_establish:
            return self._session
        return None

    @property
    def session_established(self) -> bool:
        return self._session_establish

    @property
    def session_reused(self) -> bool:
        return self._session_reused

    @property
    def hostname(self) -> bytes | None:
        return self._hostname

    @property
    def version(self) -> int:
        return self._version

    @property
    def is_early_version(self) -> bool:
        return self._is_early_version

    @property
    def in_early_data(self) -> bool:
        return self._in_early_data

    @property
    def skip_early_data(self) -> bool:
        """instructs the record layer to discard unexpected early data messages
        when 0-RTT is rejected"""

        return self._skip_early_data

    @property
    def can_early_write(self) -> bool:
        """indicates whether the record layer is currently allowed to send
        early data (0-RTT)"""

        return self._can_early_write

    @property
    def can_early_read(self) -> bool:
        """indicates whether the record layer is currently allowed to process
        incoming early data (0-RTT)"""

        return self._can_early_read

    @property
    def max_early_data(self) -> int:
        if self._in_early_data:
            assert self._session is not None
            return self._session.ticket_max_early_data
        return 0

    @property
    def early_data_accepted(self) -> bool:
        return self._early_data_accepted

    @property
    def early_data_offered(self) -> bool:
        return self._early_data_offered

    @property
    def cipher_suite(self) -> CipherSuite | None:
        return self._cipher_suite

    @property
    def npn_protocol(self) -> bytes | None:
        return self._npn_protocol

    @property
    def alpn_protocol(self) -> bytes | None:
        if self._in_early_data:
            assert self._session is not None
            return self._session.early_alpn
        return self._alpn_protocol

    @property
    def peer_cipher_suites(self) -> tuple[int, ...] | None:
        return None

    @property
    def peer_certificate(self) -> x509.Certificate | None:
        session = self._session
        if session is not None:
            return session.peer_cert
        return None

    @property
    def peer_ech_retry_configs(self) -> bytes | None:
        return None

    @property
    def peer_application_settings(self) -> bytes | None:
        if self._session is not None and self._session.has_alps:
            return self._session.peer_alps
        return None

    @property
    def ech_status(self) -> ECHStatus:
        return self._ech_status

    def get_peer_cert_chain(self) -> list[x509.Certificate]:
        session = self._session
        chain: list[x509.Certificate] = []
        if session is not None:
            if session.peer_cert is not None:
                chain.append(session.peer_cert)
            if session.peer_chain is not None:
                assert session.peer_cert is not None
                chain.extend(session.peer_chain)
        return chain

    def get_verified_chain(self) -> list[x509.Certificate]:
        session = self._session
        chain: list[x509.Certificate] = []
        if session is not None:
            if session.verified_peer_cert is not None:
                chain.append(session.verified_peer_cert)
            if session.verified_peer_chain is not None:
                assert session.verified_peer_cert is not None
                chain.extend(session.verified_peer_chain)
        return chain

    def do_handshake(self) -> Status:
        ret = Status.OK
        while not self.done:
            f = self._handle_dispatch[self.state]
            try:
                ret = f()
            except ParseError as exc:
                raise AlertDecodeError(str(exc)) from exc
            if ret != Status.OK:
                break
        return ret

    def trigger_post_handshake(self) -> None:
        raise NotImplementedError

    def send_key_update(self, message_type: KeyUpdateMessageType) -> None:
        raise NotImplementedError

    def close_early_data(self) -> None:
        self._skip_early_data = False
        self._can_early_read = False
        self._can_early_write = False

    def protocol_version(self) -> int:
        assert self._version != UNSPECIFIED
        return self._version

    def feed_data(self, data: Buffer) -> None:
        self._incoming_data.extend(data)

    def has_unprocessed_data(self) -> bool:
        return len(self._incoming_data) > 0

    def pending_flight(self) -> list[bytes]:
        return self._outgoing_messages

    def clear_flight(self) -> None:
        self._outgoing_messages.clear()

    # Internal

    @staticmethod
    def _pack_handshake(message: HandshakeMessage) -> bytes:
        message_data = message.serialize()
        return (
            bytes([message.handshake_type])
            + int_to_bytes(len(message_data), 3)
            + message_data
        )

    def _get_message(self) -> Handshake | None:
        if self._cache is not None:
            return self._cache

        if len(self._incoming_data) < 4:
            return None

        data_len = 4 + bytes_to_int(self._incoming_data[1:4])
        if len(self._incoming_data) < data_len:
            return None

        self._cache = Handshake(
            handshake_type=self._incoming_data[0],
            data=bytes(self._incoming_data[4:data_len]),
        )
        del self._incoming_data[:data_len]
        return self._cache

    def _add_message(
        self,
        message: HandshakeMessage,
        update_hash: bool = True,
    ) -> None:
        handshake_data = self._pack_handshake(message)
        self._outgoing_messages.append(handshake_data)
        if update_hash:
            self._transcript.update_hash(handshake_data)

    def _next_message(self, update_hash: bool = True) -> None:
        assert self._cache is not None
        if update_hash:
            handshake = self._cache
            self._transcript.update_hash(handshake.tobytes())
        self._cache = None

    def _set_state(self, state: int) -> None:
        # print("TLS {} -> {}".format(self.state, state))
        self._state = state

    def _setup_traffic(self, direction: Direction) -> None:
        if direction == Direction.READ:
            traffic = self._read_traffic
        else:
            traffic = self._write_traffic

        assert traffic is not None

        self.setup_traffic_cb(direction, Epoch.APPLICATION_DATA, traffic)

    def _setup_traffic_tls13(self, direction: Direction, epoch: Epoch) -> None:
        if direction == Direction.READ:
            secret = self._dec_secret.get(epoch, None)
        else:
            secret = self._enc_secret.get(epoch, None)

        if secret is not None:
            assert self._session is not None
            session = self._session
            assert session.cipher_suite is not None

            traffic = TrafficContext(
                version=session.protocol_version(),
                cipher_suite=session.cipher_suite,
                client_random=self._client_random,
                server_random=self._server_random,
                secret=secret,
            )
        else:
            traffic = None

        self.setup_traffic_cb(direction, epoch, traffic)

    def _derive_secret(
        self,
        premaster_secret: bytes,
        label: bytes,
        transcript: Transcript | None = None,
    ) -> bytes:
        assert self._cipher_suite is not None

        if self.version == TLSVersion.TLSv1_2:
            hash_algorithm = cast(int, self._cipher_suite.prf_hash)
            algorithm = get_algorithm(hash_algorithm)
        else:
            hash_algorithm = UNSPECIFIED
            algorithm = None

        if transcript is None:
            seed = self._client_random + self._server_random
        else:
            # seed for Extended Master Secret
            seed = transcript.digest(hash_algorithm)

        return prf(
            secret=premaster_secret,
            label=label,
            seed=seed,
            length=48,
            algorithm=algorithm,
        )

    def _derive_finished_verify_data(
        self,
        secret: bytes,
        label: bytes,
    ) -> bytes:
        if self.version == TLSVersion.TLSv1_2:
            assert self._cipher_suite is not None
            hash_algorithm = cast(int, self._cipher_suite.prf_hash)
            algorithm = get_algorithm(hash_algorithm)
        else:
            hash_algorithm = UNSPECIFIED
            algorithm = None

        seed = self._transcript.digest(hash_algorithm)

        return prf(
            secret=secret,
            label=label,
            seed=seed,
            length=12,
            algorithm=algorithm,
        )

    def _derive_key(self, secret: bytes) -> None:
        assert self._cipher_suite is not None
        version = self.protocol_version()
        cipher_suite = self._cipher_suite
        encrypt_then_mac = self._encrypt_then_mac
        seed = self._server_random + self._client_random

        if version == TLSVersion.TLSv1_2:
            algorithm = get_algorithm(cipher_suite.prf_hash)
        else:
            algorithm = None

        key_len, iv_len = get_key_iv_lens(cipher_suite)
        if cipher_suite.aead:
            mac_len = 0
        else:
            if cipher_suite.digest is None:
                raise AlertInternalError("unsupported cipher suite selected")
            digest_algorithm = get_algorithm(cipher_suite.digest)
            mac_len = digest_algorithm.digest_size

        # Parse Keys (STRICT PROTOCOL ORDER: Client first, then Server)
        # RFC 5246 Section 6.3
        # client_write_MAC_key, server_write_MAC_key, client_write_key...
        out_len = (mac_len * 2) + (key_len * 2) + (iv_len * 2)
        key_block = prf(
            secret=secret,
            label=b"key expansion",
            seed=seed,
            length=out_len,
            algorithm=algorithm,
        )
        key_parser = Parser(key_block)
        cl_mac = key_parser.read_bytes(mac_len)
        sv_mac = key_parser.read_bytes(mac_len)
        cl_key = key_parser.read_bytes(key_len)
        sv_key = key_parser.read_bytes(key_len)
        cl_iv = key_parser.read_bytes(iv_len)
        sv_iv = key_parser.read_bytes(iv_len)

        # Map Client/Server keys to Read/Write keys
        # Server: Write = Server Key, Read = Client Key
        # Client: Write = Client Key, Read = Server Key
        if self.is_server:
            read_mac, read_key, read_iv = cl_mac, cl_key, cl_iv
            write_mac, write_key, write_iv = sv_mac, sv_key, sv_iv
        else:
            read_mac, read_key, read_iv = sv_mac, sv_key, sv_iv
            write_mac, write_key, write_iv = cl_mac, cl_key, cl_iv

        self._read_traffic = TrafficContext(
            version=version,
            cipher_suite=cipher_suite,
            client_random=self._client_random,
            server_random=self._server_random,
            secret=secret,
            enc_key=read_key,
            mac_key=read_mac,
            fixed_iv=read_iv,
            encrypt_then_mac=encrypt_then_mac,
        )
        self._write_traffic = TrafficContext(
            version=version,
            cipher_suite=cipher_suite,
            client_random=self._client_random,
            server_random=self._server_random,
            secret=secret,
            enc_key=write_key,
            mac_key=write_mac,
            fixed_iv=write_iv,
            encrypt_then_mac=encrypt_then_mac,
        )

    def _derive_secret_tls13(
        self,
        direction: Direction,
        epoch: Epoch,
        label: bytes,
        transcript: Transcript,
    ) -> None:
        assert self._key_schedule is not None
        secret = self._key_schedule.derive_secret(label, transcript)
        if direction == Direction.WRITE:
            self._enc_secret[epoch] = secret
        else:
            self._dec_secret[epoch] = secret

    def _derive_upd_secret_tls13(self, direction: Direction) -> None:
        assert self._key_schedule is not None

        epoch = Epoch.APPLICATION_DATA

        if direction == Direction.WRITE:
            secret = self._enc_secret[epoch]
            new_secret = self._key_schedule.upd_secret(secret)
            self._enc_secret[epoch] = new_secret
        else:
            secret = self._dec_secret[epoch]
            new_secret = self._key_schedule.upd_secret(secret)
            self._dec_secret[epoch] = new_secret

        self._setup_traffic_tls13(direction, epoch)

    def _write_key_update(self, message_type: KeyUpdateMessageType) -> None:
        if message_type not in (
            KeyUpdateMessageType.UPDATE_NOT_REQUESTED,
            KeyUpdateMessageType.UPDATE_REQUESTED,
        ):
            raise ValueError(f"unsupported message_type '{message_type}'")
        if self.protocol_version() < TLSVersion.TLSv1_3:
            raise ValueError("key update is only support for TLSv1.3")

        key_update = KeyUpdate(message_type)
        self.message_cb(Direction.WRITE, key_update)
        self._add_message(key_update, update_hash=False)

    def _close_early_data(self) -> None:
        assert self._in_early_data

        self._in_early_data = False
        self.close_early_data()

    def _get_new_session(self) -> TLSSession:
        version = self.protocol_version()
        session = TLSSession(
            is_server=self.is_server,
            version=version,
            not_resumable=True,
        )
        return session

    def _get_key_exchange(self, group: int) -> BaseKeyExchange | None:
        if group in ECC_GROUPS:
            return ECDHKeyExchange(group)
        if group in FFDHE_GROUPS:
            return FFDHKeyExchange(get_dh_parameters(group))
        if group in KEM_GROUPS:
            return KEMKeyExchange(group)
        return None

    @staticmethod
    def _create_certificate(
        credential: TLSCredential | None = None,
    ) -> Certificate:
        if credential is not None:
            certificates = [
                certificate.public_bytes(Encoding.DER)
                for certificate in (
                    credential.certificate,
                    *credential.certificate_chain,
                )
            ]
        else:
            certificates = []
        return Certificate(certificates)

    @staticmethod
    def _create_certificate_tls13(
        credential: TLSCredential | None = None,
        context: bytes = b"",
        compression: int | None = None,
    ) -> CompressedCertificate | CertificateTLS13:
        if credential is not None:
            cert_entries = [
                CertificateEntry(
                    certificate=certificate.public_bytes(Encoding.DER),
                    extensions=Extensions(),
                )
                for certificate in (
                    credential.certificate,
                    *credential.certificate_chain,
                )
            ]
        else:
            cert_entries = []

        certificate = CertificateTLS13(context, cert_entries)

        if cert_entries and compression is not None:
            try:
                return CompressedCertificate.from_certificate(
                    compression, certificate
                )
            except UnsupportedCompression:
                raise AlertInternalError(
                    "unsupported compression algorithm is selected"
                ) from None

        return certificate

    @staticmethod
    def _get_pubkey_cert_type(public_key: BasePublicKey) -> int:
        if isinstance(public_key, RSAPublicKey):
            return ClientCertificateType.RSA_SIGN
        if isinstance(public_key, ECPublicKey):
            return ClientCertificateType.ECDSA_SIGN
        if isinstance(public_key, (Ed25519PublicKey, Ed448PublicKey)):
            return ClientCertificateType.ECDSA_SIGN
        if isinstance(public_key, DSAPublicKey):
            return ClientCertificateType.DSS_SIGN
        raise AlertInternalError("given public key type is unsupported")

    @staticmethod
    def _get_pubkey_auth(public_key: BasePublicKey) -> Authentication:
        if isinstance(public_key, RSAPublicKey):
            return Authentication.RSA
        if isinstance(public_key, ECPublicKey):
            return Authentication.ECDSA
        if isinstance(public_key, (Ed25519PublicKey, Ed448PublicKey)):
            return Authentication.ECDSA
        if isinstance(public_key, DSAPublicKey):
            return Authentication.DSS
        raise AlertHandshakeFailure("recevied unsupported public key type")

    @staticmethod
    def _sigalgs_for_pubkey(
        version: int,
        public_key: BasePublicKey,
        public_key_oid: x509.ObjectIdentifier,
        supported_sigalgs: Sequence[int] | None = None,
    ) -> tuple[int | None, list[int]]:
        """Return supported signature algorithms based on public_key_oid"""
        sigalgs: set[int] = set()
        default_sigalg: int | None = None

        if public_key_oid == PublicKeyAlgorithmOID.RSAES_PKCS1_v1_5:
            if not isinstance(public_key, RSAPublicKey):
                raise AlertInternalError("not a RSA public key")

            # RFC 8446
            # RSA signatures MUST use an RSASSA-PSS algorithm, regardless
            # of whether RSASSA-PKCS1-v1_5 algorithms appear in
            # "signature_algorithms"
            if version >= TLSVersion.TLSv1_3:
                sigalgs.update(RSA_PSS_RSAE_SIGNATURE_ALGORITHMS)
            else:
                sigalgs.update(RSA_PKCS1_SIGNATURE_ALGORITHMS)
                if version == TLSVersion.TLSv1_2:
                    default_sigalg = SignatureScheme.RSA_PKCS1_SHA1
                    sigalgs.update(RSA_PSS_RSAE_SIGNATURE_ALGORITHMS)
                else:
                    default_sigalg = UNSPECIFIED

        elif public_key_oid == PublicKeyAlgorithmOID.RSASSA_PSS:
            if not isinstance(public_key, RSAPublicKey):
                raise AlertInternalError("not a RSA public key")

            if version >= TLSVersion.TLSv1_2:
                sigalgs.update(RSA_PSS_PSS_SIGNATURE_ALGORITHMS)

        elif public_key_oid == PublicKeyAlgorithmOID.DSA:
            if not isinstance(public_key, DSAPublicKey):
                raise AlertInternalError("not a DSA public key")

            if version <= TLSVersion.TLSv1_2:
                default_sigalg = SignatureScheme.DSA_SHA1
                sigalgs.update(DSA_SIGNATURE_ALGORITHMS)

        elif public_key_oid == PublicKeyAlgorithmOID.EC_PUBLIC_KEY:
            if not isinstance(public_key, ECPublicKey):
                raise AlertInternalError("not a EC public key")

            if version >= TLSVersion.TLSv1_3:
                group_id = public_key.group_id
                if group_id == NamedGroup.SECP256R1:
                    sigalgs.add(SignatureScheme.ECDSA_SECP256R1_SHA256)
                elif group_id == NamedGroup.SECP384R1:
                    sigalgs.add(SignatureScheme.ECDSA_SECP384R1_SHA384)
                elif group_id == NamedGroup.SECP521R1:
                    sigalgs.add(SignatureScheme.ECDSA_SECP521R1_SHA512)
            else:
                default_sigalg = SignatureScheme.ECDSA_SHA1
                sigalgs.update(ECDSA_SIGNATURE_ALGORITHMS)

        elif public_key_oid == PublicKeyAlgorithmOID.ED25519:
            if not isinstance(public_key, Ed25519PublicKey):
                raise AlertInternalError("not a Ed25519 public key")

            if version >= TLSVersion.TLSv1_2:
                default_sigalg = SignatureScheme.ED25519
                sigalgs.add(SignatureScheme.ED25519)

        elif public_key_oid == PublicKeyAlgorithmOID.ED448:
            if not isinstance(public_key, Ed448PublicKey):
                raise AlertInternalError("not a Ed448 public key")

            if version >= TLSVersion.TLSv1_2:
                default_sigalg = SignatureScheme.ED448
                sigalgs.add(SignatureScheme.ED448)

        if supported_sigalgs is not None:
            valid_sigalgs = [s for s in supported_sigalgs if s in sigalgs]
        else:
            valid_sigalgs = []

        return (default_sigalg, valid_sigalgs)

    @classmethod
    def _get_sigalg_tls1(
        cls,
        version: int,
        public_key: BasePublicKey,
        public_key_oid: x509.ObjectIdentifier,
    ) -> int:
        assert version <= TLSVersion.TLSv1_1

        default_verify_alg, _ = cls._sigalgs_for_pubkey(
            version=version,
            public_key=public_key,
            public_key_oid=public_key_oid,
        )
        if default_verify_alg is not None:
            return default_verify_alg
        raise AlertIllegalParameter("received unsupported certificate")

    @classmethod
    def _verify_sigalg_tls12(
        cls,
        version: int,
        public_key: BasePublicKey,
        public_key_oid: x509.ObjectIdentifier,
        signature_algorihtm: int,
        supported_sigalgs: Sequence[int],
    ) -> None:
        assert version >= TLSVersion.TLSv1_2

        _, valid_sigalgs = cls._sigalgs_for_pubkey(
            version=version,
            public_key=public_key,
            public_key_oid=public_key_oid,
            supported_sigalgs=supported_sigalgs,
        )
        if signature_algorihtm not in valid_sigalgs:
            raise AlertIllegalParameter("received wrong signature algorithm")

    def _verify_x509(
        self,
        session: TLSSession,
        hostname: bytes | None = None,
    ) -> None:
        assert session.peer_cert is not None
        assert session.peer_chain is not None

        configuration = self.configuration

        if configuration.castore is None:
            raise AlertUnknownCA("castore is not provided")

        ee_policy = ExtensionPolicy.defaults_ee()
        ca_policy = ExtensionPolicy.defaults_ca()

        if self.is_server:
            purpose = ExtendedKeyUsageOID.CLIENT_AUTH
        else:
            purpose = ExtendedKeyUsageOID.SERVER_AUTH

            if configuration.check_hostname and hostname:
                san_validator = SANValidator(hostname)
                ee_policy = ee_policy.require_present(
                    san_validator.oid, san_validator
                )

        eku_validator = EKUValidator(purpose)
        ee_policy = ee_policy.require_present(eku_validator.oid, eku_validator)

        verifier = Verifier(
            store=configuration.castore,
            allow_partial_chain=True,
            ee_policy=ee_policy,
            ca_policy=ca_policy,
        )
        try:
            certs = verifier.verify(session.peer_cert, session.peer_chain)
        except (CertificateExpired, CertificateNotYetValid) as exc:
            raise AlertCertificateExpired(str(exc)) from None
        except UntrustedRoot as exc:
            raise AlertUnknownCA(str(exc)) from None
        except VerificationError as exc:
            raise AlertBadCertificate(str(exc)) from None

        session.verified_peer_cert = certs[0]
        session.verified_peer_chain = tuple(certs[1:])

    def _process_certificate(
        self,
        message: Handshake,
        session: TLSSession,
        allow_anon: bool,
    ) -> Certificate:
        certificate = message.parse_as(Certificate)

        cert_chain = certificate.certificates
        if not cert_chain:
            if not allow_anon:
                raise AlertCertificateRequired("certificate is not received")
            return certificate

        try:
            peer_cert = x509.load_der_x509_certificate(cert_chain[0])
            peer_chain = tuple(
                x509.load_der_x509_certificate(cert) for cert in cert_chain[1:]
            )
        except ValueError as exc:
            raise AlertBadCertificate(str(exc)) from exc

        session.peer_cert = peer_cert
        session.peer_chain = peer_chain

        return certificate

    def _process_certificate_tls13(
        self,
        message: Handshake,
        session: TLSSession,
        allow_anon: bool,
        compression_supported: bool,
    ) -> CompressedCertificate | CertificateTLS13:
        c_certificate: CompressedCertificate | None = None

        if message.handshake_type == HandshakeType.COMPRESSED_CERTIFICATE:
            if not compression_supported:
                raise AlertUnexpectedMessage(
                    "received unexpected compressed certificate"
                )

            c_certificate = message.parse_as(CompressedCertificate)

            if c_certificate.compression not in self._certificate_compressions:
                raise AlertIllegalParameter(
                    "received invalid compression algorithm"
                )

            try:
                certificate = c_certificate.to_certificate()
            except ValueError as exc:
                raise AlertBadCertificate(str(exc)) from exc
            except UnsupportedCompression:
                raise AlertInternalError(
                    "unsupported compression algorithm is selected"
                ) from None
        else:
            certificate = message.parse_as(CertificateTLS13)

        cert_entries = certificate.certificate_entries
        if not cert_entries:
            if not allow_anon:
                raise AlertCertificateRequired("certificate is not received")
            return certificate

        cert_entry = cert_entries[0]
        try:
            peer_cert = x509.load_der_x509_certificate(cert_entry.certificate)
            peer_chain = tuple(
                x509.load_der_x509_certificate(cert_entry.certificate)
                for cert_entry in cert_entries[1:]
            )
        except ValueError as exc:
            raise AlertBadCertificate(str(exc)) from exc

        # Process extensions of first cert_entires
        extensions = cert_entry.extensions

        cert_status = extensions.get(StatusRequestCertificateExtension)
        if cert_status is not None:
            ocsp_response = cert_status.response
        else:
            ocsp_response = None

        session.peer_cert = peer_cert
        session.peer_chain = peer_chain
        session.ocsp_response = ocsp_response

        return c_certificate or certificate

    def _process_certificate_verify(
        self,
        session: TLSSession,
        cert_verify: CertificateVerify | CertificateVerifyTLS12,
        supported_sigalgs: Sequence[int],
    ) -> None:
        assert session.peer_cert is not None

        if not cert_verify.signature:
            raise AlertIllegalParameter(
                "received certificate verify message with empty signature"
            )

        version = self.protocol_version()
        peer_cert = session.peer_cert
        try:
            peer_public_key = load_certificate_public_key(peer_cert)
        except ValueError as exc:
            raise AlertHandshakeFailure(str(exc)) from exc

        peer_public_key_oid = peer_cert.public_key_algorithm_oid
        if version >= TLSVersion.TLSv1_2:
            cert_verify = cast(CertificateVerifyTLS12, cert_verify)
            verify_alg = cert_verify.signature_algorithm
            self._verify_sigalg_tls12(
                version=version,
                public_key=peer_public_key,
                public_key_oid=peer_public_key_oid,
                signature_algorihtm=verify_alg,
                supported_sigalgs=supported_sigalgs,
            )
        else:
            verify_alg = self._get_sigalg_tls1(
                version=version,
                public_key=peer_public_key,
                public_key_oid=peer_public_key_oid,
            )

        if version >= TLSVersion.TLSv1_3:
            assert self._key_schedule is not None

            if self.is_server:
                context = TLS13_CLIENT_CONTEXT_STRING
            else:
                context = TLS13_SERVER_CONTEXT_STRING

            data = self._key_schedule.certificate_verify_data(
                context, self._transcript
            )
        else:
            data = self._transcript.get()

        try:
            peer_public_key.verify(cert_verify.signature, data, verify_alg)
        except InvalidSignature:
            raise AlertDecryptError("failed to verify signature") from None
