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
from dataclasses import dataclass, field

from .. import x509
from ..io.serialization import Encoding
from ..key import InvalidSignature, dsa, ec, ed448, ed25519, rsa
from ..key.types import CertificatePublicKeyTypes
from ..protocol.hpke import Context as HPKEContext
from ..utils.codec import ParseError, Parser
from ..utils.compression import UnsupportedCompression
from ..utils.math import bytes_to_int, bytes_to_str
from ._alert import (
    AlertBadCertificate,
    AlertCertificateExpired,
    AlertCertificateRequired,
    AlertDecodeError,
    AlertDecryptError,
    AlertHandshakeFailure,
    AlertIllegalParameter,
    AlertInternalError,
    AlertUnknownCA,
)
from ._cipher import TLSCipher
from ._common import get_algorithm, verify_signature
from ._constant import (
    CLIENT_CONTEXT_STRING,
    DSA_SIGNATURE_ALGORITHMS,
    ECDSA_SIGNATURE_ALGORITHMS,
    RSA_PKCS1_SIGNATURE_ALGORITHMS,
    RSA_PSS_PSS_SIGNATURE_ALGORITHMS,
    RSA_PSS_RSAE_SIGNATURE_ALGORITHMS,
    SERVER_CONTEXT_STRING,
    Authentication,
    CipherSuite,
    ClientCertificateType,
    HandshakeType,
    KeyUpdateMessageType,
    SignatureScheme,
    TLSVersion,
)
from ._context import TLSContext
from ._enum import Direction, ECHStatus, Epoch, Status
from ._extension import (
    CertStatusRequestExtension,
    ECHConfig,
    TLSExtension,
)
from ._message import (
    Certificate,
    CertificateEntry,
    CertificateTLS13,
    CertificateVerify,
    CertificateVerifyTLS12,
    CompressedCertificate,
    Handshake,
    HandshakeMessage,
    KeyUpdate,
)
from ._session import TLSSession
from ._transcript import KeyDeriver, KeySchedule, Transcript
from ._types import ReadableBuffer
from ._x509_validator import EKUValidator, SANValidator

SessionTicketHandler = typing.Callable[[TLSSession], None]


@dataclass(frozen=True, slots=True)
class ECHConfigContent:
    kdf_id: int
    aead_id: int
    kem_id: int
    hpke_context: HPKEContext
    config_id: int
    public_name: bytes
    maximum_name_length: int
    enc: bytes = b""
    extensions: list[tuple[int, bytes]] = field(default_factory=list)


class TLSHandshake:
    server_side: typing.ClassVar[bool]

    def __init__(self, context: TLSContext) -> None:
        self.do_message_cb: typing.Callable[[str, HandshakeMessage], None] = (
            lambda rw, m: None
        )
        self.setup_traffic_cb: typing.Callable[
            [Direction, Epoch, TLSCipher], None
        ] = lambda d, e, c: None
        self.update_traffic_cb: typing.Callable[[Direction, Epoch], None] = (
            lambda d, e: None
        )
        self.add_ccs_cb: typing.Callable[[], None] = lambda: None

        self.context = context
        """TLS context"""
        self.skip_early_data: bool = False
        """Instructs the record layer should skip the unexpected early data
        messages when 0-RTT is rejected"""
        self.can_early_write: bool = False
        """"""
        self.can_early_read: bool = False
        """"""

        self._session: TLSSession | None = None
        """Session currently establishing from previous session"""
        self._established_session: TLSSession | None = None
        """Session established by the conneciton, only available upon the
        handshake completed"""
        self._new_session: TLSSession | None = None
        """"""
        self._early_session: TLSSession | None = None
        """"""

        self._hs_state = 0
        """The current handshake state"""
        self._hostname: bytes | None = None
        """hostname, on the server, is the value of the SNI extension"""
        self._session_reused: bool = False
        """"""
        self._cipher_suite: CipherSuite | None = None
        """cipher suite being negotitaed in this handshake"""
        self._minimum_version: int = context.minimum_version
        """minimumversion is the minimum accepted protocol version"""
        self._maximum_version: int = context.maximum_version
        """maximum_version is the maximum accepted protocol version"""
        self._client_version: int = TLSVersion.UNSPECIFIED
        """the value sent or received in the ClientHello version."""
        self._session_id: bytes = b""
        """session ID in the ClientHello"""
        self._version: int = TLSVersion.UNSPECIFIED
        """Negotiate protocol version, or zero if the version has not yet
        been set"""
        self._is_early_version: bool = False
        """Predicted 0-RTT version"""
        self._in_early_data: bool = False
        """True while in early data state"""
        self._early_data_accepted: bool = False
        """True when early data accepted"""

        self._npn_selected: bytes | None = None
        """Selected NPN protocol"""
        self._alpn_selected: bytes | None = None
        """Selected ALPN Protocol"""

        self._client_random: bytes = b""
        self._server_random: bytes = b""

        self._previous_client_finished: bytes | None = None
        self._previous_server_finished: bytes | None = None

        # dispatch function handler
        self._handle_dispatch: dict[int, typing.Callable] = {}

        # Buffer
        self._hs_buf = bytearray()
        """handshake data waiting to be process"""
        self._pending_hs_data = bytearray()
        """pending handshake data to be send"""
        self._cache: Handshake | None = None
        """cached Handshake"""

        # Transcript and secrets
        self._transcript: Transcript = Transcript()
        self._key_deriver: KeyDeriver | None = None
        self._key_schedule: KeySchedule | None = None
        self._enc_secret: dict[Epoch, bytes] = {}
        self._dec_secret: dict[Epoch, bytes] = {}

        if self._minimum_version > self._maximum_version:
            raise ValueError(
                "minimum_version cannot be larger then maximum_version"
            )

    @property
    def done(self) -> bool:
        raise NotImplementedError()

    @property
    def hs_state(self):
        return self._hs_state

    @property
    def context(self) -> TLSContext:
        return self._context

    @context.setter
    def context(self, value: TLSContext) -> None:
        if not isinstance(value, TLSContext):
            raise TypeError("context must be TLSContext object")
        self._context = value

    @property
    def session(self) -> TLSSession | None:
        return self._session

    @property
    def early_session(self) -> TLSSession | None:
        return self._early_session

    @property
    def new_session(self) -> TLSSession | None:
        return self._new_session

    @property
    def established_session(self) -> TLSSession | None:
        return self._established_session

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
    def early_data_accepted(self) -> bool:
        return self._early_data_accepted

    @property
    def session_reused(self) -> bool:
        return self._session_reused

    @property
    def npn_selected(self) -> bytes | None:
        return self._npn_selected

    @property
    def alpn_selected(self) -> bytes | None:
        return self._alpn_selected

    @property
    def peer_cipher_suites(self) -> tuple[int, ...] | None:
        return None

    @property
    def ech_retry_configs(self) -> list[ECHConfig] | None:
        return None

    @property
    def ech_status(self) -> ECHStatus:
        return ECHStatus.NONE

    def do_handshake(self) -> Status:
        ret = Status.OK
        while not self.done:
            f = self._handle_dispatch[self.hs_state]
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

    def protocol_version(self) -> int:
        assert self._version != TLSVersion.UNSPECIFIED
        return self._version

    def cipher(self) -> CipherSuite:
        assert self._cipher_suite is not None
        return self._cipher_suite

    @staticmethod
    def _update_hash(message: HandshakeMessage, transcript: Transcript):
        handshake = Handshake(message.handshake_type, message.serialize())
        handshake_data = handshake.serialize()
        transcript.update_hash(handshake_data)

    def add_hs_data(self, data: ReadableBuffer) -> None:
        self._hs_buf.extend(data)

    def has_unprocessed_hs_data(self) -> bool:
        return len(self._hs_buf) > 0

    def pending_flight(self) -> bytearray:
        return self._pending_hs_data

    def clear_flight(self) -> None:
        self._pending_hs_data.clear()

    def _get_message(self) -> Handshake | None:
        if self._cache is not None:
            return self._cache

        if len(self._hs_buf) < 4:
            return None

        data_len = 4 + bytes_to_int(self._hs_buf[1:4])
        if len(self._hs_buf) < data_len:
            return None

        handshake = Handshake(self._hs_buf[0], bytes(self._hs_buf[4:data_len]))
        self._cache = handshake
        del self._hs_buf[:data_len]
        return self._cache

    def _add_message(
        self, message: HandshakeMessage, update_hash: bool = True
    ) -> None:
        handshake = Handshake(message.handshake_type, message.serialize())
        handshake_data = handshake.serialize()
        self._pending_hs_data.extend(handshake_data)
        if update_hash:
            self._transcript.update_hash(handshake_data)

    def _next_message(self, update_hash: bool = True):
        assert self._cache is not None
        if update_hash:
            self._transcript.update_hash(self._cache.serialize())
        self._cache = None

    def _set_state(self, state: int) -> None:
        # print("TLS {} -> {}".format(self.hs_state, state))
        self._hs_state = state

    def _setup_traffic_key(self, session: TLSSession) -> None:
        if self._key_deriver is None:
            raise AlertInternalError("Missing key_deriver")
        if session.cipher_suite is None:
            raise AlertInternalError("Missing cipher_suite in session")

        version = session.protocol_version()
        cipher_suite = session.cipher_suite
        master_secret = session.secret
        encrypt_then_mac = session.encrypt_then_mac

        key_len, iv_len = TLSCipher.get_key_iv_size(version, cipher_suite)
        if cipher_suite.aead:
            mac_size = 0
        else:
            if cipher_suite.digest is None:
                raise AlertInternalError("Unexpected cipher_suite provided")
            digest_algorithm = get_algorithm(cipher_suite.digest)
            mac_size = digest_algorithm.digest_size

        # Parse Keys (STRICT PROTOCOL ORDER: Client first, then Server)
        # RFC 5246 Section 6.3
        # client_write_MAC_key, server_write_MAC_key, client_write_key...
        out_len = (mac_size * 2) + (key_len * 2) + (iv_len * 2)
        key_block = self._key_deriver.derive_key(master_secret, out_len)
        key_parser = Parser(key_block)

        cl_mac = key_parser.read_bytes(mac_size)
        sv_mac = key_parser.read_bytes(mac_size)
        cl_key = key_parser.read_bytes(key_len)
        sv_key = key_parser.read_bytes(key_len)
        cl_iv = key_parser.read_bytes(iv_len)
        sv_iv = key_parser.read_bytes(iv_len)

        # Map Client/Server keys to Read/Write keys
        # Server: Write = Server Key, Read = Client Key
        # Client: Write = Client Key, Read = Server Key
        if self.server_side:
            read_mac, read_key, read_iv = cl_mac, cl_key, cl_iv
            write_mac, write_key, write_iv = sv_mac, sv_key, sv_iv
        else:
            read_mac, read_key, read_iv = sv_mac, sv_key, sv_iv
            write_mac, write_key, write_iv = cl_mac, cl_key, cl_iv

        read_cipher = TLSCipher(
            direction=Direction.DECRYPT,
            version=version,
            cipher_suite=cipher_suite,
            enc_key=read_key,
            mac_key=read_mac,
            fixed_iv=read_iv,
            encrypt_then_mac=encrypt_then_mac,
        )
        self.setup_traffic_cb(
            Direction.DECRYPT, Epoch.APPLICATION_DATA, read_cipher
        )

        write_cipher = TLSCipher(
            direction=Direction.ENCRYPT,
            version=version,
            cipher_suite=cipher_suite,
            enc_key=write_key,
            mac_key=write_mac,
            fixed_iv=write_iv,
            encrypt_then_mac=encrypt_then_mac,
        )
        self.setup_traffic_cb(
            Direction.ENCRYPT, Epoch.APPLICATION_DATA, write_cipher
        )

    def _setup_traffic_key_tls13(
        self,
        session: TLSSession,
        direction: Direction,
        epoch: Epoch,
        label: bytes,
        transcript: Transcript | None = None,
    ) -> None:
        if self._key_schedule is None:
            raise AlertInternalError("Missing key_schedule")
        if transcript is None:
            transcript = self._transcript

        secret = self._key_schedule.derive_secret(label, transcript)
        if direction == Direction.ENCRYPT:
            self._enc_secret[epoch] = secret
        else:
            self._dec_secret[epoch] = secret

        self._set_traffic_key_tls13(session, direction, epoch, secret)

    def _update_traffic_key_tls13(self, direction: Direction) -> None:
        if self._key_schedule is None:
            raise AlertInternalError("Missing key_schedule")
        if self._established_session is None:
            raise AlertInternalError("session not establish")

        epoch = Epoch.APPLICATION_DATA
        session = self._established_session

        if direction == Direction.ENCRYPT:
            secret = self._enc_secret[epoch]
            new_secret = self._key_schedule.upd_secret(secret)
            self._enc_secret[epoch] = new_secret
        else:
            secret = self._dec_secret[epoch]
            new_secret = self._key_schedule.upd_secret(secret)
            self._dec_secret[epoch] = new_secret

        self._set_traffic_key_tls13(session, direction, epoch, new_secret)
        self.update_traffic_cb(direction, epoch)

    def _set_traffic_key_tls13(
        self,
        session: TLSSession,
        direction: Direction,
        epoch: Epoch,
        secret: bytes,
    ) -> None:
        if self._key_schedule is None:
            raise AlertInternalError("Missing key_schedule")
        if session.cipher_suite is None:
            raise AlertInternalError("Missing cipher_suite in session")

        version = session.protocol_version()
        cipher_suite = session.cipher_suite
        key_size, iv_size = TLSCipher.get_key_iv_size(version, cipher_suite)
        key = self._key_schedule.hkdf_expand_label(
            secret, b"key", b"", key_size
        )
        fixed_nonce = self._key_schedule.hkdf_expand_label(
            secret, b"iv", b"", iv_size
        )
        cipher = TLSCipher(
            direction=direction,
            version=version,
            cipher_suite=cipher_suite,
            enc_key=key,
            mac_key=b"",
            fixed_iv=fixed_nonce,
        )
        self.setup_traffic_cb(direction, epoch, cipher)

    def _write_key_update(self, message_type: KeyUpdateMessageType) -> None:
        if message_type not in (
            KeyUpdateMessageType.UPDATE_NOT_REQUESTED,
            KeyUpdateMessageType.UPDATE_REQUESTED,
        ):
            raise ValueError(f"Invalid message_type '{message_type}'")
        if self.protocol_version() < TLSVersion.TLSv1_3:
            raise ValueError("KeyUpdate is only support for TLSv1.3")

        key_update = KeyUpdate(message_type)
        self.do_message_cb("write", key_update)
        self._add_message(key_update, update_hash=False)

    def _close_early_data(self) -> None:
        assert self._in_early_data

        self._in_early_data = False
        self.can_early_write = False

    def _get_new_session(self) -> TLSSession:
        version = self.protocol_version()
        session = TLSSession(
            server_side=self.server_side,
            version=version,
            not_resumable=True,
        )
        return session

    @staticmethod
    def _serialize_extensions(
        extensions: typing.Iterable[TLSExtension],
    ) -> list[tuple[int, bytes]]:
        return [(e.extension_type, e.serialize()) for e in extensions]

    @staticmethod
    def _process_certificate(
        message: Handshake,
        session: TLSSession,
        allow_anon: bool = False,
    ) -> Certificate:
        certificate = message.get_handshake(Certificate)
        cert_chain = certificate.certificates
        if not cert_chain:
            if not allow_anon:
                raise AlertCertificateRequired()
            return certificate

        try:
            x509_peer = x509.load_der_x509_certificate(cert_chain[0])
            x509_chain = tuple(
                x509.load_der_x509_certificate(cert) for cert in cert_chain[1:]
            )
        except ValueError as exc:
            raise AlertBadCertificate(str(exc)) from exc

        session.x509_peer = x509_peer
        session.x509_chain = x509_chain

        return certificate

    @staticmethod
    def _process_certificate_tls13(
        message: Handshake,
        session: TLSSession,
        supported_compressions: typing.Iterable[int] | None = None,
        allow_anon: bool = False,
    ) -> CompressedCertificate | CertificateTLS13:
        c_certificate: CompressedCertificate | None = None

        if (
            message.handshake_type == HandshakeType.COMPRESSED_CERTIFICATE
            and supported_compressions is not None
        ):
            c_certificate = message.get_handshake(CompressedCertificate)
            compression = c_certificate.compression
            if compression not in supported_compressions:
                raise AlertIllegalParameter("Invalid compression algorithm")

            try:
                certificate = c_certificate.to_certificate()
            except ValueError as exc:
                raise AlertBadCertificate(str(exc)) from exc
            except UnsupportedCompression:
                raise AlertInternalError(
                    f"Certificate compression '{compression}' is unsupported"
                ) from None
        else:
            certificate = message.get_handshake(CertificateTLS13)

        cert_entries = certificate.certificate_entries
        if not cert_entries:
            if not allow_anon:
                raise AlertCertificateRequired()
            return certificate

        cert_entry = cert_entries[0]
        try:
            x509_peer = x509.load_der_x509_certificate(cert_entry.certificate)
            x509_chain = tuple(
                x509.load_der_x509_certificate(cert_entry.certificate)
                for cert_entry in cert_entries[1:]
            )
        except ValueError as exc:
            raise AlertBadCertificate(str(exc)) from exc

        cert_status = cert_entry.get_extension(CertStatusRequestExtension)
        if cert_status is not None:
            ocsp_response = cert_status.response
        else:
            ocsp_response = b""

        session.x509_peer = x509_peer
        session.x509_chain = x509_chain
        session.ocsp_response = ocsp_response

        return c_certificate or certificate

    @staticmethod
    def _create_certificate(
        x509_certs: typing.Iterable[x509.Certificate],
    ) -> Certificate:
        certificates = [c.public_bytes(Encoding.DER) for c in x509_certs]
        return Certificate(certificates=certificates)

    @staticmethod
    def _create_certificate_tls13(
        x509_certs: typing.Iterable[x509.Certificate],
        context: bytes = b"",
        compression: int | None = None,
    ) -> CompressedCertificate | CertificateTLS13:
        cert_entries = [
            CertificateEntry(certificate.public_bytes(Encoding.DER))
            for certificate in x509_certs
        ]
        certificate = CertificateTLS13(context, cert_entries)

        if cert_entries and compression is not None:
            try:
                return CompressedCertificate.from_certificate(
                    compression, certificate
                )
            except UnsupportedCompression:
                raise AlertInternalError(
                    f"Certificate compression '{compression}' is unsupported"
                ) from None

        return certificate

    @staticmethod
    def _certificate_type(public_key_oid: x509.ObjectIdentifier) -> int:
        if public_key_oid in (
            x509.PublicKeyAlgorithmOID.RSAES_PKCS1_v1_5,
            x509.PublicKeyAlgorithmOID.RSASSA_PSS,
        ):
            cert_type = ClientCertificateType.RSA_SIGN
        elif public_key_oid == x509.PublicKeyAlgorithmOID.DSA:
            cert_type = ClientCertificateType.DSS_SIGN
        elif public_key_oid in (
            x509.PublicKeyAlgorithmOID.EC_PUBLIC_KEY,
            x509.PublicKeyAlgorithmOID.ED25519,
            x509.PublicKeyAlgorithmOID.ED25519,
        ):
            cert_type = ClientCertificateType.ECDSA_SIGN
        else:
            raise AlertInternalError("Unsupported certificate public key")

        return cert_type

    @staticmethod
    def _check_pubkey(
        version: int,
        public_key: CertificatePublicKeyTypes,
        cipher_suite: CipherSuite | None = None,
    ) -> None:
        if version >= TLSVersion.TLSv1_3:
            cipher_suite = None

        if isinstance(public_key, rsa.RSAPublicKey):
            if (
                cipher_suite is not None
                and cipher_suite.auth != Authentication.RSA
            ):
                raise AlertIllegalParameter("Invalid key type")

            if public_key.key_size < 1024:
                raise AlertHandshakeFailure(
                    f"Peer public key too small '{public_key.key_size}'"
                )

        elif isinstance(public_key, dsa.DSAPublicKey):
            if (
                cipher_suite is not None
                and cipher_suite.auth != Authentication.DSS
            ):
                raise AlertIllegalParameter("Invalid key type")

            if public_key.key_size < 1024:
                raise AlertHandshakeFailure(
                    f"Peer public key too small '{public_key.key_size}'"
                )

        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            if (
                cipher_suite is not None
                and cipher_suite.auth != Authentication.ECDSA
            ):
                raise AlertIllegalParameter("Invalid key type")

        elif isinstance(
            public_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)
        ):
            if version <= TLSVersion.TLSv1_1:
                raise AlertIllegalParameter(
                    "Unexpected EdDSA Key for older TLS version"
                )

            if (
                cipher_suite is not None
                and cipher_suite.auth != Authentication.ECDSA
            ):
                raise AlertIllegalParameter("Invalid key type")

        else:
            raise AlertHandshakeFailure("Unsupported public key type")

    @staticmethod
    def _sigalgs_for_pubkey(
        version: int,
        public_key: CertificatePublicKeyTypes,
        public_key_oid: x509.ObjectIdentifier,
        supported_sigalgs: typing.Sequence[int] | None = None,
    ) -> tuple[int | None, list[int]]:
        """
        Return supported signature algorithms based on public_key_oid

        **Notes**: Public key type should were check earlier
        """
        sigalgs: set[int] = set()
        default_sigalg: int | None = None

        if public_key_oid == x509.PublicKeyAlgorithmOID.RSAES_PKCS1_v1_5:
            if not isinstance(public_key, rsa.RSAPublicKey):
                raise AlertInternalError("Not a RSA public key")

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
                    default_sigalg = SignatureScheme.RSA_MD5_SHA1

        elif public_key_oid == x509.PublicKeyAlgorithmOID.RSASSA_PSS:
            if not isinstance(public_key, rsa.RSAPublicKey):
                raise AlertInternalError("Not a RSA public key")
            if version >= TLSVersion.TLSv1_2:
                sigalgs.update(RSA_PSS_PSS_SIGNATURE_ALGORITHMS)

        elif public_key_oid == x509.PublicKeyAlgorithmOID.DSA:
            if not isinstance(public_key, dsa.DSAPublicKey):
                raise AlertInternalError("Not a DSA public key")
            if version <= TLSVersion.TLSv1_2:
                default_sigalg = SignatureScheme.DSA_SHA1
                sigalgs.update(DSA_SIGNATURE_ALGORITHMS)

        elif public_key_oid == x509.PublicKeyAlgorithmOID.EC_PUBLIC_KEY:
            if not isinstance(public_key, ec.EllipticCurvePublicKey):
                raise AlertInternalError("Not a EC public key")
            if version >= TLSVersion.TLSv1_3:
                ec_curve = public_key.curve
                if isinstance(ec_curve, ec.SECP256R1):
                    sigalgs.add(SignatureScheme.ECDSA_SECP256R1_SHA256)
                elif isinstance(ec_curve, ec.SECP384R1):
                    sigalgs.add(SignatureScheme.ECDSA_SECP384R1_SHA384)
                elif isinstance(ec_curve, ec.SECP521R1):
                    sigalgs.add(SignatureScheme.ECDSA_SECP521R1_SHA512)
            else:
                default_sigalg = SignatureScheme.ECDSA_SHA1
                sigalgs.update(ECDSA_SIGNATURE_ALGORITHMS)

        elif public_key_oid == x509.PublicKeyAlgorithmOID.ED25519:
            if not isinstance(public_key, ed25519.Ed25519PublicKey):
                raise AlertInternalError("Not a Ed25519 public key")
            if version >= TLSVersion.TLSv1_2:
                default_sigalg = SignatureScheme.ED25519
                sigalgs.add(SignatureScheme.ED25519)

        elif public_key_oid == x509.PublicKeyAlgorithmOID.ED448:
            if not isinstance(public_key, ed448.Ed448PublicKey):
                raise AlertInternalError("Not a Ed448 public key")
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
        public_key: CertificatePublicKeyTypes,
        public_key_oid: x509.ObjectIdentifier,
    ) -> int:
        if version > TLSVersion.TLSv1_1:
            raise AlertInternalError("Unexpected call on higer version")

        default_verify_alg, _ = cls._sigalgs_for_pubkey(
            version == version,
            public_key=public_key,
            public_key_oid=public_key_oid,
        )
        if default_verify_alg is None:
            raise AlertIllegalParameter("Unsupported certificate")

        return default_verify_alg

    @classmethod
    def _verify_sigalg_tls12(
        cls,
        version: int,
        public_key: CertificatePublicKeyTypes,
        public_key_oid: x509.ObjectIdentifier,
        signature_algorihtm: int,
        supported_sigalgs: typing.Sequence[int] | None,
    ) -> None:
        if version < TLSVersion.TLSv1_2:
            raise AlertInternalError("Unexpected call on lower version")

        default_verify_alg, valid_sigalgs = cls._sigalgs_for_pubkey(
            version=version,
            public_key=public_key,
            public_key_oid=public_key_oid,
            supported_sigalgs=supported_sigalgs,
        )
        if supported_sigalgs is not None:
            if signature_algorihtm not in valid_sigalgs:
                raise AlertIllegalParameter("Wrong signature algorithm")
        elif signature_algorihtm != default_verify_alg:
            raise AlertIllegalParameter("Wrong signature algorithm")

    @classmethod
    def _verify_x509(
        cls,
        context: TLSContext,
        session: TLSSession,
        hostname: bytes | str | None = None,
    ) -> None:
        if session.x509_peer is None or session.x509_chain is None:
            raise AlertInternalError(
                "Missing x509_peer or x509_chain in session"
            )

        ee_policy = context.ee_policy
        ca_policy = context.ca_policy

        if cls.server_side:
            purpose = x509.ExtendedKeyUsageOID.CLIENT_AUTH
        else:
            purpose = x509.ExtendedKeyUsageOID.SERVER_AUTH

            if hostname:
                san_validator = SANValidator(bytes_to_str(hostname))
                ee_policy = ee_policy.require_present(
                    san_validator.oid, san_validator
                )

        eku_validator = EKUValidator(purpose)
        ee_policy = ee_policy.require_present(eku_validator.oid, eku_validator)

        verifier = x509.Verifier(
            store=context.castore,
            allow_partial_chain=True,
            ee_policy=ee_policy,
            ca_policy=ca_policy,
        )
        try:
            verified_certs = verifier.verify(
                session.x509_peer, session.x509_chain
            )
        except (x509.CertificateExpired, x509.CertificateNotYetValid) as exc:
            raise AlertCertificateExpired(str(exc)) from None
        except x509.UntrustedRoot as exc:
            raise AlertUnknownCA(str(exc)) from None
        except x509.VerificationError as exc:
            raise AlertBadCertificate(str(exc)) from None

        session.verified_x509_peer = verified_certs[0]
        session.verified_x509_chain = verified_certs[1:]

    def _process_certificate_verify(
        self,
        session: TLSSession,
        cert_verify: CertificateVerify | CertificateVerifyTLS12,
        supported_sigalgs: typing.Sequence[int] | None,
    ) -> None:
        if session.x509_peer is None:
            raise AlertInternalError("Missing x509_peer in session")
        if not cert_verify.signature:
            raise AlertIllegalParameter("Empty signature")

        version = self.protocol_version()
        x509_peer = session.x509_peer
        try:
            peer_public_key = x509_peer.public_key()
        except ValueError as exc:
            raise AlertHandshakeFailure(
                "Unsupported public key format"
            ) from exc

        peer_public_key_oid = x509_peer.public_key_algorithm_oid

        if version >= TLSVersion.TLSv1_2:
            cert_verify = typing.cast(CertificateVerifyTLS12, cert_verify)
            verify_alg = cert_verify.signature_algorithm
            self._verify_sigalg_tls12(
                version=version,
                public_key=peer_public_key,
                public_key_oid=peer_public_key_oid,
                signature_algorihtm=verify_alg,
                supported_sigalgs=supported_sigalgs,
            )
            session.peer_signature_algorithm = verify_alg
        else:
            verify_alg = self._get_sigalg_tls1(
                version=version,
                public_key=peer_public_key,
                public_key_oid=peer_public_key_oid,
            )

        self._check_pubkey(version, peer_public_key)

        if version >= TLSVersion.TLSv1_3:
            if self._key_schedule is None:
                raise AlertInternalError("Missing key_schedule")

            context_string = (
                CLIENT_CONTEXT_STRING
                if self.server_side
                else SERVER_CONTEXT_STRING
            )
            data = self._key_schedule.certificate_verify_data(
                context_string, self._transcript
            )
        else:
            data = self._transcript.get()

        try:
            verify_signature(
                peer_public_key, cert_verify.signature, data, verify_alg
            )
        except InvalidSignature:
            raise AlertDecryptError(
                "Invalid signature in certificate verify"
            ) from None
