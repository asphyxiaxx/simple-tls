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

import dataclasses
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .. import x509
from ..utils.codec import Parser, Writer, ParseError
from ..utils.constant_time import compare_digest
from ..utils.misc import utcnow
from ..utils.random import get_random_bytes
from ._constant import CipherSuite, TLSVersion
from ._enum import TLSSessionType


@dataclass
class TLSSession:
    context_id: int = 0
    """"""
    server_side: bool = False
    """indicate this session was create by server side"""
    not_resumable: bool = False
    """"""
    version: int = TLSVersion.UNSPECIFIED
    """TLS version"""
    cipher_suite: CipherSuite | None = None
    """selected cipher suite"""
    secret: bytes = b""
    """secret is master secret for TLSv1.2 below and resumption secret 
    for TLSv1.3 above"""
    session_id: bytes = b""
    """session id"""
    ticket: bytes = b""
    """ticket"""
    group_id: int | None = None
    """ID of the ECDH group used to establish this session 0 if NA"""
    peer_signature_algorithm: int | None = None
    """signature algorithm used to authenticate the peer, None if NA"""
    early_alpn: bytes | None = None
    """Negotiated ALPN"""
    has_alps: bool = False
    """indicates whether ALPS was negotiated in this session"""
    local_alps: bytes = b""
    """local ALPS"""
    peer_alps: bytes = b""
    """peer ALPS"""
    encrypt_then_mac: bool = False
    """encrypt then mac negotiated for TLSv1.2 below"""
    extended_master_secret: bool = False
    """extended master secret negotiated for TLSv1.2 below"""

    x509_peer: x509.Certificate | None = None
    """peer's certificate"""
    x509_chain: tuple[x509.Certificate, ...] | None = None
    """certificate chain sent by the peer, without leaf certificate"""
    verified_x509_peer: x509.Certificate | None = None
    """verified peer's certificate"""
    verified_x509_chain: tuple[x509.Certificate, ...] | None = None
    """verified certificate chain sent by the peer, without leaf certificate"""
    ocsp_response: bytes = b""
    """OCSP Response"""

    time: datetime = field(default_factory=utcnow)
    """time issued"""
    timeout: timedelta = field(default_factory=lambda: timedelta(days=2))
    """timeout"""
    ticket_age_add: int = 0
    """age added"""
    ticket_max_early_data: int = 0
    """Max early data size can be send after ClientHello for TLSv1.3"""

    def rebase_time(self) -> None:
        now = utcnow()
        if self.time > now:
            self.time = now
            self.timeout = timedelta(seconds=0)

        delta = now - self.time
        if self.timeout < delta:
            self.timeout = timedelta(seconds=0)
        else:
            self.timeout = self.timeout - delta

    def set_timeout(self, timeout: int) -> None:
        delta = timedelta(seconds=timeout)
        if self.timeout > delta:
            self.timeout = delta

    def renew_timeout(self, timeout: int) -> None:
        self.rebase_time()
        delta = timedelta(seconds=timeout)
        if self.timeout > delta:
            return

        self.timeout = delta

    def time_valid(self) -> bool:
        now = utcnow()
        not_valid_before = self.time
        not_valid_after = not_valid_before + self.timeout
        return now >= not_valid_before and now <= not_valid_after

    def obfuscated_age(self) -> int:
        ticket_age = int((utcnow() - self.time).total_seconds() * 1000)
        return (ticket_age + self.ticket_age_add) % (1 << 32)

    def protocol_version(self) -> int:
        assert self.version != TLSVersion.UNSPECIFIED
        return self.version

    def session_type(self) -> TLSSessionType:
        if self.not_resumable:
            return TLSSessionType.not_resumable

        if self.protocol_version() >= TLSVersion.TLSv1_3:
            if self.server_side or self.ticket:
                return TLSSessionType.pre_shared_key
            return TLSSessionType.not_resumable

        if self.ticket:
            return TLSSessionType.session_ticket

        if self.session_id:
            return TLSSessionType.session_id

        return TLSSessionType.not_resumable

    def copy(
        self, include_noauth: bool = False, include_ticket: bool = False
    ) -> TLSSession:
        new = TLSSession(
            server_side=self.server_side,
            not_resumable=True,
            version=self.version,
            secret=self.secret,
            cipher_suite=self.cipher_suite,
            peer_signature_algorithm=self.peer_signature_algorithm,
            time=self.time,
            timeout=self.timeout,
            x509_peer=self.x509_peer,
            x509_chain=self.x509_chain,
            verified_x509_peer=self.verified_x509_peer,
            verified_x509_chain=self.verified_x509_chain,
            ocsp_response=self.ocsp_response,
        )
        if include_noauth:
            new.session_id = self.session_id
            new.group_id = self.group_id
            new.ticket_age_add = self.ticket_age_add
            new.ticket_max_early_data = self.ticket_max_early_data
            new.extended_master_secret = self.extended_master_secret
            new.encrypt_then_mac = self.encrypt_then_mac
            new.has_alps = self.has_alps
            new.early_alpn = self.early_alpn
            new.local_alps = self.local_alps
            new.peer_alps = self.peer_alps
        if include_ticket:
            new.ticket = self.ticket
        return new

    @classmethod
    def from_bytes(self, data: bytes) -> TLSSession:
        parser = Parser(data)

        server_side = bool(parser.read_int(1))
        version = parser.read_int(2)
        cipher_suite = CipherSuite(parser.read_int(2))
        secret = parser.read_prefixed_bytes(2)
        session_id = parser.read_prefixed_bytes(2)
        ticket = parser.read_prefixed_bytes(2)
        time = datetime.fromtimestamp(float(parser.read_int(8)))
        timeout = timedelta(seconds=parser.read_int(8))
        ticket_age_add = parser.read_int(8)
        ticket_max_early_data = parser.read_int(8)

        group_id = parser.read_int(2) or None
        peer_signature_algorithm = parser.read_int(2) or None
        early_alpn = parser.read_prefixed_bytes(2) or None
        local_alps = parser.read_prefixed_bytes(2)
        peer_alps = parser.read_prefixed_bytes(2)
        has_alps = bool(parser.read_int(1))
        encrypt_then_mac = bool(parser.read_int(1))
        extended_master_secret = bool(parser.read_int(1))

        return TLSSession(
            server_side=server_side,
            not_resumable=False,
            version=version,
            cipher_suite=cipher_suite,
            secret=secret,
            session_id=session_id,
            ticket=ticket,
            group_id=group_id,
            peer_signature_algorithm=peer_signature_algorithm,
            early_alpn=early_alpn,
            has_alps=has_alps,
            local_alps=local_alps,
            peer_alps=peer_alps,
            encrypt_then_mac=encrypt_then_mac,
            extended_master_secret=extended_master_secret,
            time=time,
            timeout=timeout,
            ticket_age_add=ticket_age_add,
            ticket_max_early_data=ticket_max_early_data,
        )

    def serialize(self) -> bytes:
        writer = Writer()

        writer.write_int(int(self.server_side), 1)
        writer.write_int(self.version, 2)
        writer.write_int(
            self.cipher_suite.id if self.cipher_suite is not None else 0, 2
        )
        writer.write_prefixed_bytes(self.secret, 2)
        writer.write_prefixed_bytes(self.session_id, 2)
        writer.write_prefixed_bytes(self.ticket, 2)
        writer.write_int(int(self.time.timestamp()), 8)
        writer.write_int(int(self.timeout.total_seconds()), 8)
        writer.write_int(int(self.ticket_age_add), 8)
        writer.write_int(int(self.ticket_max_early_data), 4)

        writer.write_int(self.group_id or 0, 2)
        writer.write_int(self.peer_signature_algorithm or 0, 2)
        writer.write_prefixed_bytes(self.early_alpn or b"", 2)
        writer.write_prefixed_bytes(self.local_alps, 2)
        writer.write_prefixed_bytes(self.peer_alps, 2)
        writer.write_int(int(self.has_alps), 1)
        writer.write_int(int(self.encrypt_then_mac), 1)
        writer.write_int(int(self.extended_master_secret), 1)

        return writer.tobytes()


@dataclasses.dataclass
class SessionKey:
    key_id: bytes  # 16 bytes
    aead_key: bytes  # 32 bytes for AES-256-GCM
    aead: AESGCM

    @classmethod
    def generate(cls) -> SessionKey:
        key_id = get_random_bytes(16)
        aead_key = get_random_bytes(32)
        aead = AESGCM(aead_key)
        return SessionKey(key_id, aead_key, aead)


class TLSSessionKeys:
    def __init__(self) -> None:
        self._keys = [SessionKey.generate()]
        self._current_key = self._keys[0]
        self._lock = threading.Lock()

    def rotate_key(self) -> None:
        with self._lock:
            new_key = SessionKey.generate()
            self._keys.insert(0, new_key)
            self._current_key = new_key
            self._keys = self._keys[:2]  # keep only 2 (current + old)

    def create_ticket(self, session: TLSSession) -> bytes:
        plaintext = session.serialize()
        key = self._current_key
        nonce = get_random_bytes(12)
        ciphertext = key.aead.encrypt(nonce, plaintext, b"")
        return key.key_id + nonce + ciphertext

    def decrypt_ticket(self, ticket_bytes: bytes) -> TLSSession | None:
        try:
            parser = Parser(ticket_bytes)
            key_id = parser.read_bytes(16)
            ciphertext = parser.read_prefixed_bytes(2)
            nonce = parser.read_bytes(12)
        except ParseError:
            return None

        for key in self._keys:
            if not compare_digest(key.key_id, key_id):
                continue
            try:
                plaintext = key.aead.decrypt(nonce, ciphertext, b"")
                return TLSSession.from_bytes(plaintext)
            except Exception:
                pass
        return None


class TLSSessionStorage:
    def __init__(self) -> None:
        self._storage: dict[bytes, TLSSession] = {}

    def get(self, key: bytes) -> TLSSession | None:
        return self._storage.get(key, None)

    def put(self, key: bytes, session: TLSSession) -> None:
        self._storage[key] = session
