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

import abc
import typing
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from cryptography import x509

from simple_tls.utils.codec import Parser, Writer
from simple_tls.utils.misc import utcnow

from ._constant import CipherSuite, TLSVersion
from ._enum import Protocol
from ._utils import Buffer


@dataclass
class TLSSession:
    protocol: Protocol = Protocol.TLS
    """"""
    is_server: bool = False
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
    early_alpn: bytes | None = None
    """Negotiated ALPN"""
    has_alps: bool = False
    """indicates whether ALPS was negotiated in this session"""
    local_alps: bytes = b""
    """local ALPS"""
    peer_alps: bytes = b""
    """peer ALPS"""
    extended_master_secret: bool = False
    """extended master secret negotiated for TLSv1.2 below"""
    ticket_max_early_data: int = 0
    """Max early data size can be send after ClientHello for TLSv1.3"""
    time: datetime = field(default_factory=utcnow)
    """time issued"""
    timeout: timedelta = field(default_factory=lambda: timedelta(days=2))
    """timeout"""
    ticket_age_add: int = 0
    """age added"""

    x509_peer: x509.Certificate | None = None
    """peer's certificate"""
    x509_chain: tuple[x509.Certificate, ...] | None = None
    """certificate chain sent by the peer, without leaf certificate"""
    verified_x509_peer: x509.Certificate | None = None
    """verified peer's certificate"""
    verified_x509_chain: tuple[x509.Certificate, ...] | None = None
    """verified certificate chain sent by the peer, without leaf certificate"""
    ocsp_response: bytes | None = None
    """OCSP Response"""

    def rebase_time(self) -> None:
        now = utcnow()
        if self.time > now:
            self.time = now
            self.timeout = timedelta(seconds=0)
            return

        delta = now - self.time
        self.time = now
        if self.timeout < delta:
            self.timeout = timedelta(seconds=0)
        else:
            self.timeout -= delta

    def set_timeout(self, timeout: int) -> None:
        delta = timedelta(seconds=timeout)
        if self.timeout > delta:
            self.timeout = delta

    def renew_timeout(self, timeout: int) -> None:
        self.rebase_time()
        delta = timedelta(seconds=timeout)
        if self.timeout <= delta:
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

    def copy(
        self, include_noauth: bool = False, include_ticket: bool = False
    ) -> TLSSession:
        new = TLSSession(
            protocol=self.protocol,
            is_server=self.is_server,
            not_resumable=True,
            version=self.version,
            secret=self.secret,
            cipher_suite=self.cipher_suite,
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
            new.ticket_age_add = self.ticket_age_add
            new.ticket_max_early_data = self.ticket_max_early_data
            new.extended_master_secret = self.extended_master_secret
            new.has_alps = self.has_alps
            new.early_alpn = self.early_alpn
            new.local_alps = self.local_alps
            new.peer_alps = self.peer_alps
        if include_ticket:
            new.ticket = self.ticket
        return new

    @classmethod
    def from_bytes(cls, data: bytes) -> TLSSession:
        parser = Parser(data)

        protocol = Protocol(parser.read_int(1))
        is_server = bool(parser.read_int(1))
        version = parser.read_int(2)
        cipher_suite = CipherSuite(parser.read_int(2))
        secret = parser.read_prefixed_bytes(2)
        session_id = parser.read_prefixed_bytes(2)
        ticket = parser.read_prefixed_bytes(2)
        time = datetime.fromtimestamp(
            float(parser.read_int(8)), tz=timezone.utc
        )
        timeout = timedelta(seconds=parser.read_int(8))
        ticket_age_add = parser.read_int(4)
        ticket_max_early_data = parser.read_int(4)

        early_alpn = parser.read_prefixed_bytes(2) or None
        local_alps = parser.read_prefixed_bytes(2)
        peer_alps = parser.read_prefixed_bytes(2)
        has_alps = bool(parser.read_int(1))
        extended_master_secret = bool(parser.read_int(1))

        return TLSSession(
            protocol=protocol,
            is_server=is_server,
            not_resumable=False,
            version=version,
            cipher_suite=cipher_suite,
            secret=secret,
            session_id=session_id,
            ticket=ticket,
            early_alpn=early_alpn,
            has_alps=has_alps,
            local_alps=local_alps,
            peer_alps=peer_alps,
            extended_master_secret=extended_master_secret,
            time=time,
            timeout=timeout,
            ticket_age_add=ticket_age_add,
            ticket_max_early_data=ticket_max_early_data,
        )

    def serialize(self) -> bytes:
        writer = Writer()

        writer.write_int(self.protocol.value, 1)
        writer.write_int(int(self.is_server), 1)
        writer.write_int(self.version, 2)
        writer.write_int(
            self.cipher_suite.id if self.cipher_suite is not None else 0, 2
        )
        writer.write_prefixed_bytes(self.secret, 2)
        writer.write_prefixed_bytes(self.session_id, 2)
        writer.write_prefixed_bytes(self.ticket, 2)
        writer.write_int(int(self.time.timestamp()), 8)
        writer.write_int(int(self.timeout.total_seconds()), 8)
        writer.write_int(int(self.ticket_age_add), 4)
        writer.write_int(int(self.ticket_max_early_data), 4)

        writer.write_prefixed_bytes(self.early_alpn or b"", 2)
        writer.write_prefixed_bytes(self.local_alps, 2)
        writer.write_prefixed_bytes(self.peer_alps, 2)
        writer.write_int(int(self.has_alps), 1)
        writer.write_int(int(self.extended_master_secret), 1)

        return writer.tobytes()


class TicketAEAD(typing.Protocol):
    """Protocol-agnostic ticket AEAD interface"""

    @abc.abstractmethod
    def seal(self, plaintext: bytes) -> Buffer | None:
        """Encrypts raw session bytes into an opaque ticket payload."""
        ...

    @abc.abstractmethod
    def open(self, ticket: bytes) -> Buffer | None:
        """Decrypts ticket payload back into raw session bytes."""
        ...
