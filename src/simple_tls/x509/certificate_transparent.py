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

import enum
import typing
from dataclasses import dataclass
from datetime import datetime, timezone

from ..utils.codec import Parser, Writer

__all__ = [
    "LogEntryType",
    "SignedCertificateTimestamp",
]


class LogEntryType(enum.IntEnum):
    X509_CERTIFICATE = 0
    PRE_CERTIFICATE = 1


@dataclass(frozen=True)
class SignedCertificateTimestamp:
    version: int
    log_id: bytes
    log_entry_type: LogEntryType
    timestamp_ms: int
    signature_algorihtm: int
    signature: bytes
    extensions: bytes = b""

    @classmethod
    def parse(
        cls,
        parser: Parser[bytes],
        log_entry_type: LogEntryType,
    ) -> SignedCertificateTimestamp:
        with parser.assert_length(2):
            version = parser.read_int(1)
            log_id = parser.read_bytes(32)
            timestamp_ms = parser.read_int(8)  # milliseconds since the epoch
            extensions = parser.read_prefixed_bytes(2)
            signature_algorithm = parser.read_int(2)
            signature = parser.read_prefixed_bytes(2)

        return SignedCertificateTimestamp(
            version=version,
            log_id=log_id,
            log_entry_type=log_entry_type,
            timestamp_ms=timestamp_ms,
            signature_algorihtm=signature_algorithm,
            signature=signature,
            extensions=extensions,
        )

    def write(self, writer: Writer) -> None:
        sct_writer = Writer()
        sct_writer.write_int(self.version, 1)
        sct_writer.write_bytes(self.log_id)
        sct_writer.write_int(self.timestamp_ms, 8)
        sct_writer.write_prefixed_bytes(self.extensions, 2)
        sct_writer.write_int(self.signature_algorihtm, 2)
        sct_writer.write_prefixed_bytes(self.signature, 2)

        writer.write_prefixed_bytes(sct_writer, 2)

    @property
    def timestamp(self) -> datetime:
        return datetime.fromtimestamp(
            self.timestamp_ms / 1000, tz=timezone.utc
        )


def _parse_signed_certificate_timestamps(
    data: bytes, log_entry_type: LogEntryType
) -> list[SignedCertificateTimestamp]:
    parser = Parser(data)
    scts: list[SignedCertificateTimestamp] = []

    with parser.assert_length(2) as end:
        while parser.tell() < end:
            sct = SignedCertificateTimestamp.parse(parser, log_entry_type)
            scts.append(sct)

    return scts


def _serialize_signed_certificate_timestamps(
    scts: typing.Iterable[SignedCertificateTimestamp],
) -> bytes:
    sct_writer = Writer()
    for sct in scts:
        sct.write(sct_writer)

    writer = Writer()
    writer.write_prefixed_bytes(sct_writer, 2)
    return writer.tobytes()
