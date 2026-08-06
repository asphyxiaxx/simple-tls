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
from _ssl import txt2obj as _txt2obj
from datetime import datetime
from typing import Annotated, TypeAlias

_T = typing.TypeVar("_T")


class Marker(enum.IntEnum):
    ANY = enum.auto()
    SET_OF = enum.auto()
    ENUMERATED = enum.auto()
    NUMERIC_STRING = enum.auto()
    PRINTABLE_STRING = enum.auto()
    TELETEX_STRING = enum.auto()
    VIDEOTEX_STRING = enum.auto()
    IA5_STRING = enum.auto()
    GRAPHIC_STRING = enum.auto()
    VISIBLE_STRING = enum.auto()
    GENERAL_STRING = enum.auto()
    BMP_STRING = enum.auto()
    UTC_TIME = enum.auto()
    GENERAL_TIME = enum.auto()


Any: TypeAlias = Annotated[bytes, Marker.ANY]
Boolean: TypeAlias = bool
Integer: TypeAlias = int
OctetString: TypeAlias = bytes
Real: TypeAlias = float
Enumerated: TypeAlias = Annotated[int, Marker.ENUMERATED]
UTF8String: TypeAlias = str
NumericString: TypeAlias = Annotated[str, Marker.NUMERIC_STRING]
PrintableString: TypeAlias = Annotated[str, Marker.PRINTABLE_STRING]
TeletexString: TypeAlias = Annotated[str, Marker.TELETEX_STRING]
VideotexString: TypeAlias = Annotated[str, Marker.VIDEOTEX_STRING]
IA5String: TypeAlias = Annotated[str, Marker.IA5_STRING]
GraphicString: TypeAlias = Annotated[str, Marker.GRAPHIC_STRING]
VisibleString: TypeAlias = Annotated[str, Marker.VISIBLE_STRING]
GeneralString: TypeAlias = Annotated[str, Marker.GENERAL_STRING]
BMPString: TypeAlias = Annotated[str, Marker.BMP_STRING]
UTCTime: TypeAlias = Annotated[datetime, Marker.UTC_TIME]
GeneralizedTime: TypeAlias = Annotated[datetime, Marker.GENERAL_TIME]
SequenceOf: TypeAlias = list[_T]
SetOf: TypeAlias = Annotated[list[_T], Marker.SET_OF]


class BitString:
    def __init__(self, data: bytes, unused_bits: int) -> None:
        if not (0 <= unused_bits <= 7):
            raise ValueError("Unused bits not within 0 to 7")

        self._data = data
        self._unused_bits = unused_bits

    def as_bits(self) -> list[bool]:
        payload = self.data
        total_bits = (len(payload) * 8) - self.unused_bits
        return [
            (payload[i // 8] & (1 << (7 - (i % 8)))) != 0
            for i in range(total_bits)
        ]

    @classmethod
    def from_bits(cls, bits: typing.Iterable[bool]) -> BitString:
        bits = list(bits)

        idx = 0
        for b in reversed(bits):
            if b:
                break
            idx += 1

        bits = bits[: len(bits) - idx]
        bit_len = len(bits)
        unused_bits = (8 - (bit_len % 8)) % 8

        full_bytes = (bit_len + 7) // 8
        bit_bytes = bytearray(full_bytes)
        for i, bit in enumerate(bits):
            byte_index = i // 8
            bit_index = 7 - (i % 8)
            if bit:
                bit_bytes[byte_index] |= 1 << bit_index

        return BitString(bytes(bit_bytes), unused_bits)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, BitString):
            return NotImplemented
        return (
            self.data == other.data and self.unused_bits == other.unused_bits
        )

    def __hash__(self) -> int:
        return hash((self.data, self.unused_bits))

    def __repr__(self) -> str:
        return (
            f"<BitString(data={self.data!r}, unused_bits={self.unused_bits})>"
        )

    @property
    def data(self) -> bytes:
        return self._data

    @property
    def unused_bits(self) -> int:
        return self._unused_bits


class Null:
    _SENTINEL = object()

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Null):
            return NotImplemented
        return True

    def __hash__(self) -> int:
        return hash(self._SENTINEL)

    def __repr__(self) -> str:
        return "<Null()>"


class ObjectIdentifier:
    def __init__(self, dotted_string: str) -> None:
        try:
            _, name, short_name, _ = _txt2obj(dotted_string)
        except ValueError as exc:
            if str(exc) == "Unknown object":
                name = "Unknown OID"
                short_name = "Unknown OID"
            else:
                raise

        self._name = name
        self._short_name = short_name
        self._oid = dotted_string

    def __eq__(self, other: object) -> bool:
        if isinstance(other, ObjectIdentifier):
            return self.dotted_string == other.dotted_string
        if isinstance(other, str):
            return self.dotted_string == other
        return NotImplemented

    def __hash__(self) -> int:
        return hash(self.dotted_string)

    def __repr__(self) -> str:
        return (
            f"<ObjectIdentifier(oid={self.dotted_string}, name={self.name})>"
        )

    @property
    def dotted_string(self) -> str:
        return self._oid

    @property
    def name(self) -> str:
        return self._name

    @property
    def short_name(self) -> str:
        return self._short_name
