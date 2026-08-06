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

import math
import struct
import typing
from datetime import datetime, timezone

from ...utils.math import bytes_to_int
from ._errors import InvalidPayload, InvalidType, InvalidValue
from ._types import BitString, Marker, Null, ObjectIdentifier


class PrimitiveCodec:
    tag_id: typing.ClassVar[int | None]

    @classmethod
    def decode_value(cls, data: bytes) -> typing.Any:
        raise NotImplementedError

    @classmethod
    def encode_value(cls, value: typing.Any) -> bytes:
        raise NotImplementedError


class AnyCodec(PrimitiveCodec):
    tag_id = None

    @classmethod
    def decode_value(cls, data: bytes) -> typing.Any:
        return data

    @classmethod
    def encode_value(cls, value: typing.Any) -> bytes:
        if not isinstance(value, bytes):
            raise InvalidType(
                f"DER ANY: value should be bytes (not '{type(value)}')"
            )
        return value


class BooleanCodec(PrimitiveCodec):
    tag_id = 0x01

    @classmethod
    def decode_value(cls, data: bytes) -> typing.Any:
        if len(data) != 1:
            raise InvalidPayload("DER BOOLEAN: payload is not 1 byte")

        value = data[0]
        if value == 0:
            return False
        if value == 0xFF:
            return True
        raise InvalidPayload("DER BOOLEAN: payload not '0x00' or '0xFF'")

    @classmethod
    def encode_value(cls, value: typing.Any) -> bytes:
        if not isinstance(value, bool):
            raise InvalidType(
                f"DER BOOLEAN: value should be bool (not '{type(value)}')"
            )
        return b"\xff" if value else b"\x00"


class IntegerCodec(PrimitiveCodec):
    tag_id = 0x02

    @classmethod
    def decode_value(cls, data: bytes) -> typing.Any:
        if not data:
            raise InvalidPayload("DER INTEGER: Empty payload")
        if len(data) >= 2 and struct.unpack(">H", data[:2])[0] < 0x80:
            raise InvalidPayload("DER INTEGER: Leading zero")
        return bytes_to_int(data, "big", signed=True)

    @classmethod
    def encode_value(cls, value: typing.Any) -> bytes:
        if not isinstance(value, int) or isinstance(value, bool):
            raise InvalidType(
                f"DER INTEGER: value should be int (not '{type(value)}')"
            )

        length = (value.bit_length() + 8) // 8
        return value.to_bytes(length, "big", signed=True)


class BitStringCodec(PrimitiveCodec):
    tag_id = 0x03

    @classmethod
    def decode_value(cls, data: bytes) -> typing.Any:
        # missing the unused_bits byte
        if len(data) == 0:
            raise InvalidPayload("DER BIT STRING: Missing unused byte")

        unused_bits = data[0]
        payload = data[1:]

        if unused_bits > 7:
            raise InvalidPayload(
                "DER BIT STRING: Unused bits not within 0 to 7"
            )
        if len(payload) == 0 and unused_bits > 0:
            raise InvalidPayload(
                "DER BIT STRING: Cannot have unused bits with no payload"
            )

        return BitString(payload, unused_bits)

    @classmethod
    def encode_value(cls, value: typing.Any) -> bytes:
        if not isinstance(value, BitString):
            raise InvalidType(
                f"DER BIT STRING: value should be BitString object "
                f"(not '{type(value)}')"
            )
        return bytes([value.unused_bits]) + value.data


class OctetStringCodec(PrimitiveCodec):
    tag_id = 0x04

    @classmethod
    def decode_value(cls, data: bytes) -> bytes:
        return data

    @classmethod
    def encode_value(cls, value: typing.Any) -> bytes:
        if not isinstance(value, bytes):
            raise InvalidType(
                f"DER OCTET STRING: value should be bytes "
                f"(not '{type(value)}')"
            )
        return value


class NullCodec(PrimitiveCodec):
    tag_id = 0x05

    @classmethod
    def decode_value(cls, data: bytes) -> Null:
        if len(data) != 0:
            raise InvalidPayload("DER NULL: Extra payload")
        return Null()

    @classmethod
    def encode_value(cls, value: typing.Any) -> bytes:
        if not isinstance(value, Null):
            raise InvalidType(
                f"DER NULL: value should be Null object (not '{type(value)}')"
            )
        return b""


class ObjectIdentifierCodec(PrimitiveCodec):
    tag_id = 0x06

    @classmethod
    def decode_value(cls, data: bytes) -> ObjectIdentifier:
        if len(data) == 0:
            raise InvalidPayload("DER OID: Empty payload")

        first = data[0]
        oid = [first // 40, first % 40]
        val = 0
        for b in data[1:]:
            val = (val << 7) | (b & 0x7F)
            if not b & 0x80:
                oid.append(val)
                val = 0

        return ObjectIdentifier(".".join(map(str, oid)))

    @classmethod
    def encode_value(cls, value: typing.Any) -> bytes:
        if not isinstance(value, ObjectIdentifier):
            raise InvalidType(
                f"DER OID: value should be ObjectIdentifier object "
                f"(not '{type(value)}')"
            )

        oid = value.dotted_string
        comps = [int(x) for x in oid.split(".")]

        if len(comps) < 2:
            raise InvalidValue("DER OID: Not a valid string")
        if comps[0] > 2:
            raise InvalidValue(
                "DER OID: First component must be within 0 to 2"
            )
        if comps[0] < 2 and comps[1] > 39:
            raise InvalidValue(
                "DER OID: Second component must be less than 39"
            )

        subcomps = [40 * comps[0] + comps[1], *comps[2:]]
        encoding = bytearray()

        for v in reversed(subcomps):
            encoding.append(v & 0x7F)
            v >>= 7
            while v:
                encoding.append((v & 0x7F) | 0x80)
                v >>= 7

        encoding.reverse()
        return bytes(encoding)


class RealCodec(PrimitiveCodec):
    tag_id = 0x09

    @classmethod
    def decode_value(cls, data: bytes) -> float:
        if len(data) == 0:
            return 0.0

        first = data[0]

        if first == 0x40:
            return float("inf")
        if first == 0x41:
            return float("-inf")
        if first == 0x42:
            return float("nan")  # allowed but uncommon

        if first & 0x80 == 0:
            raise ValueError("DER REAL: decimal encoding not allowed")

        # Binary encoding
        # Sign bit is Bit 7 (0x40)
        sign = -1 if (first & 0x40) else 1

        base = (first >> 4) & 0x03
        if base != 0:
            raise ValueError("DER REAL: only base-2 allowed")

        scale = (first >> 2) & 0x03
        if scale != 0:
            raise ValueError("DER REAL: scaling factor must be 0")

        # Exponent length is Bits 2 and 1
        exp_len_code = first & 0x03
        idx = 1

        # Exponent length
        if exp_len_code == 0:
            exp_len = 1
        elif exp_len_code == 1:
            exp_len = 2
        elif exp_len_code == 2:
            exp_len = 3
        else:
            if idx >= len(data):
                raise ValueError("DER REAL: Invalid REAL encoding")
            exp_len = data[idx]
            idx += 1

        if idx + exp_len > len(data):
            raise ValueError("DER REAL: Invalid exponent length")

        exponent_bytes = data[idx : idx + exp_len]
        exponent = int.from_bytes(exponent_bytes, "big", signed=True)
        idx += exp_len

        # Mantissa
        mantissa_bytes = data[idx:]
        if not mantissa_bytes:
            raise ValueError("DER REAL: missing mantissa")

        mantissa = int.from_bytes(mantissa_bytes, "big")

        # Mantissa must be odd (no trailing zero bits)
        if mantissa & 1 == 0:
            raise ValueError("DER REAL: mantissa not normalized")

        # Exponent must be minimally encoded (no leading 0x00 or 0xFF padding)
        if len(exponent_bytes) > 1:
            if exponent_bytes[0] == 0x00 and exponent_bytes[1] & 0x80 == 0:
                raise ValueError("DER REAL: non-minimal exponent encoding")
            if exponent_bytes[0] == 0xFF and exponent_bytes[1] & 0x80 == 0x80:
                raise ValueError("DER REAL: non-minimal exponent encoding")

        # mantissa * (2**exponent)
        return math.ldexp(sign * mantissa, exponent)

    @classmethod
    def encode_value(cls, value: typing.Any) -> bytes:
        if not isinstance(value, float):
            raise ValueError(
                f"DER REAL: value should be float object (not '{type(value)}')"
            )

        # Special values
        if math.isinf(value):
            return b"\x40" if value > 0 else b"\x41"
        if math.isnan(value):
            raise ValueError("DER REAL: NaN not allowed")
        if value == 0.0:
            return b""

        sign_bit = 0 if value >= 0 else 1
        value = abs(value)

        # Decompose
        mantissa, exponent = math.frexp(value)
        # value = mantissa * 2^exponent, mantissa ∈ [0.5, 1)

        # Convert float mantissa → 53-bit integer
        mantissa *= 1 << 53
        exponent -= 53
        mantissa = int(mantissa)

        # Normalize (no trailing zeros for DER)
        while mantissa & 1 == 0:
            mantissa >>= 1
            exponent += 1

        # minimal two's complement encoding for the exponent length
        exp_byte_len = ((exponent + (exponent < 0)).bit_length() + 8) // 8
        exp_bytes = exponent.to_bytes(exp_byte_len, "big", signed=True)

        # Encode mantissa (positive integer, minimal)
        mant_byte_len = (mantissa.bit_length() + 7) // 8
        mant_bytes = mantissa.to_bytes(mant_byte_len, "big")

        # Shift the sign bit into Bit 7 (0x40) position
        first = 0x80 | (sign_bit << 6)

        # Set the correct bits for Exponent length
        if len(exp_bytes) == 1:
            pass  # Bits 2,1 remain 00
        elif len(exp_bytes) == 2:
            first |= 0x01
        elif len(exp_bytes) == 3:
            first |= 0x02
        else:
            first |= 0x03
            exp_bytes = bytes([len(exp_bytes)]) + exp_bytes

        return bytes([first]) + exp_bytes + mant_bytes


class EnumeratedCodec(PrimitiveCodec):
    tag_id = 0x0A

    @classmethod
    def decode_value(cls, data: bytes) -> typing.Any:
        if not data:
            raise InvalidPayload("DER ENUMTERAED: Empty payload")
        if len(data) >= 2 and struct.unpack(">H", data[:2])[0] < 0x80:
            raise InvalidPayload("DER ENUMTERAED: Leading zero")
        return bytes_to_int(data, "big", signed=True)

    @classmethod
    def encode_value(cls, value: typing.Any) -> bytes:
        if not isinstance(value, int) or isinstance(value, bool):
            raise InvalidType(
                f"DER ENUMTERAED: value should be int (not '{type(value)}')"
            )

        length = (value.bit_length() + 8) // 8
        return value.to_bytes(length, "big", signed=True)


class CharacterStringCodec(PrimitiveCodec):
    encoding: typing.ClassVar[str]

    @classmethod
    def decode_value(cls, data: bytes) -> str:
        try:
            return str(data, encoding=cls.encoding)
        except UnicodeDecodeError as exc:
            raise InvalidPayload(
                f"DER STRING: Unable to decode with {cls.encoding}"
            ) from exc

    @classmethod
    def encode_value(cls, value: typing.Any) -> bytes:
        if not isinstance(value, str):
            raise InvalidType(
                f"DER STRING: value should be str (not '{type(value)}')"
            )

        try:
            return bytes(value, encoding=cls.encoding)
        except UnicodeEncodeError as exc:
            raise InvalidValue(f"DER STRING: {exc!s}") from exc


class UTF8StringCodec(CharacterStringCodec):
    tag_id = 0x0C
    encoding = "utf-8"


class NumericStringCodec(CharacterStringCodec):
    tag_id = 0x12
    encoding = "us-ascii"


class PrintableStringCodec(CharacterStringCodec):
    tag_id = 0x13
    encoding = "us-ascii"


class TeletexStringCodec(CharacterStringCodec):
    tag_id = 0x14
    encoding = "iso-8859-1"


class VideotexStringCodec(CharacterStringCodec):
    tag_id = 0x15
    encoding = "iso-8859-1"


class IA5StringCodec(CharacterStringCodec):
    tag_id = 0x16
    encoding = "us-ascii"


class GraphicStringCodec(CharacterStringCodec):
    tag_id = 0x19
    encoding = "iso-8859-1"


class VisibleStringCodec(CharacterStringCodec):
    tag_id = 0x1A
    encoding = "us-ascii"


class GeneralStringCodec(CharacterStringCodec):
    tag_id = 0x1B
    encoding = "iso-8859-1"


class BMPStringCodec(CharacterStringCodec):
    tag_id = 0x1E
    encoding = "utf-16-be"


class TimeCodec(PrimitiveCodec):
    format: typing.ClassVar[str]

    @classmethod
    def decode_value(cls, data: bytes) -> datetime:
        date_string = str(data, encoding="utf-8")
        try:
            dt = datetime.strptime(date_string, cls.format)
        except ValueError as exc:
            raise InvalidPayload(f"DER TIME: {exc!s}") from exc
        return dt.replace(tzinfo=timezone.utc)

    @classmethod
    def encode_value(cls, value: typing.Any) -> bytes:
        if not isinstance(value, datetime):
            raise InvalidType(
                f"DER TIME: value should be datetime.datetime "
                f"(not '{type(value)}')"
            )

        dt = value
        if not dt.tzinfo:
            dt = dt.replace(tzinfo=timezone.utc)

        dt = dt.astimezone(timezone.utc)
        return dt.strftime(cls.format).encode("ascii")


class UTCTimeCodec(TimeCodec):
    tag_id = 0x17
    format = "%y%m%d%H%M%SZ"


class GeneralizedTimeCodec(TimeCodec):
    tag_id = 0x18
    format = "%Y%m%d%H%M%SZ"


PRIMITIC_CODECS: dict[tuple[type, Marker | None], type[PrimitiveCodec]] = {
    (bytes, Marker.ANY): AnyCodec,
    (bool, None): BooleanCodec,
    (int, None): IntegerCodec,
    (BitString, None): BitStringCodec,
    (bytes, None): OctetStringCodec,
    (Null, None): NullCodec,
    (float, None): RealCodec,
    (ObjectIdentifier, None): ObjectIdentifierCodec,
    (int, Marker.ENUMERATED): EnumeratedCodec,
    (str, None): UTF8StringCodec,
    (str, Marker.NUMERIC_STRING): NumericStringCodec,
    (str, Marker.PRINTABLE_STRING): PrintableStringCodec,
    (str, Marker.TELETEX_STRING): TeletexStringCodec,
    (str, Marker.VIDEOTEX_STRING): VideotexStringCodec,
    (str, Marker.IA5_STRING): IA5StringCodec,
    (str, Marker.GRAPHIC_STRING): GraphicStringCodec,
    (str, Marker.VISIBLE_STRING): VisibleStringCodec,
    (str, Marker.GENERAL_STRING): GeneralStringCodec,
    (str, Marker.BMP_STRING): BMPStringCodec,
    (datetime, Marker.UTC_TIME): UTCTimeCodec,
    (datetime, Marker.GENERAL_TIME): GeneralizedTimeCodec,
}
