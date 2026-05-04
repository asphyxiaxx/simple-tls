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

from .._crypto import utils  # type: ignore

_SupportBytes = typing.Union[bytes, bytearray, memoryview]
_StrOrBytes = typing.Union[_SupportBytes, str]


def byte_length(value: int) -> int:
    return (value.bit_length() + 7) // 8


def bytes_to_int(
    data: _SupportBytes,
    byteorder: typing.Literal["little", "big"] = "big",
    *,
    signed: bool = False,
) -> int:
    return int.from_bytes(data, byteorder, signed=signed)


def int_to_bytes(
    value: int,
    length: int | None = None,
    byteorder: typing.Literal["little", "big"] = "big",
) -> bytes:
    if length is None:
        if value:
            length = byte_length(value)
        else:
            length = 1
    return value.to_bytes(length, byteorder)


@typing.overload
def str_to_bytes(value: None, encoding: str = ...) -> None: ...
@typing.overload
def str_to_bytes(value: _StrOrBytes, encoding: str = ...) -> bytes: ...
def str_to_bytes(
    value: _StrOrBytes | None, encoding: str = "latin-1"
) -> bytes | None:
    if isinstance(value, (bytearray, memoryview)):
        value = bytes(value)
    elif isinstance(value, str):
        value = value.encode(encoding=encoding)
    return value


@typing.overload
def bytes_to_str(value: None, encoding: str = ...) -> None: ...
@typing.overload
def bytes_to_str(value: typing.Any, encoding: str = ...) -> str: ...
def bytes_to_str(
    value: typing.Any | None, encoding: str = "latin-1"
) -> str | None:
    if isinstance(value, (bytes, bytearray)):
        return value.decode(encoding)
    elif isinstance(value, str):
        return value
    return str(value) if value is not None else None


strxor = utils.strxor
