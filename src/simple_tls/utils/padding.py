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

__all__ = ["pad_pkcs7", "unpad_pkcs7"]


def pad_pkcs7(data: bytes, block_length: int) -> bytes:
    padding_len = block_length - len(data) % block_length
    return b"".join((data, bytes([padding_len]) * padding_len))


def unpad_pkcs7(data: bytes, block_length: int) -> bytes:
    data_len = len(data)

    if data_len % block_length != 0:
        raise ValueError("data is not padded")

    padding_len = data[-1]
    if padding_len > data_len:
        raise ValueError("Invalid padding length")

    padding_bytes = data[-padding_len:]
    expected_padding_bytes = bytes([padding_len]) * padding_len
    if padding_bytes != expected_padding_bytes:
        raise ValueError("Invalid padding")

    return data[:-padding_len]
