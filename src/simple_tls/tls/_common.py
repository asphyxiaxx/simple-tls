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

from cryptography.hazmat.primitives import hashes

from ._constant import UNSPECIFIED, HashAlgorithm
from ._types import ReadableBuffer


def get_algorithm(hash_algorithm: int) -> hashes.HashAlgorithm:
    try:
        return _HASH_ALGORITHMS[hash_algorithm]
    except KeyError:
        raise ValueError(f"Invalid hash_algorithm '{hash_algorithm}'")


def get_hash(
    hash_algorithm: int,
    message: ReadableBuffer = b"",
) -> hashes.Hash:
    if hash_algorithm == UNSPECIFIED:
        hashobj = typing.cast(hashes.Hash, _MD5SHA1Hash())
    else:
        algorithm = get_algorithm(hash_algorithm)
        hashobj = hashes.Hash(algorithm)

    hashobj.update(message)  # type: ignore
    return hashobj


# Internal


class _MD5SHA1(hashes.HashAlgorithm):
    name = "md5-sha1"
    digest_size = 36
    block_size = 64


class _MD5SHA1Hash:
    def __init__(self) -> None:
        self.__md5 = hashes.Hash(hashes.MD5())
        self.__sha1 = hashes.Hash(hashes.SHA1())
        self.__algorithm = _MD5SHA1()

    @property
    def algorithm(self) -> hashes.HashAlgorithm:
        return self.__algorithm

    def update(self, data: bytes) -> None:
        self.__md5.update(data)
        self.__sha1.update(data)

    def finalize(self) -> bytes:
        return self.__md5.finalize() + self.__sha1.finalize()

    def copy(self) -> _MD5SHA1Hash:
        new = _MD5SHA1Hash()
        new.__md5 = self.__md5.copy()
        new.__sha1 = self.__sha1.copy()
        return new


_HASH_ALGORITHMS: dict[int, hashes.HashAlgorithm] = {
    HashAlgorithm.MD5: hashes.MD5(),
    HashAlgorithm.SHA1: hashes.SHA1(),
    HashAlgorithm.SHA224: hashes.SHA224(),
    HashAlgorithm.SHA256: hashes.SHA256(),
    HashAlgorithm.SHA384: hashes.SHA384(),
    HashAlgorithm.SHA512: hashes.SHA512(),
}
