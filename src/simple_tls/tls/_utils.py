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
from os import PathLike
from typing import TypeAlias

from cryptography.hazmat.primitives import hashes

from ._constant import UNSPECIFIED, HashAlgorithm
from ._enum import Protocol
from ._supported import TLS_VERSIONS

Buffer: TypeAlias = bytes | bytearray | memoryview
WritableBuffer: TypeAlias = bytearray | memoryview
StrOrBytesPath: TypeAlias = str | bytes | PathLike[str] | PathLike[bytes]

_T = typing.TypeVar("_T")


@typing.overload
def filter(
    items: typing.Iterable[_T] | None,
    valid_items: typing.Container[_T],
    default_items: typing.Sequence[_T],
) -> tuple[_T, ...]: ...


@typing.overload
def filter(
    items: typing.Iterable[_T] | None,
    valid_items: typing.Container[_T],
    default_items: None = None,
) -> tuple[_T, ...] | None: ...


def filter(
    items: typing.Iterable[_T] | None,
    valid_items: typing.Container[_T],
    default_items: typing.Sequence[_T] | None = None,
) -> tuple[_T, ...] | None:
    if items is not None:
        filtered = tuple(i for i in items if i in valid_items)
        if filtered:
            return filtered
    if default_items is None:
        return None
    return tuple(default_items)


def version_from_wire(protocol: Protocol, version: int) -> int:
    if protocol == Protocol.TLS:
        if version in TLS_VERSIONS:
            return version
    raise ValueError(f"Unknown version {version}")


def version_to_wire(protocol: Protocol, version: int) -> int:
    if protocol == Protocol.TLS:
        if version in TLS_VERSIONS:
            return version
    raise ValueError(f"Unknown version {version}")


def get_algorithm(hash_algorithm: int) -> hashes.HashAlgorithm:
    try:
        return _HASH_ALGORITHMS[hash_algorithm]
    except KeyError:
        raise ValueError(f"Invalid hash_algorithm '{hash_algorithm}'")


def get_hash(
    hash_algorithm: int,
    message: Buffer = b"",
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
