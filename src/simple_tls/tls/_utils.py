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

import ipaddress
import typing
from datetime import datetime, timezone
from os import PathLike
from typing import TypeAlias

from cryptography.hazmat.primitives import hashes, hmac

from simple_tls.codec import Writer
from simple_tls.crypto.kdf import hkdf_expand
from simple_tls.crypto.utils import strxor

from ._constant import UNSPECIFIED, HashAlgorithm
from ._enum import Protocol
from ._supported import TLS_VERSIONS

Buffer: TypeAlias = bytes | bytearray | memoryview
WritableBuffer: TypeAlias = bytearray | memoryview
StrOrBytesPath: TypeAlias = str | bytes | PathLike[str] | PathLike[bytes]

_T = typing.TypeVar("_T")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


@typing.overload
def negotiate(
    supported: typing.Iterable[_T],
    offered: typing.Iterable[typing.Any] | None,
    exception: None = None,
) -> _T | None: ...


@typing.overload
def negotiate(
    supported: typing.Iterable[_T],
    offered: typing.Iterable[typing.Any] | None,
    exception: Exception = ...,
) -> _T: ...


def negotiate(
    supported: typing.Iterable[_T],
    offered: typing.Iterable[typing.Any] | None,
    exception: Exception | None = None,
) -> _T | None:
    if offered is not None:
        for item in supported:
            if item in offered:
                return item
    if exception is not None:
        raise exception
    return None


def is_valid_sni(server_hostname: str) -> bool:
    # must be a non-empty string
    if (
        not server_hostname
        or not isinstance(server_hostname, str)
        or server_hostname.startswith(".")
        or server_hostname.endswith(".")
    ):
        raise ValueError(
            "server_hostname cannot be an empty or start with a leading dot."
        )

    # RFC 6066 explicitly forbids literal IP addresses in SNI
    try:
        ipaddress.ip_address(server_hostname)
        # If this succeeds, it's an IP address, which is INVALID for SNI
        return False
    except ValueError:
        pass  # Not an IP address, proceed to next checks

    # max 253 characters for a domain name
    if len(server_hostname) > 253:
        raise ValueError("SNI hostname is too long")

    return True


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


def prf(
    secret: bytes,
    label: bytes,
    seed: bytes,
    length: int,
    algorithm: hashes.HashAlgorithm | None,
) -> bytes:
    seed = label + seed

    if algorithm is None:
        secret_len = len(secret)
        s1 = secret[: ((secret_len + 1) // 2)]
        s2 = secret[(secret_len // 2) :]
        p_md5 = _prf_hash(s1, seed, length, hashes.MD5())
        p_sha1 = _prf_hash(s2, seed, length, hashes.SHA1())
        return strxor(p_md5, p_sha1)
    else:
        return _prf_hash(secret, seed, length, algorithm)


def hkdf_expand_label(
    secret: bytes,
    label: bytes,
    data: bytes,
    length: int,
    algorithm: hashes.HashAlgorithm,
) -> bytes:
    """
    TLS 1.3 key derivation function (HKDF-Expand-Label).
    """
    hkdf_label = Writer()
    hkdf_label.write_int(length, 2)
    hkdf_label.write_prefixed_bytes(b"tls13 " + label, 1)
    hkdf_label.write_prefixed_bytes(data, 1)
    info = hkdf_label.tobytes()
    return hkdf_expand(secret, info, length, algorithm)


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


def _prf_hash(
    secret: bytes,
    seed: bytes,
    length: int,
    algorithm: hashes.HashAlgorithm,
) -> bytes:
    out = []
    prev = seed
    index = 0
    mac = hmac.HMAC(secret, algorithm)
    while index < length:
        a_func = mac.copy()
        a_func.update(prev)
        prev = a_func.finalize()

        m = mac.copy()
        m.update(prev)
        m.update(seed)
        digest = m.finalize()

        n = min(length - index, len(digest))
        out.append(digest[:n])
        index += n

    return b"".join(out)


_HASH_ALGORITHMS: dict[int, hashes.HashAlgorithm] = {
    HashAlgorithm.MD5: hashes.MD5(),
    HashAlgorithm.SHA1: hashes.SHA1(),
    HashAlgorithm.SHA224: hashes.SHA224(),
    HashAlgorithm.SHA256: hashes.SHA256(),
    HashAlgorithm.SHA384: hashes.SHA384(),
    HashAlgorithm.SHA512: hashes.SHA512(),
}
