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

from .._crypto import mlkem  # type: ignore
from ..io._serialization import (
    Encoding,
    KeySerializationEncryption,
    PrivateFormat,
    PublicFormat,
)
from ..utils.random import get_random_bytes


class MLKEM768PublicKey:
    def __init__(self, *, _pk: bytes) -> None:
        if len(_pk) != 1184:
            raise ValueError("public key not 1184 bytes")
        self._pk = _pk

    @classmethod
    def from_public_bytes(cls, data: bytes) -> MLKEM768PublicKey:
        return MLKEM768PublicKey(_pk=data)

    def encapsulate(self) -> tuple[bytes, bytes]:
        """
        Generates shared secret and cipher text for given public key

        :param pk: public key received
        :type pk: bytes
        :return: shared secret and cipher text
        :rtype: tuple[bytes, bytes]
        """
        coins = get_random_bytes(32)
        ct, ss = mlkem.encaps(768, self._pk, coins)
        return ss, ct

    def public_bytes(
        self,
        encoding: Encoding,
        format: PublicFormat,
    ) -> bytes:
        raise NotImplementedError

    def public_bytes_raw(self) -> bytes:
        return self._pk


class MLKEM768PrivateKey:
    def __init__(self, *, _pk: bytes, _sk: bytes) -> None:
        self._pk = _pk
        self._sk = _sk

    @classmethod
    def generate(cls) -> MLKEM768PrivateKey:
        seed = get_random_bytes(64)
        return cls.from_seed_bytes(seed)

    @classmethod
    def from_seed_bytes(cls, data: bytes) -> MLKEM768PrivateKey:
        if len(data) != 64:
            raise ValueError("seed not 64 bytes")
        pk, sk = mlkem.keygen(768, data)
        return MLKEM768PrivateKey(_pk=pk, _sk=sk)

    def public_key(self) -> MLKEM768PublicKey:
        return MLKEM768PublicKey(_pk=self._pk)

    def decapsulate(self, ciphertext: bytes) -> bytes:
        """
        Generates shared secret from given cipher text

        :param ciphertext: cipher text recevied
        :type ciphertext: bytes
        :return: shared secret
        :rtype: bytes
        """
        return mlkem.decaps(768, ciphertext, self._sk)

    def private_bytes(
        self,
        encoding: Encoding,
        format: PrivateFormat,
        encryption_algorithm: KeySerializationEncryption,
    ) -> bytes:
        raise NotImplementedError

    def private_bytes_raw(self) -> bytes:
        return self._sk


class MLKEM1024PublicKey:
    def __init__(self, *, _pk: bytes) -> None:
        if len(_pk) != 1568:
            raise ValueError("public key not 1568 bytes")
        self._pk = _pk

    @classmethod
    def from_public_bytes(cls, data: bytes) -> MLKEM1024PublicKey:
        return MLKEM1024PublicKey(_pk=data)

    def encapsulate(self) -> tuple[bytes, bytes]:
        """
        Generates shared secret and cipher text for given public key

        :param pk: public key received
        :type pk: bytes
        :return: shared secret and cipher text
        :rtype: tuple[bytes, bytes]
        """
        coins = get_random_bytes(32)
        ct, ss = mlkem.encaps(1024, self._pk, coins)
        return ss, ct

    def public_bytes(
        self,
        encoding: Encoding,
        format: PublicFormat,
    ) -> bytes:
        raise NotImplementedError

    def public_bytes_raw(self) -> bytes:
        return self._pk


class MLKEM1024PrivateKey:
    def __init__(self, *, _pk: bytes, _sk: bytes) -> None:
        self._pk = _pk
        self._sk = _sk

    @classmethod
    def generate(cls) -> MLKEM1024PrivateKey:
        seed = get_random_bytes(64)
        return cls.from_seed_bytes(seed)

    @classmethod
    def from_seed_bytes(cls, data: bytes) -> MLKEM1024PrivateKey:
        if len(data) != 64:
            raise ValueError("seed not 64 bytes")
        pk, sk = mlkem.keygen(1024, data)
        return MLKEM1024PrivateKey(_pk=pk, _sk=sk)

    def public_key(self) -> MLKEM1024PublicKey:
        return MLKEM1024PublicKey(_pk=self._pk)

    def decapsulate(self, ciphertext: bytes) -> bytes:
        """
        Generates shared secret from given cipher text

        :param ciphertext: cipher text recevied
        :type ciphertext: bytes
        :return: shared secret
        :rtype: bytes
        """
        return mlkem.decaps(1024, ciphertext, self._sk)

    def private_bytes(
        self,
        encoding: Encoding,
        format: PrivateFormat,
        encryption_algorithm: KeySerializationEncryption,
    ) -> bytes:
        raise NotImplementedError

    def private_bytes_raw(self) -> bytes:
        return self._sk
