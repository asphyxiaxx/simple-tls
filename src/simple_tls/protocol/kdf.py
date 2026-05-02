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

import struct
import typing
from dataclasses import dataclass
from hashlib import pbkdf2_hmac, scrypt

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf import hkdf

from ..utils.math import strxor

__all__ = [
    "PBKDF1",
    "PBKDF2HMAC",
    "Bcrypt",
    "Scrypt",
    "hkdf_expand",
    "hkdf_extract",
]


@dataclass(frozen=True)
class PBKDF1:
    algorithm: hashes.HashAlgorithm
    length: int
    salt: bytes
    iterations: int = 1000

    def __post_init__(self) -> None:
        if len(self.salt) != 8:
            raise ValueError("salt must be 8 bytes long")
        if self.length > self.algorithm.digest_size:
            raise ValueError(
                f"length too long for given algorithm ({self.algorithm.name})"
            )

    def derive(self, password: bytes) -> bytes:
        """
        :params bytes password:
            an octet string
        :params bytes salt:
            an eight-octet string
        :params int count:
            iteration count, a positive integer
        :params int dklen:
            intended length in octets of derived key
        :params type[hashes.Hash]:
            underlying hash function

        Reference: https://datatracker.ietf.org/doc/html/rfc2898#section-5.1
        """

        # Apply the underlying hash function Hash for c iterations to the
        # concatenation of the password P and the salt S, then extract
        # the first dkLen octets to produce a derived key DK:
        #   T_1 = Hash (P || S) ,
        #   T_2 = Hash (T_1) ,
        #   ...
        #   T_c = Hash (T_{c-1}) ,
        #   DK = Tc<0..dkLen-1>

        hashobj = hashes.Hash(self.algorithm)
        out = password + self.salt

        for _ in range(self.iterations):
            h = hashobj.copy()
            h.update(out)
            out = h.finalize()

        return out[: self.length]


@dataclass(frozen=True)
class PBKDF2HMAC:
    algorithm: hashes.HashAlgorithm
    length: int
    salt: bytes
    iterations: int = 2048

    def derive(self, password: bytes) -> bytes:
        return pbkdf2_hmac(
            hash_name=self.algorithm.name,
            password=password,
            salt=self.salt,
            iterations=self.iterations,
            dklen=self.length,
        )


@dataclass(frozen=True)
class Scrypt:
    salt: bytes
    length: int
    n: int = 16384
    """Cost parameter"""
    r: int = 9
    """Block size (in bits)"""
    p: int = 1
    """Parallelization parameter"""

    def __post_init__(self) -> None:
        if self.p > ((2 ** (32 - 1)) * 32) // (128 * self.r):
            raise ValueError("p or r are too big")
        if self.n <= 1 or (self.n & (self.n - 1)) != 0:
            raise ValueError("n must be > 1 and a power of two")
        if self.n >= 2 ** (128 * self.r // 8):
            raise ValueError("n is too big")

    def derive(self, password: bytes) -> bytes:
        return scrypt(
            password,
            salt=self.salt,
            n=self.n,
            r=self.r,
            p=self.p,
            dklen=self.length,
        )


_BCRYPT_CONSTANT = b"OxychromaticBlowfishSwatDynamite"


@dataclass(frozen=True)
class Bcrypt:
    SUPPORTED: typing.ClassVar[bool] = False

    salt: bytes
    length: int
    iterations: int = 50

    def __post_init__(self) -> None:
        if not self.SUPPORTED:
            raise ValueError("Bcrypt is not supported")

        if self.iterations < 1:
            raise ValueError("iterations must be larger than 1")
        if len(self.salt) < 16:
            raise ValueError("salt must be larger than 16")
        if self.length > 1024:
            raise ValueError("length is too large")

    try:
        from bcrypt import kdf as _bcrypt  # type: ignore

    except ImportError:
        try:
            from Crypto.Cipher import (
                _EKSBlowfish as _EKSBlowfish,  # type: ignore
            )

        except ImportError:

            def derive(self, password: bytes) -> bytes:
                raise ValueError("Bcrypt is not supported")

        else:
            SUPPORTED = True

            def derive(self, password: bytes) -> bytes:
                hashobj = hashes.Hash(hashes.SHA512())

                def hashfunc(data: bytes) -> bytes:
                    new = hashobj.copy()
                    new.update(data)
                    return new.finalize()

                password_hash = hashfunc(password)

                def _bcrypt_hash(salt) -> bytes:
                    cipher = self._EKSBlowfish.new(
                        password_hash,
                        mode=self._EKSBlowfish.MODE_ECB,
                        salt=salt,
                        cost=6,
                        invert=False,
                    )  # type: ignore
                    ciphertext = _BCRYPT_CONSTANT
                    for _ in range(64):
                        ciphertext = cipher.encrypt(ciphertext)
                    return ciphertext

                salt = self.salt
                length = self.length
                iterations = self.iterations

                blocks_needed = length // 32 + int(length % 32 > 0)
                stripes: list[bytes] = []

                for count in range(1, blocks_needed + 1):
                    salt_hash = hashfunc(salt + struct.pack(">I", count))

                    out_le = _bcrypt_hash(salt_hash)  # little endian
                    out = struct.pack(
                        "<IIIIIIII", *struct.unpack(">IIIIIIII", out_le)
                    )
                    acc = out

                    for _ in range(iterations - 1):
                        salt_hash = hashfunc(out)
                        out_le = _bcrypt_hash(salt_hash)
                        out = struct.pack(
                            "<IIIIIIII", *struct.unpack(">IIIIIIII", out_le)
                        )
                        acc = strxor(acc, out)

                    stripes.append(acc)

                # Interleave stripes
                result = (stripe[i] for i in range(32) for stripe in stripes)
                return bytes(result)[:length]

    else:
        SUPPORTED = True

        def derive(self, password: bytes) -> bytes:
            return self._bcrypt(
                password=password,
                salt=self.salt,
                desired_key_bytes=self.length,
                rounds=self.iterations,
                ignore_few_rounds=True,
            )


def hkdf_expand(
    prk: bytes,
    info: bytes,
    length: int,
    algorithm: hashes.HashAlgorithm,
) -> bytes:
    return hkdf.HKDFExpand(algorithm, length, info).derive(prk)


def hkdf_extract(
    salt: bytes,
    ikm: bytes,
    algorithm: hashes.HashAlgorithm,
) -> bytes:
    prk = hmac.HMAC(salt, algorithm)
    prk.update(ikm)
    return prk.finalize()
