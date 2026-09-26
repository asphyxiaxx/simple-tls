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

from cryptography.hazmat.primitives import hashes

from simple_tls.codec import Writer
from simple_tls.crypto.kdf import hkdf_extract

from ._constant import HandshakeType
from ._utils import get_algorithm, get_hash, hkdf_expand_label


class Transcript:
    def __init__(self) -> None:
        self.__buffer = bytearray()
        self.__hashes: dict[int, hashes.Hash] = {}

    def update_hash(self, data: bytes) -> None:
        self.__buffer.extend(data)
        for h in self.__hashes.values():
            h.update(data)

    def update_for_hello_retry_request(self, hash_algorithm: int) -> None:
        writer = Writer()
        writer.write_int(HandshakeType.MESSAGE_HASH, 1)
        writer.write_prefixed_bytes(self.digest(hash_algorithm), 3)
        self.__buffer.clear()
        self.__hashes.clear()
        self.update_hash(writer.tobytes())

    def get(self) -> bytes:
        return bytes(self.__buffer)

    def digest(self, hash_algorithm: int) -> bytes:
        try:
            hashobj = self.__hashes[hash_algorithm]
        except KeyError:
            hashobj = get_hash(hash_algorithm, self.__buffer)
            self.__hashes[hash_algorithm] = hashobj

        return hashobj.copy().finalize()

    def copy(self) -> Transcript:
        cls = self.__class__
        new = cls.__new__(cls)
        new.__buffer = self.__buffer.copy()
        new.__hashes = {
            hashalg: h.copy() for hashalg, h in self.__hashes.items()
        }
        return new


class KeySchedule:
    def __init__(self, hash_algorithm: int) -> None:
        self.hash_algorithm = hash_algorithm
        self.algorithm = get_algorithm(self.hash_algorithm)
        self.digest_size = self.algorithm.digest_size
        self.generation = 0
        self.secret = bytes(self.digest_size)
        self.label_prefix = b"tls13"

    def certificate_verify_data(
        self, context: bytes, transcript: Transcript
    ) -> bytes:
        return (
            (b"\x20" * 64)
            + context
            + b"\x00"
            + transcript.digest(self.hash_algorithm)
        )

    def finished_verify_data(
        self, secret: bytes, transcript: Transcript
    ) -> bytes:
        hmac_key = hkdf_expand_label(
            secret=secret,
            label=b"finished",
            data=b"",
            length=self.digest_size,
            algorithm=self.algorithm,
        )
        data = transcript.digest(self.hash_algorithm)
        return hkdf_extract(hmac_key, data, self.algorithm)

    def ech_accept_confirmation(
        self,
        inner_client_random: bytes,
        label: bytes,
        transcript: Transcript,
    ) -> bytes:
        secret = hkdf_extract(b"", inner_client_random, self.algorithm)
        data = transcript.digest(self.hash_algorithm)
        return hkdf_expand_label(
            secret=secret,
            label=label,
            data=data,
            length=8,
            algorithm=self.algorithm,
        )

    def upd_secret(self, secret: bytes) -> bytes:
        return hkdf_expand_label(
            secret=secret,
            label=b"traffic upd",
            data=b"",
            length=self.digest_size,
            algorithm=self.algorithm,
        )

    def resumption_secret(self, secret: bytes, ticket_nonce: bytes) -> bytes:
        return hkdf_expand_label(
            secret=secret,
            label=b"resumption",
            data=ticket_nonce,
            length=self.digest_size,
            algorithm=self.algorithm,
        )

    def derive_secret(self, label: bytes, transcript: Transcript) -> bytes:
        data = transcript.digest(self.hash_algorithm)
        return hkdf_expand_label(
            secret=self.secret,
            label=label,
            data=data,
            length=self.digest_size,
            algorithm=self.algorithm,
        )

    def extract(self, key_material: bytes | None = None) -> None:
        if key_material is None:
            key_material = bytes(self.digest_size)

        if self.generation:
            data = get_hash(self.hash_algorithm).finalize()
            self.secret = hkdf_expand_label(
                secret=self.secret,
                label=b"derived",
                data=data,
                length=self.digest_size,
                algorithm=self.algorithm,
            )

        self.generation += 1
        self.secret = hkdf_extract(self.secret, key_material, self.algorithm)
