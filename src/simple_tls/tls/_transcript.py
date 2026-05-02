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

from cryptography.hazmat.primitives import hashes, hmac

from ..protocol.kdf import hkdf_expand, hkdf_extract
from ..utils.codec import Writer
from ..utils.math import strxor
from ._common import get_algorithm, get_hash
from ._constant import CipherSuite, HandshakeType, HashAlgorithm, TLSVersion


class Transcript:
    def __init__(self) -> None:
        self.__buffer = bytearray()
        self.__hashes: dict[HashAlgorithm, hashes.Hash] = {}

    def update_hash(self, data: bytes) -> None:
        self.__buffer.extend(data)
        for h in self.__hashes.values():
            h.update(data)

    def update_for_hello_retry_request(self, algorithm: HashAlgorithm) -> None:
        writer = Writer()
        writer.write_int(HandshakeType.MESSAGE_HASH, 1)
        writer.write_prefixed_bytes(self.digest(algorithm), 3)
        self.__buffer.clear()
        self.__hashes.clear()
        self.update_hash(writer.tobytes())

    def get(self) -> bytes:
        return bytes(self.__buffer)

    def digest(self, hashalg: HashAlgorithm) -> bytes:
        try:
            hashobj = self.__hashes[hashalg]
        except KeyError:
            hashobj = get_hash(hashalg, self.__buffer)
            self.__hashes[hashalg] = hashobj

        return hashobj.copy().finalize()

    def copy(self) -> Transcript:
        cls = self.__class__
        new = cls.__new__(cls)
        new.__buffer = self.__buffer.copy()
        new.__hashes = {
            hashalg: h.copy() for hashalg, h in self.__hashes.items()
        }
        return new


class KeyDeriver:
    def __init__(
        self,
        version: int,
        cipher_suite: CipherSuite,
        client_random: bytes,
        server_random: bytes,
    ) -> None:
        self.algorithm: hashes.HashAlgorithm | None
        self.client_random = client_random
        self.server_random = server_random

        if version == TLSVersion.TLSv1_2:
            self.prf = self._prf_tlsv1_2
            self.hash_algorithm = cipher_suite.prf_hash
            self.algorithm = get_algorithm(self.hash_algorithm)
        elif version in (TLSVersion.TLSv1, TLSVersion.TLSv1_1):
            self.prf = self._prf_tlsv1
            self.hash_algorithm = HashAlgorithm.MD5_SHA1
            self.algorithm = None
        else:
            raise ValueError("Unsupported version")

    def finished_verify_data(
        self,
        master_secret: bytes,
        label: bytes,
        transcript: Transcript,
    ) -> bytes:
        seed = transcript.digest(self.hash_algorithm)
        return self.prf(master_secret, label, seed, 12)

    def derive_key(self, master_secret: bytes, length: int) -> bytes:
        label = b"key expansion"
        seed = self.server_random + self.client_random
        return self.prf(master_secret, label, seed, length)

    def derive_master_secret(
        self,
        premaster_secret: bytes,
        label: bytes,
        transcript: Transcript | None = None,
    ) -> bytes:
        if transcript is None:
            seed = self.client_random + self.server_random
        else:
            # seed for Extended Master Secret
            seed = transcript.digest(self.hash_algorithm)
        return self.prf(premaster_secret, label, seed, 48)

    def _prf_tlsv1(
        self,
        secret: bytes,
        label: bytes,
        seed: bytes,
        length: int,
    ) -> bytes:
        seed = label + seed
        return self._prf_md5_sha1(secret, seed, length)

    def _prf_tlsv1_2(
        self,
        secret: bytes,
        label: bytes,
        seed: bytes,
        length: int,
    ) -> bytes:
        seed = label + seed
        assert self.algorithm is not None
        return self._prf_hash(secret, seed, length, self.algorithm)

    def _prf_hash(
        self,
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

    def _prf_md5_sha1(self, secret: bytes, seed: bytes, length: int) -> bytes:
        secret_len = len(secret)
        s1 = secret[: ((secret_len + 1) // 2)]
        s2 = secret[(secret_len // 2) :]
        p_md5 = self._prf_hash(s1, seed, length, hashes.MD5())
        p_sha1 = self._prf_hash(s2, seed, length, hashes.SHA1())
        return strxor(p_md5, p_sha1)


class KeySchedule:
    def __init__(self, hash_algorithm: HashAlgorithm) -> None:
        self.hash_algorithm = hash_algorithm
        self.algorithm = get_algorithm(self.hash_algorithm)
        self.digest_size = self.algorithm.digest_size
        self.empty_digest = get_hash(self.hash_algorithm).finalize()
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
        hmac_key = self.hkdf_expand_label(
            secret=secret,
            label=b"finished",
            hash_data=b"",
        )
        msg = transcript.digest(self.hash_algorithm)
        return hkdf_extract(hmac_key, msg, self.algorithm)

    def ech_accept_confirmation(
        self,
        inner_client_random: bytes,
        label: bytes,
        transcript: Transcript,
    ) -> bytes:
        secret = hkdf_extract(b"", inner_client_random, self.algorithm)
        hash_data = transcript.digest(self.hash_algorithm)
        return self.hkdf_expand_label(secret, label, hash_data, length=8)

    def upd_secret(self, secret: bytes) -> bytes:
        return self.hkdf_expand_label(
            secret=secret,
            label=b"traffic upd",
            hash_data=b"",
        )

    def resumption_secret(self, secret: bytes, ticket_nonce: bytes) -> bytes:
        return self.hkdf_expand_label(
            secret=secret,
            label=b"resumption",
            hash_data=ticket_nonce,
        )

    def derive_secret(self, label: bytes, transcript: Transcript) -> bytes:
        hash_data = transcript.digest(self.hash_algorithm)
        return self.hkdf_expand_label(
            secret=self.secret,
            label=label,
            hash_data=hash_data,
        )

    def hkdf_expand_label(
        self,
        secret: bytes,
        label: bytes,
        hash_data: bytes,
        length: int | None = None,
    ) -> bytes:
        """
        TLS 1.3 key derivation function (HKDF-Expand-Label).
        """
        if length is None:
            length = self.digest_size

        hkdf_label = Writer()
        hkdf_label.write_int(length, 2)
        hkdf_label.write_prefixed_bytes(self.label_prefix + b" " + label, 1)
        hkdf_label.write_prefixed_bytes(hash_data, 1)
        info = hkdf_label.tobytes()
        return hkdf_expand(secret, info, length, self.algorithm)

    def extract(self, key_material: bytes | None = None) -> None:
        if key_material is None:
            key_material = bytes(self.digest_size)

        if self.generation:
            self.secret = self.hkdf_expand_label(
                secret=self.secret,
                label=b"derived",
                hash_data=self.empty_digest,
            )

        self.generation += 1
        self.secret = hkdf_extract(self.secret, key_material, self.algorithm)
