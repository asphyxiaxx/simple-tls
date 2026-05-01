# Copyright (c) 2026 The simple-tls Contributors

# Permission is hereby granted, free of charge, to any person obtaining a copy of
# this software and associated documentation files (the “Software”), to deal in
# the Software without restriction, including without limitation the rights to
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
# the Software, and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
# FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
# COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
# IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

from __future__ import annotations

import struct
import typing

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives.ciphers import (
    Cipher,
    CipherContext,
    aead,
    algorithms,
    modes,
)

from ..utils.constant_time import cbc_remove_pad_and_mac, compare_digest
from ..utils.math import strxor
from ..utils.random import get_random_bytes
from ._types import ReadableBuffer, WritableBuffer
from ._common import get_algorithm
from ._constant import CipherSuite, Symmetric, TLSVersion
from ._enum import Direction

try:
    from cryptography.hazmat.decrepit.ciphers.algorithms import (  # type: ignore
        ARC4,
        TripleDES,
    )
except ImportError:
    from cryptography.hazmat.primitives.ciphers.algorithms import (  # type: ignore
        ARC4,
        TripleDES,
    )

AEADCipherType = typing.Union[aead.AESCCM, aead.AESGCM, aead.ChaCha20Poly1305]
CipherType = CipherContext


# key_length, iv_length, cipher_func
_CIPHERS = {
    Symmetric.AES_128_CBC: (
        16,
        16,
        lambda key, iv: Cipher(algorithms.AES(key), modes.CBC(iv)),
    ),
    Symmetric.AES_256_CBC: (
        32,
        16,
        lambda key, iv: Cipher(algorithms.AES(key), modes.CBC(iv)),
    ),
    Symmetric.RC4_128: (
        16,
        0,
        lambda key, iv: Cipher(ARC4(key), None),
    ),
    Symmetric.TRIPLE_DES_EDE_CBC: (
        24,
        8,
        lambda key, iv: Cipher(TripleDES(key), modes.CBC(iv)),
    ),
    Symmetric.NULL: (0, 0, lambda key, iv: None),
}


# key_length, iv_length, tag_length, aead cipher class
_AEAD_CIPHERS = {
    Symmetric.AES_256_GCM: (32, 4, 16, aead.AESGCM),
    Symmetric.AES_128_GCM: (16, 4, 16, aead.AESGCM),
    Symmetric.AES_256_CCM_8: (32, 4, 8, aead.AESCCM),
    Symmetric.AES_128_CCM_8: (16, 4, 8, aead.AESCCM),
    Symmetric.AES_256_CCM: (32, 4, 16, aead.AESCCM),
    Symmetric.AES_128_CCM: (16, 4, 16, aead.AESCCM),
    Symmetric.CHACHA20_POLY1305: (32, 12, 16, aead.ChaCha20Poly1305),
    Symmetric.CHACHA20_DRAFT_00: (32, 4, 16, aead.ChaCha20Poly1305),
}


class TLSCipher:
    def __init__(
        self,
        direction: Direction,
        version: int,
        cipher_suite: CipherSuite,
        enc_key: ReadableBuffer,
        mac_key: ReadableBuffer,
        fixed_iv: ReadableBuffer,
        encrypt_then_mac: bool = False,
    ) -> None:
        self.open: typing.Callable[
            [int, int, ReadableBuffer, int, ReadableBuffer, WritableBuffer],
            int,
        ]
        self.seal: typing.Callable[
            [int, int, ReadableBuffer, int, ReadableBuffer, WritableBuffer],
            int,
        ]

        self._cipher: AEADCipherType | CipherType | None = None
        self._mac: hmac.HMAC | None = None
        self._max_overhead: int = 0
        self._fixed_nonce: bytes = b""
        self._block_size: int = 1
        self._variable_nonce_len: int = 0
        self._variable_nonce_included_in_record: bool = False
        self._xor_fixed_nonce: bool = False
        self._aad_is_header: bool = False
        self._is_etm: bool = encrypt_then_mac

        if cipher_suite.aead:
            if encrypt_then_mac:
                raise ValueError(
                    "encrypt-then-mac is not supported for this cipher suite"
                )
            if mac_key:
                raise ValueError("mac_key must be empty for aead cipher suite")

            key_len, iv_len, tag_len, cipher_cls = self._aead_cipher_params(
                cipher_suite
            )
            nonce_len = 12

            if version >= TLSVersion.TLSv1_3:
                iv_len = nonce_len
            if len(enc_key) != key_len:
                raise ValueError("Incorrect enc_key length")
            if len(fixed_iv) != iv_len:
                raise ValueError("Incorrect fixed_iv length")

            if (
                version >= TLSVersion.TLSv1_3
                or cipher_suite.symmetric == Symmetric.CHACHA20_POLY1305
            ):
                self._xor_fixed_nonce = True
                self._variable_nonce_len = 8
                self._max_overhead = tag_len
                assert len(fixed_iv) >= self._variable_nonce_len

            else:
                assert len(fixed_iv) <= nonce_len
                self._variable_nonce_len = nonce_len - len(fixed_iv)
                self._variable_nonce_included_in_record = True
                self._max_overhead = tag_len + self._variable_nonce_len

            self._fixed_nonce = fixed_iv

            if version >= TLSVersion.TLSv1_3:
                self._aad_is_header = True

            if issubclass(cipher_cls, aead.AESCCM):
                self._cipher = cipher_cls(enc_key, tag_len)
            else:
                self._cipher = cipher_cls(enc_key)

            if direction == Direction.ENCRYPT:
                self.seal = self._encrypt_aead
            else:
                self.open = self._decrypt_aead

        else:
            if version >= TLSVersion.TLSv1_3:
                raise ValueError("cipher suite is not supported for TLSv1.3")
            if cipher_suite.digest is None:
                raise ValueError("cipher suite is not supported")

            key_len, iv_len, cipher_func = self._cipher_params(cipher_suite)

            if len(enc_key) != key_len:
                raise ValueError("Incorrect enc_key length")
            if len(fixed_iv) != iv_len:
                raise ValueError("Incorrect fixed_iv length")

            algorithm = get_algorithm(cipher_suite.digest)
            cipher = cipher_func(enc_key, fixed_iv)
            self._mac = hmac.HMAC(mac_key, algorithm)

            if version >= TLSVersion.TLSv1_1 and iv_len > 0:
                self._fixed_nonce = get_random_bytes(iv_len)
                self._variable_nonce_len = iv_len

            if cipher_suite.symmetric in (
                Symmetric.AES_128_CBC,
                Symmetric.AES_256_CBC,
                Symmetric.TRIPLE_DES_EDE_CBC,
            ):
                if cipher_suite.symmetric == Symmetric.TRIPLE_DES_EDE_CBC:
                    self._block_size = 8
                else:
                    self._block_size = 16

                if encrypt_then_mac:
                    seal = self._encrypt_then_mac
                    open = self._mac_then_decrypt
                else:
                    seal = self._mac_then_encrypt
                    open = self._decrypt_then_mac

                self._max_overhead = (
                    self._block_size
                    + algorithm.digest_size
                    + self._variable_nonce_len
                )

            else:
                if encrypt_then_mac:
                    raise ValueError(
                        "encrypt-then-mac is not supported for this cipher suite"
                    )

                seal = self._mac_then_encrypt_stream
                open = self._decrypt_stream_then_mac

                self._max_overhead = algorithm.digest_size

            if direction == Direction.ENCRYPT:
                if cipher is not None:
                    self._cipher = cipher.encryptor()
                self.seal = seal
            else:
                if cipher is not None:
                    self._cipher = cipher.decryptor()
                self.open = open

    def ciphertext_length(self, plaintext_length: int) -> int:
        """
        Return the exact ciphertext length produced by seal()
        for a given plaintext length.
        """
        # AEAD and stream ciphers are simple
        if not self.is_block_cipher():
            return plaintext_length + self._max_overhead

        # CBC block ciphers
        block_size = self._block_size
        mac_size = self._mac.algorithm.digest_size if self._mac else 0
        iv_len = self._variable_nonce_len

        if self._is_etm:
            # In ETM, only the raw plaintext is padded and encrypted.
            data_to_pad = plaintext_length
        else:
            # In standard MtE, the plaintext + MAC are padded and encrypted.
            data_to_pad = plaintext_length + mac_size

        # TLS requires at least 1 byte of padding (0x00), up to a full block.
        # This formula rounds up to the next exact multiple of block_size.
        pad_bytes = block_size - (data_to_pad % block_size)
        padded_ciphertext_len = data_to_pad + pad_bytes

        if self._is_etm:
            # IV (clear) + Padded Ciphertext + MAC (clear)
            return iv_len + padded_ciphertext_len + mac_size
        else:
            # IV (clear) + Padded Ciphertext (which already contains the MAC)
            return iv_len + padded_ciphertext_len

    @classmethod
    def get_key_iv_size(
        cls, version: int, cipher_suite: CipherSuite
    ) -> tuple[int, int]:
        if cipher_suite.aead:
            key_size, iv_size, _, _ = cls._aead_cipher_params(cipher_suite)
            if version >= TLSVersion.TLSv1_3:
                iv_size = 12
        else:
            if version >= TLSVersion.TLSv1_3:
                raise ValueError("cipher suite is not supported for TLSv1.3")
            key_size, iv_size, _ = cls._cipher_params(cipher_suite)
        return key_size, iv_size

    def max_overhead(self) -> int:
        return self._max_overhead

    def is_block_cipher(self) -> bool:
        return self._block_size > 1

    @classmethod
    def _cipher_params(
        cls, cipher_suite: CipherSuite
    ) -> tuple[
        int,
        int,
        typing.Callable[[ReadableBuffer, ReadableBuffer], Cipher | None],
    ]:
        return _CIPHERS[cipher_suite.symmetric]

    @classmethod
    def _aead_cipher_params(
        cls, cipher_suite: CipherSuite
    ) -> tuple[int, int, int, type[AEADCipherType]]:
        return _AEAD_CIPHERS[cipher_suite.symmetric]

    @staticmethod
    def _get_pad(data_len: int, block_size: int) -> bytes:
        pad_len = block_size - 1 - (data_len % block_size)
        return bytes([pad_len]) * (pad_len + 1)

    @staticmethod
    def _get_mac(
        mac: hmac.HMAC,
        seq_num: int,
        content_type: int,
        record_version: int,
        plaintext: ReadableBuffer,
    ) -> bytes:
        aad = struct.pack(
            "!QBHH", seq_num, content_type, record_version, len(plaintext)
        )
        m = mac.copy()
        m.update(aad)
        m.update(plaintext)
        return m.finalize()

    def _encrypt_raw(
        self,
        content_type: int,
        record_version: int,
        plaintext: ReadableBuffer,
        seq_num: int,
        header: ReadableBuffer,
        out: WritableBuffer,
    ) -> int:
        if len(out) < len(plaintext) + self._max_overhead:
            raise ValueError("out buffer too small")

        out[0 : len(plaintext)] = plaintext
        return len(plaintext)

    def _encrypt_aead(
        self,
        content_type: int,
        record_version: int,
        plaintext: ReadableBuffer,
        seq_num: int,
        header: ReadableBuffer,
        out: WritableBuffer,
    ) -> int:
        assert self._variable_nonce_len == 8

        if len(out) < len(plaintext) + self._max_overhead:
            raise ValueError("out buffer too small")

        if self._aad_is_header:
            aad = header
        else:
            aad = struct.pack(
                "!QBHH", seq_num, content_type, record_version, len(plaintext)
            )

        seq_bytes = struct.pack("!Q", seq_num)

        if self._xor_fixed_nonce:
            pad = bytes(len(self._fixed_nonce) - len(seq_bytes))
            nonce = strxor(pad + seq_bytes, self._fixed_nonce)
        else:
            nonce = self._fixed_nonce + seq_bytes

        cipher = typing.cast(AEADCipherType, self._cipher)
        ciphertext = cipher.encrypt(nonce, plaintext, aad)

        written = 0
        if self._variable_nonce_included_in_record:
            assert not self._xor_fixed_nonce
            out[written : written + len(seq_bytes)] = seq_bytes
            written = len(seq_bytes)

        out[written : written + len(ciphertext)] = ciphertext
        written += len(ciphertext)

        return written

    def _encrypt_then_mac(
        self,
        content_type: int,
        record_version: int,
        plaintext: ReadableBuffer,
        seq_num: int,
        header: ReadableBuffer,
        out: WritableBuffer,
    ) -> int:
        mac = typing.cast(hmac.HMAC, self._mac)
        cipher = typing.cast(CipherContext, self._cipher)
        block_size = self._block_size
        mac_size = mac.algorithm.digest_size
        rand_iv = self._fixed_nonce

        if len(out) < len(plaintext) + self._max_overhead:
            raise ValueError("out buffer too small")

        pad_bytes = self._get_pad(len(plaintext), block_size)
        data_len = len(rand_iv) + len(plaintext) + len(pad_bytes)
        out_len = data_len + mac_size

        written = 0
        if not isinstance(out, memoryview):
            out = memoryview(out)
        for b in (rand_iv, plaintext, pad_bytes):
            written += cipher.update_into(b, out[written:])
        assert written == data_len

        mac_bytes = self._get_mac(
            mac=mac,
            seq_num=seq_num,
            content_type=content_type,
            record_version=record_version,
            plaintext=out[:data_len],  # encrypt-then-mac use ciphertext
        )
        out[data_len:out_len] = mac_bytes

        return out_len

    def _mac_then_encrypt(
        self,
        content_type: int,
        record_version: int,
        plaintext: ReadableBuffer,
        seq_num: int,
        header: ReadableBuffer,
        out: WritableBuffer,
    ) -> int:
        mac = typing.cast(hmac.HMAC, self._mac)
        cipher = typing.cast(CipherContext, self._cipher)
        block_size = self._block_size
        rand_iv = self._fixed_nonce

        if len(out) < len(plaintext) + self._max_overhead:
            raise ValueError("out buffer too small")

        mac_bytes = self._get_mac(
            mac=mac,
            seq_num=seq_num,
            content_type=content_type,
            record_version=record_version,
            plaintext=plaintext,
        )

        data_len = len(rand_iv) + len(plaintext) + len(mac_bytes)
        pad_bytes = self._get_pad(data_len, block_size)
        out_len = data_len + len(pad_bytes)

        written = 0
        if not isinstance(out, memoryview):
            out = memoryview(out)
        for b in (rand_iv, plaintext, mac_bytes, pad_bytes):
            written += cipher.update_into(b, out[written:])
        assert written == out_len

        return written

    def _mac_then_encrypt_stream(
        self,
        content_type: int,
        record_version: int,
        plaintext: ReadableBuffer,
        seq_num: int,
        header: ReadableBuffer,
        out: WritableBuffer,
    ) -> int:
        mac = typing.cast(hmac.HMAC, self._mac)
        cipher = typing.cast(CipherContext | None, self._cipher)

        if len(out) < len(plaintext) + self._max_overhead:
            raise ValueError("out buffer too small")

        mac_bytes = self._get_mac(
            mac=mac,
            seq_num=seq_num,
            content_type=content_type,
            record_version=record_version,
            plaintext=plaintext,
        )

        written = 0
        if cipher is not None:
            if not isinstance(out, memoryview):
                out = memoryview(out)
            for b in (plaintext, mac_bytes):
                written += cipher.update_into(b, out[written:])
            assert written == len(plaintext) + len(mac_bytes)
        else:
            out[written : written + len(plaintext)] = plaintext
            written += len(plaintext)
            out[written : written + len(mac_bytes)] = mac_bytes
            written += len(mac_bytes)

        return written

    def _decrypt_raw(
        self,
        content_type: int,
        record_version: int,
        ciphertext: ReadableBuffer,
        seq_num: int,
        header: ReadableBuffer,
        out: WritableBuffer,
    ) -> int:
        if len(out) < len(ciphertext):
            raise ValueError("out buffer too small")

        out[0 : len(ciphertext)] = ciphertext
        return len(ciphertext)

    def _decrypt_aead(
        self,
        content_type: int,
        record_version: int,
        ciphertext: ReadableBuffer,
        seq_num: int,
        header: ReadableBuffer,
        out: WritableBuffer,
    ) -> int:
        assert self._variable_nonce_len == 8

        if len(out) < len(ciphertext):
            raise ValueError("out buffer too small")

        if self._aad_is_header:
            aad = header
        else:
            plaintext_len = len(ciphertext) - self.max_overhead()
            aad = struct.pack(
                "!QBHH", seq_num, content_type, record_version, plaintext_len
            )

        seq_bytes = struct.pack("!Q", seq_num)

        if self._variable_nonce_included_in_record:
            assert not self._xor_fixed_nonce

            if self._variable_nonce_len > len(ciphertext):
                raise InvalidTag("Truncated nonce")

            nonce = self._fixed_nonce + ciphertext[: self._variable_nonce_len]
            ciphertext = ciphertext[self._variable_nonce_len :]

        elif self._xor_fixed_nonce:
            pad = bytes(len(self._fixed_nonce) - len(seq_bytes))
            nonce = strxor(pad + seq_bytes, self._fixed_nonce)

        else:
            nonce = self._fixed_nonce + seq_bytes

        cipher = typing.cast(AEADCipherType, self._cipher)
        plaintext = cipher.decrypt(nonce, ciphertext, aad)
        out[: len(plaintext)] = plaintext

        return len(plaintext)

    def _mac_then_decrypt(
        self,
        content_type: int,
        record_version: int,
        ciphertext: ReadableBuffer,
        seq_num: int,
        header: ReadableBuffer,
        out: WritableBuffer,
    ) -> int:
        mac = typing.cast(hmac.HMAC, self._mac)
        cipher = typing.cast(CipherType, self._cipher)
        block_size = self._block_size
        mac_size = mac.algorithm.digest_size
        rand_iv_len = self._variable_nonce_len

        if len(out) < len(ciphertext) + block_size:
            raise ValueError("out buffer too small")

        if len(ciphertext) < mac_size + rand_iv_len:
            raise InvalidTag("Truncated mac")

        if not isinstance(ciphertext, memoryview):
            ciphertext = memoryview(ciphertext)

        extracted_mac = ciphertext[-mac_size:]
        ciphertext = ciphertext[:-mac_size]

        expected_mac = self._get_mac(
            mac=mac,
            seq_num=seq_num,
            content_type=content_type,
            record_version=record_version,
            plaintext=ciphertext,  # encrypt-then-mac use ciphertext
        )
        if not compare_digest(extracted_mac, expected_mac):
            raise InvalidTag("MAC mismatch")

        # For TLSv1.1+, remove explicit IV
        iv, ciphertext = ciphertext[:rand_iv_len], ciphertext[rand_iv_len:]

        written = cipher.update_into(iv, out)
        assert written == rand_iv_len

        written = cipher.update_into(ciphertext, out)
        if written != len(ciphertext):
            raise InvalidTag("ciphertext length not multiple of block_length")

        try:
            plaintext_len, _ = cbc_remove_pad_and_mac(
                out[:written], 0, block_size
            )
        except ValueError as exc:
            raise InvalidTag(exc)

        return plaintext_len

    def _decrypt_then_mac(
        self,
        content_type: int,
        record_version: int,
        ciphertext: ReadableBuffer,
        seq_num: int,
        header: ReadableBuffer,
        out: WritableBuffer,
    ) -> int:
        mac = typing.cast(hmac.HMAC, self._mac)
        cipher = typing.cast(CipherType, self._cipher)
        block_size = self._block_size
        mac_size = mac.algorithm.digest_size
        rand_iv_len = self._variable_nonce_len

        if len(out) < len(ciphertext) + self._block_size:
            raise ValueError("out buffer too small")

        if len(ciphertext) < mac_size + rand_iv_len:
            raise InvalidTag("Truncated mac")

        # For TLSv1.1+, remove explicit IV
        iv, ciphertext = ciphertext[:rand_iv_len], ciphertext[rand_iv_len:]

        written = cipher.update_into(iv, out)
        assert written == rand_iv_len

        written = cipher.update_into(ciphertext, out)
        if written != len(ciphertext):
            raise InvalidTag("ciphertext length not multiple of block_length")

        try:
            plaintext_len, extracted_mac = cbc_remove_pad_and_mac(
                out[:written], mac_size, block_size
            )
        except ValueError as exc:
            raise InvalidTag(exc)

        expected_mac = self._get_mac(
            mac=mac,
            seq_num=seq_num,
            content_type=content_type,
            record_version=record_version,
            plaintext=out[:plaintext_len],
        )
        if not compare_digest(extracted_mac, expected_mac):
            raise InvalidTag("MAC mismatch")

        return plaintext_len

    def _decrypt_stream_then_mac(
        self,
        content_type: int,
        record_version: int,
        ciphertext: ReadableBuffer,
        seq_num: int,
        header: ReadableBuffer,
        out: WritableBuffer,
    ) -> int:
        mac = typing.cast(hmac.HMAC, self._mac)
        cipher = typing.cast(CipherType | None, self._cipher)
        block_size = 1
        mac_size = mac.algorithm.digest_size

        if len(out) < len(ciphertext):
            raise ValueError("out buffer too small")

        if cipher is not None:
            written = cipher.update_into(ciphertext, out)
            assert written == len(ciphertext)
        else:
            out[0 : len(ciphertext)] = ciphertext
            written = len(ciphertext)

        try:
            plaintext_len, extracted_mac = cbc_remove_pad_and_mac(
                out[:written], mac_size, block_size
            )
        except ValueError as exc:
            raise InvalidTag(exc)

        expected_mac = self._get_mac(
            mac=mac,
            seq_num=seq_num,
            content_type=content_type,
            record_version=record_version,
            plaintext=out[:plaintext_len],
        )

        if not compare_digest(expected_mac, extracted_mac):
            raise InvalidTag("Mac mismatch")

        return plaintext_len


class NullCipher(TLSCipher):
    def __init__(self, direction: Direction):
        self._max_overhead = 0
        self._block_size = 1

        if direction == Direction.ENCRYPT:
            self.seal = self._encrypt_raw
        else:
            self.open = self._decrypt_raw

    def ciphertext_length(self, plaintext_len: int) -> int:
        return plaintext_len
