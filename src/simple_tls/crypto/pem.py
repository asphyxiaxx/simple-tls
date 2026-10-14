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

import binascii
import dataclasses
import enum
import re

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7

from simple_tls.crypto.utils import get_random_bytes

__all__ = ["EncryptionAlgorithm", "decode", "encode"]


_PEM_RC = re.compile(
    b"-----BEGIN (?P<label>.*?)-----"  # Header
    b"[\\r\\n]+"  # Flexible line endings
    b"(?P<content>.*?)"  # Body
    b"[\\r\\n]+-----END (?P=label)-----",  # Footer:
    flags=re.DOTALL,
)
_DEK_INFO = b"DEK-Info"
_PROC_TYPE_4_ENCRYPTED = b"Proc-Type: 4,ENCRYPTED"


class EncryptionAlgorithm(bytes, enum.Enum):
    AES128_CBC = b"AES-128-CBC"
    AES192_CBC = b"AES-192-CBC"
    AES256_CBC = b"AES-256-CBC"
    AES256_GCM = b"id-aes256-gcm"


def encode(
    data: bytes,
    marker: bytes,
    password: bytes | None = None,
    algorithm: EncryptionAlgorithm = EncryptionAlgorithm.AES128_CBC,
) -> bytes:
    if not isinstance(algorithm, EncryptionAlgorithm):
        raise ValueError("algorithm must be EncryptionAlgorithm enum")

    begin_boundary = b"-----BEGIN " + marker + b"-----"
    end_boundary = b"-----END " + marker + b"-----\n"
    out = [begin_boundary]

    if password is not None:
        if not password:
            raise ValueError("password is empty")

        salt = get_random_bytes(8)
        cipher_alg = _PEM_CIPHERS[algorithm].get_algorithm(password, salt)

        block_len = cipher_alg.block_size
        if block_len >= len(salt):
            salt += get_random_bytes((block_len // 8) - len(salt))

        mode = _PEM_CIPHERS[algorithm].get_mode(salt)

        if isinstance(mode, modes.CBC):
            padder = PKCS7(cipher_alg.block_size).padder()
            data = padder.update(data) + padder.finalize()

        cipher = Cipher(cipher_alg, mode).encryptor()
        data = cipher.update(data) + cipher.finalize()
        hex_salt = salt.hex().upper().encode("ascii")
        out.append(_PROC_TYPE_4_ENCRYPTED)
        out.append(_DEK_INFO + b": " + algorithm + b"," + hex_salt)
        out.append(b"")

    width = 48
    out.extend(
        binascii.b2a_base64(data[i : i + width], newline=False)
        for i in range(0, len(data), width)
    )
    out.append(end_boundary)
    return b"\n".join(out)


@dataclasses.dataclass(frozen=True)
class Result:
    data: bytes
    marker: bytes
    enc_flag: bool
    endpos: int


def decode(
    pem_data: bytes,
    password: bytes | None = None,
    pos: int = 0,
) -> Result:
    m = _PEM_RC.search(pem_data, pos=pos)
    if m is None:
        raise ValueError("PEM boundary not found")

    marker = m["label"]
    contents = m["content"].split(b"\n")
    if not contents:
        raise ValueError("PEM content is empty")

    if contents[0].startswith(_PROC_TYPE_4_ENCRYPTED):
        if not password:
            raise ValueError("PEM is encrypted but password is not provided")
        if not len(contents) > 2:
            raise ValueError("PEM structure is malformed")

        label, sep, info = contents[1].partition(b": ")
        if not sep or not label == _DEK_INFO:
            raise ValueError("PEM decryption format not supported")

        enc_algo, sep, hex_salt = info.partition(b",")
        if not sep:
            raise ValueError("PEM DEK-Info is invalid")
        if enc_algo not in _PEM_CIPHERS:
            raise ValueError(
                f"PEM decryption algorithm '{enc_algo!s}' is not supported"
            )

        salt = binascii.unhexlify(hex_salt)
        cipher_alg = _PEM_CIPHERS[enc_algo].get_algorithm(password, salt[:8])
        mode = _PEM_CIPHERS[enc_algo].get_mode(salt)
        contents = contents[2:]
    else:
        cipher_alg = None
        mode = None

    data = binascii.a2b_base64(b"".join(contents))

    if cipher_alg is not None:
        assert mode is not None
        enc_flag = True
        cipher = Cipher(cipher_alg, mode).decryptor()
        data = cipher.update(data)

        if isinstance(mode, modes.CBC):
            data += cipher.finalize()
            unpadder = PKCS7(cipher_alg.block_size).unpadder()
            data = unpadder.update(data) + unpadder.finalize()
    else:
        enc_flag = False

    return Result(data, marker, enc_flag, m.end())


def _evp_bytes_to_key(
    password: bytes,
    salt: bytes | None,
    key_len: int,
    iv_len: int,
    algorithm: hashes.HashAlgorithm | None = None,
    iterations: int = 1,
) -> tuple[bytes, bytes]:
    """
    OpenSSL-compatible EVP_BytesToKey implementation.

    :param bytes password: password bytes
    :param bytes salt: 8 bytes salt or None
    :param int key_len: desired key length
    :param int iv_len: desired IV length
    :param str digest: hash name (default: md5)
    :param int iterations: number of hash iterations (default: 1)
    :return: (key, iv)
    """

    if salt is not None and len(salt) != 8:
        raise ValueError("salt must be 8 bytes or None")

    if algorithm is None:
        algorithm = hashes.MD5()

    hashobj = hashes.Hash(algorithm)
    derived = []
    derived_bytes_count = 0
    prev = b""

    while derived_bytes_count < key_len + iv_len:
        h = hashobj.copy()
        h.update(prev)
        h.update(password)
        if salt:
            h.update(salt)
        digest_bytes = h.finalize()

        # Additional iterations
        for _ in range(1, iterations):
            h = hashobj.copy()
            h.update(digest_bytes)
            digest_bytes = h.finalize()

        derived.append(digest_bytes)
        prev = digest_bytes
        derived_bytes_count += len(digest_bytes)

    out = b"".join(derived)
    key = out[:key_len]
    iv = out[key_len : key_len + iv_len]
    return key, iv


class _PEMCipher:
    def __init__(
        self,
        key_len: int,
        algorithm: type[algorithms.AES],
        mode: type[modes.CBC] | type[modes.GCM],
    ) -> None:
        self.key_len = key_len
        self.algorithm = algorithm
        self.mode = mode

    def get_algorithm(self, password: bytes, salt: bytes) -> algorithms.AES:
        key, _ = _evp_bytes_to_key(password, salt, self.key_len, 0)
        return self.algorithm(key)

    def get_mode(self, iv: bytes) -> modes.CBC | modes.GCM:
        return self.mode(iv)


_PEM_CIPHERS: dict[bytes, _PEMCipher] = {
    EncryptionAlgorithm.AES128_CBC: _PEMCipher(16, algorithms.AES, modes.CBC),
    EncryptionAlgorithm.AES192_CBC: _PEMCipher(24, algorithms.AES, modes.CBC),
    EncryptionAlgorithm.AES256_CBC: _PEMCipher(32, algorithms.AES, modes.CBC),
    EncryptionAlgorithm.AES256_GCM: _PEMCipher(32, algorithms.AES, modes.GCM),
}
