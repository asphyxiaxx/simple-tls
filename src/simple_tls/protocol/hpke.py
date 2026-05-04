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

import enum
import struct
import typing
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import aead

from ..io.serialization import Encoding, PublicFormat
from ..key import ec, x448, x25519
from ..protocol.kdf import hkdf_expand, hkdf_extract
from ..utils.math import bytes_to_int, int_to_bytes, strxor

HPKEPrivateKeyType = typing.Union[
    ec.EllipticCurvePrivateKey,
    x25519.X25519PrivateKey,
    x448.X448PrivateKey,
]
HPKEPublicKeyType = typing.Union[
    ec.EllipticCurvePublicKey,
    x25519.X25519PublicKey,
    x448.X448PublicKey,
]
AEADContext = typing.Union[aead.AESGCM, aead.ChaCha20Poly1305]

_C = typing.TypeVar("_C", bound="Context")

_HPKE_VERSION_V1 = b"HPKE-v1"


# Constant
class Mode(int, enum.Enum):
    BASE = 0x00
    PSK = 0x01
    AUTH = 0x02
    AUTH_PSK = 0x03


# KDF
class HKDF:
    id: int
    algorithm: hashes.HashAlgorithm

    @classmethod
    def labeled_extract(
        cls, salt: bytes, label: bytes, ikm: bytes, suite_id: bytes
    ) -> bytes:
        ikm = _HPKE_VERSION_V1 + suite_id + label + ikm
        return hkdf_extract(salt, ikm, cls.algorithm)

    @classmethod
    def labeled_expand(
        cls,
        prk: bytes,
        label: bytes,
        labeled_info: bytes,
        length: int,
        suite_id: bytes,
    ) -> bytes:
        labeled_info = (
            struct.pack(">H", length)
            + _HPKE_VERSION_V1
            + suite_id
            + label
            + labeled_info
        )
        return hkdf_expand(prk, labeled_info, length, cls.algorithm)


class HKDF_SHA256(HKDF):
    id = 0x0001
    algorithm = hashes.SHA256()


class HKDF_SHA384(HKDF):
    id = 0x0002
    algorithm = hashes.SHA384()


class HKDF_SHA512(HKDF):
    id = 0x0003
    algorithm = hashes.SHA512()


# KEM
class DHKEM:
    id: typing.ClassVar[int]
    kdf: typing.ClassVar[type[HKDF]]

    @classmethod
    def extract_and_expand(cls, dh: bytes, kem_context: bytes) -> bytes:
        suite_id = b"KEM" + struct.pack(">H", cls.id)
        n_secret = cls.kdf.algorithm.digest_size
        eae_prk = cls.kdf.labeled_extract(b"", b"eae_prk", dh, suite_id)
        shared_secret = cls.kdf.labeled_expand(
            eae_prk, b"shared_secret", kem_context, n_secret, suite_id
        )
        return shared_secret

    @classmethod
    def encap(cls, pk_r: HPKEPublicKeyType) -> tuple[bytes, bytes]:
        sk_e = cls.generate()
        pk_e = sk_e.public_key()
        dh = cls.dh(sk_e, pk_r)
        enc = cls.serialize_public_key(pk_e)

        pk_rm = cls.serialize_public_key(pk_r)
        kem_context = enc + pk_rm

        shared_secret = cls.extract_and_expand(dh, kem_context)
        return shared_secret, enc

    @classmethod
    def decap(cls, enc: bytes, sk_r: HPKEPrivateKeyType) -> bytes:
        pk_e = cls.deserialize_public_key(enc)
        dh = cls.dh(sk_r, pk_e)

        pk_rm = cls.serialize_public_key(sk_r.public_key())
        kem_context = enc + pk_rm

        shared_secret = cls.extract_and_expand(dh, kem_context)
        return shared_secret

    @classmethod
    def auth_encap(
        cls, pk_r: HPKEPublicKeyType, sk_s: HPKEPrivateKeyType
    ) -> tuple[bytes, bytes]:
        sk_e = cls.generate()
        pk_e = sk_e.public_key()
        dh = cls.dh(sk_e, pk_r) + cls.dh(sk_s, pk_r)
        enc = cls.serialize_public_key(pk_e)

        pk_rm = cls.serialize_public_key(pk_r)
        pk_sm = cls.serialize_public_key(sk_s.public_key())
        kem_context = enc + pk_rm + pk_sm

        shared_secret = cls.extract_and_expand(dh, kem_context)
        return shared_secret, enc

    @classmethod
    def auth_decap(
        cls,
        enc: bytes,
        sk_r: HPKEPrivateKeyType,
        pk_s: HPKEPublicKeyType,
    ) -> bytes:
        pk_e = cls.deserialize_public_key(enc)
        dh = cls.dh(sk_r, pk_e) + cls.dh(sk_r, pk_s)

        pk_rm = cls.serialize_public_key(sk_r.public_key())
        pk_sm = cls.serialize_public_key(pk_s)
        kem_context = enc + pk_rm + pk_sm

        shared_secret = cls.extract_and_expand(dh, kem_context)
        return shared_secret

    @classmethod
    def dh(cls, sk_x: HPKEPrivateKeyType, pk_y: HPKEPublicKeyType) -> bytes:
        """
        Perform a non-interactive Diffie-Hellman exchange using the
        private key *sk_x* and public key *pk_y* to produce a Diffie-Hellman
        shared secret of length *n_dh*
        """
        raise NotImplementedError

    @classmethod
    def serialize_public_key(cls, pk_x: HPKEPublicKeyType) -> bytes:
        raise NotImplementedError

    @classmethod
    def deserialize_public_key(cls, pk_xm: bytes) -> HPKEPublicKeyType:
        raise NotImplementedError

    @classmethod
    def serialize_private_key(cls, sk_x: HPKEPrivateKeyType) -> bytes:
        raise NotImplementedError

    @classmethod
    def deserialize_private_key(cls, sk_xm: bytes) -> HPKEPrivateKeyType:
        raise NotImplementedError

    @classmethod
    def generate(cls) -> HPKEPrivateKeyType:
        raise NotImplementedError


class DHKEM_Weierstrass(DHKEM):
    curve: typing.ClassVar[ec.EllipticCurve]

    @classmethod
    def dh(cls, sk_x: HPKEPrivateKeyType, pk_y: HPKEPublicKeyType) -> bytes:
        if not isinstance(sk_x, ec.EllipticCurvePrivateKey):
            raise TypeError("sk_x must be ec.EllipticCurvePrivateKey")
        if not isinstance(pk_y, ec.EllipticCurvePublicKey):
            raise TypeError("pk_y must be ec.EllipticCurvePublicKey")
        return sk_x.exchange(ec.ECDH(), pk_y)

    @classmethod
    def serialize_public_key(cls, pk_x: HPKEPublicKeyType) -> bytes:
        if not isinstance(pk_x, ec.EllipticCurvePublicKey):
            raise TypeError("pk_x must be ec.EllipticCurvePublicKey")
        return pk_x.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)

    @classmethod
    def deserialize_public_key(cls, pk_xm: bytes) -> ec.EllipticCurvePublicKey:
        return ec.EllipticCurvePublicKey.from_encoded_point(cls.curve, pk_xm)

    @classmethod
    def serialize_private_key(cls, sk_x: HPKEPrivateKeyType) -> bytes:
        if not isinstance(sk_x, ec.EllipticCurvePrivateKey):
            raise TypeError("sk_x must be ec.EllipticCurvePrivateKey")
        scalar = sk_x.private_numbers().private_value
        return int_to_bytes(scalar, sk_x.key_size // 8)

    @classmethod
    def deserialize_private_key(
        cls, sk_xm: bytes
    ) -> ec.EllipticCurvePrivateKey:
        scalar = bytes_to_int(sk_xm)
        return ec.derive_private_key(scalar, cls.curve)

    @classmethod
    def generate(cls) -> ec.EllipticCurvePrivateKey:
        return ec.generate_private_key(cls.curve)


class DHKEM_P256_HKDF_SHA256(DHKEM_Weierstrass):
    id = 0x0010
    kdf = HKDF_SHA256
    curve = ec.SECP256R1()


class DHKEM_P384_HKDF_SHA384(DHKEM_Weierstrass):
    id = 0x0011
    kdf = HKDF_SHA384
    curve = ec.SECP384R1()


class DHKEM_P521_HKDF_SHA512(DHKEM_Weierstrass):
    id = 0x0012
    kdf = HKDF_SHA512
    curve = ec.SECP521R1()


class DHKEM_X25519_HKDF_SHA256(DHKEM):
    id = 0x0020
    kdf = HKDF_SHA256

    @classmethod
    def dh(cls, sk_x: HPKEPrivateKeyType, pk_y: HPKEPublicKeyType) -> bytes:
        if not isinstance(sk_x, x25519.X25519PrivateKey):
            raise TypeError("sk_x must be x25519.X25519PrivateKey")
        if not isinstance(pk_y, x25519.X25519PublicKey):
            raise TypeError("pk_y must be x25519.X25519PublicKey")
        return sk_x.exchange(pk_y)

    @classmethod
    def serialize_public_key(cls, pk_x: HPKEPublicKeyType) -> bytes:
        if not isinstance(pk_x, x25519.X25519PublicKey):
            raise TypeError("pk_x must be x25519.X25519PublicKey")
        return pk_x.public_bytes(Encoding.Raw, PublicFormat.Raw)

    @classmethod
    def deserialize_public_key(cls, pk_xm: bytes) -> x25519.X25519PublicKey:
        return x25519.X25519PublicKey.from_public_bytes(pk_xm)

    @classmethod
    def serialize_private_key(cls, sk_x: HPKEPrivateKeyType) -> bytes:
        if not isinstance(sk_x, x25519.X25519PrivateKey):
            raise TypeError("sk_x must be x25519.X25519PrivateKey")
        return sk_x.private_bytes_raw()

    @classmethod
    def deserialize_private_key(cls, sk_xm: bytes) -> x25519.X25519PrivateKey:
        return x25519.X25519PrivateKey.from_private_bytes(sk_xm)

    @classmethod
    def generate(cls) -> x25519.X25519PrivateKey:
        return x25519.X25519PrivateKey.generate()


# AEAD
class AEAD:
    id: typing.ClassVar[int]
    key_size: typing.ClassVar[int]
    nonce_size: typing.ClassVar[int]
    tag_length: typing.ClassVar[int] = 16

    @classmethod
    def get_cipher(cls, key: bytes) -> AEADContext:
        raise NotImplementedError


class AEAD_AES_GCM(AEAD):
    @classmethod
    def get_cipher(cls, key: bytes) -> aead.AESGCM:
        return aead.AESGCM(key)


class AEAD_AES_128_GCM(AEAD_AES_GCM):
    id = 0x0001
    key_size = 16
    nonce_size = 12


class AEAD_AES_256_GCM(AEAD_AES_GCM):
    id = 0x0002
    key_size = 32
    nonce_size = 12


class AEAD_ChaCha20Poly1305(AEAD):
    id = 0x0003
    key_size = 32
    nonce_size = 12

    @classmethod
    def get_cipher(cls, key: bytes) -> aead.ChaCha20Poly1305:
        return aead.ChaCha20Poly1305(key)


class AEAD_ExportOnly(AEAD):
    id = 0xFFFF
    key_size = 0
    nonce_size = 0


class Context:
    def __init__(
        self,
        kdf: type[HKDF],
        aead: type[AEAD],
        key: bytes,
        base_nonce: bytes,
        exporter_secret: bytes,
        suite_id: bytes,
    ) -> None:
        # Secret State (Immutable)
        self._kdf = kdf
        self._aead = aead
        self._cipher = aead.get_cipher(key)
        self._base_nonce = base_nonce
        self._exporter_secret = exporter_secret
        self._suite_id = suite_id

        # Mutable State (The Counter)
        self._seq_num = 0

    @property
    def aead_overhead(self) -> int:
        return self._aead.tag_length

    def export(self, exporter_context: bytes, length: int) -> bytes:
        """
        Derives a new secret using the exporter_secret and the KDF.
        """
        exporter_secret = self._exporter_secret
        suite_id = self._suite_id
        return self._kdf.labeled_expand(
            exporter_secret, b"sec", exporter_context, length, suite_id
        )

    def _get_seq_num_bytes(self) -> bytes:
        """
        Return encoded sequence number and increment it.

        :Raises OverflowError: when seq_num > 2**64
        """
        if self._seq_num >= (1 << 64):
            raise OverflowError("HPKE sequence number overflow")

        result = int_to_bytes(self._seq_num, self._aead.nonce_size)
        self._seq_num += 1
        return result

    def _compute_nonce(self) -> bytes:
        """
        RFC 9180 Logic: Nonce = BaseNonce XOR SequenceNumber
        """
        seq_num_bytes = self._get_seq_num_bytes()
        return strxor(self._base_nonce, seq_num_bytes)


class SenderContext(Context):
    def seal(self, plaintext: bytes, aad: bytes = b"") -> bytes:
        nonce = self._compute_nonce()
        ciphertext = self._cipher.encrypt(nonce, plaintext, aad)
        return ciphertext


class ReceiverContext(Context):
    def open(self, ciphertext: bytes, aad: bytes = b"") -> bytes:
        nonce = self._compute_nonce()
        plaintext = self._cipher.decrypt(nonce, ciphertext, aad)
        return plaintext


@dataclass(frozen=True)
class CipherSuite:
    kem: type[DHKEM]
    kdf: type[HKDF]
    aead: type[AEAD]

    def _verify_psk_inputs(
        self, mode: Mode, psk: bytes, psk_id: bytes
    ) -> None:
        if not isinstance(psk, bytes):
            raise TypeError("psk must be bytes object")
        if not isinstance(psk_id, bytes):
            raise TypeError("psk_id must be bytes object")

        default_psk = b""
        default_psk_id = b""

        got_psk = psk != default_psk
        got_psk_id = psk_id != default_psk_id
        if got_psk != got_psk_id:
            raise ValueError("Inconsistent PSK inputs")

        if got_psk:
            assert mode in (Mode.PSK, Mode.AUTH_PSK)
            if len(psk) < 32:
                raise ValueError(
                    "the PSK MUST have at least 32 bytes of entropy"
                )
        else:
            assert mode in (Mode.BASE, Mode.AUTH)

    def _key_schedule(
        self,
        context_cls: type[_C],
        mode: Mode,
        shared_secret: bytes,
        info: bytes,
        psk: bytes = b"",
        psk_id: bytes = b"",
    ) -> _C:
        self._verify_psk_inputs(mode, psk, psk_id)

        kem = self.kem
        kdf = self.kdf
        aead = self.aead
        suite_id = b"HPKE" + struct.pack(">HHH", kem.id, kdf.id, aead.id)

        psk_id_hash = kdf.labeled_extract(
            b"", b"psk_id_hash", psk_id, suite_id
        )
        info_hash = kdf.labeled_extract(b"", b"info_hash", info, suite_id)
        key_schedule_context = bytes([mode]) + psk_id_hash + info_hash

        secret = kdf.labeled_extract(shared_secret, b"secret", psk, suite_id)

        nk = aead.key_size
        nn = aead.nonce_size
        key = kdf.labeled_expand(
            secret, b"key", key_schedule_context, nk, suite_id
        )
        base_nonce = kdf.labeled_expand(
            secret, b"base_nonce", key_schedule_context, nn, suite_id
        )
        nh = kdf.algorithm.digest_size
        exporter_secret = kdf.labeled_expand(
            secret, b"exp", key_schedule_context, nh, suite_id
        )
        return context_cls(
            kdf=kdf,
            aead=aead,
            key=key,
            base_nonce=base_nonce,
            exporter_secret=exporter_secret,
            suite_id=suite_id,
        )

    def setup_send(
        self, pk_r: HPKEPublicKeyType, info: bytes
    ) -> tuple[bytes, SenderContext]:
        mode = Mode.BASE
        shared_secret, enc = self.kem.encap(pk_r)
        return enc, self._key_schedule(
            SenderContext, mode, shared_secret, info
        )

    def setup_recv(
        self, enc: bytes, sk_r: HPKEPrivateKeyType, info: bytes
    ) -> ReceiverContext:
        mode = Mode.BASE
        shared_secret = self.kem.decap(enc, sk_r)
        return self._key_schedule(ReceiverContext, mode, shared_secret, info)

    def setup_psk_send(
        self, pk_r: HPKEPublicKeyType, info: bytes, psk: bytes, psk_id: bytes
    ) -> tuple[bytes, SenderContext]:
        mode = Mode.PSK
        shared_secret, enc = self.kem.encap(pk_r)
        return enc, self._key_schedule(
            SenderContext, mode, shared_secret, info, psk, psk_id
        )

    def setup_psk_recv(
        self,
        enc: bytes,
        sk_r: HPKEPrivateKeyType,
        info: bytes,
        psk: bytes,
        psk_id: bytes,
    ) -> ReceiverContext:
        mode = Mode.PSK
        shared_secret = self.kem.decap(enc, sk_r)
        return self._key_schedule(
            ReceiverContext, mode, shared_secret, info, psk, psk_id
        )

    def setup_auth_send(
        self, pk_r: HPKEPublicKeyType, info: bytes, sk_s: HPKEPrivateKeyType
    ) -> tuple[bytes, SenderContext]:
        mode = Mode.AUTH
        shared_secret, enc = self.kem.auth_encap(pk_r, sk_s)
        return enc, self._key_schedule(
            SenderContext, mode, shared_secret, info
        )

    def setup_auth_recv(
        self,
        enc: bytes,
        sk_r: HPKEPrivateKeyType,
        info: bytes,
        pk_s: HPKEPublicKeyType,
    ) -> ReceiverContext:
        mode = Mode.AUTH
        shared_secret = self.kem.auth_decap(enc, sk_r, pk_s)
        return self._key_schedule(ReceiverContext, mode, shared_secret, info)

    def setup_auth_psk_send(
        self,
        pk_r: HPKEPublicKeyType,
        info: bytes,
        sk_s: HPKEPrivateKeyType,
        psk: bytes,
        psk_id: bytes,
    ) -> tuple[bytes, SenderContext]:
        mode = Mode.AUTH_PSK
        shared_secret, enc = self.kem.auth_encap(pk_r, sk_s)
        return enc, self._key_schedule(
            SenderContext, mode, shared_secret, info, psk, psk_id
        )

    def setup_auth_psk_recv(
        self,
        enc: bytes,
        sk_r: HPKEPrivateKeyType,
        info: bytes,
        pk_s: HPKEPublicKeyType,
        psk: bytes,
        psk_id: bytes,
    ) -> ReceiverContext:
        mode = Mode.AUTH_PSK
        shared_secret = self.kem.auth_decap(enc, sk_r, pk_s)
        return self._key_schedule(
            ReceiverContext, mode, shared_secret, info, psk, psk_id
        )


_KEMS: dict[int, type[DHKEM]] = {
    kem.id: kem
    for kem in (
        DHKEM_P256_HKDF_SHA256,
        DHKEM_P384_HKDF_SHA384,
        DHKEM_P521_HKDF_SHA512,
        DHKEM_X25519_HKDF_SHA256,
    )
}
_KDFS: dict[int, type[HKDF]] = {
    kdf.id: kdf
    for kdf in (
        HKDF_SHA256,
        HKDF_SHA384,
        HKDF_SHA512,
    )
}
_AEADS: dict[int, type[AEAD]] = {
    aead.id: aead
    for aead in (
        AEAD_AES_128_GCM,
        AEAD_AES_256_GCM,
        AEAD_ChaCha20Poly1305,
    )
}
_CACHE: dict[tuple[int, int, int], CipherSuite] = {}


def create_suite(kem_id: int, kdf_id: int, aead_id: int) -> CipherSuite:
    id_pairs = (kem_id, kdf_id, aead_id)
    try:
        return _CACHE[id_pairs]
    except KeyError:
        pass

    name_pairs = ("KEM", "KDF", "AEAD")
    maps = (_KEMS, _KDFS, _AEADS)
    args = []

    for name, id, map in zip(name_pairs, id_pairs, maps, strict=True):
        try:
            args.append(map[id])  # type: ignore
        except KeyError:
            raise ValueError(f"Unsupported {name} id: {id}") from None

    _CACHE[id_pairs] = cipher_suite = CipherSuite(*args)
    return cipher_suite
