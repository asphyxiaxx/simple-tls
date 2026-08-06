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

from cryptography import exceptions
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import (
    dsa,
    ec,
    ed448,
    ed25519,
    padding,
    rsa,
    utils,
)
from cryptography.hazmat.primitives.asymmetric.types import (
    PrivateKeyTypes,
    PublicKeyTypes,
)

from .. import x509
from ._common import _MD5SHA1, _MD5SHA1Hash, get_algorithm
from ._constant import UNSPECIFIED, HashAlgorithm, NamedGroup, SignatureScheme
from ._supported import DSA_SIGNATURE_ALGORITHMS, ECDSA_SIGNATURE_ALGORITHMS


class InvalidSignature(Exception):
    pass


class BasePrivateKey:
    def sign(self, msg: bytes, signature_algorithm: int) -> bytes:
        raise NotImplementedError


class BasePublicKey:
    def verify(
        self, signature: bytes, msg: bytes, signature_algorithm: int
    ) -> None:
        raise NotImplementedError


class RSAPrivateKey(BasePrivateKey):
    def __init__(self, key: rsa.RSAPrivateKey) -> None:
        self._key = key

    def sign(self, msg: bytes, signature_algorithm: int) -> bytes:
        try:
            func, hashalg = self._SIGNING_FUNCS[signature_algorithm]
        except KeyError:
            raise ValueError(
                f"Invalid signature_algorithm '{signature_algorithm}'"
            ) from None

        if hashalg == UNSPECIFIED:
            algorithm = typing.cast(hashes.HashAlgorithm, _MD5SHA1())
            hashobj = typing.cast(hashes.Hash, _MD5SHA1Hash())
        else:
            algorithm = get_algorithm(hashalg)
            hashobj = hashes.Hash(algorithm)

        hashobj.update(msg)
        msg_hash = hashobj.finalize()

        return func(self._key, msg_hash, algorithm)

    def decrypt(self, ciphertext: bytes) -> bytes | None:
        try:
            return self._key.decrypt(ciphertext, padding.PKCS1v15())
        except ValueError:
            return None

    @property
    def key_size(self) -> int:
        return self._key.key_size

    @staticmethod
    def _sign_rsa_pkcs115(
        key: rsa.RSAPrivateKey,
        data: bytes,
        algorithm: hashes.HashAlgorithm,
    ) -> bytes:
        p = padding.PKCS1v15()
        return key.sign(data, p, utils.Prehashed(algorithm))

    @staticmethod
    def _sign_rsa_pss(
        key: rsa.RSAPrivateKey,
        data: bytes,
        algorithm: hashes.HashAlgorithm,
    ) -> bytes:
        p = padding.PSS(
            mgf=padding.MGF1(algorithm),
            salt_length=algorithm.digest_size,
        )
        return key.sign(data, p, utils.Prehashed(algorithm))

    # fmt: off
    # ruff: disable[E501]
    _SIGNING_FUNCS: typing.ClassVar[dict[int, tuple[typing.Callable, int]]] = {
        SignatureScheme.RSA_PSS_RSAE_SHA512: (_sign_rsa_pss, HashAlgorithm.SHA512),
        SignatureScheme.RSA_PSS_RSAE_SHA384: (_sign_rsa_pss, HashAlgorithm.SHA384),
        SignatureScheme.RSA_PSS_RSAE_SHA256: (_sign_rsa_pss, HashAlgorithm.SHA256),
        SignatureScheme.RSA_PSS_PSS_SHA512: (_sign_rsa_pss, HashAlgorithm.SHA512),
        SignatureScheme.RSA_PSS_PSS_SHA384: (_sign_rsa_pss, HashAlgorithm.SHA384),
        SignatureScheme.RSA_PSS_PSS_SHA256: (_sign_rsa_pss, HashAlgorithm.SHA256),
        SignatureScheme.RSA_PKCS1_SHA512: (_sign_rsa_pkcs115, HashAlgorithm.SHA512),
        SignatureScheme.RSA_PKCS1_SHA384: (_sign_rsa_pkcs115, HashAlgorithm.SHA384),
        SignatureScheme.RSA_PKCS1_SHA256: (_sign_rsa_pkcs115, HashAlgorithm.SHA256),
        SignatureScheme.RSA_PKCS1_SHA224: (_sign_rsa_pkcs115, HashAlgorithm.SHA224),
        SignatureScheme.RSA_PKCS1_SHA1: (_sign_rsa_pkcs115, HashAlgorithm.SHA1),
        UNSPECIFIED: (_sign_rsa_pkcs115, UNSPECIFIED),
    }
    # fmt: on
    # ruff: enable[E501]


class RSAPublicKey(BasePublicKey):
    def __init__(self, key: rsa.RSAPublicKey) -> None:
        self._key = key

    def verify(
        self, signature: bytes, msg: bytes, signature_algorithm: int
    ) -> None:
        try:
            func, hashalg = self._VERIFYING_FUNCS[signature_algorithm]
        except KeyError:
            raise ValueError(
                f"Invalid signature_algorithm '{signature_algorithm}'"
            ) from None

        if hashalg == UNSPECIFIED:
            algorithm = typing.cast(hashes.HashAlgorithm, _MD5SHA1())
            hashobj = typing.cast(hashes.Hash, _MD5SHA1Hash())
        else:
            algorithm = get_algorithm(hashalg)
            hashobj = hashes.Hash(algorithm)

        hashobj.update(msg)
        msg_hash = hashobj.finalize()

        try:
            func(self._key, signature, msg_hash, algorithm)
        except exceptions.InvalidSignature:
            raise InvalidSignature from None

    def encrypt(self, plaintext: bytes) -> bytes:
        return self._key.encrypt(plaintext, padding.PKCS1v15())

    @property
    def key_size(self) -> int:
        return self._key.key_size

    @staticmethod
    def _verify_rsa_pkcs115(
        key: rsa.RSAPublicKey,
        signature: bytes,
        data: bytes,
        algorithm: hashes.HashAlgorithm,
    ) -> None:
        p = padding.PKCS1v15()
        key.verify(signature, data, p, utils.Prehashed(algorithm))

    @staticmethod
    def _verify_rsa_pss(
        key: rsa.RSAPublicKey,
        signature: bytes,
        data: bytes,
        algorithm: hashes.HashAlgorithm,
    ) -> None:
        p = padding.PSS(
            mgf=padding.MGF1(algorithm),
            salt_length=algorithm.digest_size,
        )
        key.verify(signature, data, p, utils.Prehashed(algorithm))

    # fmt: off
    # ruff: disable[E501]
    _VERIFYING_FUNCS: typing.ClassVar[dict[int, tuple[typing.Callable, int]]] = {
        SignatureScheme.RSA_PSS_RSAE_SHA512: (_verify_rsa_pss, HashAlgorithm.SHA512),
        SignatureScheme.RSA_PSS_RSAE_SHA384: (_verify_rsa_pss, HashAlgorithm.SHA384),
        SignatureScheme.RSA_PSS_RSAE_SHA256: (_verify_rsa_pss, HashAlgorithm.SHA256),
        SignatureScheme.RSA_PSS_PSS_SHA512: (_verify_rsa_pss, HashAlgorithm.SHA512),
        SignatureScheme.RSA_PSS_PSS_SHA384: (_verify_rsa_pss, HashAlgorithm.SHA384),
        SignatureScheme.RSA_PSS_PSS_SHA256: (_verify_rsa_pss, HashAlgorithm.SHA256),
        SignatureScheme.RSA_PKCS1_SHA512: (_verify_rsa_pkcs115, HashAlgorithm.SHA512),
        SignatureScheme.RSA_PKCS1_SHA384: (_verify_rsa_pkcs115, HashAlgorithm.SHA384),
        SignatureScheme.RSA_PKCS1_SHA256: (_verify_rsa_pkcs115, HashAlgorithm.SHA256),
        SignatureScheme.RSA_PKCS1_SHA224: (_verify_rsa_pkcs115, HashAlgorithm.SHA224),
        SignatureScheme.RSA_PKCS1_SHA1: (_verify_rsa_pkcs115, HashAlgorithm.SHA1),
        UNSPECIFIED: (_verify_rsa_pkcs115, UNSPECIFIED),
    }
    # fmt: on
    # ruff: enable[E501]


class DSAPrivateKey(BasePrivateKey):
    def __init__(self, key: dsa.DSAPrivateKey) -> None:
        self._key = key

    def sign(self, msg: bytes, signature_algorithm: int) -> bytes:
        if signature_algorithm not in DSA_SIGNATURE_ALGORITHMS:
            raise ValueError(
                f"Invalid signature_algorithm '{signature_algorithm}'"
            )

        hashalg = (signature_algorithm >> 8) & 0xFF
        algorithm = get_algorithm(hashalg)

        return self._key.sign(msg, algorithm)

    @property
    def key_size(self) -> int:
        return self._key.key_size


class DSAPublicKey(BasePublicKey):
    def __init__(self, key: dsa.DSAPublicKey) -> None:
        self._key = key

    def verify(
        self, signature: bytes, msg: bytes, signature_algorithm: int
    ) -> None:
        if signature_algorithm not in DSA_SIGNATURE_ALGORITHMS:
            raise ValueError(
                f"Invalid signature_algorithm '{signature_algorithm}'"
            )

        hashalg = (signature_algorithm >> 8) & 0xFF
        algorithm = get_algorithm(hashalg)

        try:
            self._key.verify(signature, msg, algorithm)
        except exceptions.InvalidSignature:
            raise InvalidSignature from None

    @property
    def key_size(self) -> int:
        return self._key.key_size


_GROUP_IDS = {
    "secp192r1": NamedGroup.SECP192R1,
    "secp224r1": NamedGroup.SECP224R1,
    "secp256r1": NamedGroup.SECP256R1,
    "secp384r1": NamedGroup.SECP384R1,
    "secp521r1": NamedGroup.SECP521R1,
    "secp256k1": NamedGroup.SECP256K1,
}


def _get_curve_group_id(curve: ec.EllipticCurve) -> int:
    try:
        return _GROUP_IDS[curve.name]
    except KeyError:
        raise ValueError(f"Unsupported curve '{curve.name}'")


class ECPrivateKey(BasePrivateKey):
    def __init__(self, key: ec.EllipticCurvePrivateKey) -> None:
        self._key = key

    def sign(self, msg: bytes, signature_algorithm: int) -> bytes:
        if signature_algorithm not in ECDSA_SIGNATURE_ALGORITHMS:
            raise ValueError(
                f"Invalid signature_algorithm '{signature_algorithm}'"
            )

        hashalg = (signature_algorithm >> 8) & 0xFF
        algorithm = get_algorithm(hashalg)

        return self._key.sign(msg, ec.ECDSA(algorithm))

    @property
    def group_id(self) -> int:
        return _get_curve_group_id(self._key.curve)


class ECPublicKey(BasePublicKey):
    def __init__(self, key: ec.EllipticCurvePublicKey) -> None:
        self._key = key

    def verify(
        self, signature: bytes, msg: bytes, signature_algorithm: int
    ) -> None:
        if signature_algorithm not in ECDSA_SIGNATURE_ALGORITHMS:
            raise ValueError(
                f"Invalid signature_algorithm '{signature_algorithm}'"
            )

        hashalg = (signature_algorithm >> 8) & 0xFF
        algorithm = get_algorithm(hashalg)

        try:
            self._key.verify(signature, msg, ec.ECDSA(algorithm))
        except exceptions.InvalidSignature:
            raise InvalidSignature from None

    @property
    def group_id(self) -> int:
        return _get_curve_group_id(self._key.curve)


class Ed25519PrivateKey(BasePrivateKey):
    def __init__(self, key: ed25519.Ed25519PrivateKey) -> None:
        self._key = key

    def sign(self, msg: bytes, signature_algorithm: int) -> bytes:
        if signature_algorithm != SignatureScheme.ED25519:
            raise ValueError(
                f"Invalid signature_algorithm '{signature_algorithm}'"
            )

        return self._key.sign(msg)


class Ed25519PublicKey(BasePublicKey):
    def __init__(self, key: ed25519.Ed25519PublicKey) -> None:
        self._key = key

    def verify(
        self, signature: bytes, msg: bytes, signature_algorithm: int
    ) -> None:
        if signature_algorithm != SignatureScheme.ED25519:
            raise ValueError(
                f"Invalid signature_algorithm '{signature_algorithm}'"
            )

        try:
            self._key.verify(signature, msg)
        except exceptions.InvalidSignature:
            raise InvalidSignature from None


class Ed448PrivateKey(BasePrivateKey):
    def __init__(self, key: ed448.Ed448PrivateKey) -> None:
        self._key = key

    def sign(self, msg: bytes, signature_algorithm: int) -> bytes:
        if signature_algorithm != SignatureScheme.ED448:
            raise ValueError(
                f"Invalid signature_algorithm '{signature_algorithm}'"
            )

        return self._key.sign(msg)


class Ed448PublicKey(BasePublicKey):
    def __init__(self, key: ed448.Ed448PublicKey) -> None:
        self._key = key

    def verify(
        self, signature: bytes, msg: bytes, signature_algorithm: int
    ) -> None:
        if signature_algorithm != SignatureScheme.ED448:
            raise ValueError(
                f"Invalid signature_algorithm '{signature_algorithm}'"
            )

        try:
            self._key.verify(signature, msg)
        except exceptions.InvalidSignature:
            raise InvalidSignature from None


def _map_public_key(public_key: PublicKeyTypes) -> BasePublicKey:
    if isinstance(public_key, rsa.RSAPublicKey):
        return RSAPublicKey(public_key)
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return ECPublicKey(public_key)
    if isinstance(public_key, ed25519.Ed25519PublicKey):
        return Ed25519PublicKey(public_key)
    if isinstance(public_key, ed448.Ed448PublicKey):
        return Ed448PublicKey(public_key)
    if isinstance(public_key, dsa.DSAPublicKey):
        return DSAPublicKey(public_key)

    raise TypeError(
        f"Unsupported key type in certificate: {type(public_key).__name__}"
    )


def _map_private_key(private_key: PrivateKeyTypes) -> BasePrivateKey:
    if isinstance(private_key, rsa.RSAPrivateKey):
        return RSAPrivateKey(private_key)
    if isinstance(private_key, ec.EllipticCurvePrivateKey):
        return ECPrivateKey(private_key)
    if isinstance(private_key, ed25519.Ed25519PrivateKey):
        return Ed25519PrivateKey(private_key)
    if isinstance(private_key, ed448.Ed448PrivateKey):
        return Ed448PrivateKey(private_key)
    if isinstance(private_key, dsa.DSAPrivateKey):
        return DSAPrivateKey(private_key)

    raise TypeError(
        f"Unsupported key type in certificate: {type(private_key).__name__}"
    )


def load_certificate_public_key(
    certificate: x509.Certificate,
) -> BasePublicKey:
    public_key = certificate.public_key()
    return _map_public_key(public_key)


def load_pem_private_key(
    data: bytes, password: bytes | None
) -> BasePrivateKey:
    private_key: PrivateKeyTypes
    if b"-----BEGIN OPENSSH PRIVATE KEY-----" in data:
        private_key = serialization.load_ssh_private_key(data, password)
    else:
        private_key = serialization.load_pem_private_key(data, password)

    return _map_private_key(private_key)
