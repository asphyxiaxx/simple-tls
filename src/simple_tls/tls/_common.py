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

import typing

from cryptography.hazmat.primitives import hashes

from ..key import dsa, ec, ed448, ed25519, padding, rsa, utils
from ..key.types import (
    CertificateIssuerPrivateKeyTypes,
    CertificatePublicKeyTypes,
)
from ._constant import HashAlgorithm, SignatureScheme


class MD5_SHA1(hashes.HashAlgorithm):
    name = "md5-sha1"
    digest_size = 36
    block_size = 64


class MD5_SHA1_Hash:
    def __init__(self) -> None:
        self.__md5 = hashes.Hash(hashes.MD5())
        self.__sha1 = hashes.Hash(hashes.SHA1())
        self.__algorithm = MD5_SHA1()

    @property
    def algorithm(self) -> hashes.HashAlgorithm:
        return self.__algorithm

    def update(self, data: bytes) -> None:
        self.__md5.update(data)
        self.__sha1.update(data)

    def finalize(self) -> bytes:
        return self.__md5.finalize() + self.__sha1.finalize()

    def copy(self) -> "MD5_SHA1_Hash":
        new = MD5_SHA1_Hash()
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


def get_algorithm(hash_algorithm: int) -> hashes.HashAlgorithm:
    return _HASH_ALGORITHMS[hash_algorithm]


def get_hash(
    hash_algorithm: HashAlgorithm, message: bytes = b""
) -> hashes.Hash:
    if hash_algorithm == HashAlgorithm.MD5_SHA1:
        hashobj = typing.cast(hashes.Hash, MD5_SHA1_Hash())
    else:
        algorithm = get_algorithm(hash_algorithm)
        hashobj = hashes.Hash(algorithm)

    hashobj.update(message)
    return hashobj


def _sign_dsa(
    key: CertificateIssuerPrivateKeyTypes,
    data: bytes,
    algorithm: hashes.HashAlgorithm | None,
) -> bytes:
    if not isinstance(key, dsa.DSAPrivateKey):
        raise TypeError("Invalid key type")
    if algorithm is None:
        raise ValueError("Missing algorithm")
    return key.sign(data, utils.Prehashed(algorithm))


def _sign_ec(
    key: CertificateIssuerPrivateKeyTypes,
    data: bytes,
    algorithm: hashes.HashAlgorithm | None,
) -> bytes:
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise TypeError("Invalid key type")
    if algorithm is None:
        raise ValueError("Missing algorithm")
    signature_algorithm = ec.ECDSA(utils.Prehashed(algorithm))
    return key.sign(data, signature_algorithm)


def _sign_rsa_pkcs115(
    key: CertificateIssuerPrivateKeyTypes,
    data: bytes,
    algorithm: hashes.HashAlgorithm | None,
) -> bytes:
    if not isinstance(key, rsa.RSAPrivateKey):
        raise TypeError("Invalid key type")
    if algorithm is None:
        raise ValueError("Missing algorithm")
    p = padding.PKCS1v15()
    return key.sign(data, p, utils.Prehashed(algorithm))


def _sign_rsa_pss(
    key: CertificateIssuerPrivateKeyTypes,
    data: bytes,
    algorithm: hashes.HashAlgorithm | None,
) -> bytes:
    if not isinstance(key, rsa.RSAPrivateKey):
        raise TypeError("Invalid key type")
    if algorithm is None:
        raise ValueError("Missing algorithm")
    p = padding.PSS(
        mgf=padding.MGF1(algorithm),
        salt_length=algorithm.digest_size,
    )
    return key.sign(data, p, utils.Prehashed(algorithm))


def _sign_ed25519(
    key: CertificateIssuerPrivateKeyTypes,
    data: bytes,
    algorithm: hashes.HashAlgorithm | None,
) -> bytes:
    if not isinstance(key, ed25519.Ed25519PrivateKey):
        raise TypeError("Invalid key type")
    if algorithm is not None:
        raise ValueError("algorithm not None")
    return key.sign(data)


def _sign_ed448(
    key: CertificateIssuerPrivateKeyTypes,
    data: bytes,
    algorithm: hashes.HashAlgorithm | None,
) -> bytes:
    if not isinstance(key, ed448.Ed448PrivateKey):
        raise TypeError("Invalid key type")
    if algorithm is not None:
        raise ValueError("algorithm not None")
    return key.sign(data)


_CREATE_SIGNATURE_FUNC: dict[int, tuple[typing.Any, int]] = {
    SignatureScheme.RSA_PSS_RSAE_SHA512: (_sign_rsa_pss, HashAlgorithm.SHA512),
    SignatureScheme.RSA_PSS_PSS_SHA512: (_sign_rsa_pss, HashAlgorithm.SHA512),
    SignatureScheme.RSA_PSS_RSAE_SHA384: (_sign_rsa_pss, HashAlgorithm.SHA384),
    SignatureScheme.RSA_PSS_PSS_SHA384: (_sign_rsa_pss, HashAlgorithm.SHA384),
    SignatureScheme.RSA_PSS_RSAE_SHA256: (_sign_rsa_pss, HashAlgorithm.SHA256),
    SignatureScheme.RSA_PSS_PSS_SHA256: (_sign_rsa_pss, HashAlgorithm.SHA256),
    SignatureScheme.DSA_SHA512: (_sign_dsa, HashAlgorithm.SHA512),
    SignatureScheme.DSA_SHA384: (_sign_dsa, HashAlgorithm.SHA384),
    SignatureScheme.DSA_SHA256: (_sign_dsa, HashAlgorithm.SHA256),
    SignatureScheme.DSA_SHA224: (_sign_dsa, HashAlgorithm.SHA224),
    SignatureScheme.DSA_SHA1: (_sign_dsa, HashAlgorithm.SHA1),
    SignatureScheme.RSA_PKCS1_SHA512: (
        _sign_rsa_pkcs115,
        HashAlgorithm.SHA512,
    ),
    SignatureScheme.RSA_PKCS1_SHA384: (
        _sign_rsa_pkcs115,
        HashAlgorithm.SHA384,
    ),
    SignatureScheme.RSA_PKCS1_SHA256: (
        _sign_rsa_pkcs115,
        HashAlgorithm.SHA256,
    ),
    SignatureScheme.RSA_PKCS1_SHA224: (
        _sign_rsa_pkcs115,
        HashAlgorithm.SHA224,
    ),
    SignatureScheme.RSA_PKCS1_SHA1: (_sign_rsa_pkcs115, HashAlgorithm.SHA1),
    SignatureScheme.ECDSA_SHA224: (_sign_ec, HashAlgorithm.SHA224),
    SignatureScheme.ECDSA_SHA1: (_sign_ec, HashAlgorithm.SHA1),
    SignatureScheme.ECDSA_SECP521R1_SHA512: (_sign_ec, HashAlgorithm.SHA512),
    SignatureScheme.ECDSA_SECP384R1_SHA384: (_sign_ec, HashAlgorithm.SHA384),
    SignatureScheme.ECDSA_SECP256R1_SHA256: (_sign_ec, HashAlgorithm.SHA256),
    SignatureScheme.ED25519: (_sign_ed25519, HashAlgorithm.INTRINSIC),
    SignatureScheme.ED448: (_sign_ed448, HashAlgorithm.INTRINSIC),
    SignatureScheme.RSA_MD5_SHA1: (_sign_rsa_pkcs115, HashAlgorithm.MD5_SHA1),
}


def create_signature(
    private_key: CertificateIssuerPrivateKeyTypes,
    msg: bytes,
    signature_algorithm: int,
) -> bytes:
    try:
        sign_func, hashalg = _CREATE_SIGNATURE_FUNC[signature_algorithm]
    except KeyError:
        raise ValueError("Invalid signature_algorithm")

    if hashalg == HashAlgorithm.INTRINSIC:
        algorithm = None
        msg_hash = msg
    else:
        if hashalg == HashAlgorithm.MD5_SHA1:
            algorithm = typing.cast(hashes.HashAlgorithm, MD5_SHA1())
            hashobj = typing.cast(hashes.Hash, MD5_SHA1_Hash())
        else:
            algorithm = get_algorithm(hashalg)
            hashobj = hashes.Hash(algorithm)

        hashobj.update(msg)
        msg_hash = hashobj.finalize()

    return sign_func(private_key, msg_hash, algorithm)


def _verify_dsa(
    key: CertificatePublicKeyTypes,
    signature: bytes,
    data: bytes,
    algorithm: hashes.HashAlgorithm | None,
) -> None:
    if not isinstance(key, dsa.DSAPublicKey):
        raise TypeError("Invalid key type")
    if algorithm is None:
        raise ValueError("Missing algorithm")
    key.verify(signature, data, utils.Prehashed(algorithm))


def _verify_ec(
    key: CertificatePublicKeyTypes,
    signature: bytes,
    data: bytes,
    algorithm: hashes.HashAlgorithm | None,
) -> None:
    if not isinstance(key, ec.EllipticCurvePublicKey):
        raise TypeError("Invalid key type")
    if algorithm is None:
        raise ValueError("Missing algorithm")
    signature_algorithm = ec.ECDSA(utils.Prehashed(algorithm))
    key.verify(signature, data, signature_algorithm)


def _verify_rsa_pkcs115(
    key: CertificatePublicKeyTypes,
    signature: bytes,
    data: bytes,
    algorithm: hashes.HashAlgorithm | None,
) -> None:
    if not isinstance(key, rsa.RSAPublicKey):
        raise TypeError("Invalid key type")
    if algorithm is None:
        raise ValueError("Missing algorithm")
    p = padding.PKCS1v15()
    key.verify(signature, data, p, utils.Prehashed(algorithm))


def _verify_rsa_pss(
    key: CertificatePublicKeyTypes,
    signature: bytes,
    data: bytes,
    algorithm: hashes.HashAlgorithm | None,
) -> None:
    if not isinstance(key, rsa.RSAPublicKey):
        raise TypeError("Invalid key type")
    if algorithm is None:
        raise ValueError("Missing algorithm")
    p = padding.PSS(
        mgf=padding.MGF1(algorithm),
        salt_length=algorithm.digest_size,
    )
    key.verify(signature, data, p, utils.Prehashed(algorithm))


def _verify_ed25519(
    key: CertificatePublicKeyTypes,
    signature: bytes,
    data: bytes,
    algorithm: hashes.HashAlgorithm | None,
) -> None:
    if not isinstance(key, ed25519.Ed25519PublicKey):
        raise TypeError("Invalid key type")
    if algorithm is not None:
        raise ValueError("algorithm not None")
    key.verify(signature, data)


def _verify_ed448(
    key: CertificatePublicKeyTypes,
    signature: bytes,
    data: bytes,
    algorithm: hashes.HashAlgorithm | None,
) -> None:
    if not isinstance(key, ed448.Ed448PublicKey):
        raise TypeError("Invalid key type")
    if algorithm is not None:
        raise ValueError("algorithm not None")
    key.verify(signature, data)


_VERIFY_SIGNATURE_FUNC: dict[int, tuple[typing.Any, int]] = {
    SignatureScheme.RSA_PSS_RSAE_SHA512: (
        _verify_rsa_pss,
        HashAlgorithm.SHA512,
    ),
    SignatureScheme.RSA_PSS_PSS_SHA512: (
        _verify_rsa_pss,
        HashAlgorithm.SHA512,
    ),
    SignatureScheme.RSA_PSS_RSAE_SHA384: (
        _verify_rsa_pss,
        HashAlgorithm.SHA384,
    ),
    SignatureScheme.RSA_PSS_PSS_SHA384: (
        _verify_rsa_pss,
        HashAlgorithm.SHA384,
    ),
    SignatureScheme.RSA_PSS_RSAE_SHA256: (
        _verify_rsa_pss,
        HashAlgorithm.SHA256,
    ),
    SignatureScheme.RSA_PSS_PSS_SHA256: (
        _verify_rsa_pss,
        HashAlgorithm.SHA256,
    ),
    SignatureScheme.DSA_SHA512: (_verify_dsa, HashAlgorithm.SHA512),
    SignatureScheme.DSA_SHA384: (_verify_dsa, HashAlgorithm.SHA384),
    SignatureScheme.DSA_SHA256: (_verify_dsa, HashAlgorithm.SHA256),
    SignatureScheme.DSA_SHA224: (_verify_dsa, HashAlgorithm.SHA224),
    SignatureScheme.DSA_SHA1: (_verify_dsa, HashAlgorithm.SHA1),
    SignatureScheme.RSA_PKCS1_SHA512: (
        _verify_rsa_pkcs115,
        HashAlgorithm.SHA512,
    ),
    SignatureScheme.RSA_PKCS1_SHA384: (
        _verify_rsa_pkcs115,
        HashAlgorithm.SHA384,
    ),
    SignatureScheme.RSA_PKCS1_SHA256: (
        _verify_rsa_pkcs115,
        HashAlgorithm.SHA256,
    ),
    SignatureScheme.RSA_PKCS1_SHA224: (
        _verify_rsa_pkcs115,
        HashAlgorithm.SHA224,
    ),
    SignatureScheme.RSA_PKCS1_SHA1: (_verify_rsa_pkcs115, HashAlgorithm.SHA1),
    SignatureScheme.ECDSA_SHA224: (_verify_ec, HashAlgorithm.SHA224),
    SignatureScheme.ECDSA_SHA1: (_verify_ec, HashAlgorithm.SHA1),
    SignatureScheme.ECDSA_SECP521R1_SHA512: (_verify_ec, HashAlgorithm.SHA512),
    SignatureScheme.ECDSA_SECP384R1_SHA384: (_verify_ec, HashAlgorithm.SHA384),
    SignatureScheme.ECDSA_SECP256R1_SHA256: (_verify_ec, HashAlgorithm.SHA256),
    SignatureScheme.ED25519: (_verify_ed25519, HashAlgorithm.INTRINSIC),
    SignatureScheme.ED448: (_verify_ed448, HashAlgorithm.INTRINSIC),
    SignatureScheme.RSA_MD5_SHA1: (
        _verify_rsa_pkcs115,
        HashAlgorithm.MD5_SHA1,
    ),
}


def verify_signature(
    public_key: CertificatePublicKeyTypes,
    signature: bytes,
    msg: bytes,
    signature_algorithm: int,
) -> None:
    try:
        verify_func, hashalg = _VERIFY_SIGNATURE_FUNC[signature_algorithm]
    except KeyError:
        raise ValueError("Invalid signature_algorithm")

    if hashalg == HashAlgorithm.INTRINSIC:
        algorithm = None
        msg_hash = msg
    else:
        if hashalg == HashAlgorithm.MD5_SHA1:
            algorithm = typing.cast(hashes.HashAlgorithm, MD5_SHA1())
            hashobj = typing.cast(hashes.Hash, MD5_SHA1_Hash())
        else:
            algorithm = get_algorithm(hashalg)
            hashobj = hashes.Hash(algorithm)

        hashobj.update(msg)
        msg_hash = hashobj.finalize()

    verify_func(public_key, signature, msg_hash, algorithm)
