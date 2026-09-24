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

from simple_tls.compression import ZLIB, ZSTD, Brotli

from ._constant import (
    CertificateCompressionAlgorithm,
    NamedGroup,
    SignatureScheme,
    TLSVersion,
)

## TLS Version

TLS_VERSIONS = (
    TLSVersion.TLSv1,
    TLSVersion.TLSv1_1,
    TLSVersion.TLSv1_2,
    TLSVersion.TLSv1_3,
)

## Signature algorithms

ECDSA_SIGNATURE_ALGORITHMS = (
    SignatureScheme.ECDSA_SHA224,
    SignatureScheme.ECDSA_SHA1,
    SignatureScheme.ECDSA_SECP521R1_SHA512,
    SignatureScheme.ECDSA_SECP384R1_SHA384,
    SignatureScheme.ECDSA_SECP256R1_SHA256,
)
DSA_SIGNATURE_ALGORITHMS = (
    SignatureScheme.DSA_SHA512,
    SignatureScheme.DSA_SHA384,
    SignatureScheme.DSA_SHA256,
    SignatureScheme.DSA_SHA224,
    SignatureScheme.DSA_SHA1,
)
RSA_PKCS1_SIGNATURE_ALGORITHMS = (
    SignatureScheme.RSA_PKCS1_SHA512,
    SignatureScheme.RSA_PKCS1_SHA384,
    SignatureScheme.RSA_PKCS1_SHA256,
    SignatureScheme.RSA_PKCS1_SHA224,
    SignatureScheme.RSA_PKCS1_SHA1,
)
RSA_PSS_RSAE_SIGNATURE_ALGORITHMS = (
    SignatureScheme.RSA_PSS_RSAE_SHA512,
    SignatureScheme.RSA_PSS_RSAE_SHA384,
    SignatureScheme.RSA_PSS_RSAE_SHA256,
)
RSA_PSS_PSS_SIGNATURE_ALGORITHMS = (
    SignatureScheme.RSA_PSS_PSS_SHA512,
    SignatureScheme.RSA_PSS_PSS_SHA384,
    SignatureScheme.RSA_PSS_PSS_SHA256,
)
RSA_SIGNATURE_ALGORITHMS = (
    RSA_PKCS1_SIGNATURE_ALGORITHMS
    + RSA_PSS_RSAE_SIGNATURE_ALGORITHMS
    + RSA_PSS_PSS_SIGNATURE_ALGORITHMS
)
EDDSA_SIGNATURE_ALGORITHMS = (
    SignatureScheme.ED25519,
    SignatureScheme.ED448,
)
SIGNATURE_ALGORITHMS = (
    RSA_SIGNATURE_ALGORITHMS
    + DSA_SIGNATURE_ALGORITHMS
    + ECDSA_SIGNATURE_ALGORITHMS
    + EDDSA_SIGNATURE_ALGORITHMS
)

## Groups

ECC_GROUPS = (
    NamedGroup.SECP192R1,
    NamedGroup.SECP224R1,
    NamedGroup.SECP256R1,
    NamedGroup.SECP384R1,
    NamedGroup.SECP521R1,
    NamedGroup.X25519,
    NamedGroup.X448,
)
FFDHE_GROUPS = (
    NamedGroup.FFDHE2048,
    NamedGroup.FFDHE3072,
    NamedGroup.FFDHE4096,
    NamedGroup.FFDHE6144,
    NamedGroup.FFDHE8192,
)
KEM_GROUPS = (
    NamedGroup.SECP256R1MLKEM768,
    NamedGroup.X25519MLKEM768,
    NamedGroup.SECP384R1MLKEM1024,
)
SUPPORTED_GROUPS = ECC_GROUPS + FFDHE_GROUPS + KEM_GROUPS

## Certificate compression algorithmms

CERTIFICATE_COMPRESSIONS: tuple[int, ...] = ()
if ZLIB.SUPPORTED:
    CERTIFICATE_COMPRESSIONS += (CertificateCompressionAlgorithm.ZLIB,)
if ZSTD.SUPPORTED:
    CERTIFICATE_COMPRESSIONS += (CertificateCompressionAlgorithm.ZSTD,)
if Brotli.SUPPORTED:
    CERTIFICATE_COMPRESSIONS += (CertificateCompressionAlgorithm.BROTLI,)
