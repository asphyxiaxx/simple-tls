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

from . import dh, dsa, ec, ed448, ed25519, mlkem, rsa, x448, x25519

__all__ = [
    "CertificateIssuerPrivateKeyTypes",
    "CertificatePublicKeyTypes",
    "ParameterTypes",
    "PrivateKeyTypes",
    "PublicKeyTypes",
]


ParameterTypes = typing.Union[dh.DHParameters, dsa.DSAParameters]


PublicKeyTypes = typing.Union[
    dh.DHPublicKey,
    dsa.DSAPublicKey,
    ec.EllipticCurvePublicKey,
    ed25519.Ed25519PublicKey,
    ed448.Ed448PublicKey,
    mlkem.MLKEM768PublicKey,
    mlkem.MLKEM1024PublicKey,
    rsa.RSAPublicKey,
    x25519.X25519PublicKey,
    x448.X448PublicKey,
]
PrivateKeyTypes = typing.Union[
    dh.DHPrivateKey,
    dsa.DSAPrivateKey,
    ec.EllipticCurvePrivateKey,
    ed25519.Ed25519PrivateKey,
    ed448.Ed448PrivateKey,
    mlkem.MLKEM768PrivateKey,
    mlkem.MLKEM1024PrivateKey,
    rsa.RSAPrivateKey,
    x25519.X25519PrivateKey,
    x448.X448PrivateKey,
]


CertificateIssuerPrivateKeyTypes = typing.Union[
    dsa.DSAPrivateKey,
    ec.EllipticCurvePrivateKey,
    ed25519.Ed25519PrivateKey,
    ed448.Ed448PrivateKey,
    rsa.RSAPrivateKey,
]
CertificatePublicKeyTypes = typing.Union[
    dsa.DSAPublicKey,
    rsa.RSAPublicKey,
    ec.EllipticCurvePublicKey,
    ed25519.Ed25519PublicKey,
    ed448.Ed448PublicKey,
    x25519.X25519PublicKey,
    x448.X448PublicKey,
]


SSHPrivateKeyTypes = typing.Union[
    rsa.RSAPrivateKey,
    dsa.DSAPrivateKey,
    ec.EllipticCurvePrivateKey,
    ed25519.Ed25519PrivateKey,
]
SSHPublicKeyTypes = typing.Union[
    rsa.RSAPublicKey,
    dsa.DSAPublicKey,
    ec.EllipticCurvePublicKey,
    ed25519.Ed25519PublicKey,
]
