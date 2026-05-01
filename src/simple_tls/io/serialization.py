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

from cryptography.hazmat.primitives.serialization import (
    load_der_parameters,
    load_der_private_key,
    load_der_public_key,
    load_pem_parameters,
    load_pem_public_key,
    load_ssh_public_key,
)

from ..key.types import PrivateKeyTypes
from ._serialization import (
    BestAvailableEncryption,
    Encoding,
    KeySerializationEncryption,
    NoEncryption,
    ParameterFormat,
    PrivateFormat,
    PublicFormat,
)


def load_pem_private_key(
    data: bytes,
    password: bytes | None,
    backend: typing.Any = None,
    *,
    unsafe_skip_rsa_key_validation: bool = False,
) -> PrivateKeyTypes:
    from cryptography.hazmat.primitives import serialization

    if b"-----BEGIN OPENSSH PRIVATE KEY-----" in data:
        return serialization.load_ssh_private_key(data, password, backend)

    return serialization.load_pem_private_key(
        data,
        password,
        backend,
        unsafe_skip_rsa_key_validation=unsafe_skip_rsa_key_validation,
    )


__all__ = [
    "BestAvailableEncryption",
    "Encoding",
    "KeySerializationEncryption",
    "NoEncryption",
    "ParameterFormat",
    "PrivateFormat",
    "PublicFormat",
    "load_der_parameters",
    "load_der_private_key",
    "load_der_public_key",
    "load_pem_parameters",
    "load_pem_private_key",
    "load_pem_public_key",
    "load_ssh_public_key",
]
