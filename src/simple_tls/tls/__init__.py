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

from simple_tls.tls.config import (
    Credential,
    TLSConfiguration,
    load_ech_configs,
)
from simple_tls.tls.connection import TLSConnection
from simple_tls.tls.constants import (
    AlertDescription,
    Authentication,
    CertificateCompressionAlgorithm,
    CipherSuite,
    HashAlgorithm,
    KeyExchange,
    NamedGroup,
    SignatureScheme,
    Symmetric,
    TLSVersion,
)
from simple_tls.tls.enums import Direction, Protocol, VerifyMode
from simple_tls.tls.exceptions import (
    TLSAlert,
    TLSEOFError,
    TLSError,
    TLSLocalAlert,
    TLSRemoteAlert,
    TLSWantReadError,
)
from simple_tls.tls.extensions import ECHConfig
from simple_tls.tls.handshake_server import ClientHelloInfo, HandshakeContext
from simple_tls.tls.key import BasePrivateKey, load_pem_private_key
from simple_tls.tls.keyexchange import DHParameters, load_pem_parameters
from simple_tls.tls.session import TicketAEAD, TicketContext, TLSSession

__all__ = [
    "AlertDescription",
    "Authentication",
    "BasePrivateKey",
    "CertificateCompressionAlgorithm",
    "CipherSuite",
    "ClientHelloInfo",
    "Credential",
    "DHParameters",
    "Direction",
    "ECHConfig",
    "HandshakeContext",
    "HashAlgorithm",
    "KeyExchange",
    "NamedGroup",
    "Protocol",
    "SignatureScheme",
    "Symmetric",
    "TLSAlert",
    "TLSConfiguration",
    "TLSConnection",
    "TLSEOFError",
    "TLSError",
    "TLSLocalAlert",
    "TLSRemoteAlert",
    "TLSSession",
    "TLSVersion",
    "TLSWantReadError",
    "TicketAEAD",
    "TicketContext",
    "VerifyMode",
    "load_ech_configs",
    "load_pem_parameters",
    "load_pem_private_key",
]
