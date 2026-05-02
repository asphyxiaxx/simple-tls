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

_ALERT_MAP = {
    0: "close_notify",
    10: "unexpected_message",
    20: "bad_record_mac",
    21: "decryption_failed",
    22: "record_overflow",
    30: "decompression_failure",
    40: "handshake_failure",
    41: "no_certificate",
    42: "bad_certificate",
    43: "unsupported_certificate",
    44: "certificate_revoked",
    45: "certificate_expired",
    46: "certificate_unknown",
    47: "illegal_parameter",
    48: "unknown_ca",
    49: "access_denied",
    50: "decode_error",
    51: "decrypt_error",
    70: "protocol_version",
    71: "insufficient_security",
    80: "internal_error",
    86: "inappropriate_fallback",
    90: "user_cancelled",
    100: "no_renegotiation",
    109: "missing_extension",
    110: "unsupported_extension",
    111: "certificate_unobtainable",
    112: "unrecognized_name",
    113: "bad_certificate_status_response",
    114: "bad_certificate_hash_value",
    115: "unknown_psk_identity",
    116: "certificate_required",
    120: "no_application_protocol",
    121: "ech_required",
}


class TLSError(Exception):
    default: str = ""

    def __init__(self, message: str | Exception | None = None) -> None:
        if not message:
            message = self.default
        elif isinstance(message, Exception):
            message = f"{type(message).__name__}: {message}"
        Exception.__init__(self, message)


class TLSEOFError(TLSError):
    default = "The socket was closed."


class TLSAlert(TLSError):
    def __init__(self, description: int, reason: typing.Any = None) -> None:
        self.description = description
        self.reason = reason
        message = _ALERT_MAP.get(description, "")
        if reason:
            message += f": {reason}"
        TLSError.__init__(self, message)


class TLSLocalAlert(TLSAlert):
    pass


class TLSRemoteAlert(TLSAlert):
    pass


class TLSWantReadError(TLSError):
    default = (
        "I'm ready to process the next TLS step, but I need more "
        "encrypted data first — please read from the wire and give"
        " it to me."
    )
