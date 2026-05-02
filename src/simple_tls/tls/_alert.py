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

from ._constant import AlertDescription


class AlertException(Exception):
    description: AlertDescription

    def __init__(self, message: str = "", fatal: bool = True) -> None:
        self.message = message
        self.fatal = fatal

    def __str__(self) -> str:
        return self.message


class CustomAlert(AlertException):
    def __init__(self, description: AlertDescription, fatal: bool = True):
        self.description = description
        self.fatal = fatal
        super().__init__("", fatal)


class AlertBadCertificate(AlertException):
    description = AlertDescription.BAD_CERTIFICATE


class AlertBadRecordMac(AlertException):
    description = AlertDescription.BAD_RECORD_MAC


class AlertCertificateExpired(AlertException):
    description = AlertDescription.CERTIFICATE_EXPIRED


class AlertCertificateRequired(AlertException):
    description = AlertDescription.CERTIFICATE_REQUIRED


class AlertDecodeError(AlertException):
    description = AlertDescription.DECODE_ERROR


class AlertDecryptError(AlertException):
    description = AlertDescription.DECRYPT_ERROR


class AlertHandshakeFailure(AlertException):
    description = AlertDescription.HANDSHAKE_FAILURE


class AlertMissingExtension(AlertException):
    description = AlertDescription.MISSING_EXTENSION


class AlertIllegalParameter(AlertException):
    description = AlertDescription.ILLEGAL_PARAMETER


class AlertInappropriateFallback(AlertException):
    description = AlertDescription.INAPPROPRIATE_FALLBACK


class AlertInsufficientSecurity(AlertException):
    description = AlertDescription.INSUFFICIENT_SECURITY


class AlertInternalError(AlertException):
    description = AlertDescription.INTERNAL_ERROR


class AlertRecordOverflow(AlertException):
    description = AlertDescription.RECORD_OVERFLOW


class AlertProtocolVersion(AlertException):
    description = AlertDescription.PROTOCOL_VERSION


class AlertUnexpectedMessage(AlertException):
    description = AlertDescription.UNEXPECTED_MESSAGE


class AlertUnsupportedExtension(AlertException):
    description = AlertDescription.UNSUPPORTED_EXTENSION


class AlertUnknownCA(AlertException):
    description = AlertDescription.UNKNOWN_CA


class AlertNoRenegotiation(AlertException):
    description = AlertDescription.NO_RENEGOTIATION


class AlertECHRequired(AlertException):
    description = AlertDescription.ECH_REQUIRED
