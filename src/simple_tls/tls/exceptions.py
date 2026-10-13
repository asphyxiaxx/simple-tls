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

from .constants import AlertDescription


class TLSError(Exception):
    def __init__(self, message: str | Exception | None = None) -> None:
        if message:
            if isinstance(message, Exception):
                message = f"{type(message).__name__}: {message}"
            super().__init__(message)
        else:
            super().__init__()


class TLSEOFError(TLSError):
    pass


class TLSWantReadError(TLSError):
    pass


class TLSAlert(TLSError):
    def __init__(self, description: int, reason: typing.Any = None) -> None:
        self.description = description
        self.reason = reason
        try:
            alert_name = AlertDescription(description).name.lower()
            message = f"[{alert_name}]"
        except ValueError:
            message = f"[unknown alert type: {description}]"
        if reason:
            message += f" {reason}"
        TLSError.__init__(self, message)


class TLSLocalAlert(TLSAlert):
    pass


class TLSRemoteAlert(TLSAlert):
    pass
