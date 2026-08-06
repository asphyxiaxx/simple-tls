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

_E = typing.TypeVar("_E", bound="ASN1Error")


class ASN1Error(Exception):
    def __init__(self, message: str, *args: typing.Any) -> None:
        Exception.__init__(self, *args)
        self.message = message
        self.root_name = "root"
        self.path: list[str | int] = []

    def with_trace(self: _E, path: str | int) -> _E:
        self.path.append(path)
        return self

    def with_root(self: _E, name: str) -> _E:
        self.root_name = name
        return self

    def __str__(self) -> str:
        # Formats the path like: root.tbsCertificate.extensions[2].extnId
        path_str = "".join(
            f"[{p}]" if isinstance(p, int) else f".{p}"
            for p in reversed(self.path)
        )
        return f"{self.message}, Location: {self.root_name}{path_str}"


class InvalidTemplate(ASN1Error): ...


class NestedTooDeep(ASN1Error): ...


class UnexpectedTag(ASN1Error): ...


class InvalidTag(ASN1Error): ...


class InvalidLength(ASN1Error): ...


class InvalidType(ASN1Error): ...


class InvalidPayload(ASN1Error): ...


class InvalidValue(ASN1Error): ...


class MissingField(ASN1Error): ...


class UnsupportedDefinedByType(ASN1Error): ...


class MappingError(ASN1Error):
    def __init__(self, exception: Exception) -> None:
        ASN1Error.__init__(self, repr(exception), exception)
