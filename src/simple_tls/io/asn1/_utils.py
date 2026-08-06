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

import enum
import sys
import typing
from collections.abc import Hashable
from dataclasses import dataclass

if sys.version_info < (3, 11):
    from typing_extensions import LiteralString
else:
    from typing import LiteralString


_T = typing.TypeVar("_T")
_N = typing.TypeVar("_N", bound="LiteralString")


@dataclass(frozen=True)
class OpenType:
    """Public marker for dynamic ASN.1 OpenType resolution."""

    base_type: typing.Any
    defined_by: str
    typemap: dict[Hashable, typing.Any] | None = None
    default_type: typing.Any | None = None


@dataclass(frozen=True, repr=False, slots=True, eq=True)
class Variant(typing.Generic[_N, _T]):
    """
    A runtime wrapper to distinguish CHOICE branches that share the same
    underlying Python type but have different ASN.1 tags.
    """

    name: _N
    value: _T

    def __repr__(self) -> str:
        return f"Variant({self.name}={self.value!r})"

    def __hash__(self) -> int:
        return hash((self.name, self.value))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Variant):
            return False
        return self.name == other.name and self.value == other.value


@dataclass(frozen=True)
class Explicit:
    tag: int


@dataclass(frozen=True)
class Implicit:
    tag: int


class TagClass(enum.IntEnum):
    UNIVERSAL = 0x00
    APPLICATION = 0x40
    CONTEXT = 0x80
    PRIVATE = 0xC0


class TagFormat(enum.IntEnum):
    SIMPLE = 0x00
    CONSTRUCTED = 0x20


@dataclass(frozen=True)
class Tag:
    tag_id: int
    tag_class: int = TagClass.UNIVERSAL
    tag_format: int = TagFormat.SIMPLE
