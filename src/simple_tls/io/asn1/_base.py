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

import sys
import typing
from dataclasses import dataclass

from ._decoder import Decoder
from ._encoder import Encoder
from ._nodes import register_mapped_type, register_seq

if sys.version_info < (3, 11):
    from typing_extensions import dataclass_transform
else:
    from typing import dataclass_transform


_T = typing.TypeVar("_T")

_Wrapper = typing.Callable[[type[_T]], type[_T]]


@typing.overload
def sequence(
    cls: type[_T],
    /,
    *,
    repr: bool = True,
    eq: bool = True,
    unsafe_hash: bool = False,
    frozen: bool = False,
    slots: bool = False,
) -> type[_T]: ...


@typing.overload
def sequence(
    cls: None = None,
    /,
    *,
    repr: bool = True,
    eq: bool = True,
    unsafe_hash: bool = False,
    frozen: bool = False,
    slots: bool = False,
) -> _Wrapper: ...


@dataclass_transform(kw_only_default=True)
def sequence(
    cls: type[_T] | None = None,
    /,
    *,
    repr: bool = True,
    eq: bool = True,
    unsafe_hash: bool = False,
    frozen: bool = False,
    slots: bool = False,
) -> type[_T] | _Wrapper:
    def wrapper(cls: type[_T]) -> type[_T]:
        dataclass_cls = dataclass(
            repr=repr,
            eq=eq,
            unsafe_hash=unsafe_hash,
            frozen=frozen,
            slots=slots,
            match_args=False,
            kw_only=True,
        )(cls)

        register_seq(dataclass_cls, is_set=False)
        return dataclass_cls

    if cls is not None:
        return wrapper(cls)
    return wrapper


@typing.overload
def set(cls: type[_T]) -> type[_T]: ...


@typing.overload
def set(cls: None = None) -> _Wrapper: ...


@dataclass_transform(kw_only_default=True)
def set(cls: type[_T] | None = None) -> type[_T] | _Wrapper:
    def wrapper(cls: type[_T]) -> type[_T]:
        dataclass_cls = dataclass(
            repr=True,
            eq=True,
            match_args=False,
            kw_only=True,
        )(cls)
        register_seq(dataclass_cls, is_set=True)
        return dataclass_cls

    if cls is not None:
        return wrapper(cls)
    return wrapper


def mapped(base_type: typing.Any) -> _Wrapper:
    """
    Decorator to map a custom Python class to an underlying ASN.1 type.
    The class must implement `to_encoder(self) -> base_type`
    and `from_decoder(cls, value: base_type) -> cls`.
    """

    def wrapper(cls: type[_T]) -> type[_T]:
        register_mapped_type(cls, base_type)
        return cls

    return wrapper


decode = Decoder().decode
encode = Encoder().encode
