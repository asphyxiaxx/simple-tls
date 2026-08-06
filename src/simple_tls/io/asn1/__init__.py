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

from typing import Annotated

from ._base import decode, encode, mapped, sequence, set
from ._errors import (
    ASN1Error,
    InvalidLength,
    InvalidPayload,
    InvalidTag,
    InvalidTemplate,
    InvalidType,
    InvalidValue,
    MappingError,
    MissingField,
    NestedTooDeep,
    UnexpectedTag,
    UnsupportedDefinedByType,
)
from ._types import (
    Any,
    BitString,
    BMPString,
    Boolean,
    Enumerated,
    GeneralizedTime,
    GeneralString,
    GraphicString,
    IA5String,
    Integer,
    Null,
    NumericString,
    ObjectIdentifier,
    OctetString,
    PrintableString,
    Real,
    SequenceOf,
    SetOf,
    TeletexString,
    UTCTime,
    UTF8String,
    VideotexString,
    VisibleString,
)
from ._utils import Explicit, Implicit, OpenType, Variant

__all__ = [
    "ASN1Error",
    "Annotated",
    "Any",
    "BMPString",
    "BitString",
    "Boolean",
    "Enumerated",
    "Explicit",
    "GeneralString",
    "GeneralizedTime",
    "GraphicString",
    "IA5String",
    "Implicit",
    "Integer",
    "InvalidLength",
    "InvalidPayload",
    "InvalidTag",
    "InvalidTemplate",
    "InvalidType",
    "InvalidValue",
    "MappingError",
    "MissingField",
    "NestedTooDeep",
    "Null",
    "NumericString",
    "ObjectIdentifier",
    "OctetString",
    "OpenType",
    "PrintableString",
    "Real",
    "SequenceOf",
    "SetOf",
    "TeletexString",
    "UTCTime",
    "UTF8String",
    "UnexpectedTag",
    "UnsupportedDefinedByType",
    "Variant",
    "VideotexString",
    "VisibleString",
    "decode",
    "encode",
    "mapped",
    "sequence",
    "set",
]
