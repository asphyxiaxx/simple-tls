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

import types
import typing
from collections.abc import Hashable
from dataclasses import MISSING as _MISSING
from dataclasses import dataclass, replace
from functools import lru_cache
from typing import Annotated, TypeAlias

from ._codecs import PRIMITIC_CODECS
from ._types import Marker
from ._utils import Explicit, Implicit, OpenType, Variant

get_type_hints = typing.get_type_hints
get_type_args = typing.get_args
get_type_origin = typing.get_origin

NoneType: TypeAlias = types.NoneType  # type: ignore


@dataclass(frozen=True)
class Type:
    python_type: type | None


@dataclass(frozen=True)
class Field:
    node: Type
    default_value: Hashable | None = None
    is_optional: bool = False
    defined_by: str | None = None
    typemap: dict[Hashable, Type] | None = None
    default_type: Type | None = None

    def get_opentype(self, key: Hashable) -> Type | None:
        if self.typemap is not None:
            return self.typemap.get(key, self.default_type)
        return None


@dataclass(frozen=True)
class SequenceType(Type):
    python_type: type
    fields: dict[str, Field]
    required_fields: set[str]
    explicit: int | None = None
    implicit: int | None = None


@dataclass(frozen=True)
class SetType(Type):
    python_type: type
    fields: dict[str, Field]
    required_fields: set[str]
    explicit: int | None = None
    implicit: int | None = None


@dataclass(frozen=True)
class SequenceOfType(Type):
    python_type: type[list]
    inner_node: Type
    explicit: int | None = None
    implicit: int | None = None


@dataclass(frozen=True)
class SetOfType(Type):
    python_type: type[list]
    inner_node: Type
    explicit: int | None = None
    implicit: int | None = None


@dataclass(frozen=True)
class PrimitiveType(Type):
    python_type: type
    marker: Marker | None = None
    explicit: int | None = None
    implicit: int | None = None


@dataclass(frozen=True)
class Branch:
    name: str | None
    node: Type


@dataclass(frozen=True)
class ChoiceType(Type):
    python_type: None
    branches: tuple[Branch, ...]
    explicit: int | None = None


@dataclass(frozen=True)
class MappedType(Type):
    python_type: type
    inner_node: Type


def _is_union(t: typing.Any) -> bool:
    """
    Check for Union[T, None] or T | None
    """
    return t is typing.Union or (
        hasattr(types, "UnionType") and t is types.UnionType
    )


def _extract_metadata(
    args: typing.Sequence[typing.Any],
) -> dict[str, typing.Any]:
    """
    Scans the metadata arguments of an Annotated type hint
    """
    metadata: dict[str, typing.Any] = {}

    for arg in args:
        if isinstance(arg, Explicit):
            if "implicit" in metadata:
                raise TypeError(
                    "A field cannot be both EXPLICITLY and IMPLICITLY tagged."
                )
            metadata["explicit"] = arg.tag

        elif isinstance(arg, Implicit):
            if "explicit" in metadata:
                raise TypeError(
                    "A field cannot be both EXPLICITLY and IMPLICITLY tagged."
                )
            metadata["implicit"] = arg.tag

        elif isinstance(arg, Marker):
            metadata["marker"] = arg

        else:
            raise TypeError(f"Unknown metadata argument in Annotated: {arg}")

    return metadata


def _extract_branch(t: typing.Any) -> Branch:
    is_annotated = get_type_origin(t) is Annotated
    inner_type = get_type_args(t)[0] if is_annotated else t

    if get_type_origin(inner_type) is Variant:
        name_literal, value_type = get_type_args(inner_type)

        if get_type_origin(name_literal) is not typing.Literal:
            raise TypeError("Variant name must be a typing.Literal string.")

        name = get_type_args(name_literal)[0]

        if is_annotated:
            # Reconstruct Annotated without the Variant wrapper
            metadata = typing.cast(tuple[typing.Any, ...], t.__metadata__)
            annotated_value_type = Annotated[(value_type, *metadata)]  # type: ignore
            node = resolve_type(annotated_value_type)
        else:
            node = resolve_type(value_type)
    else:
        name = None
        node = resolve_type(t)

    return Branch(name, node)


def _apply_metadata(node: Type, metadata: dict[str, typing.Any]) -> Type:
    """
    Recursively pushes metadata down through MappedTypes to the base ASN.1
    node.
    """
    if not metadata:
        return node

    if isinstance(node, MappedType):
        new_inner = _apply_metadata(node.inner_node, metadata)
        return replace(node, inner_node=new_inner)

    return replace(node, **metadata)


def _has_function(t: object, name: str) -> bool:
    return hasattr(t, name) and callable(getattr(t, name))


@lru_cache(maxsize=256, typed=True)
def resolve_type(t: typing.Any) -> Type:
    """Helper to convert a Python type hint into a _Type AST."""
    node: Type
    origin = get_type_origin(t)

    # Peel Annotated
    if origin is Annotated:
        metadata = _extract_metadata(t.__metadata__)
        t = get_type_args(t)[0]
        origin = get_type_origin(t)
    else:
        metadata = {}

    # Handle Arrays (SEQUENCE OF / SET OF)
    if origin is list:
        inner_type = get_type_args(t)[0]

        if isinstance(inner_type, typing.TypeVar):
            raise TypeError(f"'{origin}' has no inner type")

        inner_node = resolve_type(inner_type)
        marker = metadata.pop("marker", None)

        if marker is None:
            node = SequenceOfType(
                python_type=origin,
                inner_node=inner_node,
                **metadata,
            )
        elif marker == Marker.SET_OF:
            node = SetOfType(
                python_type=origin,
                inner_node=inner_node,
                **metadata,
            )
        else:
            raise TypeError(f"Unknown marker '{marker}'")

    # Handle Inline Choice (Union)
    elif _is_union(origin):
        branches: list[Branch] = []

        for arg in get_type_args(t):
            if arg is NoneType:
                raise TypeError(
                    "Optional types should be handled by the Sequence compiler"
                )
            branches.append(_extract_branch(arg))

        node = ChoiceType(
            python_type=None,
            branches=tuple(branches),
            **metadata,
        )

    # Handle SEQUENCE / SET
    elif hasattr(t, "__asn1_spec__"):
        node = t.__asn1_spec__
        node = _apply_metadata(node, metadata)

    # Handle Primitive
    else:
        if not isinstance(t, type):
            raise TypeError(
                f"Expected a valid Python type class, got '{type(t).__name__}'"
            )
        if issubclass(t, NoneType):
            raise TypeError(
                "Cannot use 'NoneType' as a standalone ASN.1 type."
            )

        marker = metadata.get("marker", None)
        key = (t, marker)

        if key not in PRIMITIC_CODECS:
            raise TypeError(f"Cannot handle type '{key}'.")

        node = PrimitiveType(python_type=t, **metadata)

    return node


def register_seq(cls: type, is_set: bool) -> None:
    """Parses a class and attaches the _SequenceType AST."""
    raw_fields = get_type_hints(cls, include_extras=True)
    fields: dict[str, Field] = {}
    required_fields: set[str] = set()

    for field_name, field_type in raw_fields.items():
        base_type = field_type
        origin = get_type_origin(base_type)
        is_optional = False
        defined_by = typemap = default_type = None

        # Check for native class default values
        default_value = getattr(cls, field_name, None)
        if default_value is not None:
            if not isinstance(default_value, Hashable):
                raise TypeError("default_value should be Hashable")

            is_optional = True
            delattr(cls, field_name)
        else:
            try:
                dataclass_fields = getattr(cls, "__dataclass_fields__")
                default_factory = dataclass_fields[field_name].default_factory
            except (AttributeError, KeyError):
                default_factory = None

            if default_factory is not None and default_factory is not _MISSING:
                raise TypeError(
                    "default_value should not using default_factory"
                )

        # Check for Annotated
        if origin is Annotated:
            metadata = base_type.__metadata__
            opentypes = [d for d in metadata if isinstance(d, OpenType)]

            if opentypes:
                if len(opentypes) > 1:
                    raise TypeError(
                        "Multiple OpenType definitions found on one field."
                    )

                opentype = opentypes[0]
                inner_type = opentype.base_type
                defined_by = opentype.defined_by
                if opentype.typemap:
                    typemap = {
                        n: resolve_type(t) for n, t in opentype.typemap.items()
                    }
                if opentype.default_type is not None:
                    default_type = resolve_type(opentype.default_type)

                # Reconstruct the Annotated type hint without the OpenType
                kept_args = tuple(
                    d for d in metadata if not isinstance(d, OpenType)
                )
                if kept_args:
                    base_type = Annotated[(inner_type, *kept_args)]
                else:
                    base_type = inner_type

                origin = get_type_origin(base_type)

        # Check for Optional
        if _is_union(origin):
            args = get_type_args(base_type)

            if NoneType in args:
                if default_value is not None:
                    raise TypeError(
                        f"Field '{field_name}' has a default value "
                        f"({default_value}), so it can never be None. "
                        f"Remove 'Optional' or '| None'"
                    )

                # Strip the NoneType to isolate the actual ASN.1 payload type
                base_type = typing.Union[
                    tuple(a for a in args if a is not NoneType)
                ]
                is_optional = True

        if not is_optional:
            required_fields.add(field_name)

        inner_node = resolve_type(base_type)
        fields[field_name] = Field(
            node=inner_node,
            default_value=default_value,
            is_optional=is_optional,
            defined_by=defined_by,
            typemap=typemap,
            default_type=default_type,
        )

    spec: Type

    if is_set:
        spec = SetType(
            python_type=cls,
            fields=fields,
            required_fields=required_fields,
        )
    else:
        spec = SequenceType(
            python_type=cls,
            fields=fields,
            required_fields=required_fields,
        )

    setattr(cls, "__asn1_spec__", spec)


def register_mapped_type(cls: type, t: typing.Any) -> None:
    if hasattr(cls, "__asn1_spec__"):
        raise TypeError(
            f"Cannot map class '{cls.__name__}' because it is already "
            f"registered as an ASN.1 type"
        )

    if not _has_function(cls, "to_encoder"):
        raise TypeError(
            f"Class '{cls.__name__}' must implement 'to_encoder(self)'"
        )

    if not _has_function(cls, "from_decoder"):
        raise TypeError(
            f"Class '{cls.__name__}' must implement 'from_decoder(cls, value)'"
        )

    inner_node = resolve_type(t)
    node = MappedType(
        python_type=cls,
        inner_node=inner_node,
    )

    setattr(cls, "__asn1_spec__", node)
