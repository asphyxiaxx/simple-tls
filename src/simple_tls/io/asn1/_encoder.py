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
from collections import deque
from collections.abc import Hashable

from ...utils.math import byte_length, int_to_bytes
from ._codecs import PRIMITIC_CODECS
from ._errors import (
    ASN1Error,
    InvalidTemplate,
    InvalidType,
    InvalidValue,
    MappingError,
    MissingField,
    UnsupportedDefinedByType,
)
from ._nodes import (
    ChoiceType,
    MappedType,
    PrimitiveType,
    SequenceOfType,
    SequenceType,
    SetOfType,
    SetType,
    Type,
    resolve_type,
)
from ._utils import Tag, TagClass, TagFormat, Variant

_T = typing.TypeVar("_T")


# Encoder


class Writer:
    def __init__(self) -> None:
        self._buffer: deque[bytes] = deque()
        self._length: int = 0

    def tobytes(self) -> bytes:
        return b"".join(self._buffer)

    def write_payload(self, data: bytes | Writer) -> None:
        if isinstance(data, Writer):
            self._buffer.extend(data._buffer)
        elif data:
            self._buffer.append(data)

    def write_header(self, tag_bytes: bytes, length_bytes: bytes) -> None:
        if length_bytes:
            self._buffer.appendleft(length_bytes)
        if tag_bytes:
            self._buffer.appendleft(tag_bytes)

    def __len__(self) -> int:
        return sum(map(len, self._buffer))


class Encoder:
    def __init__(self) -> None:
        self._node_encoders: dict[type[Type], typing.Callable] = {
            PrimitiveType: self._encode_primitive,
            ChoiceType: self._encode_choice,
            SetType: self._encode_seq,
            SetOfType: self._encode_seqof,
            SequenceType: self._encode_seq,
            SequenceOfType: self._encode_seqof,
            MappedType: self._encode_mapped,
        }

    def encode(
        self,
        value: _T,
        target_spec: type[_T],
        root_name: str = "root",
    ) -> bytes:
        node = resolve_type(typing.cast(Hashable, target_spec))
        try:
            writer = self._encode_node(value, node)
        except ASN1Error as exc:
            raise exc.with_root(root_name)

        return writer.tobytes()

    def _encode_node(
        self,
        value: typing.Any,
        node: Type,
    ) -> Writer:
        try:
            encode_func = self._node_encoders[type(node)]
        except KeyError:
            raise InvalidType(f"Unknown node '{node}'") from None

        writer = encode_func(value, node)

        explicit = getattr(node, "explicit", None)
        if explicit is not None:
            tag = Tag(explicit, TagClass.CONTEXT, TagFormat.CONSTRUCTED)
            tag_bytes = self._encode_tag(tag)
            len_bytes = self._encode_length(len(writer))
            writer.write_header(tag_bytes, len_bytes)

        return writer

    def _encode_primitive(
        self,
        value: typing.Any,
        node: PrimitiveType,
    ) -> Writer:
        key = (node.python_type, node.marker)
        try:
            codec = PRIMITIC_CODECS[key]
        except KeyError:
            raise InvalidTemplate(
                f"No primitive encoder registered for spec '{key}'"
            ) from None

        writer = Writer()

        try:
            payload = codec.encode_value(value)
            writer.write_payload(payload)
        except ASN1Error:
            raise
        except Exception as exc:
            raise InvalidValue(str(exc)) from exc

        if codec.tag_id is None:
            if node.implicit is not None:
                raise InvalidTemplate("Illegal tagged")
        else:
            if node.implicit is not None:
                tag_class = TagClass.CONTEXT
                tag_id = node.implicit
            else:
                tag_class = TagClass.UNIVERSAL
                tag_id = codec.tag_id

            tag = Tag(tag_id, tag_class, TagFormat.SIMPLE)
            self._encode_header(writer, tag)

        return writer

    def _encode_choice(
        self,
        value: typing.Any,
        node: ChoiceType,
    ) -> Writer:
        branch_name = None
        actual_value = value

        if isinstance(value, Variant):
            branch_name = value.name
            actual_value = value.value
        elif isinstance(value, tuple) and len(value) == 2:
            branch_name, actual_value = value
        else:
            # If it's neither, it's a raw primitive (like `5` or `"hello"`),
            # so branch_name stays None and we match by type
            pass

        selected_branch = None

        if branch_name is not None:
            # Match by explicit branch name (User passed a Variant/Tuple)
            for branch in node.branches:
                if branch.name == branch_name:
                    selected_branch = branch
                    break

            if selected_branch is None:
                valid_names = [
                    b.name for b in node.branches if b.name is not None
                ]
                raise InvalidValue(
                    f"Invalid CHOICE branch '{branch_name}'. "
                    f"Valid Variant names for this choice: {valid_names}"
                )
        else:
            # Match by raw Python type (User passed a raw int/str)
            for branch in node.branches:
                if branch.name is None:
                    target_type = branch.node.python_type

                    if not (
                        target_type is not None
                        and isinstance(actual_value, target_type)
                    ):
                        continue

                    selected_branch = branch
                    break

            if selected_branch is None:
                allowed_types = [
                    v.node.python_type
                    for v in node.branches
                    if v.name is None and v.node.python_type is not None
                ]
                raise InvalidType(
                    f"Cannot map raw value of type "
                    f"'{type(actual_value).__name__}' to this CHOICE. "
                    f"Expected a Variant, or one of the raw types: "
                    f"{allowed_types}"
                )

        if actual_value is None:
            raise MissingField("CHOICE branch has no selected value.")

        return self._encode_node(actual_value, selected_branch.node)

    def _encode_seq(
        self,
        value: typing.Any,
        node: SequenceType | SetType,
    ) -> Writer:
        writer = Writer()
        kwargs: dict[str, typing.Any]

        if not isinstance(value, node.python_type):
            if not isinstance(value, dict):
                raise InvalidType(
                    f"value must be dict or instance of {node.python_type} "
                    f"(not '{type(value)}')"
                )
            kwargs = typing.cast(dict[str, typing.Any], value)
        else:
            kwargs = {n: getattr(value, n, None) for n in node.fields}

        for name, field in node.fields.items():
            is_opt = field.is_optional
            obj = kwargs.get(name, None)

            if obj is None:
                if is_opt:
                    continue
                raise MissingField("Value cannot be None").with_trace(name)

            if field.default_value is not None and obj == field.default_value:
                continue

            if field.defined_by is not None:
                defined_by_name = field.defined_by

                try:
                    defining_obj = kwargs[defined_by_name]
                except KeyError:
                    raise InvalidTemplate(
                        f"Unable to find defined by '{defined_by_name}'"
                    ).with_trace(name) from None

                if defining_obj is None:
                    raise InvalidTemplate(
                        f"defined-by field '{defined_by_name}' has no value"
                    ).with_trace(name)

                target_field = field.get_opentype(defining_obj)
                if target_field is None:
                    raise UnsupportedDefinedByType(
                        f"Unsupported any defined by type '{defining_obj}'"
                    ).with_trace(name)

                try:
                    obj = self._encode_node(obj, target_field).tobytes()
                except ASN1Error as exc:
                    raise exc.with_trace(name)

            try:
                payload_writer = self._encode_node(obj, field.node)
            except ASN1Error as exc:
                raise exc.with_trace(name)

            writer.write_payload(payload_writer)

        if node.implicit is not None:
            tag_class = TagClass.CONTEXT
            tag_id = node.implicit
        else:
            tag_class = TagClass.UNIVERSAL
            tag_id = 17 if isinstance(node, SetType) else 16

        tag = Tag(tag_id, tag_class, TagFormat.CONSTRUCTED)
        self._encode_header(writer, tag)

        return writer

    def _encode_seqof(
        self,
        value: typing.Any,
        node: SequenceOfType | SetOfType,
    ) -> Writer:
        if not (
            isinstance(value, node.python_type)
            or isinstance(value, typing.Iterable)
        ):
            raise InvalidType(
                f"value must be Iterable or instance of {node.python_type} "
                f"(not '{type(value)}')"
            )

        writer = Writer()
        items = value
        inner_node = node.inner_node

        for i, obj in enumerate(items):
            try:
                payload_writer = self._encode_node(obj, inner_node)
            except ASN1Error as exc:
                raise exc.with_trace(i)

            writer.write_payload(payload_writer)

        if node.implicit is not None:
            tag_class = TagClass.CONTEXT
            tag_id = node.implicit
        else:
            tag_class = TagClass.UNIVERSAL
            tag_id = 17 if isinstance(node, SetOfType) else 16

        tag = Tag(tag_id, tag_class, TagFormat.CONSTRUCTED)
        self._encode_header(writer, tag)

        return writer

    def _encode_mapped(
        self,
        value: typing.Any,
        node: MappedType,
    ) -> Writer:
        try:
            obj = value.to_encoder()
        except Exception as exc:
            raise MappingError(exc) from exc

        inner_node = node.inner_node
        return self._encode_node(obj, inner_node)

    @classmethod
    def _encode_header(cls, writer: Writer, tag: Tag) -> None:
        tag_bytes = cls._encode_tag(tag)
        len_bytes = cls._encode_length(len(writer))
        writer.write_header(tag_bytes, len_bytes)

    @staticmethod
    def _encode_length(length: int) -> bytes:
        if length <= 127:
            return int_to_bytes(length)

        len_bytes = int_to_bytes(length, byte_length(length))
        return int_to_bytes(0x80 | len(len_bytes)) + len_bytes

    @staticmethod
    def _encode_tag(tag: Tag) -> bytes:
        if tag.tag_id <= 30:
            # short-form
            return bytes([tag.tag_class | tag.tag_format | tag.tag_id])

        # long-Form
        first_byte = tag.tag_class | tag.tag_format | 0x1F

        id_chunks = bytearray()
        temp_id = tag.tag_id

        # The very last byte of the chain MUST have its 8th bit set to 0
        id_chunks.append(temp_id & 0x7F)
        temp_id >>= 7

        # Every preceding byte MUST have its 8th bit set to 1 (0x80)
        while temp_id > 0:
            id_chunks.append((temp_id & 0x7F) | 0x80)
            temp_id >>= 7

        # We extracted the chunks from right-to-left, but DER requires
        # Big-Endian (left-to-right), so we must reverse the chunks before
        # combining them.
        id_chunks.reverse()

        return bytes([first_byte]) + bytes(id_chunks)
