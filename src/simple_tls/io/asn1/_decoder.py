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
from collections.abc import Hashable
from dataclasses import dataclass

from ...utils.math import bytes_to_int
from ._codecs import PRIMITIC_CODECS
from ._errors import (
    ASN1Error,
    InvalidLength,
    InvalidPayload,
    InvalidTag,
    InvalidTemplate,
    InvalidType,
    MappingError,
    MissingField,
    NestedTooDeep,
    UnexpectedTag,
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


@dataclass
class TLCache:
    tag: Tag | None = None
    value_length: int = 0
    header_length: int = 0
    valid: bool = False


class Parser:
    def __init__(self, data: bytes) -> None:
        self._data = data
        self._index = 0
        self._bookmark = 0

    def set_bookmark(self) -> None:
        self._bookmark = self._index

    def data_since_bookmark(self) -> bytes:
        return self._data[self._bookmark : self._index]

    def tell(self) -> int:
        return self._index

    def seek(self, pos: int) -> None:
        if pos > len(self._data):
            raise InvalidLength(f"seek pos '{pos}' out of range")
        self._index = pos

    def skip(self, size: int) -> None:
        if self._index + size > len(self._data):
            raise InvalidLength(
                f"Error while parsing buffer: expected '{size}' bytes, but "
                f"only '{len(self._data) - self._index}' bytes remaining"
            )

        self._index += size

    def read_uint8(self) -> int:
        if self._index + 1 > len(self._data):
            raise InvalidLength(
                f"Error while parsing buffer: expected '1' bytes, but "
                f"only '{len(self._data) - self._index}' bytes remaining"
            )

        ret = self._data[self._index]
        self._index += 1
        return ret

    def read_int(self, size: int) -> int:
        ret = self.read_bytes(size)
        return bytes_to_int(ret, "big")

    def read_bytes(self, size: int) -> bytes:
        if size < 0:
            size = len(self._data) - self._index

        end = self._index + size
        if end > len(self._data):
            raise InvalidLength(
                f"Error while parsing buffer: expected '{size}' bytes, but "
                f"only '{len(self._data) - self._index}' bytes remaining"
            )

        ret = self._data[self._index : end]
        self._index += size
        return ret

    def remaining(self) -> int:
        return len(self._data) - self._index


class Decoder:
    def __init__(self, max_depth: int = 30) -> None:
        self._node_decoders: dict[type[Type], typing.Callable] = {
            PrimitiveType: self._decode_primitive,
            ChoiceType: self._decode_choice,
            SetType: self._decode_seq,
            SetOfType: self._decode_seqof,
            SequenceType: self._decode_seq,
            SequenceOfType: self._decode_seqof,
            MappedType: self._decode_mapped,
        }
        self._max_depth = max_depth

    def decode(
        self,
        raw_bytes: bytes,
        target_spec: type[_T],
        root_name: str = "root",
    ) -> tuple[_T, bytes]:
        parser = Parser(raw_bytes)
        ctx = TLCache()

        node = resolve_type(typing.cast(Hashable, target_spec))
        try:
            obj = self._decode_node(parser, node, ctx=ctx)
        except ASN1Error as exc:
            raise exc.with_root(root_name)

        remaining = parser.read_bytes(parser.remaining())
        return (typing.cast(_T, obj), remaining)

    def _dispatch_node(
        self,
        parser: Parser,
        node: Type,
        depth: int,
        optional: bool = False,
        ctx: TLCache | None = None,
    ) -> typing.Any | None:
        """
        Routes the node to the correct structural decoder.
        """
        depth += 1
        if depth > self._max_depth:
            raise NestedTooDeep("Nested too deep")

        try:
            decode_func = self._node_decoders[type(node)]
        except KeyError:
            raise InvalidType(f"Unknown node '{node}'") from None

        return decode_func(parser, node, depth, optional, ctx)

    def _decode_node(
        self,
        parser: Parser,
        node: Type,
        depth: int = 0,
        optional: bool = False,
        ctx: TLCache | None = None,
    ) -> typing.Any | None:
        """
        Entry point for decoding a field. Handles EXPLICIT wrappers.
        """
        explicit = getattr(node, "explicit", None)
        if explicit is None:
            return self._dispatch_node(parser, node, depth, optional, ctx)

        exptag = Tag(explicit, TagClass.CONTEXT, TagFormat.CONSTRUCTED)
        tag, length = self._check_taglen(parser, exptag, optional, ctx)

        if tag is None:
            return None  # optional and missing

        # Found the explicit wrapper, so the inner value must NOT optional
        start_exp = parser.tell()
        ret = self._dispatch_node(parser, node, depth, optional=False, ctx=ctx)

        if (parser.tell() - start_exp) != length:
            raise InvalidLength("Explicit length mismatch")

        return ret

    def _decode_primitive(
        self,
        parser: Parser,
        node: PrimitiveType,
        depth: int,
        optional: bool = False,
        ctx: TLCache | None = None,
    ) -> typing.Any | None:
        """
        Decodes a primitive ASN.1 type.
        """
        key = (node.python_type, node.marker)
        try:
            codec = PRIMITIC_CODECS[key]
        except KeyError:
            raise InvalidTemplate(
                f"No primitive decoder registered for spec '{key}'"
            ) from None

        if codec.tag_id is None:
            if node.implicit is not None:
                raise InvalidTemplate("Illegal tagged")
            if optional:
                raise InvalidTemplate("Illegal optional")

            parser.set_bookmark()
            _, length = self._check_taglen(parser, ctx=ctx)

            parser.skip(length)
            data = parser.data_since_bookmark()

            if ctx is not None:
                ctx.valid = False
        else:
            if node.implicit is not None:
                tag_class = TagClass.CONTEXT
                tag_id = node.implicit
            else:
                tag_class = TagClass.UNIVERSAL
                tag_id = codec.tag_id

            exptag = Tag(tag_id, tag_class, TagFormat.SIMPLE)
            tag, length = self._check_taglen(parser, exptag, optional, ctx)

            if tag is None:
                return None  # optional and missing

            data = parser.read_bytes(length)

        try:
            return codec.decode_value(data)
        except ASN1Error:
            raise
        except Exception as exc:
            raise InvalidPayload(
                f"Failed to decode {key} payload: {exc!s}"
            ) from exc

    def _decode_choice(
        self,
        parser: Parser,
        node: ChoiceType,
        depth: int,
        optional: bool,
        ctx: TLCache | None,
    ) -> typing.Any | None:
        for branch in node.branches:
            obj = self._decode_node(
                parser=parser,
                node=branch.node,
                depth=depth,
                optional=True,
                ctx=ctx,
            )
            if obj is None:
                continue

            if branch.name is not None:
                return Variant(branch.name, obj)

            return obj

        if optional:
            return None

        raise MissingField("No matching CHOICE type found")

    def _decode_seq(
        self,
        parser: Parser,
        node: SequenceType | SetType,
        depth: int,
        optional: bool = False,
        ctx: TLCache | None = None,
    ) -> typing.Any | None:
        """
        Decodes a SEQUENCE or SET structure.
        """
        if node.implicit is not None:
            tag_class = TagClass.CONTEXT
            tag_id = node.implicit
        else:
            tag_class = TagClass.UNIVERSAL
            tag_id = 17 if isinstance(node, SetType) else 16

        exptag = Tag(tag_id, tag_class, TagFormat.CONSTRUCTED)
        tag, length = self._check_taglen(parser, exptag, optional, ctx)

        if tag is None:
            return None  # optional and missing

        fields = node.fields
        required_fields = node.required_fields
        start_pos = parser.tell()
        end_pos = start_pos + length
        end_idx = len(fields) - 1
        seen: set[str] = set()
        kwargs: dict[str, typing.Any] = {}

        for idx, (name, field) in enumerate(fields.items()):
            obj = None

            if parser.tell() < end_pos:
                if end_idx == idx:
                    is_opt = False
                else:
                    is_opt = field.is_optional

                try:
                    obj = self._decode_node(
                        parser=parser,
                        node=field.node,
                        depth=depth,
                        optional=is_opt,
                        ctx=ctx,
                    )
                except ASN1Error as exc:
                    raise exc.with_trace(name)

            if obj is not None and field.defined_by is not None:
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

                if not isinstance(obj, bytes):
                    raise InvalidPayload(
                        f"OpenType payload for '{name}' must initially decode "
                        f"to raw bytes, but got {type(obj)}"
                    )

                sub_parser = Parser(obj)
                try:
                    obj = self._decode_node(sub_parser, target_field)
                except ASN1Error as exc:
                    raise exc.with_trace(name)

            if obj is None and field.default_value is not None:
                obj = field.default_value

            kwargs[name] = obj

            if obj is not None:
                seen.add(name)

        if parser.tell() != end_pos:
            diff_pos = abs(parser.tell() - end_pos)
            if parser.tell() > end_pos:
                raise InvalidLength(
                    f"SEQUENCE / SET payload overflowed. The header claimed "
                    f"'{length}' bytes, but the fields consumed "
                    f"'{length + diff_pos}' bytes (overshot by '{diff_pos}' "
                    f"bytes)."
                )
            raise InvalidLength(
                f"SEQUENCE / SET payload underflowed. The header claimed "
                f"'{length}' bytes, but the fields only consumed "
                f"'{length - diff_pos}' bytes. There are '{diff_pos}' "
                f"unparsed bytes remaining. Ensure your dataclass defines "
                f"all fields present in the payload."
            )

        if not required_fields.issubset(seen):
            missing = list(required_fields.difference(seen))
            raise MissingField(f"Required {missing}")

        try:
            return node.python_type(**kwargs)
        except Exception as exc:
            raise MappingError(exc) from exc

    def _decode_seqof(
        self,
        parser: Parser,
        node: SequenceOfType | SetOfType,
        depth: int,
        optional: bool = False,
        ctx: TLCache | None = None,
    ) -> typing.Any | None:
        """
        Decodes a SEQUENCE OF or SET OF array.
        """
        if node.implicit is not None:
            tag_class = TagClass.CONTEXT
            tag_id = node.implicit
        else:
            tag_class = TagClass.UNIVERSAL
            tag_id = 17 if isinstance(node, SetOfType) else 16

        exptag = Tag(tag_id, tag_class, TagFormat.CONSTRUCTED)
        tag, length = self._check_taglen(parser, exptag, optional, ctx)

        if tag is None:
            return None  # optional and missing

        start_pos = parser.tell()
        end_pos = start_pos + length
        items: list[typing.Any] = node.python_type()

        while parser.tell() < end_pos:
            try:
                obj = self._decode_node(
                    parser=parser,
                    node=node.inner_node,
                    depth=depth,
                    ctx=ctx,
                )
            except ASN1Error as exc:
                raise exc.with_trace(len(items))

            items.append(obj)

        if parser.tell() > end_pos:
            overflow_bytes = parser.tell() - end_pos
            raise InvalidLength(
                f"SEQUENCE OF / SET OF payload overflowed. The header claimed "
                f"'{length}' bytes, but the fields consumed "
                f"'{length + overflow_bytes}' bytes (overshot by "
                f"'{overflow_bytes}' bytes)."
            )

        return items

    def _decode_mapped(
        self,
        parser: Parser,
        node: MappedType,
        depth: int,
        optional: bool = False,
        ctx: TLCache | None = None,
    ) -> typing.Any | None:
        inner_node = node.inner_node
        obj = self._decode_node(parser, inner_node, depth, optional, ctx)

        if obj is None:
            return None

        try:
            return node.python_type.from_decoder(obj)  # type:ignore
        except Exception as exc:
            raise MappingError(exc) from exc

    @staticmethod
    def _check_taglen(
        parser: Parser,
        exptag: Tag | None = None,
        optional: bool = False,
        ctx: TLCache | None = None,
    ) -> tuple[None, int] | tuple[Tag, int]:
        start = parser.tell()

        if ctx is not None and ctx.valid:
            tag = typing.cast(Tag, ctx.tag)
            value_len = ctx.value_length
            parser.skip(ctx.header_length)
        else:
            b = parser.read_uint8()

            tag_class = b & 0xC0
            tag_format = b & 0x20
            tag_id = b & 0x1F

            # long-form tag number
            if tag_id == 0x1F:
                tag_id = 0
                first_byte = True
                for _ in range(5):
                    b = parser.read_uint8()
                    if first_byte and b == 0x80:
                        raise InvalidTag("Leading padding in long-form tags")

                    first_byte = False
                    tag_id = (tag_id << 7) | (b & 0x7F)
                    if not (b & 0x80):
                        break
                else:
                    raise InvalidTag("Tag number too large (exceeds 5 bytes)")

                if tag_id < 31:
                    raise InvalidTag("Unexpected long-form for tags <= 30")

            b = parser.read_uint8()

            # indefinite length
            if b == 0x80:
                raise InvalidLength("Unexpected indefinite length")

            # short form
            elif b < 0x80:
                value_len = b & 0x7F

            # definite long form
            else:
                count = b & 0x7F
                value_len = parser.read_int(count)
                if value_len < 128:
                    raise InvalidLength(
                        "Unexpected long-form length for payload < 128"
                    )

                if count > 1 and value_len < (1 << ((count - 1) * 8)):
                    raise InvalidLength(
                        "Length doesn't follow shortest possible length "
                        "encoding"
                    )

            tag = Tag(tag_id, tag_class, tag_format)
            if ctx is not None:
                ctx.tag = tag
                ctx.value_length = value_len
                ctx.header_length = parser.tell() - start
                ctx.valid = True

        if exptag is not None:
            if exptag != tag:
                parser.seek(start)

                if optional:
                    return None, 0

                raise UnexpectedTag(
                    f"Wrong tag, expected {exptag}, but get {tag}"
                )

            if ctx is not None:
                ctx.valid = False

        return tag, value_len
