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
from contextlib import contextmanager

from .math import bytes_to_int, int_to_bytes

ReadableBuffer = typing.TypeVar(
    "ReadableBuffer",
    bound=typing.Union[bytes, bytearray, memoryview],
)


class ParseError(Exception): ...


class Parser(typing.Generic[ReadableBuffer]):
    def __init__(self, data: ReadableBuffer) -> None:
        self._data = data
        self._index = 0
        self._bookmark = 0

    def set_bookmark(self) -> None:
        self._bookmark = self._index

    def data_since_bookmark(self) -> ReadableBuffer:
        return typing.cast(
            ReadableBuffer, self._data[self._bookmark : self._index]
        )

    def read_bytes(self, size: int) -> ReadableBuffer:
        if size < 0:
            raise ValueError("size cannot be negative")

        end = self._index + size
        if end > len(self._data):
            raise ParseError(
                f"Error while parsing buffer: expected '{size}' bytes, but "
                f"only '{len(self._data) - self._index}' bytes remaining"
            )

        data = typing.cast(ReadableBuffer, self._data[self._index : end])
        self._index += size
        return data

    def read_int(self, size: int) -> int:
        return bytes_to_int(self.read_bytes(size), "big")

    def read_prefixed_bytes(self, prefix_size: int) -> ReadableBuffer:
        length = self.read_int(prefix_size)
        return self.read_bytes(length)

    def read_prefixed_int_list(
        self, item_size: int, prefix_size: int
    ) -> list[int]:
        length = self.read_int(prefix_size)
        if length % item_size != 0:
            raise ParseError(
                "Error while parsing buffer: length of int list is not a "
                "multiple of item size"
            )

        size = length // item_size
        return [self.read_int(item_size) for _ in range(size)]

    @contextmanager
    def assert_length(self, prefix_size: int):
        length = self.read_int(prefix_size)
        start = self._index
        end = start + length
        yield end
        if self._index != end:
            raise ParseError(
                f"Error while parsing buffer: expected '{end}' bytes, but "
                f"consumed '{self._index - start}' bytes"
            )

    def skip(self, size: int) -> None:
        if self._index + size > len(self._data):
            raise ParseError(
                f"Error while parsing buffer: expected '{size}' bytes, but "
                f"only '{len(self._data) - self._index}' bytes remaining"
            )

        self._index += size

    def tell(self) -> int:
        return self._index

    def remaining(self) -> int:
        """
        Return amounts of data remaining
        """
        return len(self._data) - self._index


class Writer:
    def __init__(self) -> None:
        self._buffer: list[bytes] = []

    def tobytes(self) -> bytes:
        return b"".join(self._buffer)

    def write_bytes(self, data: bytes | Writer) -> None:
        if isinstance(data, Writer):
            self._buffer.extend(data._buffer)
        else:
            self._buffer.append(data)

    def write_int(self, value: int, size: int) -> None:
        try:
            self.write_bytes(int_to_bytes(value, size))
        except OverflowError:
            raise ValueError(
                f"int too big to convert given size '{size}'"
            ) from None

    def write_prefixed_bytes(
        self, data: bytes | Writer, prefix_size: int
    ) -> None:
        length = len(data)
        self.write_int(length, prefix_size)
        self.write_bytes(data)

    def write_prefixed_int_list(
        self,
        seq: typing.Sequence[int],
        item_size: int,
        prefix_size: int,
    ) -> None:
        self.write_int(len(seq) * item_size, prefix_size)
        for i in seq:
            self.write_int(i, item_size)

    def clear(self) -> None:
        self._buffer.clear()

    def __len__(self) -> int:
        return sum(map(len, self._buffer))
