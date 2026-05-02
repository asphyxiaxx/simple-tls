from __future__ import annotations

from os import PathLike
from typing import TypeAlias

Buffer: TypeAlias = bytes | bytearray | memoryview
ReadableBuffer: TypeAlias = Buffer
WritableBuffer: TypeAlias = bytearray | memoryview
StrOrBytesPath: TypeAlias = str | bytes | PathLike[str] | PathLike[bytes]
