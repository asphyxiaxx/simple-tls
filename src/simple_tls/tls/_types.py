from __future__ import annotations

import sys
import typing
from os import PathLike

if sys.version_info < (3, 10):
    from typing_extensions import TypeAlias
else:
    from typing import TypeAlias

Buffer: TypeAlias = typing.Union[bytes, bytearray, memoryview]
ReadableBuffer: TypeAlias = Buffer
WritableBuffer: TypeAlias = typing.Union[bytearray, memoryview]
StrOrBytesPath: TypeAlias = typing.Union[
    str, bytes, PathLike[str], PathLike[bytes]
]
