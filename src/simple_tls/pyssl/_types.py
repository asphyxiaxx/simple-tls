from __future__ import annotations

import sys
import typing
from os import PathLike

if sys.version_info < (3, 10):
    from typing_extensions import TypeAlias
else:
    from typing import TypeAlias

if sys.version_info < (3, 12):
    from typing_extensions import Buffer
else:
    from collections.abc import Buffer


ReadableBuffer: TypeAlias = Buffer
WritableBuffer: TypeAlias = Buffer
StrOrBytesPath: TypeAlias = typing.Union[str, bytes, PathLike[str], PathLike[bytes]]
