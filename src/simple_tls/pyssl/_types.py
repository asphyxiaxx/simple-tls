from __future__ import annotations

import sys
from os import PathLike
from typing import TypeAlias

if sys.version_info < (3, 12):
    from typing_extensions import Buffer
else:
    from collections.abc import Buffer


ReadableBuffer: TypeAlias = Buffer
WritableBuffer: TypeAlias = Buffer
StrOrBytesPath: TypeAlias = str | bytes | PathLike[str] | PathLike[bytes]
