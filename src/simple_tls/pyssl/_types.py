from __future__ import annotations

import sys
from collections.abc import Callable
from os import PathLike
from typing import TYPE_CHECKING, TypeAlias, Union

if TYPE_CHECKING:
    from ._object import SSLObject
    from ._socket import SSLSocket

if sys.version_info < (3, 12):
    from typing_extensions import Buffer
else:
    from collections.abc import Buffer


ReadableBuffer: TypeAlias = Buffer
WritableBuffer: TypeAlias = Buffer
StrOrBytesPath: TypeAlias = str | bytes | PathLike[str] | PathLike[bytes]

PCTRTT: TypeAlias = tuple[tuple[str, str], ...]
PCTRTTT: TypeAlias = tuple[PCTRTT, ...]
PeerCertRetDictType: TypeAlias = dict[str, str | PCTRTTT | PCTRTT]

PSKClientCbType: TypeAlias = Callable[[str | None], tuple[str | None, bytes]]
PSKServerCbType: TypeAlias = Callable[[str | None], bytes]
SrvnmeCbType: TypeAlias = Callable[
    [Union["SSLSocket", "SSLObject"], str | None, "SSLSocket"], int | None
]
ExtensionsCbType: TypeAlias = Callable[[list[int]], list[int]]
