# Copyright (c) 2026 The simple-tls Contributors

# Permission is hereby granted, free of charge, to any person obtaining a copy of
# this software and associated documentation files (the “Software”), to deal in
# the Software without restriction, including without limitation the rights to
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
# the Software, and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
# FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
# COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
# IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

from __future__ import annotations

import datetime
import ipaddress
import typing

_T = typing.TypeVar("_T")


def utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


@typing.overload
def negotiate(
    supported: typing.Iterable[_T],
    offered: typing.Iterable[typing.Any] | None,
    exc: None = None,
) -> _T | None: ...


@typing.overload
def negotiate(
    supported: typing.Iterable[_T],
    offered: typing.Iterable[typing.Any] | None,
    exc: Exception = ...,
) -> _T: ...


def negotiate(
    supported: typing.Iterable[_T],
    offered: typing.Iterable[typing.Any] | None,
    exc: Exception | None = None,
) -> _T | None:
    if offered is not None:
        for c in supported:
            if c in offered:
                return c

    if exc is not None:
        raise exc

    return None


def is_valid_sni(server_hostname: str) -> bool:
    # must be a non-empty string
    if (
        not server_hostname
        or not isinstance(server_hostname, str)
        or server_hostname.startswith(".")
        or server_hostname.endswith(".")
    ):
        raise ValueError(
            "server_hostname cannot be an empty or start with a leading dot."
        )

    # RFC 6066 explicitly forbids literal IP addresses in SNI
    try:
        ipaddress.ip_address(server_hostname)
        # If this succeeds, it's an IP address, which is INVALID for SNI
        return False
    except ValueError:
        pass  # Not an IP address, proceed to next checks

    # max 253 characters for a domain name
    if len(server_hostname) > 253:
        raise ValueError("SNI hostname is too long")

    return True
