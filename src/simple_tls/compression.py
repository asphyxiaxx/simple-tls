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


class UnsupportedCompression(Exception): ...


class Compression:
    SUPPORTED: typing.ClassVar[bool] = False

    @classmethod
    def compress(cls, data: bytes) -> bytes:
        raise UnsupportedCompression

    @classmethod
    def decompress(cls, data: bytes, length: int = 0) -> bytes:
        raise UnsupportedCompression


class Brotli(Compression):
    try:
        import brotli as _brotli  # type: ignore

    except ImportError:
        pass

    else:
        SUPPORTED = True

        @classmethod
        def compress(cls, data: bytes) -> bytes:
            try:
                return typing.cast(bytes, cls._brotli.compress(data))
            except cls._brotli.error as exc:
                raise ValueError(f"Error compressing: {exc}") from None

        @classmethod
        def decompress(cls, data: bytes, length: int = 0) -> bytes:
            try:
                return typing.cast(bytes, cls._brotli.decompress(data))
            except cls._brotli.error as exc:
                raise ValueError(f"Error decompressing: {exc}") from None


class ZSTD(Compression):
    try:
        import zstandard as _zstandard  # type: ignore

    except ImportError:
        try:
            import zstd as _zstd  # type: ignore

        except ImportError:
            pass

        else:
            SUPPORTED = True

            @classmethod
            def compress(cls, data: bytes) -> bytes:
                try:
                    return typing.cast(bytes, cls._zstd.compress(data))
                except Exception as exc:
                    raise ValueError(f"Error compressing: {exc}") from None

            @classmethod
            def decompress(cls, data: bytes, length: int = 0) -> bytes:
                try:
                    return typing.cast(bytes, cls._zstd.decompress(data))
                except Exception as exc:
                    raise ValueError(f"Error decompressing: {exc}") from None

    else:
        SUPPORTED = True

        _compressor = _zstandard.ZstdCompressor()
        _decompressor = _zstandard.ZstdDecompressor()

        @classmethod
        def compress(cls, data: bytes) -> bytes:
            try:
                return cls._compressor.compress(data)
            except Exception as exc:
                raise ValueError(f"Error compressing: {exc}") from None

        @classmethod
        def decompress(cls, data: bytes, length: int = 0) -> bytes:
            try:
                return cls._decompressor.decompress(data, length)
            except Exception as exc:
                raise ValueError(f"Error decompressing: {exc}") from None


class ZLIB(Compression):
    import zlib as _zlib

    SUPPORTED = True

    @classmethod
    def compress(cls, data: bytes) -> bytes:
        try:
            return cls._zlib.compress(data)
        except Exception as exc:
            raise ValueError(f"Error compressing: {exc}") from None

    @classmethod
    def decompress(cls, data: bytes, length: int = 0) -> bytes:
        try:
            if not length:
                return cls._zlib.decompress(data)
            return cls._zlib.decompress(data, bufsize=length)
        except Exception as exc:
            raise ValueError(f"Error decompressing: {exc}") from None
