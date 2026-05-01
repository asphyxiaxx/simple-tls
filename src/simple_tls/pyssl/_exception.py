import ssl as _ssl

from ._constant import (
    SSL_ERROR_EOF,
    SSL_ERROR_SYSCALL,
    SSL_ERROR_WANT_READ,
    SSL_ERROR_WANT_WRITE,
    SSL_ERROR_ZERO_RETURN,
)

socket_error = OSError


class SSLError(_ssl.SSLError):
    pass


class SSLWantReadError(_ssl.SSLWantReadError):
    errno = SSL_ERROR_WANT_READ


class SSLWantWriteError(_ssl.SSLWantWriteError):
    errno = SSL_ERROR_WANT_WRITE


class SSLEOFError(_ssl.SSLEOFError):
    errno = SSL_ERROR_EOF


class SSLZeroReturnError(_ssl.SSLZeroReturnError):
    errno = SSL_ERROR_ZERO_RETURN


class SSLSyscallError(_ssl.SSLSyscallError):
    errno = SSL_ERROR_SYSCALL
