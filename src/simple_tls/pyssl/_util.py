from ssl import (
    DER_cert_to_PEM_cert,
    PEM_cert_to_DER_cert,
    cert_time_to_seconds,
    get_default_verify_paths,
    get_protocol_name,
    get_server_certificate,
)

from ._constant import (
    PROTOCOL_TLS_CLIENT,
    PROTOCOL_TLS_SERVER,
    CERT_REQUIRED,
    CERT_NONE,
    ASN1Object,
    Purpose,
)
from ._context import SSLContext
from ._types import ReadableBuffer, StrOrBytesPath

__all__ = [
    "DER_cert_to_PEM_cert",
    "PEM_cert_to_DER_cert",
    "cert_time_to_seconds",
    "create_default_context",
    "get_default_verify_paths",
    "get_protocol_name",
    "get_server_certificate",
]


def create_default_context(
    purpose: Purpose = Purpose.SERVER_AUTH,
    *,
    cafile: StrOrBytesPath | None = None,
    capath: StrOrBytesPath | None = None,
    cadata: str | ReadableBuffer | None = None,
) -> SSLContext:
    if not isinstance(purpose, ASN1Object):  # type: ignore[misc]
        raise TypeError(purpose)

    if purpose == Purpose.SERVER_AUTH:
        context = SSLContext(PROTOCOL_TLS_CLIENT)
        context.verify_mode = CERT_REQUIRED
        context.check_hostname = True
    elif purpose == Purpose.CLIENT_AUTH:
        context = SSLContext(PROTOCOL_TLS_SERVER)
    else:
        raise ValueError(purpose)

    if cafile or capath or cadata:
        context.load_verify_locations(cafile, capath, cadata)  # type: ignore
    elif context.verify_mode != CERT_NONE:
        # no explicit cafile, capath or cadata but the verify mode is
        # CERT_OPTIONAL or CERT_REQUIRED. Let's try to load default system
        # root CA certificates for the given purpose. This may fail silently.
        context.load_default_certs(purpose)

    return context
