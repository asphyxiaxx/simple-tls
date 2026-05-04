import typing
from ssl import (
    DER_cert_to_PEM_cert,
    PEM_cert_to_DER_cert,
    cert_time_to_seconds,
    get_default_verify_paths,
    get_protocol_name,
    get_server_certificate,
)

from simple_tls import tls, x509

from ._constant import (
    CERT_NONE,
    CERT_REQUIRED,
    PROTOCOL_TLS_CLIENT,
    PROTOCOL_TLS_SERVER,
    ASN1Object,
    Purpose,
    TLSVersion,
)
from ._types import ReadableBuffer, StrOrBytesPath

if typing.TYPE_CHECKING:
    from ._context import SSLContext


__all__ = [
    "DER_cert_to_PEM_cert",
    "PEM_cert_to_DER_cert",
    "cert_time_to_seconds",
    "create_default_context",
    "get_default_verify_paths",
    "get_protocol_name",
    "get_server_certificate",
]


def _parse_name(name: x509.Name) -> tuple[tuple[tuple[str, str], ...], ...]:
    return tuple(
        tuple(
            (attribute.oid._name, attribute.value)
            for attribute in rdn
            if isinstance(attribute.value, str)
        )
        for rdn in name.rdns
    )


def _parse_general_names(
    general_names: typing.Iterable[x509.GeneralName],
) -> tuple[tuple[str, str], ...]:
    out: list[tuple[str, str]] = []
    value: typing.Any

    for general_name in general_names:
        if isinstance(general_name, x509.DNSName):
            name = "DNS"
            value = general_name.value

        elif isinstance(general_name, x509.IPAddress):
            name = "IP Address"
            value = str(general_name.value)

        elif isinstance(general_name, x509.RegisteredID):
            name = "Registered ID"
            value = general_name.value._name
            if value == "Unknown OID":
                value = general_name.value.dotted_string

        elif isinstance(general_name, x509.OtherName):
            continue

        elif isinstance(general_name, x509.DirectoryName):
            name = "DirName"
            value = _parse_name(general_name.value)

        elif isinstance(general_name, x509.UniformResourceIdentifier):
            name = "URI"
            value = general_name.value

        elif isinstance(general_name, x509.RFC822Name):
            name = "email"
            value = general_name.value

        else:
            continue

        out.append((name, value))

    return tuple(out)


def parse_certificate(certificate: x509.Certificate) -> dict[str, typing.Any]:
    gmt_fmt = "%a, %d %b %Y %H:%M:%S GMT"
    out = {
        "subject": _parse_name(certificate.subject),
        "issuer": _parse_name(certificate.issuer),
        "version": certificate.version.value + 1,
        "serialNumber": hex(certificate.serial_number).upper(),
        "notBefore": certificate.not_valid_before_utc.strftime(gmt_fmt),
        "notAfter": certificate.not_valid_after_utc.strftime(gmt_fmt),
    }

    exts = certificate.extensions

    try:
        san_ext = exts.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        pass
    else:
        san = _parse_general_names(san_ext.value)
        if san:
            out["subjectAltName"] = san

    try:
        crl_ext = exts.get_extension_for_class(x509.CRLDistributionPoints)
    except x509.ExtensionNotFound:
        pass
    else:
        crls = tuple(
            name.value
            for x in crl_ext.value
            if x.full_name is not None
            for name in x.full_name
            if isinstance(name, x509.UniformResourceIdentifier)
        )
        if crls:
            out["crlDistributionPoints"] = crls

    try:
        aia_ext = exts.get_extension_for_class(x509.AuthorityInformationAccess)
    except x509.ExtensionNotFound:
        pass
    else:
        ocsp = tuple(
            ad.access_location.value
            for ad in aia_ext.value
            if (
                ad.access_method == x509.AuthorityInformationAccessOID.OCSP
                and isinstance(
                    ad.access_location, x509.UniformResourceIdentifier
                )
            )
        )
        if ocsp:
            out["OCSP"] = ocsp

    return out


def parse_cipher(cipher: tls.CipherSuite) -> tuple[str, str, int]:
    name = cipher.name
    version = _VERSION_MAP.get(cipher.minimum_version, "Unknown version")
    secret_bits = _SECRET_BIT_MAP.get(cipher.symmetric, 0)
    return (name, version, secret_bits)


def create_default_context(
    purpose: Purpose = Purpose.SERVER_AUTH,
    *,
    cafile: StrOrBytesPath | None = None,
    capath: StrOrBytesPath | None = None,
    cadata: str | ReadableBuffer | None = None,
) -> "SSLContext":
    if not isinstance(purpose, ASN1Object):  # type: ignore[misc]
        raise TypeError(purpose)

    from ._context import SSLContext

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


_VERSION_MAP: dict[int, str] = {
    TLSVersion.TLSv1: "TLSv1",
    TLSVersion.TLSv1_1: "TLSv1.1",
    TLSVersion.TLSv1_2: "TLSv1.2",
    TLSVersion.TLSv1_3: "TLSv1.3",
}

_SECRET_BIT_MAP: dict[tls.Symmetric, int] = {
    tls.Symmetric.AES_128_CBC: 128,
    tls.Symmetric.AES_128_CCM: 128,
    tls.Symmetric.AES_128_CCM_8: 128,
    tls.Symmetric.AES_128_GCM: 128,
    tls.Symmetric.AES_256_CBC: 256,
    tls.Symmetric.AES_256_CCM: 256,
    tls.Symmetric.AES_256_CCM_8: 256,
    tls.Symmetric.AES_256_GCM: 256,
    tls.Symmetric.CHACHA20_DRAFT_00: 256,
    tls.Symmetric.CHACHA20_POLY1305: 256,
    tls.Symmetric.TRIPLE_DES_EDE_CBC: 168,
    tls.Symmetric.RC4_128: 128,
    tls.Symmetric.NULL: 0,
}
