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

import enum

# ruff: disable[E501]

TLS11_DOWNGRADE_SENTINEL = b"DOWNGRD\x00"
TLS12_DOWNGRADE_SENTINEL = b"DOWNGRD\x01"
TLS13_HRR_SENTINEL = b"\xcf!\xadt\xe5\x9aa\x11\xbe\x1d\x8c\x02\x1ee\xb8\x91\xc2\xa2\x11\x16z\xbb\x8c^\x07\x9e\t\xe2\xc8\xa83\x9c"

CLIENT_CONTEXT_STRING = b"TLS 1.3, client CertificateVerify"
SERVER_CONTEXT_STRING = b"TLS 1.3, server CertificateVerify"

GREASES = (
    0x0A0A,
    0x1A1A,
    0x2A2A,
    0x3A3A,
    0x4A4A,
    0x5A5A,
    0x6A6A,
    0x7A7A,
    0x8A8A,
    0x9A9A,
    0xAAAA,
    0xBABA,
    0xCACA,
    0xDADA,
    0xEAEA,
    0xFAFA,
)

UNSPECIFIED = -1


def _sigscheme(hashalg: int, sigalg: int) -> int:
    return hashalg << 8 | sigalg


class TLSEnum(enum.Enum):
    """
    Base class
    """


class ContentType(int, TLSEnum):
    CHANGE_CIPHER_SPEC = 0x14
    ALERT = 0x15
    HANDSHAKE = 0x16
    APPLICATION_DATA = 0x17

    # pseudo content types
    HEADER = 0x100
    INNER_CONTENT_TYPE = 0x101


class HandshakeType(int, TLSEnum):
    HELLO_REQUEST = 0
    CLIENT_HELLO = 1
    SERVER_HELLO = 2
    NEWSESSION_TICKET = 4
    END_OF_EARLY_DATA = 5
    HELLO_RETRY_REQUEST = 6
    ENCRYPTED_EXTENSIONS = 8
    CERTIFICATE = 11
    SERVER_KEY_EXCHANGE = 12
    CERTIFICATE_REQUEST = 13
    SERVER_HELLO_DONE = 14
    CERTIFICATE_VERIFY = 15
    CLIENT_KEY_EXCHANGE = 16
    FINISHED = 20
    CERTIFICATE_STATUS = 22
    KEY_UPDATE = 24
    COMPRESSED_CERTIFICATE = 25
    NEXT_PROTO = 67
    MESSAGE_HASH = 254
    CHANGE_CIPHER_SPEC = 0x0101


class ExtensionType(int, TLSEnum):
    SERVER_NAME = 0
    STATUS_REQUEST = 5
    SUPPORTED_GROUPS = 10
    EC_POINT_FORMATS = 11
    SIGNATURE_ALGORITHMS = 13
    ALPN = 16
    SIGNED_CERTIFICATE_TIMESTAMP = 18
    CLIENT_HELLO_PADDING = 21
    ENCRYPT_THEN_MAC = 22
    EXTENDED_MAIN_SECRET = 23
    COMPRESS_CERTIFICATE = 27
    SESSION_TICKET = 35

    # TLSv1.3 specific
    PRE_SHARED_KEY = 41
    EARLY_DATA = 42
    SUPPORTED_VERSIONS = 43
    COOKIE = 44
    PSK_KEY_EXCHANGE_MODES = 45
    POST_HANDSHAKE_AUTH = 49
    KEY_SHARE = 51

    # draft
    SUPPORTS_NPN = 0x3374
    APPLICATION_SETTINGS = 0x44CD
    ECH_OUTER_EXTENSIONS = 0xFD00
    ENCRYPTED_CLIENT_HELLO = 0xFE0D
    RENEGOTIATION_INFO = 0xFF01


class AlertLevel(int, TLSEnum):
    WARNING = 1
    FATAL = 2


class AlertDescription(int, TLSEnum):
    ACCESS_DENIED = 49
    BAD_CERTIFICATE = 42
    BAD_CERTIFICATE_HASH_VALUE = 114
    BAD_CERTIFICATE_STATUS_RESPONSE = 113
    BAD_RECORD_MAC = 20
    CERTIFICATE_EXPIRED = 45
    CERTIFICATE_REQUIRED = 116
    CERTIFICATE_REVOKED = 44
    CERTIFICATE_UNKNOWN = 46
    CERTIFICATE_UNOBTAINABLE = 111
    CLOSE_NOTIFY = 0
    DECODE_ERROR = 50
    DECOMPRESSION_FAILURE = 30
    DECRYPT_ERROR = 51
    DECRYPTION_FAILED = 21
    ECH_REQUIRED = 121
    HANDSHAKE_FAILURE = 40
    ILLEGAL_PARAMETER = 47
    INAPPROPRIATE_FALLBACK = 86
    INSUFFICIENT_SECURITY = 71
    INTERNAL_ERROR = 80
    MISSING_EXTENSION = 109
    NO_APPLICATION_PROTOCOL = 120
    NO_CERTIFICATE = 41
    NO_RENEGOTIATION = 100
    PROTOCOL_VERSION = 70
    RECORD_OVERFLOW = 22
    UNEXPECTED_MESSAGE = 10
    UNKNOWN_CA = 48
    UNKNOWN_PSK_IDENTITY = 115
    UNRECOGNIZED_NAME = 112
    UNSUPPORTED_CERTIFICATE = 43
    UNSUPPORTED_EXTENSION = 110
    USER_CANCELLED = 90


class CertificateType(int, TLSEnum):
    X509 = 0
    OPENPGP = 1


class ClientCertificateType(int, TLSEnum):
    RSA_SIGN = 1
    DSS_SIGN = 2
    RSA_FIXED_DH = 3
    DSS_FIXED_DH = 4

    # RFC 8422
    ECDSA_SIGN = 64
    RSA_FIXED_ECDH = 65
    ECDSA_FIXED_ECDH = 66


class CertificateStatusType(int, TLSEnum):
    OCSP = 1


class CertificateCompressionAlgorithm(int, TLSEnum):
    """
    See RFC 8879.
    """

    ZLIB = 1
    BROTLI = 2
    ZSTD = 3


class Compression(int, TLSEnum):
    NULL = 0


class ECCurveType(int, TLSEnum):
    """
    See RFC4492.
    """

    EXPLICIT_PRIME = 1
    EXPLICIT_CHAR2 = 2
    NAMED_CURVE = 3


class ECPointFormat(int, TLSEnum):
    UNCOMPRESSED = 0
    ASNIX962_COMPRESSED_PRIME = 1
    ASN1X962_COMPRESSED_CHAR2 = 2


class KeyUpdateMessageType(int, TLSEnum):
    """
    See RFC 8446.
    """

    UPDATE_NOT_REQUESTED = 0
    UPDATE_REQUESTED = 1


class NamedGroup(int, TLSEnum):
    # RFC4492
    SECT163K1 = 1
    SECT163R1 = 2
    SECT163R2 = 3
    SECT193R1 = 4
    SECT193R2 = 5
    SECT233K1 = 6
    SECT233R1 = 7
    SECT239K1 = 8
    SECT283K1 = 9
    SECT283R1 = 10
    SECT409K1 = 11
    SECT409R1 = 12
    SECT571K1 = 13
    SECT571R1 = 14
    SECP160K1 = 15
    SECP160R1 = 16
    SECP160R2 = 17
    SECP192K1 = 18
    SECP192R1 = 19
    SECP224K1 = 20
    SECP224R1 = 21
    SECP256K1 = 22
    SECP256R1 = 23
    SECP384R1 = 24
    SECP521R1 = 25

    # RFC7919
    FFDHE2048 = 256
    FFDHE3072 = 257
    FFDHE4096 = 258
    FFDHE6144 = 259
    FFDHE8192 = 260

    # draft
    X25519 = 29
    X448 = 30
    SECP256R1MLKEM768 = 0x11EB
    X25519MLKEM768 = 0x11EC
    SECP384R1MLKEM1024 = 0x11ED


class NameType(int, TLSEnum):
    HOSTNAME = 0


class HashAlgorithm(int, TLSEnum):
    NONE = 0
    MD5 = 1
    SHA1 = 2
    SHA224 = 3
    SHA256 = 4
    SHA384 = 5
    SHA512 = 6

    # RFC 8422
    INTRINSIC = 8


class PSKKeyExchangeMode(int, TLSEnum):
    PSK_KE = 0
    PSK_DHE_KE = 1


class SignatureAlgorithm(int, TLSEnum):
    ANONYMOUS = 0
    RSA = 1
    DSA = 2
    ECDSA = 3

    # RFC 8422
    ED25519 = 7
    ED448 = 8

    # RFC 8446
    # RFC 8447
    RSA_PSS_RSAE_SHA256 = 4
    RSA_PSS_RSAE_SHA384 = 5
    RSA_PSS_RSAE_SHA512 = 6
    RSA_PSS_PSS_SHA256 = 9
    RSA_PSS_PSS_SHA384 = 10
    RSA_PSS_PSS_SHA512 = 11


class SignatureScheme(int, TLSEnum):
    # fmt: off

    RSA_MD5 = _sigscheme(HashAlgorithm.MD5, SignatureAlgorithm.RSA)

    RSA_PKCS1_SHA1 = _sigscheme(HashAlgorithm.SHA1, SignatureAlgorithm.RSA)
    RSA_PKCS1_SHA224 = _sigscheme(HashAlgorithm.SHA224, SignatureAlgorithm.RSA)
    RSA_PKCS1_SHA256 = _sigscheme(HashAlgorithm.SHA256, SignatureAlgorithm.RSA)
    RSA_PKCS1_SHA384 = _sigscheme(HashAlgorithm.SHA384, SignatureAlgorithm.RSA)
    RSA_PKCS1_SHA512 = _sigscheme(HashAlgorithm.SHA512, SignatureAlgorithm.RSA)

    RSA_PSS_RSAE_SHA256 = _sigscheme(HashAlgorithm.INTRINSIC, SignatureAlgorithm.RSA_PSS_RSAE_SHA256)
    RSA_PSS_RSAE_SHA384 = _sigscheme(HashAlgorithm.INTRINSIC, SignatureAlgorithm.RSA_PSS_RSAE_SHA384)
    RSA_PSS_RSAE_SHA512 = _sigscheme(HashAlgorithm.INTRINSIC, SignatureAlgorithm.RSA_PSS_RSAE_SHA512)
    RSA_PSS_PSS_SHA256 = _sigscheme(HashAlgorithm.INTRINSIC, SignatureAlgorithm.RSA_PSS_PSS_SHA256)
    RSA_PSS_PSS_SHA384 = _sigscheme(HashAlgorithm.INTRINSIC, SignatureAlgorithm.RSA_PSS_PSS_SHA384)
    RSA_PSS_PSS_SHA512 = _sigscheme(HashAlgorithm.INTRINSIC, SignatureAlgorithm.RSA_PSS_PSS_SHA512)

    DSA_SHA1 = _sigscheme(HashAlgorithm.SHA1, SignatureAlgorithm.DSA)
    DSA_SHA224 = _sigscheme(HashAlgorithm.SHA224, SignatureAlgorithm.DSA)
    DSA_SHA256 = _sigscheme(HashAlgorithm.SHA256, SignatureAlgorithm.DSA)
    DSA_SHA384 = _sigscheme(HashAlgorithm.SHA384, SignatureAlgorithm.DSA)
    DSA_SHA512 = _sigscheme(HashAlgorithm.SHA512, SignatureAlgorithm.DSA)

    ECDSA_SHA1 = _sigscheme(HashAlgorithm.SHA1, SignatureAlgorithm.ECDSA)
    ECDSA_SHA224 = _sigscheme(HashAlgorithm.SHA224, SignatureAlgorithm.ECDSA)
    ECDSA_SECP256R1_SHA256 = _sigscheme(HashAlgorithm.SHA256, SignatureAlgorithm.ECDSA)
    ECDSA_SECP384R1_SHA384 = _sigscheme(HashAlgorithm.SHA384, SignatureAlgorithm.ECDSA)
    ECDSA_SECP521R1_SHA512 = _sigscheme(HashAlgorithm.SHA512, SignatureAlgorithm.ECDSA)

    ED25519 = _sigscheme(HashAlgorithm.INTRINSIC, SignatureAlgorithm.ED25519)
    ED448 = _sigscheme(HashAlgorithm.INTRINSIC, SignatureAlgorithm.ED448)

    # fmt: on


class TLSVersion(int, TLSEnum):
    UNSPECIFIED = -1
    TLSv1 = 769
    TLSv1_1 = 770
    TLSv1_2 = 771
    TLSv1_3 = 772


class _Cipher:
    def __init__(
        self,
        id: int,
        name: str,
        minimum_version: int,
        maximum_version: int,
        strength_bits: int,
        alg_bits: int,
        aead: bool,
        symmetric: Symmetric,
        digest: HashAlgorithm | None,
        prf_hash: HashAlgorithm,
        kea: KeyExchange,
        auth: Authentication,
        handshake_sigs: tuple[
            HashAlgorithm, ...
        ],  # TLS 1.2: list; TLS 1.3: negotiated separately
    ):
        self.id = id
        self.name = name
        self.minimum_version = minimum_version
        self.maximum_version = maximum_version
        self.strength_bits = strength_bits
        self.alg_bits = alg_bits
        self.aead = aead
        self.symmetric = symmetric
        self.record_mac = digest
        self.prf_hash = prf_hash
        self.kea = kea
        self.auth = auth
        self.handshake_sigs = handshake_sigs

    def __hash__(self) -> int:
        return hash(self.id)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, _Cipher):
            return self.id == other.id
        return self.id == other

    def __repr__(self) -> str:
        return f"<0x{self.id:04X}:{self.name}>"


class Symmetric(enum.IntEnum):
    NULL = enum.auto()
    RC4_128 = enum.auto()
    TRIPLE_DES_EDE_CBC = enum.auto()
    AES_128_CBC = enum.auto()
    AES_256_CBC = enum.auto()
    AES_128_GCM = enum.auto()
    AES_256_GCM = enum.auto()
    CHACHA20_POLY1305 = enum.auto()
    CHACHA20_DRAFT_00 = enum.auto()
    AES_128_CCM = enum.auto()
    AES_256_CCM = enum.auto()
    AES_128_CCM_8 = enum.auto()
    AES_256_CCM_8 = enum.auto()


class KeyExchange(enum.IntEnum):
    RSA = enum.auto()
    DHE = enum.auto()
    ECDHE = enum.auto()
    NONE = enum.auto()  # TLS1.3 handled separately


class Authentication(enum.IntEnum):
    RSA = enum.auto()
    DSS = enum.auto()
    ECDSA = enum.auto()
    ANON = enum.auto()
    NONE = enum.auto()


class CipherSuite(TLSEnum):
    @property
    def id(self) -> int:
        return self.value.id

    @property
    def aead(self) -> bool:
        return self.value.aead

    @property
    def minimum_version(self) -> int:
        return self.value.minimum_version

    @property
    def maximum_version(self) -> int:
        return self.value.maximum_version

    @property
    def symmetric(self) -> Symmetric:
        return self.value.symmetric

    @property
    def digest(self) -> HashAlgorithm | None:
        return self.value.record_mac

    @property
    def prf_hash(self) -> HashAlgorithm:
        return self.value.prf_hash

    @property
    def kea(self) -> KeyExchange:
        return self.value.kea

    @property
    def auth(self) -> Authentication:
        return self.value.auth

    @property
    def name(self) -> str:
        return self.value.name

    def __eq__(self, other: object) -> bool:
        if isinstance(other, CipherSuite):
            return self.id == other.id
        return self.id == other

    def __hash__(self) -> int:
        return hash(self.id)

    def __repr__(self) -> str:
        return f"{self.value}"

    TLS_RSA_WITH_NULL_MD5 = _Cipher(
        id=0x0001,
        name="TLS_RSA_WITH_NULL_MD5",
        minimum_version=TLSVersion.TLSv1,
        maximum_version=TLSVersion.TLSv1_2,
        strength_bits=0,
        alg_bits=0,
        aead=False,
        symmetric=Symmetric.NULL,
        digest=HashAlgorithm.MD5,
        prf_hash=HashAlgorithm.SHA256,
        kea=KeyExchange.RSA,
        auth=Authentication.RSA,
        handshake_sigs=(),
    )

    TLS_RSA_WITH_NULL_SHA = _Cipher(
        id=0x0002,
        name="TLS_RSA_WITH_NULL_SHA",
        minimum_version=TLSVersion.TLSv1,
        maximum_version=TLSVersion.TLSv1_2,
        strength_bits=0,
        alg_bits=0,
        aead=False,
        symmetric=Symmetric.NULL,
        digest=HashAlgorithm.SHA1,
        prf_hash=HashAlgorithm.SHA256,
        kea=KeyExchange.RSA,
        auth=Authentication.RSA,
        handshake_sigs=(),
    )

    TLS_RSA_WITH_NULL_SHA256 = _Cipher(
        id=0x003B,
        name="TLS_RSA_WITH_NULL_SHA256",
        minimum_version=TLSVersion.TLSv1,
        maximum_version=TLSVersion.TLSv1_2,
        strength_bits=0,
        alg_bits=0,
        aead=False,
        symmetric=Symmetric.NULL,
        digest=HashAlgorithm.SHA256,
        prf_hash=HashAlgorithm.SHA256,
        kea=KeyExchange.RSA,
        auth=Authentication.RSA,
        handshake_sigs=(),
    )

    TLS_RSA_WITH_RC4_128_MD5 = _Cipher(
        id=0x0004,
        name="TLS_RSA_WITH_RC4_128_MD5",
        minimum_version=TLSVersion.TLSv1,
        maximum_version=TLSVersion.TLSv1_2,
        strength_bits=128,
        alg_bits=128,
        aead=False,
        symmetric=Symmetric.RC4_128,
        digest=HashAlgorithm.MD5,
        prf_hash=HashAlgorithm.SHA256,
        kea=KeyExchange.RSA,
        auth=Authentication.RSA,
        handshake_sigs=(),
    )

    TLS_RSA_WITH_RC4_128_SHA = _Cipher(
        id=0x0005,
        name="TLS_RSA_WITH_RC4_128_SHA",
        minimum_version=TLSVersion.TLSv1,
        maximum_version=TLSVersion.TLSv1_2,
        strength_bits=128,
        alg_bits=128,
        aead=False,
        symmetric=Symmetric.RC4_128,
        digest=HashAlgorithm.SHA1,
        prf_hash=HashAlgorithm.SHA256,
        kea=KeyExchange.RSA,
        auth=Authentication.RSA,
        handshake_sigs=(),
    )

    TLS_RSA_WITH_3DES_EDE_CBC_SHA = _Cipher(
        id=0x000A,
        name="TLS_RSA_WITH_3DES_EDE_CBC_SHA",
        minimum_version=TLSVersion.TLSv1,
        maximum_version=TLSVersion.TLSv1_2,
        strength_bits=112,
        alg_bits=168,
        aead=False,
        symmetric=Symmetric.TRIPLE_DES_EDE_CBC,
        digest=HashAlgorithm.SHA1,
        prf_hash=HashAlgorithm.SHA256,
        kea=KeyExchange.RSA,
        auth=Authentication.RSA,
        handshake_sigs=(),
    )

    TLS_RSA_WITH_AES_128_CBC_SHA = _Cipher(
        id=0x002F,
        name="TLS_RSA_WITH_AES_128_CBC_SHA",
        minimum_version=TLSVersion.TLSv1,
        maximum_version=TLSVersion.TLSv1_2,
        strength_bits=128,
        alg_bits=128,
        aead=False,
        symmetric=Symmetric.AES_128_CBC,
        digest=HashAlgorithm.SHA1,
        prf_hash=HashAlgorithm.SHA256,
        kea=KeyExchange.RSA,
        auth=Authentication.RSA,
        handshake_sigs=(),
    )

    TLS_RSA_WITH_AES_256_CBC_SHA = _Cipher(
        id=0x0035,
        name="TLS_RSA_WITH_AES_256_CBC_SHA",
        minimum_version=TLSVersion.TLSv1,
        maximum_version=TLSVersion.TLSv1_2,
        strength_bits=256,
        alg_bits=256,
        aead=False,
        symmetric=Symmetric.AES_256_CBC,
        digest=HashAlgorithm.SHA1,
        prf_hash=HashAlgorithm.SHA256,
        kea=KeyExchange.RSA,
        auth=Authentication.RSA,
        handshake_sigs=(),
    )

    TLS_RSA_WITH_AES_128_CBC_SHA256 = _Cipher(
        id=0x003C,
        name="TLS_RSA_WITH_AES_128_CBC_SHA256",
        minimum_version=TLSVersion.TLSv1_2,
        maximum_version=TLSVersion.TLSv1_2,
        strength_bits=128,
        alg_bits=128,
        aead=False,
        symmetric=Symmetric.AES_128_CBC,
        digest=HashAlgorithm.SHA256,
        prf_hash=HashAlgorithm.SHA256,
        kea=KeyExchange.RSA,
        auth=Authentication.RSA,
        handshake_sigs=(),
    )

    TLS_RSA_WITH_AES_256_CBC_SHA256 = _Cipher(
        id=0x003D,
        name="TLS_RSA_WITH_AES_256_CBC_SHA256",
        minimum_version=TLSVersion.TLSv1_2,
        maximum_version=TLSVersion.TLSv1_2,
        strength_bits=256,
        alg_bits=256,
        aead=False,
        symmetric=Symmetric.AES_256_CBC,
        digest=HashAlgorithm.SHA256,
        prf_hash=HashAlgorithm.SHA256,
        kea=KeyExchange.RSA,
        auth=Authentication.RSA,
        handshake_sigs=(),
    )

    TLS_RSA_WITH_AES_128_CCM = _Cipher(
        id=0xC09C,
        name="TLS_RSA_WITH_AES_128_CCM",
        minimum_version=TLSVersion.TLSv1_2,
        maximum_version=TLSVersion.TLSv1_2,
        strength_bits=128,
        alg_bits=128,
        aead=True,
        symmetric=Symmetric.AES_128_CCM,
        digest=None,
        prf_hash=HashAlgorithm.SHA256,
        kea=KeyExchange.RSA,
        auth=Authentication.RSA,
        handshake_sigs=(),
    )

    TLS_RSA_WITH_AES_256_CCM = _Cipher(
        id=0xC09D,
        name="TLS_RSA_WITH_AES_256_CCM",
        minimum_version=TLSVersion.TLSv1_2,
        maximum_version=TLSVersion.TLSv1_2,
        strength_bits=256,
        alg_bits=256,
        aead=True,
        symmetric=Symmetric.AES_256_CCM,
        digest=None,
        prf_hash=HashAlgorithm.SHA256,
        kea=KeyExchange.RSA,
        auth=Authentication.RSA,
        handshake_sigs=(),
    )

    TLS_RSA_WITH_AES_128_CCM_8 = _Cipher(
        id=0xC0A0,
        name="TLS_RSA_WITH_AES_128_CCM_8",
        minimum_version=TLSVersion.TLSv1_2,
        maximum_version=TLSVersion.TLSv1_2,
        strength_bits=128,
        alg_bits=128,
        aead=True,
        symmetric=Symmetric.AES_128_CCM_8,
        digest=None,
        prf_hash=HashAlgorithm.SHA256,
        kea=KeyExchange.RSA,
        auth=Authentication.RSA,
        handshake_sigs=(),
    )

    TLS_RSA_WITH_AES_256_CCM_8 = _Cipher(
        id=0xC0A1,
        name="TLS_RSA_WITH_AES_256_CCM_8",
        minimum_version=TLSVersion.TLSv1_2,
        maximum_version=TLSVersion.TLSv1_2,
        strength_bits=256,
        alg_bits=256,
        aead=True,
        symmetric=Symmetric.AES_256_CCM_8,
        digest=None,
        prf_hash=HashAlgorithm.SHA256,
        kea=KeyExchange.RSA,
        auth=Authentication.RSA,
        handshake_sigs=(),
    )

    TLS_RSA_WITH_AES_128_GCM_SHA256 = _Cipher(
        id=0x009C,
        name="TLS_RSA_WITH_AES_128_GCM_SHA256",
        minimum_version=TLSVersion.TLSv1_2,
        maximum_version=TLSVersion.TLSv1_2,
        strength_bits=128,
        alg_bits=128,
        aead=True,
        symmetric=Symmetric.AES_128_GCM,
        digest=None,
        prf_hash=HashAlgorithm.SHA256,
        kea=KeyExchange.RSA,
        auth=Authentication.RSA,
        handshake_sigs=(),
    )

    TLS_RSA_WITH_AES_256_GCM_SHA384 = _Cipher(
        id=0x009D,
        name="TLS_RSA_WITH_AES_256_GCM_SHA384",
        minimum_version=TLSVersion.TLSv1_2,
        maximum_version=TLSVersion.TLSv1_2,
        strength_bits=256,
        alg_bits=256,
        aead=True,
        symmetric=Symmetric.AES_256_GCM,
        digest=None,
        prf_hash=HashAlgorithm.SHA384,
        kea=KeyExchange.RSA,
        auth=Authentication.RSA,
        handshake_sigs=(),
    )

    TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA = _Cipher(
        id=0x0013,
        name="TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
        minimum_version=TLSVersion.TLSv1,
        maximum_version=TLSVersion.TLSv1_2,
        strength_bits=112,
        alg_bits=168,
        aead=False,
        symmetric=Symmetric.TRIPLE_DES_EDE_CBC,
        digest=HashAlgorithm.SHA1,
        prf_hash=HashAlgorithm.SHA256,
        kea=KeyExchange.DHE,
        auth=Authentication.DSS,
        handshake_sigs=(),
    )

    TLS_DHE_DSS_WITH_AES_128_CBC_SHA = _Cipher(
        id=0x0032,
        name="TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
        minimum_version=TLSVersion.TLSv1,
        maximum_version=TLSVersion.TLSv1_2,
        strength_bits=128,
        alg_bits=128,
        aead=False,
        symmetric=Symmetric.AES_128_CBC,
        digest=HashAlgorithm.SHA1,
        prf_hash=HashAlgorithm.SHA256,
        kea=KeyExchange.DHE,
        auth=Authentication.DSS,
        handshake_sigs=(),
    )

    TLS_DHE_DSS_WITH_AES_256_CBC_SHA = _Cipher(
        id=0x0038,
        name="TLS_DHE_DSS_WITH_AES_256_CBC_SHA",
        minimum_version=TLSVersion.TLSv1,
        maximum_version=TLSVersion.TLSv1_2,
        strength_bits=256,
        alg_bits=256,
        aead=False,
        symmetric=Symmetric.AES_256_CBC,
        digest=HashAlgorithm.SHA1,
        prf_hash=HashAlgorithm.SHA256,
        kea=KeyExchange.DHE,
        auth=Authentication.DSS,
        handshake_sigs=(),
    )

    TLS_DHE_DSS_WITH_AES_128_CBC_SHA256 = _Cipher(
        id=0x0040,
        name="TLS_DHE_DSS_WITH_AES_128_CBC_SHA256",
        minimum_version=TLSVersion.TLSv1_2,
        maximum_version=TLSVersion.TLSv1_2,
        strength_bits=128,
        alg_bits=128,
        aead=False,
        symmetric=Symmetric.AES_128_CBC,
        digest=None,
        prf_hash=HashAlgorithm.SHA256,
        kea=KeyExchange.DHE,
        auth=Authentication.DSS,
        handshake_sigs=(),
    )

    TLS_DHE_DSS_WITH_AES_256_CBC_SHA256 = _Cipher(
        id=0x006A,
        name="TLS_DHE_DSS_WITH_AES_256_CBC_SHA256",
        minimum_version=TLSVersion.TLSv1_2,
        maximum_version=TLSVersion.TLSv1_2,
        strength_bits=256,
        alg_bits=256,
        aead=False,
        symmetric=Symmetric.AES_256_CBC,
        digest=None,
        prf_hash=HashAlgorithm.SHA256,
        kea=KeyExchange.DHE,
        auth=Authentication.DSS,
        handshake_sigs=(),
    )

    TLS_DHE_DSS_WITH_AES_128_GCM_SHA256 = _Cipher(
        id=0x00A2,
        name="TLS_DHE_DSS_WITH_AES_128_GCM_SHA256",
        minimum_version=TLSVersion.TLSv1_2,
        maximum_version=TLSVersion.TLSv1_2,
        strength_bits=128,
        alg_bits=128,
        aead=True,
        symmetric=Symmetric.AES_128_GCM,
        digest=None,
        prf_hash=HashAlgorithm.SHA256,
        kea=KeyExchange.DHE,
        auth=Authentication.DSS,
        handshake_sigs=(),
    )

    TLS_DHE_DSS_WITH_AES_256_GCM_SHA384 = _Cipher(
        id=0x00A3,
        name="TLS_DHE_DSS_WITH_AES_256_GCM_SHA384",
        minimum_version=TLSVersion.TLSv1_2,
        maximum_version=TLSVersion.TLSv1_2,
        strength_bits=256,
        alg_bits=256,
        aead=True,
        symmetric=Symmetric.AES_256_GCM,
        digest=HashAlgorithm.SHA384,
        prf_hash=HashAlgorithm.SHA384,
        kea=KeyExchange.DHE,
        auth=Authentication.DSS,
        handshake_sigs=(),
    )

    TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA = _Cipher(
        id=0x0016,
        name="TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
        minimum_version=TLSVersion.TLSv1,
        maximum_version=TLSVersion.TLSv1_2,
        strength_bits=112,
        alg_bits=168,
        aead=False,
        symmetric=Symmetric.TRIPLE_DES_EDE_CBC,
        digest=HashAlgorithm.SHA1,
        prf_hash=HashAlgorithm.SHA256,
        kea=KeyExchange.DHE,
        auth=Authentication.RSA,
        handshake_sigs=(),
    )

    TLS_DHE_RSA_WITH_AES_128_CBC_SHA = _Cipher(
        id=0x0033,
        name="TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
        minimum_version=TLSVersion.TLSv1,
        maximum_version=TLSVersion.TLSv1_2,
        strength_bits=128,
        alg_bits=128,
        aead=False,
        symmetric=Symmetric.AES_128_CBC,
        digest=HashAlgorithm.SHA1,
        prf_hash=HashAlgorithm.SHA256,
        kea=KeyExchange.DHE,
        auth=Authentication.RSA,
        handshake_sigs=(),
    )

    TLS_DHE_RSA_WITH_AES_256_CBC_SHA = _Cipher(
        id=0x0039,
        name="TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
        minimum_version=TLSVersion.TLSv1,
        maximum_version=TLSVersion.TLSv1_2,
        strength_bits=256,
        alg_bits=256,
        aead=False,
        symmetric=Symmetric.AES_256_CBC,
        digest=HashAlgorithm.SHA1,
        prf_hash=HashAlgorithm.SHA256,
        kea=KeyExchange.DHE,
        auth=Authentication.RSA,
        handshake_sigs=(),
    )

    TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 = _Cipher(
        id=0x0067,
        name="TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
        minimum_version=TLSVersion.TLSv1_2,
        maximum_version=TLSVersion.TLSv1_2,
        strength_bits=128,
        alg_bits=128,
        aead=False,
        symmetric=Symmetric.AES_128_CBC,
        digest=HashAlgorithm.SHA256,
        prf_hash=HashAlgorithm.SHA256,
        kea=KeyExchange.DHE,
        auth=Authentication.RSA,
        handshake_sigs=(),
    )

    TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 = _Cipher(
        id=0x006B,
        name="TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
        minimum_version=TLSVersion.TLSv1_2,
        maximum_version=TLSVersion.TLSv1_2,
        strength_bits=256,
        alg_bits=256,
        aead=False,
        symmetric=Symmetric.AES_256_CBC,
        digest=HashAlgorithm.SHA256,
        prf_hash=HashAlgorithm.SHA256,
        kea=KeyExchange.DHE,
        auth=Authentication.RSA,
        handshake_sigs=(),
    )

    TLS_DHE_RSA_WITH_AES_128_CCM = _Cipher(
        id=0xC09E,
        name="TLS_DHE_RSA_WITH_AES_128_CCM",
        minimum_version=TLSVersion.TLSv1_2,
        maximum_version=TLSVersion.TLSv1_2,
        strength_bits=128,
        alg_bits=128,
        aead=True,
        symmetric=Symmetric.AES_128_CCM,
        digest=None,
        prf_hash=HashAlgorithm.SHA256,
        kea=KeyExchange.DHE,
        auth=Authentication.RSA,
        handshake_sigs=(),
    )

    TLS_DHE_RSA_WITH_AES_256_CCM = _Cipher(
        id=0xC09F,
        name="TLS_DHE_RSA_WITH_AES_256_CCM",
        minimum_version=TLSVersion.TLSv1_2,
        maximum_version=TLSVersion.TLSv1_2,
        strength_bits=256,
        alg_bits=256,
        aead=True,
        symmetric=Symmetric.AES_256_CCM,
        digest=None,
        prf_hash=HashAlgorithm.SHA256,
        kea=KeyExchange.DHE,
        auth=Authentication.RSA,
        handshake_sigs=(),
    )

    TLS_DHE_RSA_WITH_AES_128_CCM_8 = _Cipher(
        id=0xC0A2,
        name="TLS_DHE_RSA_WITH_AES_128_CCM_8",
        minimum_version=TLSVersion.TLSv1_2,
        maximum_version=TLSVersion.TLSv1_2,
        strength_bits=128,
        alg_bits=128,
        aead=True,
        symmetric=Symmetric.AES_128_CCM_8,
        digest=None,
        prf_hash=HashAlgorithm.SHA256,
        kea=KeyExchange.DHE,
        auth=Authentication.RSA,
        handshake_sigs=(),
    )

    TLS_DHE_RSA_WITH_AES_256_CCM_8 = _Cipher(
        id=0xC0A3,
        name="TLS_DHE_RSA_WITH_AES_256_CCM_8",
        minimum_version=TLSVersion.TLSv1_2,
        maximum_version=TLSVersion.TLSv1_2,
        strength_bits=256,
        alg_bits=256,
        aead=True,
        symmetric=Symmetric.AES_256_CCM_8,
        digest=None,
        prf_hash=HashAlgorithm.SHA256,
        kea=KeyExchange.DHE,
        auth=Authentication.RSA,
        handshake_sigs=(),
    )

    TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 = _Cipher(
        id=0x009E,
        name="TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
        minimum_version=TLSVersion.TLSv1_2,
        maximum_version=TLSVersion.TLSv1_2,
        strength_bits=128,
        alg_bits=128,
        aead=True,
        symmetric=Symmetric.AES_128_GCM,
        digest=None,
        prf_hash=HashAlgorithm.SHA256,
        kea=KeyExchange.DHE,
        auth=Authentication.RSA,
        handshake_sigs=(),
    )

    TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 = _Cipher(
        id=0x009F,
        name="TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
        minimum_version=TLSVersion.TLSv1_2,
        maximum_version=TLSVersion.TLSv1_2,
        strength_bits=256,
        alg_bits=256,
        aead=True,
        symmetric=Symmetric.AES_256_GCM,
        digest=None,
        prf_hash=HashAlgorithm.SHA384,
        kea=KeyExchange.DHE,
        auth=Authentication.RSA,
        handshake_sigs=(),
    )

    TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = _Cipher(
        id=0xCCAA,
        name="TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        minimum_version=TLSVersion.TLSv1_2,
        maximum_version=TLSVersion.TLSv1_2,
        strength_bits=256,
        alg_bits=256,
        aead=True,
        symmetric=Symmetric.CHACHA20_POLY1305,
        digest=None,
        prf_hash=HashAlgorithm.SHA256,
        kea=KeyExchange.DHE,
        auth=Authentication.RSA,
        handshake_sigs=(),
    )

    TLS_DHE_RSA_WITH_CHACHA20_POLY1305_draft_00 = _Cipher(
        id=0xCCA3,
        name="TLS_DHE_RSA_WITH_CHACHA20_POLY1305_draft_00",
        minimum_version=TLSVersion.TLSv1_2,
        maximum_version=TLSVersion.TLSv1_2,
        strength_bits=256,
        alg_bits=256,
        aead=True,
        symmetric=Symmetric.CHACHA20_DRAFT_00,
        digest=None,
        prf_hash=HashAlgorithm.SHA256,
        kea=KeyExchange.DHE,
        auth=Authentication.RSA,
        handshake_sigs=(),
    )

    TLS_ECDHE_RSA_WITH_NULL_SHA = _Cipher(
        id=0xC010,
        name="TLS_ECDHE_RSA_WITH_NULL_SHA",
        minimum_version=TLSVersion.TLSv1,
        maximum_version=TLSVersion.TLSv1_2,
        strength_bits=0,
        alg_bits=0,
        aead=False,
        symmetric=Symmetric.NULL,
        digest=HashAlgorithm.SHA1,
        prf_hash=HashAlgorithm.SHA256,
        kea=KeyExchange.ECDHE,
        auth=Authentication.RSA,
        handshake_sigs=(),
    )

    TLS_ECDHE_RSA_WITH_RC4_128_SHA = _Cipher(
        id=0xC011,
        name="TLS_ECDHE_RSA_WITH_RC4_128_SHA",
        minimum_version=TLSVersion.TLSv1,
        maximum_version=TLSVersion.TLSv1_2,
        strength_bits=128,
        alg_bits=128,
        aead=False,
        symmetric=Symmetric.RC4_128,
        digest=HashAlgorithm.SHA1,
        prf_hash=HashAlgorithm.SHA256,
        kea=KeyExchange.ECDHE,
        auth=Authentication.RSA,
        handshake_sigs=(),
    )

    TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA = _Cipher(
        id=0xC012,
        name="TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
        minimum_version=TLSVersion.TLSv1,
        maximum_version=TLSVersion.TLSv1_2,
        strength_bits=112,
        alg_bits=168,
        aead=False,
        symmetric=Symmetric.TRIPLE_DES_EDE_CBC,
        digest=HashAlgorithm.SHA1,
        prf_hash=HashAlgorithm.SHA256,
        kea=KeyExchange.ECDHE,
        auth=Authentication.RSA,
        handshake_sigs=(),
    )

    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA = _Cipher(
        id=0xC013,
        name="TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
        minimum_version=TLSVersion.TLSv1,
        maximum_version=TLSVersion.TLSv1_2,
        strength_bits=128,
        alg_bits=128,
        aead=False,
        symmetric=Symmetric.AES_128_CBC,
        digest=HashAlgorithm.SHA1,
        prf_hash=HashAlgorithm.SHA256,
        kea=KeyExchange.ECDHE,
        auth=Authentication.RSA,
        handshake_sigs=(),
    )

    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA = _Cipher(
        id=0xC014,
        name="TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
        minimum_version=TLSVersion.TLSv1,
        maximum_version=TLSVersion.TLSv1_2,
        strength_bits=256,
        alg_bits=256,
        aead=False,
        symmetric=Symmetric.AES_256_CBC,
        digest=HashAlgorithm.SHA1,
        prf_hash=HashAlgorithm.SHA256,
        kea=KeyExchange.ECDHE,
        auth=Authentication.RSA,
        handshake_sigs=(),
    )

    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 = _Cipher(
        id=0xC027,
        name="TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
        minimum_version=TLSVersion.TLSv1_2,
        maximum_version=TLSVersion.TLSv1_2,
        strength_bits=128,
        alg_bits=128,
        aead=False,
        symmetric=Symmetric.AES_128_CBC,
        digest=HashAlgorithm.SHA256,
        prf_hash=HashAlgorithm.SHA256,
        kea=KeyExchange.ECDHE,
        auth=Authentication.RSA,
        handshake_sigs=(),
    )

    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 = _Cipher(
        id=0xC028,
        name="TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
        minimum_version=TLSVersion.TLSv1_2,
        maximum_version=TLSVersion.TLSv1_2,
        strength_bits=256,
        alg_bits=256,
        aead=False,
        symmetric=Symmetric.AES_256_CBC,
        digest=HashAlgorithm.SHA384,
        prf_hash=HashAlgorithm.SHA384,
        kea=KeyExchange.ECDHE,
        auth=Authentication.RSA,
        handshake_sigs=(),
    )

    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = _Cipher(
        id=0xC02F,
        name="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        minimum_version=TLSVersion.TLSv1_2,
        maximum_version=TLSVersion.TLSv1_2,
        strength_bits=128,
        alg_bits=128,
        aead=True,
        symmetric=Symmetric.AES_128_GCM,
        digest=None,
        prf_hash=HashAlgorithm.SHA256,
        kea=KeyExchange.ECDHE,
        auth=Authentication.RSA,
        handshake_sigs=(),
    )

    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = _Cipher(
        id=0xC030,
        name="TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        minimum_version=TLSVersion.TLSv1_2,
        maximum_version=TLSVersion.TLSv1_2,
        strength_bits=256,
        alg_bits=256,
        aead=True,
        symmetric=Symmetric.AES_256_GCM,
        digest=None,
        prf_hash=HashAlgorithm.SHA384,
        kea=KeyExchange.ECDHE,
        auth=Authentication.RSA,
        handshake_sigs=(),
    )

    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_draft_00 = _Cipher(
        id=0xCCA1,
        name="TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_draft_00",
        minimum_version=TLSVersion.TLSv1_2,
        maximum_version=TLSVersion.TLSv1_2,
        strength_bits=256,
        alg_bits=256,
        aead=True,
        symmetric=Symmetric.CHACHA20_DRAFT_00,
        digest=None,
        prf_hash=HashAlgorithm.SHA256,
        kea=KeyExchange.ECDHE,
        auth=Authentication.RSA,
        handshake_sigs=(),
    )

    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = _Cipher(
        id=0xCCA8,
        name="TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        minimum_version=TLSVersion.TLSv1_2,
        maximum_version=TLSVersion.TLSv1_2,
        strength_bits=256,
        alg_bits=256,
        aead=True,
        symmetric=Symmetric.CHACHA20_POLY1305,
        digest=None,
        prf_hash=HashAlgorithm.SHA256,
        kea=KeyExchange.ECDHE,
        auth=Authentication.RSA,
        handshake_sigs=(),
    )

    TLS_ECDHE_ECDSA_WITH_NULL_SHA = _Cipher(
        id=0xC006,
        name="TLS_ECDHE_ECDSA_WITH_NULL_SHA",
        minimum_version=TLSVersion.TLSv1,
        maximum_version=TLSVersion.TLSv1_2,
        strength_bits=0,
        alg_bits=0,
        aead=False,
        symmetric=Symmetric.NULL,
        digest=HashAlgorithm.SHA1,
        prf_hash=HashAlgorithm.SHA256,
        kea=KeyExchange.ECDHE,
        auth=Authentication.ECDSA,
        handshake_sigs=(),
    )

    TLS_ECDHE_ECDSA_WITH_RC4_128_SHA = _Cipher(
        id=0xC007,
        name="TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
        minimum_version=TLSVersion.TLSv1,
        maximum_version=TLSVersion.TLSv1_2,
        strength_bits=128,
        alg_bits=128,
        aead=False,
        symmetric=Symmetric.RC4_128,
        digest=HashAlgorithm.SHA1,
        prf_hash=HashAlgorithm.SHA256,
        kea=KeyExchange.ECDHE,
        auth=Authentication.ECDSA,
        handshake_sigs=(),
    )

    TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA = _Cipher(
        id=0xC008,
        name="TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
        minimum_version=TLSVersion.TLSv1,
        maximum_version=TLSVersion.TLSv1_2,
        strength_bits=112,
        alg_bits=168,
        aead=False,
        symmetric=Symmetric.TRIPLE_DES_EDE_CBC,
        digest=HashAlgorithm.SHA1,
        prf_hash=HashAlgorithm.SHA256,
        kea=KeyExchange.ECDHE,
        auth=Authentication.ECDSA,
        handshake_sigs=(),
    )

    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA = _Cipher(
        id=0xC009,
        name="TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
        minimum_version=TLSVersion.TLSv1,
        maximum_version=TLSVersion.TLSv1_2,
        strength_bits=128,
        alg_bits=128,
        aead=False,
        symmetric=Symmetric.AES_128_CBC,
        digest=HashAlgorithm.SHA1,
        prf_hash=HashAlgorithm.SHA256,
        kea=KeyExchange.ECDHE,
        auth=Authentication.ECDSA,
        handshake_sigs=(),
    )

    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA = _Cipher(
        id=0xC00A,
        name="TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
        minimum_version=TLSVersion.TLSv1,
        maximum_version=TLSVersion.TLSv1_2,
        strength_bits=256,
        alg_bits=256,
        aead=False,
        symmetric=Symmetric.AES_256_CBC,
        digest=HashAlgorithm.SHA1,
        prf_hash=HashAlgorithm.SHA256,
        kea=KeyExchange.ECDHE,
        auth=Authentication.ECDSA,
        handshake_sigs=(),
    )

    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 = _Cipher(
        id=0xC023,
        name="TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
        minimum_version=TLSVersion.TLSv1_2,
        maximum_version=TLSVersion.TLSv1_2,
        strength_bits=128,
        alg_bits=128,
        aead=False,
        symmetric=Symmetric.AES_128_CBC,
        digest=HashAlgorithm.SHA256,
        prf_hash=HashAlgorithm.SHA256,
        kea=KeyExchange.ECDHE,
        auth=Authentication.ECDSA,
        handshake_sigs=(),
    )

    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 = _Cipher(
        id=0xC024,
        name="TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
        minimum_version=TLSVersion.TLSv1_2,
        maximum_version=TLSVersion.TLSv1_2,
        strength_bits=256,
        alg_bits=256,
        aead=False,
        symmetric=Symmetric.AES_256_CBC,
        digest=HashAlgorithm.SHA384,
        prf_hash=HashAlgorithm.SHA384,
        kea=KeyExchange.ECDHE,
        auth=Authentication.ECDSA,
        handshake_sigs=(),
    )

    TLS_ECDHE_ECDSA_WITH_AES_128_CCM = _Cipher(
        id=0xC0AC,
        name="TLS_ECDHE_ECDSA_WITH_AES_128_CCM",
        minimum_version=TLSVersion.TLSv1_2,
        maximum_version=TLSVersion.TLSv1_2,
        strength_bits=128,
        alg_bits=128,
        aead=True,
        symmetric=Symmetric.AES_128_CCM,
        digest=None,
        prf_hash=HashAlgorithm.SHA256,
        kea=KeyExchange.ECDHE,
        auth=Authentication.ECDSA,
        handshake_sigs=(),
    )

    TLS_ECDHE_ECDSA_WITH_AES_256_CCM = _Cipher(
        id=0xC0AD,
        name="TLS_ECDHE_ECDSA_WITH_AES_256_CCM",
        minimum_version=TLSVersion.TLSv1_2,
        maximum_version=TLSVersion.TLSv1_2,
        strength_bits=256,
        alg_bits=256,
        aead=True,
        symmetric=Symmetric.AES_256_CCM,
        digest=None,
        prf_hash=HashAlgorithm.SHA256,
        kea=KeyExchange.ECDHE,
        auth=Authentication.ECDSA,
        handshake_sigs=(),
    )

    TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 = _Cipher(
        id=0xC0AE,
        name="TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8",
        minimum_version=TLSVersion.TLSv1_2,
        maximum_version=TLSVersion.TLSv1_2,
        strength_bits=128,
        alg_bits=128,
        aead=True,
        symmetric=Symmetric.AES_128_CCM_8,
        digest=None,
        prf_hash=HashAlgorithm.SHA256,
        kea=KeyExchange.ECDHE,
        auth=Authentication.ECDSA,
        handshake_sigs=(),
    )

    TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8 = _Cipher(
        id=0xC0AF,
        name="TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8",
        minimum_version=TLSVersion.TLSv1_2,
        maximum_version=TLSVersion.TLSv1_2,
        strength_bits=256,
        alg_bits=256,
        aead=True,
        symmetric=Symmetric.AES_256_CCM_8,
        digest=None,
        prf_hash=HashAlgorithm.SHA256,
        kea=KeyExchange.ECDHE,
        auth=Authentication.ECDSA,
        handshake_sigs=(),
    )

    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = _Cipher(
        id=0xC02B,
        name="TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        minimum_version=TLSVersion.TLSv1_2,
        maximum_version=TLSVersion.TLSv1_2,
        strength_bits=128,
        alg_bits=128,
        aead=True,
        symmetric=Symmetric.AES_128_GCM,
        digest=None,
        prf_hash=HashAlgorithm.SHA256,
        kea=KeyExchange.ECDHE,
        auth=Authentication.ECDSA,
        handshake_sigs=(),
    )

    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 = _Cipher(
        id=0xC02C,
        name="TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        minimum_version=TLSVersion.TLSv1_2,
        maximum_version=TLSVersion.TLSv1_2,
        strength_bits=256,
        alg_bits=256,
        aead=True,
        symmetric=Symmetric.AES_256_GCM,
        digest=None,
        prf_hash=HashAlgorithm.SHA384,
        kea=KeyExchange.ECDHE,
        auth=Authentication.ECDSA,
        handshake_sigs=(),
    )

    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_draft_00 = _Cipher(
        id=0xCCA2,
        name="TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_draft_00",
        minimum_version=TLSVersion.TLSv1_2,
        maximum_version=TLSVersion.TLSv1_2,
        strength_bits=256,
        alg_bits=256,
        aead=True,
        symmetric=Symmetric.CHACHA20_DRAFT_00,
        digest=None,
        prf_hash=HashAlgorithm.SHA256,
        kea=KeyExchange.ECDHE,
        auth=Authentication.ECDSA,
        handshake_sigs=(),
    )

    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 = _Cipher(
        id=0xCCA9,
        name="TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
        minimum_version=TLSVersion.TLSv1_2,
        maximum_version=TLSVersion.TLSv1_2,
        strength_bits=256,
        alg_bits=256,
        aead=True,
        symmetric=Symmetric.CHACHA20_POLY1305,
        digest=None,
        prf_hash=HashAlgorithm.SHA256,
        kea=KeyExchange.ECDHE,
        auth=Authentication.ECDSA,
        handshake_sigs=(),
    )

    TLS_FALLBACK_SCSV = _Cipher(
        id=0x5600,
        name="TLS_FALLBACK_SCSV",
        minimum_version=TLSVersion.TLSv1,
        maximum_version=TLSVersion.TLSv1_2,
        strength_bits=0,
        alg_bits=0,
        aead=False,
        symmetric=Symmetric.NULL,
        digest=None,
        prf_hash=HashAlgorithm.SHA256,
        kea=KeyExchange.NONE,
        auth=Authentication.NONE,
        handshake_sigs=(),
    )

    TLS_EMPTY_RENEGOTIATION_INFO_SCSV = _Cipher(
        id=0x00FF,
        name="TLS_EMPTY_RENEGOTIATION_INFO_SCSV",
        minimum_version=TLSVersion.TLSv1,
        maximum_version=TLSVersion.TLSv1_2,
        strength_bits=128,
        alg_bits=128,
        aead=False,
        symmetric=Symmetric.NULL,
        digest=None,
        prf_hash=HashAlgorithm.SHA256,
        kea=KeyExchange.NONE,
        auth=Authentication.NONE,
        handshake_sigs=(),
    )

    TLS_AES_128_GCM_SHA256 = _Cipher(
        id=0x1301,
        name="TLS_AES_128_GCM_SHA256",
        minimum_version=TLSVersion.TLSv1_3,
        maximum_version=TLSVersion.TLSv1_3,
        strength_bits=128,
        alg_bits=128,
        aead=True,
        symmetric=Symmetric.AES_128_GCM,
        digest=None,
        prf_hash=HashAlgorithm.SHA256,
        kea=KeyExchange.NONE,
        auth=Authentication.NONE,
        handshake_sigs=(),
    )

    TLS_AES_256_GCM_SHA384 = _Cipher(
        id=0x1302,
        name="TLS_AES_256_GCM_SHA384",
        minimum_version=TLSVersion.TLSv1_3,
        maximum_version=TLSVersion.TLSv1_3,
        strength_bits=256,
        alg_bits=256,
        aead=True,
        symmetric=Symmetric.AES_256_GCM,
        digest=None,
        prf_hash=HashAlgorithm.SHA384,
        kea=KeyExchange.NONE,
        auth=Authentication.NONE,
        handshake_sigs=(),
    )

    TLS_CHACHA20_POLY1305_SHA256 = _Cipher(
        id=0x1303,
        name="TLS_CHACHA20_POLY1305_SHA256",
        minimum_version=TLSVersion.TLSv1_3,
        maximum_version=TLSVersion.TLSv1_3,
        strength_bits=256,
        alg_bits=256,
        aead=True,
        symmetric=Symmetric.CHACHA20_POLY1305,
        digest=None,
        prf_hash=HashAlgorithm.SHA256,
        kea=KeyExchange.NONE,
        auth=Authentication.NONE,
        handshake_sigs=(),
    )

    TLS_AES_128_CCM_SHA256 = _Cipher(
        id=0x1304,
        name="TLS_AES_128_CCM_SHA256",
        minimum_version=TLSVersion.TLSv1_3,
        maximum_version=TLSVersion.TLSv1_3,
        strength_bits=128,
        alg_bits=128,
        aead=True,
        symmetric=Symmetric.AES_128_CCM,
        digest=None,
        prf_hash=HashAlgorithm.SHA256,
        kea=KeyExchange.NONE,
        auth=Authentication.NONE,
        handshake_sigs=(),
    )

    TLS_AES_128_CCM_8_SHA256 = _Cipher(
        id=0x1305,
        name="TLS_AES_128_CCM_8_SHA256",
        minimum_version=TLSVersion.TLSv1_3,
        maximum_version=TLSVersion.TLSv1_3,
        strength_bits=128,
        alg_bits=128,
        aead=True,
        symmetric=Symmetric.AES_128_CCM_8,
        digest=None,
        prf_hash=HashAlgorithm.SHA256,
        kea=KeyExchange.NONE,
        auth=Authentication.NONE,
        handshake_sigs=(),
    )


class ECHClientHelloType(int, TLSEnum):
    OUTER = 0
    INNER = 1


class HpkeKdfId(int, TLSEnum):
    HKDF_SHA256 = 0x0001
    HKDF_SHA384 = 0x0002
    HKDF_SHA512 = 0x0003


class HpkeAeadId(int, TLSEnum):
    AES_128_GCM = 0x0001
    AES_256_GCM = 0x0002
    CHACHA20_POLY1305 = 0x0003


class HpkeKemId(int, TLSEnum):
    DHKEM_P256_HKDF_SHA256 = 0x0010
    DHKEM_P384_HKDF_SHA384 = 0x0011
    DHKEM_P512_HKDF_SHA512 = 0x0012
    DHKEM_X25519_HKDF_SHA256 = 0x0020


# ruff: enable[E501]
