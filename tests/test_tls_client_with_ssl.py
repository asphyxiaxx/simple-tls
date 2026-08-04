import ssl
import warnings

import pytest

from simple_tls import tls

from .utils import (
    SERVER_DSA_CERTFILE,
    SERVER_DSA_KEYFILE,
    SERVER_EC_SECP256R1_CERTFILE,
    SERVER_EC_SECP256R1_KEYFILE,
    SERVER_RSA_CERTFILE,
    SERVER_RSA_KEYFILE,
    format_path,
)


class VirtualTLSServer:
    """A reusable, socket-free Python TLS server for testing clients."""

    def __init__(self, context):
        self.in_bio = ssl.MemoryBIO()
        self.out_bio = ssl.MemoryBIO()
        self.tls = context.wrap_bio(
            self.in_bio,
            self.out_bio,
            server_side=True,
        )
        self.handshake_complete = False

    def process(self, data=b""):
        """
        Feeds raw bytes from your custom client into the Python server,
        cranks the TLS state machine, and returns the server's raw response.
        """
        if data:
            self.in_bio.write(data)

        # Try to advance the handshake
        if not self.handshake_complete:
            try:
                self.tls.do_handshake()
                self.handshake_complete = True
            except ssl.SSLWantReadError:
                pass

        return self.out_bio.read()

    def read_decrypted(self):
        """Reads application data that the client sent after the handshake."""
        try:
            return self.tls.read()
        except ssl.SSLWantReadError:
            return b""

    def write_encrypted(self, plaintext):
        """Encrypts a message from the server to send to the client."""
        self.tls.write(plaintext)
        return self.out_bio.read()


def create_ssl_context(certfile, keyfile):
    warnings.filterwarnings("ignore", category=DeprecationWarning)

    certfile = format_path("certs", certfile)
    keyfile = format_path("certs", keyfile)

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    ctx.set_ciphers("ALL:aNULL:eNULL:@SECLEVEL=0")
    ctx.load_cert_chain(certfile=certfile, keyfile=keyfile)

    return ctx


@pytest.fixture
def rsa_server():
    ctx = create_ssl_context(SERVER_RSA_CERTFILE, SERVER_RSA_KEYFILE)
    return VirtualTLSServer(ctx)


@pytest.fixture
def dsa_server():
    ctx = create_ssl_context(SERVER_DSA_CERTFILE, SERVER_DSA_KEYFILE)
    return VirtualTLSServer(ctx)


@pytest.fixture
def ec_server():
    ctx = create_ssl_context(
        SERVER_EC_SECP256R1_CERTFILE, SERVER_EC_SECP256R1_KEYFILE
    )
    return VirtualTLSServer(ctx)


def do_handshake(conn, virtual_server):
    for _ in range(20):
        try:
            conn.do_handshake()
            break
        except tls.TLSWantReadError:
            data_to_send = conn.bio_read(2**14)
            data_recieved = virtual_server.process(data_to_send)
            conn.bio_write(data_recieved)
    else:
        pytest.fail("Handshake loop got stuck")

    try:
        data_to_send = conn.bio_read(2**14)
    except tls.TLSWantReadError:
        pass
    else:
        data_recieved = virtual_server.process(data_to_send)
        conn.bio_write(data_recieved)

    assert conn.handshake_complete()
    assert virtual_server.handshake_complete


@pytest.mark.parametrize(
    "cipher_suite",
    (
        tls.CipherSuite.TLS_AES_128_CCM_SHA256,
        tls.CipherSuite.TLS_AES_128_CCM_8_SHA256,
        tls.CipherSuite.TLS_AES_128_GCM_SHA256,
        tls.CipherSuite.TLS_AES_256_GCM_SHA384,
        tls.CipherSuite.TLS_CHACHA20_POLY1305_SHA256,
    ),
)
def test_tls13_handshake(cipher_suite, rsa_server):
    context = tls.TLSContext()
    context.minimum_version = tls.TLSVersion.TLSv1_3
    context.maximum_version = tls.TLSVersion.TLSv1_3
    context.cipher_suites = [cipher_suite]
    conn = tls.TLSConnection(context)

    try:
        do_handshake(conn, rsa_server)
    except ssl.SSLError as e:
        no_shared_cipher_str = "[SSL: NO_SHARED_CIPHER] no shared cipher"
        if e.errno == 1 and no_shared_cipher_str in e.args[-1]:
            pytest.skip("Skipping no shared cipher")
        else:
            raise
    else:
        assert rsa_server.tls.version() == "TLSv1.3"
        assert conn.version() == "TLSv1.3"


@pytest.mark.parametrize(
    "cipher_suite",
    (
        tls.CipherSuite.TLS_RSA_WITH_NULL_MD5,
        tls.CipherSuite.TLS_RSA_WITH_NULL_SHA,
        tls.CipherSuite.TLS_RSA_WITH_NULL_SHA256,
        tls.CipherSuite.TLS_RSA_WITH_RC4_128_MD5,
        tls.CipherSuite.TLS_RSA_WITH_RC4_128_SHA,
        tls.CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
        tls.CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
        tls.CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA,
        tls.CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256,
        tls.CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256,
        tls.CipherSuite.TLS_RSA_WITH_AES_128_CCM,
        tls.CipherSuite.TLS_RSA_WITH_AES_256_CCM,
        tls.CipherSuite.TLS_RSA_WITH_AES_128_CCM_8,
        tls.CipherSuite.TLS_RSA_WITH_AES_256_CCM_8,
        tls.CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256,
        tls.CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384,
        tls.CipherSuite.TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA,
        tls.CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
        tls.CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
        tls.CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
        tls.CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
        tls.CipherSuite.TLS_DHE_RSA_WITH_AES_128_CCM,
        tls.CipherSuite.TLS_DHE_RSA_WITH_AES_256_CCM,
        tls.CipherSuite.TLS_DHE_RSA_WITH_AES_128_CCM_8,
        tls.CipherSuite.TLS_DHE_RSA_WITH_AES_256_CCM_8,
        tls.CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
        tls.CipherSuite.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
        tls.CipherSuite.TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        tls.CipherSuite.TLS_DHE_RSA_WITH_CHACHA20_POLY1305_draft_00,
        tls.CipherSuite.TLS_ECDHE_RSA_WITH_NULL_SHA,
        tls.CipherSuite.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
        tls.CipherSuite.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
        tls.CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
        tls.CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
        tls.CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
        tls.CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
        tls.CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        tls.CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        tls.CipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_draft_00,
        tls.CipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    ),
)
def test_tls12_rsa_handshake(cipher_suite, rsa_server):
    context = tls.TLSContext()
    context.cipher_suites = [cipher_suite]
    context.minimum_version = tls.TLSVersion.TLSv1_2
    context.maximum_version = tls.TLSVersion.TLSv1_2
    conn = tls.TLSConnection(context)

    try:
        do_handshake(conn, rsa_server)
    except ssl.SSLError as e:
        no_shared_cipher_str = "[SSL: NO_SHARED_CIPHER] no shared cipher"
        if e.errno == 1 and no_shared_cipher_str in e.args[-1]:
            pytest.skip("Skipping no shared cipher")
        else:
            raise
    else:
        assert rsa_server.tls.version() == "TLSv1.2"
        assert conn.version() == "TLSv1.2"


@pytest.mark.parametrize(
    "cipher_suite",
    (
        tls.CipherSuite.TLS_ECDHE_ECDSA_WITH_NULL_SHA,
        tls.CipherSuite.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
        tls.CipherSuite.TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,
        tls.CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
        tls.CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
        tls.CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
        tls.CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
        tls.CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM,
        tls.CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CCM,
        tls.CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8,
        tls.CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8,
        tls.CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        tls.CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        tls.CipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_draft_00,
        tls.CipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    ),
)
def test_tls12_ecdsa_handshake(cipher_suite, ec_server):
    context = tls.TLSContext()
    context.cipher_suites = [cipher_suite]
    context.minimum_version = tls.TLSVersion.TLSv1_2
    context.maximum_version = tls.TLSVersion.TLSv1_2
    conn = tls.TLSConnection(context)

    try:
        do_handshake(conn, ec_server)
    except ssl.SSLError as e:
        no_shared_cipher_str = "[SSL: NO_SHARED_CIPHER] no shared cipher"
        if e.errno == 1 and no_shared_cipher_str in e.args[-1]:
            pytest.skip("Skipping no shared cipher")
        else:
            raise
    else:
        assert ec_server.tls.version() == "TLSv1.2"
        assert conn.version() == "TLSv1.2"


@pytest.mark.parametrize(
    "cipher_suite",
    (
        tls.CipherSuite.TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA,
        tls.CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA,
        tls.CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA,
        tls.CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA256,
        tls.CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA256,
        tls.CipherSuite.TLS_DHE_DSS_WITH_AES_128_GCM_SHA256,
        tls.CipherSuite.TLS_DHE_DSS_WITH_AES_256_GCM_SHA384,
    ),
)
def test_tls12_dss_handshake(cipher_suite, dsa_server):
    context = tls.TLSContext()
    context.cipher_suites = [cipher_suite]
    context.minimum_version = tls.TLSVersion.TLSv1_2
    context.maximum_version = tls.TLSVersion.TLSv1_2
    conn = tls.TLSConnection(context)

    try:
        do_handshake(conn, dsa_server)
    except ssl.SSLError as e:
        no_shared_cipher_str = "[SSL: NO_SHARED_CIPHER] no shared cipher"
        if e.errno == 1 and no_shared_cipher_str in e.args[-1]:
            pytest.skip("Skipping no shared cipher")
        else:
            raise
    else:
        assert dsa_server.tls.version() == "TLSv1.2"
        assert conn.version() == "TLSv1.2"


@pytest.mark.parametrize(
    "cipher_suite",
    (
        tls.CipherSuite.TLS_RSA_WITH_NULL_MD5,
        tls.CipherSuite.TLS_RSA_WITH_NULL_SHA,
        tls.CipherSuite.TLS_RSA_WITH_RC4_128_MD5,
        tls.CipherSuite.TLS_RSA_WITH_RC4_128_SHA,
        tls.CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
        tls.CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
        tls.CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA,
        tls.CipherSuite.TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA,
        tls.CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
        tls.CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
        tls.CipherSuite.TLS_ECDHE_RSA_WITH_NULL_SHA,
        tls.CipherSuite.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
        tls.CipherSuite.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
        tls.CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
        tls.CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
    ),
)
def test_tls11_rsa_handshake(cipher_suite, rsa_server):
    context = tls.TLSContext()
    context.cipher_suites = [cipher_suite]
    context.minimum_version = tls.TLSVersion.TLSv1_1
    context.maximum_version = tls.TLSVersion.TLSv1_1
    conn = tls.TLSConnection(context)

    try:
        do_handshake(conn, rsa_server)
    except ssl.SSLError as e:
        no_shared_cipher_str = "[SSL: NO_SHARED_CIPHER] no shared cipher"
        if e.errno == 1 and no_shared_cipher_str in e.args[-1]:
            pytest.skip("Skipping no shared cipher")
        else:
            raise
    else:
        assert rsa_server.tls.version() == "TLSv1.1"
        assert conn.version() == "TLSv1.1"


@pytest.mark.parametrize(
    "cipher_suite",
    (
        tls.CipherSuite.TLS_ECDHE_ECDSA_WITH_NULL_SHA,
        tls.CipherSuite.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
        tls.CipherSuite.TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,
        tls.CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
        tls.CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
    ),
)
def test_tls11_ecdsa_handshake(cipher_suite, ec_server):
    context = tls.TLSContext()
    context.cipher_suites = [cipher_suite]
    context.minimum_version = tls.TLSVersion.TLSv1_1
    context.maximum_version = tls.TLSVersion.TLSv1_1
    conn = tls.TLSConnection(context)

    try:
        do_handshake(conn, ec_server)
    except ssl.SSLError as e:
        no_shared_cipher_str = "[SSL: NO_SHARED_CIPHER] no shared cipher"
        if e.errno == 1 and no_shared_cipher_str in e.args[-1]:
            pytest.skip("Skipping no shared cipher")
        else:
            raise
    else:
        assert ec_server.tls.version() == "TLSv1.1"
        assert conn.version() == "TLSv1.1"


@pytest.mark.parametrize(
    "cipher_suite",
    (
        tls.CipherSuite.TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA,
        tls.CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA,
        tls.CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA,
    ),
)
def test_tls11_dss_handshake(cipher_suite, dsa_server):
    context = tls.TLSContext()
    context.cipher_suites = [cipher_suite]
    context.minimum_version = tls.TLSVersion.TLSv1_1
    context.maximum_version = tls.TLSVersion.TLSv1_1
    conn = tls.TLSConnection(context)

    try:
        do_handshake(conn, dsa_server)
    except ssl.SSLError as e:
        no_shared_cipher_str = "[SSL: NO_SHARED_CIPHER] no shared cipher"
        if e.errno == 1 and no_shared_cipher_str in e.args[-1]:
            pytest.skip("Skipping no shared cipher")
        else:
            raise
    else:
        assert dsa_server.tls.version() == "TLSv1.1"
        assert conn.version() == "TLSv1.1"


@pytest.mark.parametrize(
    "cipher_suite",
    (
        tls.CipherSuite.TLS_RSA_WITH_NULL_MD5,
        tls.CipherSuite.TLS_RSA_WITH_NULL_SHA,
        tls.CipherSuite.TLS_RSA_WITH_RC4_128_MD5,
        tls.CipherSuite.TLS_RSA_WITH_RC4_128_SHA,
        tls.CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
        tls.CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
        tls.CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA,
        tls.CipherSuite.TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA,
        tls.CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
        tls.CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
        tls.CipherSuite.TLS_ECDHE_RSA_WITH_NULL_SHA,
        tls.CipherSuite.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
        tls.CipherSuite.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
        tls.CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
        tls.CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
    ),
)
def test_tls1_rsa_handshake(cipher_suite, rsa_server):
    context = tls.TLSContext()
    context.cipher_suites = [cipher_suite]
    context.minimum_version = tls.TLSVersion.TLSv1
    context.maximum_version = tls.TLSVersion.TLSv1
    conn = tls.TLSConnection(context)

    try:
        do_handshake(conn, rsa_server)
    except ssl.SSLError as e:
        no_shared_cipher_str = "[SSL: NO_SHARED_CIPHER] no shared cipher"
        if e.errno == 1 and no_shared_cipher_str in e.args[-1]:
            pytest.skip("Skipping no shared cipher")
        else:
            raise
    else:
        assert rsa_server.tls.version() == "TLSv1"
        assert conn.version() == "TLSv1"


@pytest.mark.parametrize(
    "cipher_suite",
    (
        tls.CipherSuite.TLS_ECDHE_ECDSA_WITH_NULL_SHA,
        tls.CipherSuite.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
        tls.CipherSuite.TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,
        tls.CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
        tls.CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
    ),
)
def test_tls1_ecdsa_handshake(cipher_suite, ec_server):
    context = tls.TLSContext()
    context.cipher_suites = [cipher_suite]
    context.minimum_version = tls.TLSVersion.TLSv1
    context.maximum_version = tls.TLSVersion.TLSv1
    conn = tls.TLSConnection(context)

    try:
        do_handshake(conn, ec_server)
    except ssl.SSLError as e:
        no_shared_cipher_str = "[SSL: NO_SHARED_CIPHER] no shared cipher"
        if e.errno == 1 and no_shared_cipher_str in e.args[-1]:
            pytest.skip("Skipping no shared cipher")
        else:
            raise
    else:
        assert ec_server.tls.version() == "TLSv1"
        assert conn.version() == "TLSv1"


@pytest.mark.parametrize(
    "cipher_suite",
    (
        tls.CipherSuite.TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA,
        tls.CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA,
        tls.CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA,
    ),
)
def test_tls1_dss_handshake(cipher_suite, dsa_server):
    context = tls.TLSContext()
    context.cipher_suites = [cipher_suite]
    context.minimum_version = tls.TLSVersion.TLSv1
    context.maximum_version = tls.TLSVersion.TLSv1
    conn = tls.TLSConnection(context)

    try:
        do_handshake(conn, dsa_server)
    except ssl.SSLError as e:
        no_shared_cipher_str = "[SSL: NO_SHARED_CIPHER] no shared cipher"
        if e.errno == 1 and no_shared_cipher_str in e.args[-1]:
            pytest.skip("Skipping no shared cipher")
        else:
            raise
    else:
        assert dsa_server.tls.version() == "TLSv1"
        assert conn.version() == "TLSv1"
