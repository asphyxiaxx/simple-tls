import functools
import os

import pytest

from simple_tls.crypto.verification import StoreBuilder
from simple_tls.tls.alerts import (
    AlertDecryptError,
    AlertHandshakeFailure,
    AlertNoApplicationProtocol,
    AlertProtocolVersion,
)
from simple_tls.tls.config import Credential, TLSConfiguration
from simple_tls.tls.constants import (
    CipherSuite,
    ClientCertificateType,
    KeyUpdateMessageType,
    NamedGroup,
    SignatureScheme,
    TLSVersion,
)
from simple_tls.tls.enums import (
    ClientState,
    Epoch,
    ServerState,
    Status,
    VerifyMode,
)
from simple_tls.tls.extensions import SignatureAlgorithmsExtension
from simple_tls.tls.handshake_client import TLSHandshakeClient
from simple_tls.tls.handshake_server import TLSHandshakeServer
from simple_tls.tls.keyexchange import load_pem_parameters
from simple_tls.tls.messages import (
    CertificateRequest,
    CertificateRequestTLS12,
    CertificateRequestTLS13,
)

from .utils import format_path

CAFILE = format_path("certs", "root_ca.crt")

SERVER_DH_PARAMETERS_FILE = format_path("certs", "dhparams.pem")

SERVER_RSA_CERTFILE = format_path("certs", "server_rsa.crt")
SERVER_RSA_KEYFILE = format_path("certs", "server_rsa.key")
SERVER_DSA_CERTFILE = format_path("certs", "server_dsa.crt")
SERVER_DSA_KEYFILE = format_path("certs", "server_dsa.key")
SERVER_EC_SECP256R1_CERTFILE = format_path("certs", "server_ec_secp256r1.crt")
SERVER_EC_SECP256R1_KEYFILE = format_path("certs", "server_ec_secp256r1.key")
SERVER_ED25519_CERTFILE = format_path("certs", "server_ed25519.crt")
SERVER_ED25519_KEYFILE = format_path("certs", "server_ed25519.key")
SERVER_ED448_CERTFILE = format_path("certs", "server_ed448.crt")
SERVER_ED448_KEYFILE = format_path("certs", "server_ed448.key")

CLIENT_RSA_CERTFILE = format_path("certs", "client_rsa.crt")
CLIENT_RSA_KEYFILE = format_path("certs", "client_rsa.key")
CLIENT_DSA_CERTFILE = format_path("certs", "client_dsa.crt")
CLIENT_DSA_KEYFILE = format_path("certs", "client_dsa.key")
CLIENT_EC_SECP256R1_CERTFILE = format_path("certs", "client_ec_secp256r1.crt")
CLIENT_EC_SECP256R1_KEYFILE = format_path("certs", "client_ec_secp256r1.key")
CLIENT_ED25519_CERTFILE = format_path("certs", "client_ed25519.crt")
CLIENT_ED25519_KEYFILE = format_path("certs", "client_ed25519.key")
CLIENT_ED448_CERTFILE = format_path("certs", "client_ed448.crt")
CLIENT_ED448_KEYFILE = format_path("certs", "client_ed448.key")


class SessionHandler:
    def __init__(self):
        self._sessions = []

    def __call__(self, session):
        self._sessions.append(session)

    def __iter__(self):
        return iter(self._sessions)

    def __len__(self):
        return len(self._sessions)

    def pop(self):
        return self._sessions.pop()


class TicketAEAD:
    def __init__(self):
        self._storage = {}

    def __len__(self):
        return len(self._storage)

    def seal(self, plaintext, context):
        ticket = os.urandom(32)
        self._storage[ticket] = plaintext
        return ticket

    def open(self, ticket, context):
        try:
            return self._storage[ticket]
        except KeyError:
            return None


suppress_cryptography_warning = pytest.mark.filterwarnings(
    "ignore::cryptography.utils.CryptographyDeprecationWarning"
)


@functools.lru_cache(maxsize=16)
def load_cafile(cafile=CAFILE):
    builder = StoreBuilder()
    builder.load_locations(cafile=cafile)
    return builder.build()


@functools.lru_cache(maxsize=16)
def load_dhparams_file(dhparams_file=SERVER_DH_PARAMETERS_FILE):
    with open(dhparams_file, "rb") as fp:
        dh_parameters = load_pem_parameters(fp.read())
    return dh_parameters


def create_server_config(**kwargs):
    kwargs.setdefault(
        "credential",
        Credential.from_certfile(SERVER_RSA_CERTFILE, SERVER_RSA_KEYFILE),
    )
    kwargs.setdefault("castore", load_cafile())

    return TLSConfiguration(is_server=True, **kwargs)


def create_client_config(**kwargs):
    kwargs.setdefault("server_hostname", b"localhost")
    kwargs.setdefault("verify_mode", VerifyMode.CERT_REQUIRED)
    kwargs.setdefault("check_hostname", True)
    kwargs.setdefault("castore", load_cafile())

    return TLSConfiguration(is_server=False, **kwargs)


def run_handshake(client, server, stop_condition=None):
    client_status = client.do_handshake()
    server_status = server.do_handshake()

    while not (client.done and server.done):
        if stop_condition and stop_condition(client, server):
            return

        progress_made = False

        #  Process client
        if not client.done:
            # If client wants to send data, grab it and feed it to the server
            if client_status in (Status.PACK_FLIGHT, Status.FLUSH_MESSAGE):
                flight = client.pending_flight()
                if flight:
                    server.feed_data(b"".join(flight))

                client.clear_flight()
                client_status = client.do_handshake()
                progress_made = True

            # If client is waiting to read, let it process its buffer
            elif client_status in (
                Status.READ_MESSAGE,
                Status.READ_CHANGE_CIPHER_SPEC,
                Status.READ_END_OF_EARLY_DATA,
                Status.WRITE_CHANGE_CIPHER_SPEC,
            ):
                new_status = client.do_handshake()
                # Check if it success read data
                if new_status != client_status:
                    client_status = new_status
                    progress_made = True

            elif client_status == Status.EARLY_RETURN:
                client_status = Status.OK
                progress_made = True

        # Process Server
        if not server.done:
            # If server wants to send data, grab it and feed it to the client
            if server_status in (Status.PACK_FLIGHT, Status.FLUSH_MESSAGE):
                flight = server.pending_flight()
                if flight:
                    client.feed_data(b"".join(flight))

                server.clear_flight()
                server_status = server.do_handshake()
                progress_made = True

            # If server is waiting to read, let it process its buffer
            elif server_status in (
                Status.READ_MESSAGE,
                Status.READ_CHANGE_CIPHER_SPEC,
                Status.READ_END_OF_EARLY_DATA,
                Status.WRITE_CHANGE_CIPHER_SPEC,
            ):
                new_status = server.do_handshake()
                # Check if it success read data
                if new_status != server_status:
                    server_status = new_status
                    progress_made = True

            elif server_status == Status.EARLY_RETURN:
                server_status = Status.OK
                progress_made = True

        # Prevent infinite loops
        # If neither the client nor the server made any progress in this
        # iteration, they are deadlocked (both waiting for data from each
        # other, or crashed).
        assert progress_made or (client.done and server.done)

    assert client.done, "Client did not finish handshake"
    assert server.done, "Server did not finish handshake"
    assert client_status == Status.OK
    assert server_status == Status.OK


def server_fail_hello(client, server):
    def stop_after_client_send_hello(c, s):
        return c.state == ClientState.ENTER_EARLY_DATA

    run_handshake(client, server, stop_after_client_send_hello)
    assert server.state == ServerState.READ_CLIENT_HELLO

    flight = client.pending_flight()
    server.feed_data(b"".join(flight))


def assert_tls1_secret(client, server):
    assert client.version <= TLSVersion.TLSv1_2
    assert server.version <= TLSVersion.TLSv1_2

    assert client.session is not None
    assert server.session is not None
    assert client.session.secret == server.session.secret

    assert client._write_traffic is not None
    assert client._read_traffic is not None
    assert server._write_traffic is not None
    assert server._read_traffic is not None

    assert (
        client.session.extended_master_secret
        == server.session.extended_master_secret
    )
    assert (
        client.session.secret
        == server.session.secret
        == client._write_traffic.secret
        == client._read_traffic.secret
        == server._write_traffic.secret
        == server._read_traffic.secret
    )
    assert (
        client.session.version
        == server.session.version
        == client._write_traffic.version
        == client._read_traffic.version
        == server._write_traffic.version
        == server._read_traffic.version
    )
    assert (
        client.session.cipher_suite
        == server.session.cipher_suite
        == client._write_traffic.cipher_suite
        == client._read_traffic.cipher_suite
        == server._write_traffic.cipher_suite
        == server._read_traffic.cipher_suite
    )
    assert (
        client._write_traffic.client_random
        == client._read_traffic.client_random
        == server._write_traffic.client_random
        == server._read_traffic.client_random
    )
    assert (
        client._write_traffic.server_random
        == client._read_traffic.server_random
        == server._write_traffic.server_random
        == server._read_traffic.server_random
    )
    assert (
        client._write_traffic.encrypt_then_mac
        == client._read_traffic.encrypt_then_mac
        == server._write_traffic.encrypt_then_mac
        == server._read_traffic.encrypt_then_mac
    )

    assert client._write_traffic.enc_key == server._read_traffic.enc_key
    assert client._write_traffic.mac_key == server._read_traffic.mac_key
    assert client._read_traffic.enc_key == server._write_traffic.enc_key
    assert client._read_traffic.mac_key == server._write_traffic.mac_key


def assert_tls13_secret(client, server, epoch):
    assert client._dec_secret[epoch] == server._enc_secret[epoch]
    assert client._enc_secret[epoch] == server._dec_secret[epoch]


@pytest.mark.parametrize(
    "version",
    (
        TLSVersion.TLSv1_3,
        TLSVersion.TLSv1_2,
        TLSVersion.TLSv1_1,
        TLSVersion.TLSv1,
    ),
)
def test_handshake(version):
    client = TLSHandshakeClient(
        configuration=create_client_config(
            minimum_version=version,
            maximum_version=version,
        )
    )
    server = TLSHandshakeServer(
        configuration=create_server_config(
            minimum_version=version,
            maximum_version=version,
        )
    )

    run_handshake(client, server)
    if version >= TLSVersion.TLSv1_3:
        assert_tls13_secret(client, server, Epoch.HANDSHAKE)
        assert_tls13_secret(client, server, Epoch.APPLICATION_DATA)
    else:
        assert_tls1_secret(client, server)

    assert client.version == version
    assert server.version == version


@pytest.mark.parametrize(
    "version",
    (
        TLSVersion.TLSv1_1,
        TLSVersion.TLSv1,
    ),
)
@pytest.mark.parametrize(
    "cipher_suite",
    (
        CipherSuite.TLS_RSA_WITH_NULL_MD5,
        CipherSuite.TLS_RSA_WITH_NULL_SHA,
        CipherSuite.TLS_RSA_WITH_RC4_128_MD5,
        CipherSuite.TLS_RSA_WITH_RC4_128_SHA,
        CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
        CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
        CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA,
    ),
)
def test_tls1_with_rsa_pkcs1(version, cipher_suite):
    client = TLSHandshakeClient(
        configuration=create_client_config(
            minimum_version=version,
            maximum_version=version,
            cipher_suites=[cipher_suite],
            signature_algorithms=[],
        )
    )
    server = TLSHandshakeServer(
        configuration=create_server_config(
            minimum_version=version,
            maximum_version=version,
            cipher_suites=[cipher_suite],
            signing_signature_algorithms=[],
            credential=Credential.from_certfile(
                SERVER_RSA_CERTFILE, SERVER_RSA_KEYFILE
            ),
        )
    )

    run_handshake(client, server)
    assert_tls1_secret(client, server)

    assert client.version == version
    assert server.version == version
    assert client.cipher_suite == cipher_suite
    assert server.cipher_suite == cipher_suite
    assert client.peer_certificate is not None


@pytest.mark.parametrize(
    "cipher_suite",
    (
        CipherSuite.TLS_RSA_WITH_NULL_MD5,
        CipherSuite.TLS_RSA_WITH_NULL_SHA,
        CipherSuite.TLS_RSA_WITH_RC4_128_MD5,
        CipherSuite.TLS_RSA_WITH_RC4_128_SHA,
        CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
        CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
        CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA,
        CipherSuite.TLS_RSA_WITH_NULL_SHA256,
        CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256,
        CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256,
        CipherSuite.TLS_RSA_WITH_AES_128_CCM,
        CipherSuite.TLS_RSA_WITH_AES_256_CCM,
        CipherSuite.TLS_RSA_WITH_AES_128_CCM_8,
        CipherSuite.TLS_RSA_WITH_AES_256_CCM_8,
        CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256,
        CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384,
    ),
)
@pytest.mark.parametrize(
    "signature_algorithm",
    (
        SignatureScheme.RSA_PKCS1_SHA512,
        SignatureScheme.RSA_PKCS1_SHA384,
        SignatureScheme.RSA_PKCS1_SHA256,
        SignatureScheme.RSA_PKCS1_SHA224,
        SignatureScheme.RSA_PKCS1_SHA1,
        SignatureScheme.RSA_PSS_RSAE_SHA512,
        SignatureScheme.RSA_PSS_RSAE_SHA384,
        SignatureScheme.RSA_PSS_RSAE_SHA256,
    ),
)
def test_tls12_with_rsa_pkcs1(cipher_suite, signature_algorithm):
    version = TLSVersion.TLSv1_2

    client = TLSHandshakeClient(
        configuration=create_client_config(
            minimum_version=version,
            maximum_version=version,
            cipher_suites=[cipher_suite],
            signature_algorithms=[signature_algorithm],
        )
    )
    server = TLSHandshakeServer(
        configuration=create_server_config(
            minimum_version=version,
            maximum_version=version,
            cipher_suites=[cipher_suite],
            signing_signature_algorithms=[signature_algorithm],
            credential=Credential.from_certfile(
                SERVER_RSA_CERTFILE, SERVER_RSA_KEYFILE
            ),
        )
    )

    run_handshake(client, server)
    assert_tls1_secret(client, server)

    assert client.version == version
    assert server.version == version
    assert client.cipher_suite == cipher_suite
    assert server.cipher_suite == cipher_suite
    assert client.peer_certificate is not None


@suppress_cryptography_warning
@pytest.mark.parametrize(
    "version",
    (
        TLSVersion.TLSv1_1,
        TLSVersion.TLSv1,
    ),
)
@pytest.mark.parametrize(
    "cipher_suite",
    (
        CipherSuite.TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA,
        CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA,
        CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA,
    ),
)
def test_tls1_with_dsa(version, cipher_suite):
    client = TLSHandshakeClient(
        configuration=create_client_config(
            minimum_version=version,
            maximum_version=version,
            cipher_suites=[cipher_suite],
            signature_algorithms=[],
        )
    )
    server = TLSHandshakeServer(
        configuration=create_server_config(
            minimum_version=version,
            maximum_version=version,
            cipher_suites=[cipher_suite],
            signing_signature_algorithms=[],
            dh_parameters=load_dhparams_file(),
            credential=Credential.from_certfile(
                SERVER_DSA_CERTFILE, SERVER_DSA_KEYFILE
            ),
        )
    )

    run_handshake(client, server)
    assert_tls1_secret(client, server)

    assert client.version == version
    assert server.version == version
    assert client.cipher_suite == cipher_suite
    assert server.cipher_suite == cipher_suite
    assert client.peer_certificate is not None


@suppress_cryptography_warning
@pytest.mark.parametrize(
    "cipher_suite",
    (
        CipherSuite.TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA,
        CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA,
        CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA,
        CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA256,
        CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA256,
        CipherSuite.TLS_DHE_DSS_WITH_AES_128_GCM_SHA256,
        CipherSuite.TLS_DHE_DSS_WITH_AES_256_GCM_SHA384,
    ),
)
@pytest.mark.parametrize(
    "signature_algorithm",
    (
        SignatureScheme.DSA_SHA512,
        SignatureScheme.DSA_SHA384,
        SignatureScheme.DSA_SHA256,
        SignatureScheme.DSA_SHA224,
        SignatureScheme.DSA_SHA1,
    ),
)
def test_tls12_with_dsa(cipher_suite, signature_algorithm):
    version = TLSVersion.TLSv1_2

    client = TLSHandshakeClient(
        configuration=create_client_config(
            minimum_version=version,
            maximum_version=version,
            cipher_suites=[cipher_suite],
            signature_algorithms=[signature_algorithm],
        )
    )
    server = TLSHandshakeServer(
        configuration=create_server_config(
            minimum_version=version,
            maximum_version=version,
            cipher_suites=[cipher_suite],
            signing_signature_algorithms=[signature_algorithm],
            dh_parameters=load_dhparams_file(),
            credential=Credential.from_certfile(
                SERVER_DSA_CERTFILE, SERVER_DSA_KEYFILE
            ),
        )
    )

    run_handshake(client, server)
    assert_tls1_secret(client, server)

    assert client.version == version
    assert server.version == version
    assert client.cipher_suite == cipher_suite
    assert server.cipher_suite == cipher_suite
    assert client.peer_certificate is not None


@pytest.mark.parametrize(
    "version",
    (
        TLSVersion.TLSv1_1,
        TLSVersion.TLSv1,
    ),
)
@pytest.mark.parametrize(
    "cipher_suite",
    (
        CipherSuite.TLS_ECDHE_ECDSA_WITH_NULL_SHA,
        CipherSuite.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
        CipherSuite.TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,
        CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
        CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
    ),
)
def test_tls1_with_ec_secp256r1(version, cipher_suite):
    client = TLSHandshakeClient(
        configuration=create_client_config(
            minimum_version=version,
            maximum_version=version,
            cipher_suites=[cipher_suite],
            signature_algorithms=[],
        )
    )
    server = TLSHandshakeServer(
        configuration=create_server_config(
            minimum_version=version,
            maximum_version=version,
            cipher_suites=[cipher_suite],
            signing_signature_algorithms=[],
            credential=Credential.from_certfile(
                SERVER_EC_SECP256R1_CERTFILE, SERVER_EC_SECP256R1_KEYFILE
            ),
        )
    )

    run_handshake(client, server)
    assert_tls1_secret(client, server)

    assert client.version == version
    assert server.version == version
    assert client.cipher_suite == cipher_suite
    assert server.cipher_suite == cipher_suite
    assert client.peer_certificate is not None


@pytest.mark.parametrize(
    "cipher_suite",
    (
        CipherSuite.TLS_ECDHE_ECDSA_WITH_NULL_SHA,
        CipherSuite.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
        CipherSuite.TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,
        CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
        CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
        CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
        CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
        CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM,
        CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CCM,
        CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8,
        CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8,
        CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        CipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    ),
)
@pytest.mark.parametrize(
    "signature_algorithm",
    (
        SignatureScheme.ECDSA_SHA224,
        SignatureScheme.ECDSA_SHA1,
        SignatureScheme.ECDSA_SECP521R1_SHA512,
        SignatureScheme.ECDSA_SECP384R1_SHA384,
        SignatureScheme.ECDSA_SECP256R1_SHA256,
    ),
)
def test_tls12_with_ec_secp256r1(cipher_suite, signature_algorithm):
    version = TLSVersion.TLSv1_2

    client = TLSHandshakeClient(
        configuration=create_client_config(
            minimum_version=version,
            maximum_version=version,
            cipher_suites=[cipher_suite],
            signature_algorithms=[signature_algorithm],
        )
    )
    server = TLSHandshakeServer(
        configuration=create_server_config(
            minimum_version=version,
            maximum_version=version,
            cipher_suites=[cipher_suite],
            signing_signature_algorithms=[signature_algorithm],
            credential=Credential.from_certfile(
                SERVER_EC_SECP256R1_CERTFILE, SERVER_EC_SECP256R1_KEYFILE
            ),
        )
    )

    run_handshake(client, server)
    assert_tls1_secret(client, server)

    assert client.version == version
    assert server.version == version
    assert client.cipher_suite == cipher_suite
    assert server.cipher_suite == cipher_suite
    assert client.peer_certificate is not None


@pytest.mark.parametrize(
    "version",
    (
        TLSVersion.TLSv1_2,
        TLSVersion.TLSv1_1,
        TLSVersion.TLSv1,
    ),
)
@pytest.mark.parametrize(
    "client_protocols, server_protocols, expected_protocol",
    [
        # Perfect match on the client's first preference
        ([b"h2", b"http/1.1"], [b"h2", b"http/1.1"], b"h2"),
        # Intersection with different ordering (Follow client preference)
        ([b"http/1.1", b"h2"], [b"h2", b"http/1.1"], b"http/1.1"),
        # Secondary match when first choices don't overlap
        ([b"spdy/3", b"h2"], [b"h2", b"http/1.1"], b"h2"),
        # Complete mismatch
        ([b"spdy/3"], [b"h2", b"http/1.1"], b"h2"),
        # Client sends no NPN extension, server supports NPN
        (None, [b"h2", b"http/1.1"], None),
        # Client sends NPN extension, server didn't supports NPN
        ([b"h2"], None, None),
    ],
)
def test_tls1_npn(
    version,
    client_protocols,
    server_protocols,
    expected_protocol,
):
    client = TLSHandshakeClient(
        configuration=create_client_config(
            minimum_version=version,
            maximum_version=version,
            npn_protocols=client_protocols,
        )
    )
    server = TLSHandshakeServer(
        configuration=create_server_config(
            minimum_version=version,
            maximum_version=version,
            npn_protocols=server_protocols,
        )
    )

    run_handshake(client, server)
    assert_tls1_secret(client, server)

    if client_protocols and server_protocols:
        assert client.npn_protocol == expected_protocol
        assert server.npn_protocol == expected_protocol
    else:
        assert client.npn_protocol is None
        assert server.npn_protocol is None


@pytest.mark.parametrize(
    "version",
    (
        TLSVersion.TLSv1_3,
        TLSVersion.TLSv1_2,
        TLSVersion.TLSv1_1,
        TLSVersion.TLSv1,
    ),
)
@pytest.mark.parametrize(
    "client_protocols, server_protocols, expected_protocol, should_succeed",
    [
        # Perfect match on the client's first preference
        ([b"h2", b"http/1.1"], [b"h2", b"http/1.1"], b"h2", True),
        # Intersection with different ordering (Follow server preference)
        ([b"http/1.1", b"h2"], [b"h2", b"http/1.1"], b"h2", True),
        # Secondary match when first choices don't overlap
        ([b"spdy/3", b"h2"], [b"h2", b"http/1.1"], b"h2", True),
        # Complete mismatch
        ([b"http/1.1"], [b"h2"], None, False),
        # Client sends no ALPN extension, server supports ALPN
        (None, [b"h2", b"http/1.1"], None, True),
        # Client sends ALPN extension, server didn't supports ALPN
        ([b"h2"], None, None, True),
    ],
)
def test_alpn(
    version,
    client_protocols,
    server_protocols,
    expected_protocol,
    should_succeed,
):
    client = TLSHandshakeClient(
        configuration=create_client_config(
            minimum_version=version,
            maximum_version=version,
            alpn_protocols=client_protocols,
        )
    )
    server = TLSHandshakeServer(
        configuration=create_server_config(
            minimum_version=version,
            maximum_version=version,
            alpn_protocols=server_protocols,
        )
    )

    if should_succeed:
        run_handshake(client, server)

        if client_protocols and server_protocols:
            assert client.alpn_protocol == expected_protocol
            assert server.alpn_protocol == expected_protocol
        else:
            assert client.alpn_protocol is None
            assert server.alpn_protocol is None
    else:
        with pytest.raises(
            AlertNoApplicationProtocol,
            match="no supported ALPN protocols",
        ):
            run_handshake(client, server)


@pytest.mark.parametrize(
    "version",
    (
        TLSVersion.TLSv1_2,
        TLSVersion.TLSv1_1,
        TLSVersion.TLSv1,
    ),
)
def test_tls1_ticket_resumption(version):
    session_handler = SessionHandler()
    ticket_aead = TicketAEAD()

    client = TLSHandshakeClient(
        configuration=create_client_config(
            minimum_version=version,
            maximum_version=version,
        ),
        new_session_callback=session_handler,
    )
    server = TLSHandshakeServer(
        configuration=create_server_config(
            minimum_version=version,
            maximum_version=version,
            ticket_aead=ticket_aead,
        )
    )

    run_handshake(client, server)
    assert_tls1_secret(client, server)

    assert client.version == version
    assert server.version == version
    assert not client.session_reused
    assert not server.session_reused
    assert len(session_handler) == 1

    client = TLSHandshakeClient(
        configuration=create_client_config(
            minimum_version=version,
            maximum_version=version,
            session=session_handler.pop(),
        ),
    )
    server = TLSHandshakeServer(
        configuration=create_server_config(
            minimum_version=version,
            maximum_version=version,
            ticket_aead=ticket_aead,
        )
    )

    run_handshake(client, server)
    assert_tls1_secret(client, server)

    assert client.version == version
    assert server.version == version
    assert client.session_reused
    assert server.session_reused


@pytest.mark.parametrize(
    "version",
    (
        TLSVersion.TLSv1_1,
        TLSVersion.TLSv1,
    ),
)
def test_tls1_certificate_request(version):
    exp_cert_types = [
        ClientCertificateType.RSA_SIGN,
        ClientCertificateType.DSS_SIGN,
        ClientCertificateType.ECDSA_SIGN,
    ]
    exp_cert_authorities = []

    client = TLSHandshakeClient(
        configuration=create_client_config(
            minimum_version=version,
            maximum_version=version,
        ),
    )
    server = TLSHandshakeServer(
        configuration=create_server_config(
            minimum_version=version,
            maximum_version=version,
            verify_mode=VerifyMode.CERT_OPTIONAL,
        )
    )

    run_handshake(client, server)
    assert_tls1_secret(client, server)

    assert client.version == version
    assert server.version == version

    cert_request = client._peer_cert_request
    assert isinstance(cert_request, CertificateRequest)
    assert cert_request.certificate_types == exp_cert_types
    assert cert_request.certificate_authorities == exp_cert_authorities


@pytest.mark.parametrize(
    "signature_algorithms, exp_cert_types",
    [
        (
            [SignatureScheme.RSA_PKCS1_SHA256],
            [ClientCertificateType.RSA_SIGN],
        ),
        (
            [SignatureScheme.ECDSA_SECP256R1_SHA256],
            [ClientCertificateType.ECDSA_SIGN],
        ),
        (
            [SignatureScheme.DSA_SHA256],
            [ClientCertificateType.DSS_SIGN],
        ),
        (
            [SignatureScheme.RSA_PKCS1_SHA256, SignatureScheme.DSA_SHA256],
            [ClientCertificateType.RSA_SIGN, ClientCertificateType.DSS_SIGN],
        ),
        (
            [
                SignatureScheme.RSA_PKCS1_SHA256,
                SignatureScheme.DSA_SHA256,
                SignatureScheme.ECDSA_SECP256R1_SHA256,
            ],
            [
                ClientCertificateType.RSA_SIGN,
                ClientCertificateType.DSS_SIGN,
                ClientCertificateType.ECDSA_SIGN,
            ],
        ),
    ],
)
def test_tls12_certificate_request(signature_algorithms, exp_cert_types):
    version = TLSVersion.TLSv1_2
    exp_cert_authorities = []

    client = TLSHandshakeClient(
        configuration=create_client_config(
            minimum_version=version,
            maximum_version=version,
        ),
    )
    server = TLSHandshakeServer(
        configuration=create_server_config(
            minimum_version=version,
            maximum_version=version,
            verify_mode=VerifyMode.CERT_OPTIONAL,
            signature_algorithms=signature_algorithms,
        )
    )

    run_handshake(client, server)
    assert_tls1_secret(client, server)

    assert client.version == version
    assert server.version == version

    cert_request = client._peer_cert_request
    assert isinstance(cert_request, CertificateRequestTLS12)
    assert cert_request.certificate_types == exp_cert_types
    assert cert_request.certificate_authorities == exp_cert_authorities
    assert cert_request.signature_algorithms == signature_algorithms


@pytest.mark.parametrize(
    "signature_algorithm",
    (
        SignatureScheme.RSA_PSS_RSAE_SHA512,
        SignatureScheme.RSA_PSS_RSAE_SHA384,
        SignatureScheme.RSA_PSS_RSAE_SHA256,
    ),
)
def test_tls13_with_rsa_pkcs1(signature_algorithm):
    version = TLSVersion.TLSv1_3

    client = TLSHandshakeClient(
        configuration=create_client_config(
            minimum_version=version,
            maximum_version=version,
            signature_algorithms=[signature_algorithm],
        )
    )
    server = TLSHandshakeServer(
        configuration=create_server_config(
            minimum_version=version,
            maximum_version=version,
            signing_signature_algorithms=[signature_algorithm],
            credential=Credential.from_certfile(
                SERVER_RSA_CERTFILE, SERVER_RSA_KEYFILE
            ),
        )
    )

    run_handshake(client, server)
    assert_tls13_secret(client, server, Epoch.HANDSHAKE)
    assert_tls13_secret(client, server, Epoch.APPLICATION_DATA)

    assert client.version == version
    assert server.version == version
    assert client.peer_certificate is not None


def test_tls13_with_ec_secp256r1():
    version = TLSVersion.TLSv1_3
    signature_algorithm = SignatureScheme.ECDSA_SECP256R1_SHA256

    client = TLSHandshakeClient(
        configuration=create_client_config(
            minimum_version=version,
            maximum_version=version,
            signature_algorithms=[signature_algorithm],
        )
    )
    server = TLSHandshakeServer(
        configuration=create_server_config(
            minimum_version=version,
            maximum_version=version,
            signing_signature_algorithms=[signature_algorithm],
            credential=Credential.from_certfile(
                SERVER_EC_SECP256R1_CERTFILE, SERVER_EC_SECP256R1_KEYFILE
            ),
        )
    )
    run_handshake(client, server)
    assert_tls13_secret(client, server, Epoch.HANDSHAKE)
    assert_tls13_secret(client, server, Epoch.APPLICATION_DATA)

    assert client.version == version
    assert server.version == version
    assert client.peer_certificate is not None


def test_tls13_hello_retry_request():
    version = TLSVersion.TLSv1_3

    client = TLSHandshakeClient(
        configuration=create_client_config(
            minimum_version=version,
            maximum_version=version,
            supported_groups=[
                NamedGroup.SECP256R1,
                NamedGroup.SECP384R1,
                NamedGroup.X25519,
            ],
        )
    )
    server = TLSHandshakeServer(
        configuration=create_server_config(
            minimum_version=version,
            maximum_version=version,
            supported_groups=[
                NamedGroup.X25519,
                NamedGroup.SECP384R1,
            ],
        )
    )

    run_handshake(client, server)
    assert_tls13_secret(client, server, Epoch.HANDSHAKE)
    assert_tls13_secret(client, server, Epoch.APPLICATION_DATA)

    assert client.version == TLSVersion.TLSv1_3
    assert server.version == TLSVersion.TLSv1_3
    assert client._hello_retry_request_used
    assert server._hello_retry_request_used
    assert server._group_id == NamedGroup.X25519


@pytest.mark.parametrize(
    "cipher_suite, psk_length",
    (
        (CipherSuite.TLS_AES_128_GCM_SHA256, 32),
        (CipherSuite.TLS_AES_256_GCM_SHA384, 48),
        (CipherSuite.TLS_CHACHA20_POLY1305_SHA256, 32),
        (CipherSuite.TLS_AES_128_CCM_SHA256, 32),
        (CipherSuite.TLS_AES_128_CCM_8_SHA256, 32),
    ),
)
def test_tls13_handshake_with_psk(subtests, cipher_suite, psk_length):
    version = TLSVersion.TLSv1_3
    session_handler = SessionHandler()
    ticket_aead = TicketAEAD()

    # First handshake
    client = TLSHandshakeClient(
        configuration=create_client_config(
            minimum_version=version,
            maximum_version=version,
            cipher_suites=[cipher_suite],
        ),
        new_session_callback=session_handler,
    )
    server = TLSHandshakeServer(
        configuration=create_server_config(
            minimum_version=version,
            maximum_version=version,
            cipher_suites=[cipher_suite],
            ticket_aead=ticket_aead,
        )
    )

    run_handshake(client, server)
    assert client.has_unprocessed_data()
    client.trigger_post_handshake()
    run_handshake(client, server)
    assert_tls13_secret(client, server, Epoch.HANDSHAKE)
    assert_tls13_secret(client, server, Epoch.APPLICATION_DATA)

    assert client.version == version
    assert server.version == version
    assert not client.session_reused
    assert not server.session_reused
    assert len(session_handler) == 2
    assert len(ticket_aead) == 2

    for session in session_handler:
        resumption_secret = session.secret
        assert len(resumption_secret) == psk_length

    with subtests.test(msg="session_resumption"):
        client = TLSHandshakeClient(
            configuration=create_client_config(
                minimum_version=version,
                maximum_version=version,
                cipher_suites=[cipher_suite],
                session=session_handler.pop(),
            ),
        )
        server = TLSHandshakeServer(
            configuration=create_server_config(
                minimum_version=version,
                maximum_version=version,
                cipher_suites=[cipher_suite],
                ticket_aead=ticket_aead,
            )
        )

        run_handshake(client, server)
        assert_tls13_secret(client, server, Epoch.HANDSHAKE)
        assert_tls13_secret(client, server, Epoch.APPLICATION_DATA)

        assert client.version == version
        assert server.version == version
        assert client.session_reused
        assert server.session_reused

    with subtests.test(msg="bad_binder"):
        session = session_handler.pop()
        assert not session.not_resumable
        assert session.secret is not None
        session.secret = session.secret[:-4] + bytes(4)

        client = TLSHandshakeClient(
            configuration=create_client_config(
                minimum_version=version,
                maximum_version=version,
                cipher_suites=[cipher_suite],
                session=session,
            ),
        )
        server = TLSHandshakeServer(
            configuration=create_server_config(
                minimum_version=version,
                maximum_version=version,
                cipher_suites=[cipher_suite],
                ticket_aead=ticket_aead,
            )
        )

        server_fail_hello(client, server)

        with pytest.raises(AlertDecryptError):
            server.do_handshake()


def test_tls13_certificate_request():
    version = TLSVersion.TLSv1_3
    signature_algorithms = [
        SignatureScheme.RSA_PKCS1_SHA256,
        SignatureScheme.ECDSA_SECP256R1_SHA256,
    ]

    client = TLSHandshakeClient(
        configuration=create_client_config(
            minimum_version=version,
            maximum_version=version,
        ),
    )
    server = TLSHandshakeServer(
        configuration=create_server_config(
            minimum_version=version,
            maximum_version=version,
            verify_mode=VerifyMode.CERT_OPTIONAL,
            signature_algorithms=signature_algorithms,
        )
    )

    run_handshake(client, server)

    assert client.version == version
    assert server.version == version

    cert_request = client._peer_cert_request
    assert isinstance(cert_request, CertificateRequestTLS13)
    assert cert_request.context == b""
    sigalg_ext = cert_request.extensions.get(SignatureAlgorithmsExtension)
    assert sigalg_ext is not None
    assert sigalg_ext.data == signature_algorithms


def test_tls13_client_send_key_update(subtests):
    version = TLSVersion.TLSv1_3

    with subtests.test(message_type="UPDATE_NOT_REQUESTED"):
        client = TLSHandshakeClient(
            configuration=create_client_config(
                minimum_version=version,
                maximum_version=version,
            )
        )
        server = TLSHandshakeServer(
            configuration=create_server_config(
                minimum_version=version,
                maximum_version=version,
            )
        )

        run_handshake(client, server)

        assert client.version == version
        assert server.version == version

        client_dec_secret = client._dec_secret[Epoch.APPLICATION_DATA]
        client_enc_secret = client._enc_secret[Epoch.APPLICATION_DATA]
        server_dec_secret = server._dec_secret[Epoch.APPLICATION_DATA]
        server_enc_secret = server._enc_secret[Epoch.APPLICATION_DATA]

        assert client_dec_secret == server_enc_secret
        assert client_enc_secret == server_dec_secret

        client.send_key_update(KeyUpdateMessageType.UPDATE_NOT_REQUESTED)
        run_handshake(client, server)
        server.trigger_post_handshake()
        run_handshake(client, server)

        new_client_dec_secret = client._dec_secret[Epoch.APPLICATION_DATA]
        new_client_enc_secret = client._enc_secret[Epoch.APPLICATION_DATA]
        new_server_dec_secret = server._dec_secret[Epoch.APPLICATION_DATA]
        new_server_enc_secret = server._enc_secret[Epoch.APPLICATION_DATA]

        assert new_client_enc_secret != client_enc_secret
        assert new_server_dec_secret != server_dec_secret
        assert new_client_enc_secret == new_server_dec_secret

    with subtests.test(message_type="UPDATE_REQUESTED"):
        client = TLSHandshakeClient(
            configuration=create_client_config(
                minimum_version=version,
                maximum_version=version,
            )
        )
        server = TLSHandshakeServer(
            configuration=create_server_config(
                minimum_version=version,
                maximum_version=version,
            )
        )

        run_handshake(client, server)

        assert client.version == TLSVersion.TLSv1_3
        assert server.version == TLSVersion.TLSv1_3

        client_dec_secret = client._dec_secret[Epoch.APPLICATION_DATA]
        client_enc_secret = client._enc_secret[Epoch.APPLICATION_DATA]
        server_dec_secret = server._dec_secret[Epoch.APPLICATION_DATA]
        server_enc_secret = server._enc_secret[Epoch.APPLICATION_DATA]

        assert client_dec_secret == server_enc_secret
        assert client_enc_secret == server_dec_secret

        client.send_key_update(KeyUpdateMessageType.UPDATE_REQUESTED)
        run_handshake(client, server)
        server.trigger_post_handshake()
        run_handshake(client, server)
        client.trigger_post_handshake()
        run_handshake(client, server)

        new_client_dec_secret = client._dec_secret[Epoch.APPLICATION_DATA]
        new_client_enc_secret = client._enc_secret[Epoch.APPLICATION_DATA]
        new_server_dec_secret = server._dec_secret[Epoch.APPLICATION_DATA]
        new_server_enc_secret = server._enc_secret[Epoch.APPLICATION_DATA]

        assert new_client_enc_secret != client_enc_secret
        assert new_client_dec_secret != client_dec_secret
        assert new_server_enc_secret != server_enc_secret
        assert new_server_dec_secret != server_dec_secret
        assert new_client_enc_secret == new_server_dec_secret
        assert new_client_dec_secret == new_server_enc_secret


def test_tls13_server_send_key_update(subtests):
    version = TLSVersion.TLSv1_3

    with subtests.test(message_type="UPDATE_NOT_REQUESTED"):
        client = TLSHandshakeClient(
            configuration=create_client_config(
                minimum_version=version,
                maximum_version=version,
            )
        )
        server = TLSHandshakeServer(
            configuration=create_server_config(
                minimum_version=version,
                maximum_version=version,
            )
        )

        run_handshake(client, server)

        assert client.version == version
        assert server.version == version

        client_dec_secret = client._dec_secret[Epoch.APPLICATION_DATA]
        client_enc_secret = client._enc_secret[Epoch.APPLICATION_DATA]
        server_dec_secret = server._dec_secret[Epoch.APPLICATION_DATA]
        server_enc_secret = server._enc_secret[Epoch.APPLICATION_DATA]

        assert client_dec_secret == server_enc_secret
        assert client_enc_secret == server_dec_secret

        server.send_key_update(KeyUpdateMessageType.UPDATE_NOT_REQUESTED)
        run_handshake(client, server)
        client.trigger_post_handshake()
        run_handshake(client, server)

        new_client_dec_secret = client._dec_secret[Epoch.APPLICATION_DATA]
        new_client_enc_secret = client._enc_secret[Epoch.APPLICATION_DATA]
        new_server_dec_secret = server._dec_secret[Epoch.APPLICATION_DATA]
        new_server_enc_secret = server._enc_secret[Epoch.APPLICATION_DATA]

        assert new_server_enc_secret != client_dec_secret
        assert new_client_dec_secret != client_dec_secret
        assert new_server_enc_secret == new_client_dec_secret

    with subtests.test(message_type="UPDATE_REQUESTED"):
        client = TLSHandshakeClient(
            configuration=create_client_config(
                minimum_version=version,
                maximum_version=version,
            )
        )
        server = TLSHandshakeServer(
            configuration=create_server_config(
                minimum_version=version,
                maximum_version=version,
            )
        )

        run_handshake(client, server)

        assert client.version == version
        assert server.version == version

        client_dec_secret = client._dec_secret[Epoch.APPLICATION_DATA]
        client_enc_secret = client._enc_secret[Epoch.APPLICATION_DATA]
        server_dec_secret = server._dec_secret[Epoch.APPLICATION_DATA]
        server_enc_secret = server._enc_secret[Epoch.APPLICATION_DATA]

        assert client_dec_secret == server_enc_secret
        assert client_enc_secret == server_dec_secret

        server.send_key_update(KeyUpdateMessageType.UPDATE_REQUESTED)
        run_handshake(client, server)
        client.trigger_post_handshake()
        run_handshake(client, server)
        server.trigger_post_handshake()
        run_handshake(client, server)

        new_client_dec_secret = client._dec_secret[Epoch.APPLICATION_DATA]
        new_client_enc_secret = client._enc_secret[Epoch.APPLICATION_DATA]
        new_server_dec_secret = server._dec_secret[Epoch.APPLICATION_DATA]
        new_server_enc_secret = server._enc_secret[Epoch.APPLICATION_DATA]

        assert new_client_enc_secret != client_enc_secret
        assert new_client_dec_secret != client_dec_secret
        assert new_server_enc_secret != server_enc_secret
        assert new_server_dec_secret != server_dec_secret
        assert new_client_enc_secret == new_server_dec_secret
        assert new_client_dec_secret == new_server_enc_secret


def test_server_unsupported_version():
    client = TLSHandshakeClient(
        configuration=create_client_config(
            minimum_version=TLSVersion.TLSv1,
            maximum_version=TLSVersion.TLSv1_2,
        )
    )
    server = TLSHandshakeServer(
        configuration=create_server_config(
            minimum_version=TLSVersion.TLSv1_3,
            maximum_version=TLSVersion.TLSv1_3,
        )
    )

    server_fail_hello(client, server)

    with pytest.raises(
        AlertProtocolVersion,
        match="no supported protocol version",
    ):
        server.do_handshake()


@pytest.mark.parametrize(
    "version, client_cipher_suites, server_cipher_suites",
    [
        (
            TLSVersion.TLSv1_3,
            [CipherSuite.TLS_AES_128_CCM_SHA256],
            [CipherSuite.TLS_AES_256_GCM_SHA384],
        ),
        (
            TLSVersion.TLSv1_2,
            [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA],
            [CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA],
        ),
        (
            TLSVersion.TLSv1_1,
            [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA],
            [CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA],
        ),
        (
            TLSVersion.TLSv1,
            [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA],
            [CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA],
        ),
    ],
)
def test_server_unsupported_cipher_suite(
    version, client_cipher_suites, server_cipher_suites
):
    client = TLSHandshakeClient(
        configuration=create_client_config(
            minimum_version=version,
            maximum_version=version,
            cipher_suites=client_cipher_suites,
        )
    )
    server = TLSHandshakeServer(
        configuration=create_server_config(
            minimum_version=version,
            maximum_version=version,
            cipher_suites=server_cipher_suites,
        )
    )

    server_fail_hello(client, server)

    with pytest.raises(
        AlertHandshakeFailure,
        match="no supported cipher suite",
    ):
        server.do_handshake()


@pytest.mark.parametrize(
    "version",
    (
        TLSVersion.TLSv1_2,
        TLSVersion.TLSv1_1,
        TLSVersion.TLSv1,
    ),
)
def test_tls1_server_unsuported_group(version):
    client = TLSHandshakeClient(
        configuration=create_client_config(
            minimum_version=version,
            maximum_version=version,
            cipher_suites=[CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA],
            supported_groups=[NamedGroup.X25519],
        )
    )
    server = TLSHandshakeServer(
        configuration=create_server_config(
            minimum_version=version,
            maximum_version=version,
            cipher_suites=[CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA],
            supported_groups=[NamedGroup.SECP256R1],
        )
    )

    server_fail_hello(client, server)

    with pytest.raises(
        AlertHandshakeFailure,
        match="no supported cipher suite",
    ):
        server.do_handshake()


@pytest.mark.parametrize(
    "version",
    (
        TLSVersion.TLSv1_2,
        TLSVersion.TLSv1_1,
        TLSVersion.TLSv1,
    ),
)
def test_tls1_server_unsuported_group_fallback_to_rsa(version):
    client = TLSHandshakeClient(
        configuration=create_client_config(
            minimum_version=version,
            maximum_version=version,
            cipher_suites=[
                CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
            ],
            supported_groups=[NamedGroup.X25519],
        )
    )
    server = TLSHandshakeServer(
        configuration=create_server_config(
            minimum_version=version,
            maximum_version=version,
            cipher_suites=[
                CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
            ],
            supported_groups=[NamedGroup.SECP256R1],
        )
    )

    run_handshake(client, server)

    assert client.version == version
    assert server.version == version
    assert client.cipher_suite == CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA
    assert server.cipher_suite == CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA


def test_tls13_server_unsuported_group():
    client = TLSHandshakeClient(
        configuration=create_client_config(
            minimum_version=TLSVersion.TLSv1_3,
            maximum_version=TLSVersion.TLSv1_3,
            supported_groups=[NamedGroup.X25519],
        )
    )
    server = TLSHandshakeServer(
        configuration=create_server_config(
            minimum_version=TLSVersion.TLSv1_3,
            maximum_version=TLSVersion.TLSv1_3,
            supported_groups=[NamedGroup.SECP256R1],
        )
    )

    server_fail_hello(client, server)

    with pytest.raises(
        AlertHandshakeFailure,
        match="no supported key shares group",
    ):
        server.do_handshake()


def test_tls13_server_unsupported_signature_algorithm():
    client = TLSHandshakeClient(
        configuration=create_client_config(
            minimum_version=TLSVersion.TLSv1_3,
            maximum_version=TLSVersion.TLSv1_3,
            signature_algorithms=[SignatureScheme.RSA_PSS_RSAE_SHA384],
        )
    )
    server = TLSHandshakeServer(
        configuration=create_server_config(
            credential=Credential.from_certfile(
                SERVER_RSA_CERTFILE, SERVER_RSA_KEYFILE
            ),
            minimum_version=TLSVersion.TLSv1_3,
            maximum_version=TLSVersion.TLSv1_3,
            signing_signature_algorithms=[SignatureScheme.RSA_PSS_RSAE_SHA256],
        )
    )

    server_fail_hello(client, server)

    with pytest.raises(
        AlertHandshakeFailure,
        match="no supported signature algorithm",
    ):
        server.do_handshake()
