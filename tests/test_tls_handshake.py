import pytest

from simple_tls.tls import (
    DSA_SIGNATURE_ALGORITHMS,
    RSA_PSS_RSAE_SIGNATURE_ALGORITHMS,
    SIGNATURE_ALGORITHMS,
    AlertCertificateRequired,
    AlertDecryptError,
    AlertHandshakeFailure,
    AlertProtocolVersion,
    Authentication,
    CipherSuite,
    ClientState,
    Epoch,
    KeyUpdateMessageType,
    NamedGroup,
    ServerState,
    SignatureScheme,
    TLSContext,
    TLSVerifyMode,
    TLSVersion,
)

from .utils import (
    SERVER_CAFILE,
    SERVER_DSA_CERTFILE,
    SERVER_DSA_KEYFILE,
    SERVER_EC_SECP256R1_CERTFILE,
    SERVER_EC_SECP256R1_KEYFILE,
    SERVER_ED448_CERTFILE,
    SERVER_ED448_KEYFILE,
    SERVER_ED25519_CERTFILE,
    SERVER_ED25519_KEYFILE,
    SERVER_RSA_CERTFILE,
    SERVER_RSA_KEYFILE,
    create_client,
    create_server,
    run_handshake,
)


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
    client = create_client(
        minimum_version=version,
        maximum_version=version,
    )
    server = create_server(
        minimum_version=version,
        maximum_version=version,
    )

    run_handshake(client, server)

    assert client.version == version
    assert server.version == version


@pytest.mark.parametrize(
    "version",
    (
        TLSVersion.TLSv1_2,
        TLSVersion.TLSv1_1,
        TLSVersion.TLSv1,
    ),
)
def test_handshake_with_rsa_pkcs1(version):
    client = create_client(
        minimum_version=version,
        maximum_version=version,
    )
    server = create_server(
        certfile=SERVER_RSA_CERTFILE,
        keyfile=SERVER_RSA_KEYFILE,
        minimum_version=version,
        maximum_version=version,
    )

    run_handshake(client, server)

    assert client.version == version
    assert server.version == version
    assert client.cipher().auth == Authentication.RSA


@pytest.mark.parametrize(
    "version",
    (
        TLSVersion.TLSv1_2,
        TLSVersion.TLSv1_1,
        TLSVersion.TLSv1,
    ),
)
def test_handshake_with_dsa(version):
    client = create_client(
        minimum_version=version,
        maximum_version=version,
        cipher_suites=[
            CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA,
            CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA256,
        ],
        signature_algorithms=[],
    )
    server = create_server(
        certfile=SERVER_DSA_CERTFILE,
        keyfile=SERVER_DSA_KEYFILE,
        minimum_version=version,
        maximum_version=version,
        cipher_suites=[
            CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA,
            CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA256,
        ],
        signature_algorithms=[],
    )

    run_handshake(client, server)

    assert client.version == version
    assert server.version == version
    assert client.cipher().auth == Authentication.DSS


@pytest.mark.parametrize(
    "version",
    (
        TLSVersion.TLSv1_2,
        TLSVersion.TLSv1_1,
        TLSVersion.TLSv1,
    ),
)
def test_handshake_with_ec_secp256r1(version):
    client = create_client(
        minimum_version=version,
        maximum_version=version,
        cipher_suites=[
            CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
            CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
        ],
        supported_groups=[NamedGroup.SECP256R1],
        signature_algorithms=[],
    )
    server = create_server(
        certfile=SERVER_EC_SECP256R1_CERTFILE,
        keyfile=SERVER_EC_SECP256R1_KEYFILE,
        minimum_version=version,
        maximum_version=version,
        cipher_suites=[
            CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
            CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
        ],
        supported_groups=[NamedGroup.SECP256R1],
        signature_algorithms=[],
    )

    run_handshake(client, server)

    assert client.version == version
    assert server.version == version
    assert client.cipher().auth == Authentication.ECDSA


@pytest.mark.parametrize(
    "version",
    (
        TLSVersion.TLSv1_3,
        TLSVersion.TLSv1_2,
        TLSVersion.TLSv1_1,
        TLSVersion.TLSv1,
    ),
)
def test_handshake_with_alpn(version):
    client = create_client(
        minimum_version=version,
        maximum_version=version,
        alpn_protocols=[b"h2"],
    )
    server = create_server(
        minimum_version=version,
        maximum_version=version,
        alpn_protocols=[
            b"http/1.1",
            b"h2",
        ],
    )

    run_handshake(client, server)

    assert client.version == version
    assert server.version == version
    assert client.alpn_selected == b"h2"
    assert server.alpn_selected == b"h2"


@pytest.mark.parametrize(
    "version",
    (
        TLSVersion.TLSv1_2,
        TLSVersion.TLSv1_1,
        TLSVersion.TLSv1,
    ),
)
def test_handshake_with_npn(version):
    client = create_client(
        minimum_version=version,
        maximum_version=version,
        npn_protocols=[b"h2"],
    )
    server = create_server(
        minimum_version=version,
        maximum_version=version,
        npn_protocols=[
            b"sentinel",
            b"http/1.1",
            b"h2",
        ],
    )

    run_handshake(client, server)

    assert client.version == version
    assert server.version == version
    assert client.npn_selected == b"h2"
    assert server.npn_selected == b"h2"


@pytest.mark.parametrize(
    "version",
    (
        TLSVersion.TLSv1_2,
        TLSVersion.TLSv1_1,
        TLSVersion.TLSv1,
    ),
)
def test_handshake_with_session_ticket(subtests, version):
    client_tickets = []

    def session_ticket_handler(session):
        client_tickets.append(session)

    # First handshake
    client = create_client(
        minimum_version=version,
        maximum_version=version,
    )
    server = create_server(
        minimum_version=version,
        maximum_version=version,
    )

    server_context = server.context
    client.session_ticket_handler = session_ticket_handler

    run_handshake(client, server)

    assert client.version == version
    assert server.version == version
    assert not client.session_reused
    assert not server.session_reused
    assert len(client_tickets) == 1

    session_ticket = client_tickets[0]
    assert not session_ticket.not_resumable
    assert session_ticket.secret is not None

    with subtests.test(msg="session_resumption"):
        client = create_client(
            minimum_version=version,
            maximum_version=version,
        )
        server = create_server(
            context=server_context,
            minimum_version=version,
            maximum_version=version,
        )

        client._session = session_ticket

        run_handshake(client, server)

        assert client.version == version
        assert server.version == version

        assert client.session_reused
        assert server.session_reused


@pytest.mark.parametrize(
    "version",
    (
        TLSVersion.TLSv1_2,
        TLSVersion.TLSv1_1,
        TLSVersion.TLSv1,
    ),
)
def test_handshake_with_session_id(subtests, version):
    client_tickets = []

    def session_ticket_handler(session):
        client_tickets.append(session)

    # First handshake
    client = create_client(
        minimum_version=version,
        maximum_version=version,
    )
    server = create_server(
        minimum_version=version,
        maximum_version=version,
    )

    server_context = server.context
    server_context.session_keys = None
    client.session_ticket_handler = session_ticket_handler

    run_handshake(client, server)

    assert client.version == version
    assert server.version == version
    assert not client.session_reused
    assert not server.session_reused
    assert len(client_tickets) == 1

    session_ticket = client_tickets[0]
    assert not session_ticket.not_resumable
    assert session_ticket.session_id is not None

    with subtests.test(msg="session_resumption"):
        client = create_client(
            minimum_version=version,
            maximum_version=version,
        )
        server = create_server(
            context=server_context,
            minimum_version=version,
            maximum_version=version,
        )

        client._session = session_ticket

        run_handshake(client, server)

        assert client.version == version
        assert server.version == version

        assert client.session_reused
        assert server.session_reused


@pytest.mark.parametrize(
    "version",
    (
        TLSVersion.TLSv1_2,
        TLSVersion.TLSv1_1,
        TLSVersion.TLSv1,
    ),
)
def test_handshake_with_certificate_request_no_certificate(subtests, version):
    with subtests.test(verify_mode="CERT_OPTIONAL"):
        client = create_client(
            minimum_version=version,
            maximum_version=version,
        )
        server = create_server(
            minimum_version=version,
            maximum_version=version,
            verify_mode=TLSVerifyMode.CERT_OPTIONAL,
        )

        run_handshake(client, server)

        assert client.version == version
        assert server.version == version
        assert client._peer_cert_request is not None
        assert server.established_session is not None
        assert (
            server.established_session.x509_peer is None
            and server.established_session.x509_chain is None
        )

    with subtests.test(verify_mode="CERT_REQUIRED"):
        client = create_client(
            minimum_version=version,
            maximum_version=version,
        )
        server = create_server(
            minimum_version=version,
            maximum_version=version,
            verify_mode=TLSVerifyMode.CERT_REQUIRED,
        )

        with pytest.raises(AlertCertificateRequired):
            run_handshake(client, server)


@pytest.mark.parametrize(
    "signature_algorithm",
    RSA_PSS_RSAE_SIGNATURE_ALGORITHMS,
)
def test_tls13_handshake_with_rsa_pkcs1(signature_algorithm):
    client = create_client(
        minimum_version=TLSVersion.TLSv1_3,
        maximum_version=TLSVersion.TLSv1_3,
        signature_algorithms=[signature_algorithm],
    )
    server = create_server(
        minimum_version=TLSVersion.TLSv1_3,
        maximum_version=TLSVersion.TLSv1_3,
        signature_algorithms=SIGNATURE_ALGORITHMS,
    )

    run_handshake(client, server)

    assert client.version == TLSVersion.TLSv1_3
    assert server.version == TLSVersion.TLSv1_3
    assert client.established_session is not None
    assert (
        client.established_session.peer_signature_algorithm
        == signature_algorithm
    )


def test_tls13_handshake_with_ec_secp256r1():
    signature_algorithm = SignatureScheme.ECDSA_SECP256R1_SHA256

    client = create_client(
        minimum_version=TLSVersion.TLSv1_3,
        maximum_version=TLSVersion.TLSv1_3,
        signature_algorithms=[signature_algorithm],
    )
    server = create_server(
        certfile=SERVER_EC_SECP256R1_CERTFILE,
        keyfile=SERVER_EC_SECP256R1_KEYFILE,
        minimum_version=TLSVersion.TLSv1_3,
        maximum_version=TLSVersion.TLSv1_3,
        signature_algorithms=SIGNATURE_ALGORITHMS,
    )

    run_handshake(client, server)

    assert client.version == TLSVersion.TLSv1_3
    assert server.version == TLSVersion.TLSv1_3
    assert client.established_session is not None
    assert (
        client.established_session.peer_signature_algorithm
        == signature_algorithm
    )


def test_tls13_handshake_hello_retry_request(subtests):
    def handshake(groups):
        client = create_client(
            minimum_version=TLSVersion.TLSv1_3,
            maximum_version=TLSVersion.TLSv1_3,
            key_share_groups=groups,
            supported_groups=[
                NamedGroup.X25519,
                NamedGroup.SECP256R1,
                NamedGroup.SECP384R1,
            ],
        )
        server = create_server(
            certfile=SERVER_EC_SECP256R1_CERTFILE,
            keyfile=SERVER_EC_SECP256R1_KEYFILE,
            minimum_version=TLSVersion.TLSv1_3,
            maximum_version=TLSVersion.TLSv1_3,
            supported_groups=[
                NamedGroup.X25519,
                NamedGroup.SECP384R1,
            ],
        )

        assert not client._hello_retry_request_used

        run_handshake(client, server)

        assert client.version == TLSVersion.TLSv1_3
        assert server.version == TLSVersion.TLSv1_3
        assert client._hello_retry_request_used
        assert client.established_session is not None
        assert client.established_session.group_id == NamedGroup.X25519
        assert server.established_session is not None
        assert server.established_session.group_id == NamedGroup.X25519

    with subtests.test(msg="Empty client key_share_groups"):
        handshake([])

    with subtests.test(msg="Server unsupported key_share_groups"):
        handshake([NamedGroup.SECP256R1])

    with subtests.test(msg="Server priortize key_share_groups"):
        handshake([NamedGroup.SECP384R1])


def test_tls13_handshake_with_psk(subtests):
    client_tickets = []

    def session_ticket_handler(session):
        client_tickets.append(session)

    # First handshake
    client = create_client(
        minimum_version=TLSVersion.TLSv1_3,
        maximum_version=TLSVersion.TLSv1_3,
    )
    server = create_server(
        minimum_version=TLSVersion.TLSv1_3,
        maximum_version=TLSVersion.TLSv1_3,
    )

    server_context = server.context
    client.session_ticket_handler = session_ticket_handler

    run_handshake(client, server)
    client.trigger_post_handshake()
    run_handshake(client, server)

    assert client.version == TLSVersion.TLSv1_3
    assert server.version == TLSVersion.TLSv1_3
    assert not client.session_reused
    assert not server.session_reused
    assert len(client_tickets) == 2

    with subtests.test(msg="session_resumption"):
        client = create_client(
            minimum_version=TLSVersion.TLSv1_3,
            maximum_version=TLSVersion.TLSv1_3,
        )
        server = create_server(
            context=server_context,
            minimum_version=TLSVersion.TLSv1_3,
            maximum_version=TLSVersion.TLSv1_3,
        )

        client._session = client_tickets[0]

        run_handshake(client, server)

        assert client.version == TLSVersion.TLSv1_3
        assert server.version == TLSVersion.TLSv1_3

        assert client.session_reused
        assert server.session_reused

    with subtests.test(msg="bad_binder"):
        client = create_client(
            minimum_version=TLSVersion.TLSv1_3,
            maximum_version=TLSVersion.TLSv1_3,
        )
        server = create_server(
            context=server_context,
            minimum_version=TLSVersion.TLSv1_3,
            maximum_version=TLSVersion.TLSv1_3,
        )

        session = client_tickets.pop()
        assert session.secret

        # tamper resumption secret
        session.secret = session.secret[:-4] + bytes(4)
        client._session = session

        server_fail_hello(client, server)

        with pytest.raises(AlertDecryptError):
            server.do_handshake()


def test_tls13_handshake_with_certificate_request_no_certificate(subtests):
    with subtests.test(verify_mode="CERT_OPTIONAL"):
        client = create_client(
            minimum_version=TLSVersion.TLSv1_3,
            maximum_version=TLSVersion.TLSv1_3,
        )
        server = create_server(
            minimum_version=TLSVersion.TLSv1_3,
            maximum_version=TLSVersion.TLSv1_3,
            verify_mode=TLSVerifyMode.CERT_OPTIONAL,
        )

        run_handshake(client, server)

        assert client.version == TLSVersion.TLSv1_3
        assert server.version == TLSVersion.TLSv1_3
        assert client._peer_cert_request is not None
        assert server.established_session is not None
        assert (
            server.established_session.x509_peer is None
            and server.established_session.x509_chain is None
        )

    with subtests.test(verify_mode="CERT_REQUIRED"):
        client = create_client(
            minimum_version=TLSVersion.TLSv1_3,
            maximum_version=TLSVersion.TLSv1_3,
        )
        server = create_server(
            minimum_version=TLSVersion.TLSv1_3,
            maximum_version=TLSVersion.TLSv1_3,
            verify_mode=TLSVerifyMode.CERT_REQUIRED,
        )

        with pytest.raises(AlertCertificateRequired):
            run_handshake(client, server)


@pytest.mark.skip()
def test_tls13_handshake_with_certificate_request_with_certificate():
    client_ctx = TLSContext()
    client_ctx.load_cert_chain(
        certfile=SERVER_RSA_CERTFILE,
        keyfile=SERVER_RSA_KEYFILE,
    )
    client_ctx.load_verify_locations(cafile=SERVER_CAFILE)
    client = create_client(
        context=client_ctx,
        minimum_version=TLSVersion.TLSv1_3,
        maximum_version=TLSVersion.TLSv1_3,
    )

    server_ctx = TLSContext()
    server_ctx.load_cert_chain(
        certfile=SERVER_RSA_CERTFILE,
        keyfile=SERVER_RSA_KEYFILE,
    )
    server_ctx.load_verify_locations(cafile=SERVER_CAFILE)
    server = create_server(
        context=server_ctx,
        certfile=SERVER_RSA_CERTFILE,
        keyfile=SERVER_RSA_KEYFILE,
        minimum_version=TLSVersion.TLSv1_3,
        maximum_version=TLSVersion.TLSv1_3,
        verify_mode=TLSVerifyMode.CERT_REQUIRED,
    )

    run_handshake(client, server)


def test_tls13_client_send_key_update(subtests):
    with subtests.test(message_type="UPDATE_NOT_REQUESTED"):
        client = create_client(
            minimum_version=TLSVersion.TLSv1_3,
            maximum_version=TLSVersion.TLSv1_3,
        )
        server = create_server(
            minimum_version=TLSVersion.TLSv1_3,
            maximum_version=TLSVersion.TLSv1_3,
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
        client = create_client(
            minimum_version=TLSVersion.TLSv1_3,
            maximum_version=TLSVersion.TLSv1_3,
        )
        server = create_server(
            minimum_version=TLSVersion.TLSv1_3,
            maximum_version=TLSVersion.TLSv1_3,
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
    with subtests.test(message_type="UPDATE_NOT_REQUESTED"):
        client = create_client(
            minimum_version=TLSVersion.TLSv1_3,
            maximum_version=TLSVersion.TLSv1_3,
        )
        server = create_server(
            minimum_version=TLSVersion.TLSv1_3,
            maximum_version=TLSVersion.TLSv1_3,
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
        client = create_client(
            minimum_version=TLSVersion.TLSv1_3,
            maximum_version=TLSVersion.TLSv1_3,
        )
        server = create_server(
            minimum_version=TLSVersion.TLSv1_3,
            maximum_version=TLSVersion.TLSv1_3,
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


def server_fail_hello(client, server):
    def stop_after_client_send_hello(c, s):
        return c.hs_state == ClientState.ENTER_EARLY_DATA

    run_handshake(client, server, stop_after_client_send_hello)
    assert server.hs_state == ServerState.READ_CLIENT_HELLO

    flight = client.pending_flight()
    server.add_hs_data(flight)


def test_server_unsupported_version():
    client = create_client(
        minimum_version=TLSVersion.TLSv1,
        maximum_version=TLSVersion.TLSv1_2,
    )
    server = create_server(
        minimum_version=TLSVersion.TLSv1_3,
        maximum_version=TLSVersion.TLSv1_3,
    )

    server_fail_hello(client, server)

    with pytest.raises(AlertProtocolVersion):
        server.do_handshake()


@pytest.mark.parametrize(
    "version",
    (
        TLSVersion.TLSv1_3,
        TLSVersion.TLSv1_2,
        TLSVersion.TLSv1_1,
        TLSVersion.TLSv1,
    ),
)
def test_server_unsupported_alpn(version):
    client = create_client(
        minimum_version=version,
        maximum_version=version,
        alpn_protocols=[b"h2"],
    )
    server = create_server(
        minimum_version=version,
        maximum_version=version,
        alpn_protocols=[
            b"http/1.1",
            b"h3",
        ],
    )

    server_fail_hello(client, server)

    with pytest.raises(AlertHandshakeFailure, match=r".*?ALPN.*"):
        server.do_handshake()


@pytest.mark.parametrize(
    "version",
    (
        TLSVersion.TLSv1_2,
        TLSVersion.TLSv1_1,
        TLSVersion.TLSv1,
    ),
)
def test_server_unsupported_npn(version):
    client = create_client(
        minimum_version=version,
        maximum_version=version,
        npn_protocols=[b"h2"],
    )
    server = create_server(
        minimum_version=version,
        maximum_version=version,
        npn_protocols=[
            b"sentinel",
            b"http/1.1",
            b"h3",
        ],
    )

    run_handshake(client, server)

    assert client.version == version
    assert server.version == version
    assert client.npn_selected == b"sentinel"
    assert server.npn_selected == b"sentinel"


def test_tls13_server_unsuported_cipher_suite():
    client = create_client(
        minimum_version=TLSVersion.TLSv1_3,
        maximum_version=TLSVersion.TLSv1_3,
        cipher_suites=[CipherSuite.TLS_AES_128_CCM_SHA256],
    )
    server = create_server(
        minimum_version=TLSVersion.TLSv1_3,
        maximum_version=TLSVersion.TLSv1_3,
        cipher_suites=[CipherSuite.TLS_AES_256_GCM_SHA384],
    )

    server_fail_hello(client, server)

    with pytest.raises(AlertHandshakeFailure):
        server.do_handshake()


def test_tls13_server_unsuported_group():
    client = create_client(
        minimum_version=TLSVersion.TLSv1_3,
        maximum_version=TLSVersion.TLSv1_3,
        key_share_groups=[NamedGroup.X25519],
        supported_groups=[NamedGroup.X25519],
    )
    server = create_server(
        minimum_version=TLSVersion.TLSv1_3,
        maximum_version=TLSVersion.TLSv1_3,
        supported_groups=[NamedGroup.SECP256R1],
    )

    server_fail_hello(client, server)

    with pytest.raises(AlertHandshakeFailure):
        server.do_handshake()


@pytest.mark.parametrize(
    "signature_algorithm",
    (
        signature_algorithm
        for signature_algorithm in SIGNATURE_ALGORITHMS
        if signature_algorithm not in RSA_PSS_RSAE_SIGNATURE_ALGORITHMS
    ),
)
def test_tls13_server_unsupported_signature_algorithm_with_rsa_pkcs1(
    signature_algorithm,
):
    client = create_client(
        minimum_version=TLSVersion.TLSv1_3,
        maximum_version=TLSVersion.TLSv1_3,
        signature_algorithms=[signature_algorithm],
    )
    server = create_server(
        certfile=SERVER_RSA_CERTFILE,
        keyfile=SERVER_RSA_KEYFILE,
        minimum_version=TLSVersion.TLSv1_3,
        maximum_version=TLSVersion.TLSv1_3,
        signature_algorithms=SIGNATURE_ALGORITHMS,
    )

    server_fail_hello(client, server)

    with pytest.raises(AlertHandshakeFailure):
        server.do_handshake()


@pytest.mark.parametrize(
    "signature_algorithm",
    (
        signature_algorithm
        for signature_algorithm in SIGNATURE_ALGORITHMS
        if signature_algorithm not in DSA_SIGNATURE_ALGORITHMS
    ),
)
def test_tls13_server_unsupported_signature_algorithm_with_dsa(
    signature_algorithm,
):
    client = create_client(
        minimum_version=TLSVersion.TLSv1_3,
        maximum_version=TLSVersion.TLSv1_3,
        signature_algorithms=[signature_algorithm],
    )
    server = create_server(
        certfile=SERVER_DSA_CERTFILE,
        keyfile=SERVER_DSA_KEYFILE,
        minimum_version=TLSVersion.TLSv1_3,
        maximum_version=TLSVersion.TLSv1_3,
        signature_algorithms=SIGNATURE_ALGORITHMS,
    )

    server_fail_hello(client, server)

    with pytest.raises(AlertHandshakeFailure):
        server.do_handshake()


@pytest.mark.parametrize(
    "signature_algorithm",
    (
        signature_algorithm
        for signature_algorithm in SIGNATURE_ALGORITHMS
        if signature_algorithm != SignatureScheme.ECDSA_SECP256R1_SHA256
    ),
)
def test_tls13_server_unsupported_signature_algorithm_with_ec_secp256r1(
    signature_algorithm,
):
    client = create_client(
        minimum_version=TLSVersion.TLSv1_3,
        maximum_version=TLSVersion.TLSv1_3,
        signature_algorithms=[signature_algorithm],
    )
    server = create_server(
        certfile=SERVER_EC_SECP256R1_CERTFILE,
        keyfile=SERVER_EC_SECP256R1_KEYFILE,
        minimum_version=TLSVersion.TLSv1_3,
        maximum_version=TLSVersion.TLSv1_3,
        signature_algorithms=SIGNATURE_ALGORITHMS,
    )

    server_fail_hello(client, server)

    with pytest.raises(AlertHandshakeFailure):
        server.do_handshake()


@pytest.mark.parametrize(
    "signature_algorithm",
    (
        signature_algorithm
        for signature_algorithm in SIGNATURE_ALGORITHMS
        if signature_algorithm != SignatureScheme.ED25519
    ),
)
def test_tls13_server_unsupported_signature_algorithm_with_ed25519(
    signature_algorithm,
):
    client = create_client(
        minimum_version=TLSVersion.TLSv1_3,
        maximum_version=TLSVersion.TLSv1_3,
        signature_algorithms=[signature_algorithm],
    )
    server = create_server(
        certfile=SERVER_ED25519_CERTFILE,
        keyfile=SERVER_ED25519_KEYFILE,
        minimum_version=TLSVersion.TLSv1_3,
        maximum_version=TLSVersion.TLSv1_3,
        signature_algorithms=SIGNATURE_ALGORITHMS,
    )

    server_fail_hello(client, server)

    with pytest.raises(AlertHandshakeFailure):
        server.do_handshake()


@pytest.mark.parametrize(
    "signature_algorithm",
    (
        signature_algorithm
        for signature_algorithm in SIGNATURE_ALGORITHMS
        if signature_algorithm != SignatureScheme.ED448
    ),
)
def test_tls13_server_unsupported_signature_algorithm_with_ed448(
    signature_algorithm,
):
    client = create_client(
        minimum_version=TLSVersion.TLSv1_3,
        maximum_version=TLSVersion.TLSv1_3,
        signature_algorithms=[signature_algorithm],
    )
    server = create_server(
        certfile=SERVER_ED448_CERTFILE,
        keyfile=SERVER_ED448_KEYFILE,
        minimum_version=TLSVersion.TLSv1_3,
        maximum_version=TLSVersion.TLSv1_3,
        signature_algorithms=SIGNATURE_ALGORITHMS,
    )

    server_fail_hello(client, server)

    with pytest.raises(AlertHandshakeFailure):
        server.do_handshake()
