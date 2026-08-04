import functools
import json
import os
from pathlib import Path

import pytest

from simple_tls.tls import (
    Status,
    TLSContext,
    TLSHandshakeClient,
    TLSHandshakeServer,
    TLSVerifyMode,
)


def format_path(*paths: str):
    return os.path.join(os.path.dirname(__file__), *paths)


def stdout(indicator: str = "."):
    return print(indicator, end="", flush=True)


def load(*paths: str, mode: str = "r"):
    path = format_path(*paths)
    with open(path, mode) as fp:
        return fp.read()


class WycheproofTest:
    def __init__(self, vector, test_group, test_case):
        self.vectors = vector
        self.test_group = test_group
        self.test_case = test_case

    @property
    def type(self):
        return self.test_group["type"]

    @property
    def tc_id(self):
        return self.test_case["tcId"]

    @property
    def valid(self):
        return self.test_case["result"] == "valid"

    @property
    def acceptable(self):
        return self.test_case["result"] == "acceptable"

    @property
    def invalid(self):
        return self.test_case["result"] == "invalid"


@functools.lru_cache(maxsize=32)
def load_wycheproof_json(file_path: Path) -> dict:
    """Load Wycheproof vectors from a local file path."""
    try:
        with open(file_path, encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        pytest.fail(f"Failed to read Wycheproof file at {file_path}: {e}")


def yield_wycheproof_tests(base_dir: Path, *paths: str):
    file_path = base_dir.joinpath(*paths)
    if not file_path.suffix:
        file_path = file_path.with_suffix(".json")

    vectors = load_wycheproof_json(file_path)

    for test_group in vectors["testGroups"]:
        for test_case in test_group["tests"]:
            yield WycheproofTest(vectors, test_group, test_case)


def wycheproof_tests(*paths: str, subdir: str = "testvectors_v1"):
    """
    Pytest decorator that loads local Wycheproof vectors from a directory
    provided via the --wycheproof-dir CLI option.
    """

    def decorator(func):
        @pytest.mark.parametrize("path", paths)
        def wrapper(path, subtests, pytestconfig):
            wycheproof_dir = pytestconfig.getoption(
                "--wycheproof-dir", skip=True
            )
            base_dir = Path(wycheproof_dir)

            for test_case in yield_wycheproof_tests(base_dir, subdir, path):
                with subtests.test(file=path, tc_id=test_case.tc_id):
                    func(test_case)

        wrapper.__name__ = func.__name__
        return wrapper

    return decorator


SERVER_CAFILE = format_path("certs", "root_ca.crt")
SERVER_RSA_CERTFILE = format_path("certs", "server_rsa_chain.crt")
SERVER_RSA_KEYFILE = format_path("certs", "server_rsa.key")
SERVER_DSA_CERTFILE = format_path("certs", "server_dsa_chain.crt")
SERVER_DSA_KEYFILE = format_path("certs", "server_dsa.key")
SERVER_EC_SECP256R1_CERTFILE = format_path(
    "certs", "server_ec_secp256r1_chain.crt"
)
SERVER_EC_SECP256R1_KEYFILE = format_path("certs", "server_ec_secp256r1.key")
SERVER_ED25519_CERTFILE = format_path("certs", "server_ed25519_chain.crt")
SERVER_ED25519_KEYFILE = format_path("certs", "server_ed25519.key")
SERVER_ED448_CERTFILE = format_path("certs", "server_ed448_chain.crt")
SERVER_ED448_KEYFILE = format_path("certs", "server_ed448.key")


def create_server(
    context=None,
    certfile=SERVER_RSA_CERTFILE,
    keyfile=SERVER_RSA_KEYFILE,
    **kwargs,
):
    if context is None:
        context = TLSContext()
        context.load_cert_chain(certfile, keyfile)

    for name, value in kwargs.items():
        setattr(context, name, value)

    server = TLSHandshakeServer(context)
    return server


def create_client(context=None, cafile=SERVER_CAFILE, **kwargs):
    if context is None:
        context = TLSContext()
        context.load_verify_locations(cafile)

    context.verify_mode = TLSVerifyMode.CERT_REQUIRED
    context.check_hostname = True

    for name, value in kwargs.items():
        setattr(context, name, value)

    client = TLSHandshakeClient(context, hostname=b"localhost")
    return client


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
                    server.add_hs_data(flight)

                client.clear_flight()
                client_status = client.do_handshake()
                progress_made = True

            # If client is waiting to read, let it process its buffer
            elif client_status in (
                Status.READ_MESSAGE,
                Status.READ_CHANGE_CIPHER_SPEC,
                Status.READ_END_OF_EARLY_DATA,
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
                    client.add_hs_data(flight)

                server.clear_flight()
                server_status = server.do_handshake()
                progress_made = True

            # If server is waiting to read, let it process its buffer
            elif server_status in (
                Status.READ_MESSAGE,
                Status.READ_CHANGE_CIPHER_SPEC,
                Status.READ_END_OF_EARLY_DATA,
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
