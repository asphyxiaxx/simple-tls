import functools
import json
import os
from pathlib import Path

import pytest
from cryptography import x509

from simple_tls.crypto.verification import Store
from simple_tls.tls.configuration import TLSConfiguration, TLSCredential
from simple_tls.tls.enums import Protocol, VerifyMode
from simple_tls.tls.handshake_client import TLSHandshakeClient
from simple_tls.tls.handshake_server import TLSHandshakeServer


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


class SessionHandler:
    def __init__(self):
        self._sessions = []

    def __call__(self, session):
        self._sessions.append(session)

    def __len__(self):
        return len(self._sessions)

    def pop(self):
        return self._sessions.pop()


class TicketAEAD:
    def __init__(self):
        self._storage = {}

    def seal(self, data):
        ticket = os.urandom(32)
        self._storage[ticket] = data
        return ticket

    def open(self, ticket):
        try:
            return self._storage[ticket]
        except KeyError:
            return None


def load_castore(cafile):
    with open(cafile, "rb") as fp:
        cadata = fp.read()
    return Store(x509.load_pem_x509_certificates(cadata))


def create_server(
    certfile=SERVER_RSA_CERTFILE,
    keyfile=SERVER_RSA_KEYFILE,
    **kwargs,
):
    credential = TLSCredential.from_certfile(certfile, keyfile)
    config = TLSConfiguration(
        is_server=True,
        protocol=Protocol.TLS,
        credential=credential,
        **kwargs,
    )
    return TLSHandshakeServer(config)


def create_client(cafile=SERVER_CAFILE, **kwargs):
    kwargs.setdefault("server_hostname", b"localhost")
    kwargs.setdefault("verify_mode", VerifyMode.CERT_REQUIRED)
    kwargs.setdefault("check_hostname", True)

    castore = load_castore(cafile)
    config = TLSConfiguration(castore=castore, **kwargs)
    return TLSHandshakeClient(config)
