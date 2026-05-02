from __future__ import annotations

import ssl as _ssl

from simple_tls import tls


def parse_cipher_string(cipher_str: str) -> list[tls.CipherSuite]:
    """
    Passes the string to the underlying OpenSSL engine via Python's ssl module
    and returns the actual list of cryptographic suites that result from the
    rules.
    """
    ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_SERVER)
    ctx.set_ciphers(cipher_str)

    cipher_suites: list[tls.CipherSuite] = []

    for cipher in ctx.get_ciphers():
        cipher_iana_id = cipher["id"] & 0xFFFF
        try:
            cipher_suite = tls.CipherSuite(cipher_iana_id)
        except ValueError:
            continue
        cipher_suites.append(cipher_suite)

    return cipher_suites
