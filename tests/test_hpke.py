import itertools
import json
from binascii import unhexlify
from unittest.mock import patch

import pytest
from simple_tls.protocol.hpke import (
    _AEADS,
    _KDFS,
    _KEMS,
    Mode,
    create_suite,
)

from .utils import load

KEMS = list(_KEMS.values())
CIPHER_SUITES = list(itertools.product(_KEMS, _KDFS, _AEADS))


@pytest.fixture(scope="module")
def test_vectors():
    """loads the JSON once and passes it to any test that asks for it"""
    return json.loads(load("test_vectors", "hpke.json"))


@pytest.mark.parametrize("kem", KEMS)
def test_kem_encap(test_vectors, kem):
    for vector in test_vectors:
        if vector["kem_id"] != kem.id:
            continue

        mode = vector["mode"]

        # Receiver public key
        pk_rm = unhexlify(vector["pkRm"])
        pk_r = kem.deserialize_public_key(pk_rm)

        # Ephemeral private key
        sk_em = unhexlify(vector["skEm"])
        sk_e = kem.deserialize_private_key(sk_em)

        with patch.object(kem, "generate", return_value=sk_e):
            if mode in (Mode.BASE, Mode.PSK):
                shared_secret, enc = kem.encap(pk_r)
            elif mode in (Mode.AUTH, Mode.AUTH_PSK):
                # Sender private key
                sk_sm = unhexlify(vector["skSm"])
                sk_s = kem.deserialize_private_key(sk_sm)
                shared_secret, enc = kem.auth_encap(pk_r, sk_s)
            else:
                raise RuntimeError("Unexpected error occured")

        expected_enc = unhexlify(vector["enc"])
        expected_shared_secret = unhexlify(vector["shared_secret"])
        assert enc == expected_enc
        assert shared_secret == expected_shared_secret


@pytest.mark.parametrize("kem", KEMS)
def test_kem_decap(test_vectors, kem):
    for vector in test_vectors:
        if vector["kem_id"] != kem.id:
            continue

        mode = vector["mode"]
        enc = unhexlify(vector["enc"])

        # Receiver private key
        sk_rm = unhexlify(vector["skRm"])
        sk_r = kem.deserialize_private_key(sk_rm)

        if mode in (Mode.BASE, Mode.PSK):
            shared_secret = kem.decap(enc, sk_r)
        elif mode in (Mode.AUTH, Mode.AUTH_PSK):
            # Sender public key
            pk_sm = unhexlify(vector["pkSm"])
            pk_s = kem.deserialize_public_key(pk_sm)
            shared_secret = kem.auth_decap(enc, sk_r, pk_s)
        else:
            raise RuntimeError("Unexpected error occured")

        expected_shared_secret = unhexlify(vector["shared_secret"])
        assert shared_secret == expected_shared_secret


@pytest.mark.parametrize("kem_id, kdf_id, aead_id", CIPHER_SUITES)
def test_seal(test_vectors, kem_id, kdf_id, aead_id):
    for vector in test_vectors:
        if not (
            vector["kem_id"] == kem_id
            and vector["kdf_id"] == kdf_id
            and vector["aead_id"] == aead_id
        ):
            continue

        suite = create_suite(kem_id, kdf_id, aead_id)
        mode = vector["mode"]
        info = unhexlify(vector["info"])

        # Ephemeral private key
        sk_em = unhexlify(vector["skEm"])
        sk_e = suite.kem.deserialize_private_key(sk_em)

        # Receiver public key
        pk_rm = unhexlify(vector["pkRm"])
        pk_r = suite.kem.deserialize_public_key(pk_rm)

        with patch.object(suite.kem, "generate", return_value=sk_e):
            if mode == Mode.BASE:
                enc, context = suite.setup_send(pk_r, info)

            elif mode == Mode.PSK:
                psk = unhexlify(vector["psk"])
                psk_id = unhexlify(vector["psk_id"])
                enc, context = suite.setup_psk_send(pk_r, info, psk, psk_id)

            elif mode == Mode.AUTH:
                sk_sm = unhexlify(vector["skSm"])
                sk_s = suite.kem.deserialize_private_key(sk_sm)
                enc, context = suite.setup_auth_send(pk_r, info, sk_s)

            elif mode == Mode.AUTH_PSK:
                sk_sm = unhexlify(vector["skSm"])
                sk_s = suite.kem.deserialize_private_key(sk_sm)
                psk = unhexlify(vector["psk"])
                psk_id = unhexlify(vector["psk_id"])
                enc, context = suite.setup_auth_psk_send(
                    pk_r, info, sk_s, psk, psk_id
                )
            else:
                continue

        expected_enc = unhexlify(vector["enc"])
        assert enc == expected_enc

        encryptions = vector["encryptions"]
        for encryption in encryptions:
            aad = unhexlify(encryption["aad"])
            pt = unhexlify(encryption["pt"])
            expected_ct = unhexlify(encryption["ct"])
            ct = context.seal(pt, aad)

            assert expected_ct == ct

        exports = vector["exports"]
        for export in exports:
            exporter_context = unhexlify(export["exporter_context"])
            length = export["L"]
            expected_value = unhexlify(export["exported_value"])
            value = context.export(exporter_context, length)

            assert expected_value == value


@pytest.mark.parametrize("kem_id, kdf_id, aead_id", CIPHER_SUITES)
def test_open(test_vectors, kem_id, kdf_id, aead_id):
    for vector in test_vectors:
        if not (
            vector["kem_id"] == kem_id
            and vector["kdf_id"] == kdf_id
            and vector["aead_id"] == aead_id
        ):
            continue

        suite = create_suite(kem_id, kdf_id, aead_id)

        mode = vector["mode"]
        enc = unhexlify(vector["enc"])
        info = unhexlify(vector["info"])

        # Receiver private key
        sk_rm = unhexlify(vector["skRm"])
        sk_r = suite.kem.deserialize_private_key(sk_rm)

        if mode == Mode.BASE:
            context = suite.setup_recv(enc, sk_r, info)
        elif mode == Mode.PSK:
            psk = unhexlify(vector["psk"])
            psk_id = unhexlify(vector["psk_id"])
            context = suite.setup_psk_recv(enc, sk_r, info, psk, psk_id)
        elif mode == Mode.AUTH:
            # Sender public key
            pk_sm = unhexlify(vector["pkSm"])
            pk_s = suite.kem.deserialize_public_key(pk_sm)
            context = suite.setup_auth_recv(enc, sk_r, info, pk_s)
        elif mode == Mode.AUTH_PSK:
            # Sender private key
            pk_sm = unhexlify(vector["pkSm"])
            pk_s = suite.kem.deserialize_public_key(pk_sm)
            psk = unhexlify(vector["psk"])
            psk_id = unhexlify(vector["psk_id"])
            context = suite.setup_auth_psk_recv(
                enc, sk_r, info, pk_s, psk, psk_id
            )
        else:
            continue

        encryptions = vector["encryptions"]
        for encryption in encryptions:
            aad = unhexlify(encryption["aad"])
            ct = unhexlify(encryption["ct"])
            expected_pt = unhexlify(encryption["pt"])
            pt = context.open(ct, aad)

            assert expected_pt == pt

        exports = vector["exports"]
        for export in exports:
            exporter_context = unhexlify(export["exporter_context"])
            length = export["L"]
            expected_value = unhexlify(export["exported_value"])
            value = context.export(exporter_context, length)

            assert expected_value == value
