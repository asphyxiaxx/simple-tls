from binascii import unhexlify

import pytest
from simple_tls._crypto import mlkem
from simple_tls.key.mlkem import (
    MLKEM768PrivateKey,
    MLKEM768PublicKey,
    MLKEM1024PrivateKey,
    MLKEM1024PublicKey,
)

from .utils import wycheproof_tests


def test_mlkem_end_to_end():
    """Tests the happy path: KeyGen -> Encaps -> Decaps"""

    def start(priv_key, expected_pk_len):
        pub_key = priv_key.public_key()
        assert len(pub_key.public_bytes_raw()) == expected_pk_len

        ss_sender, ct = pub_key.encapsulate()
        assert isinstance(ct, bytes)
        assert isinstance(ss_sender, bytes)
        assert len(ss_sender) == 32  # ML-KEM shared secret is always 32 bytes

        ss_receiver = priv_key.decapsulate(ct)

        assert ss_sender == ss_receiver

    start(MLKEM768PrivateKey.generate(), 1184)
    start(MLKEM1024PrivateKey.generate(), 1568)


def test_from_public_bytes_valid_lengths():
    """
    Tests that the factory method correctly identifies levels based
    on length
    """
    _ = MLKEM768PublicKey.from_public_bytes(b"\x00" * 1184)
    _ = MLKEM1024PublicKey.from_public_bytes(b"\x00" * 1568)


def test_from_public_bytes_invalid_length(subtests):
    """
    Tests that invalid byte lengths raise the correct exception
    """
    with subtests.test(level=768):
        with pytest.raises(ValueError):
            MLKEM768PublicKey.from_public_bytes(b"\x00" * 999)

    with subtests.test(level=1024):
        with pytest.raises(ValueError):
            MLKEM1024PublicKey.from_public_bytes(b"\x00" * 999)


def test_implicit_rejection(subtests):
    """
    Tests that modifying the ciphertext results in implicit rejection
    (different shared secret)
    """

    def flip_ciphertext(ciphertext: bytes):
        # Flip the first bit of the ciphertext
        tampered_ct = bytearray(ciphertext)
        tampered_ct[0] ^= 0x01
        return bytes(tampered_ct)

    with subtests.test(level=768):
        priv_key = MLKEM768PrivateKey.generate()
        pub_key = priv_key.public_key()

        original_ss, ct = pub_key.encapsulate()
        tampered_ct = flip_ciphertext(ct)

        # ML-KEM uses implicit rejection, so it should return a pseudo-random
        # string, NOT crash
        rejected_ss = priv_key.decapsulate(tampered_ct)

        assert rejected_ss != original_ss
        assert len(rejected_ss) == 32

    with subtests.test(level=1024):
        priv_key = MLKEM1024PrivateKey.generate()
        pub_key = priv_key.public_key()

        original_ss, ct = pub_key.encapsulate()
        tampered_ct = flip_ciphertext(ct)

        # ML-KEM uses implicit rejection, so it should return a pseudo-random
        # string, NOT crash
        rejected_ss = priv_key.decapsulate(tampered_ct)

        assert rejected_ss != original_ss
        assert len(rejected_ss) == 32


PARAMETER_SET_MAPPING = {
    "ML-KEM-1024": 1024,
    "ML-KEM-768": 768,
    "ML-KEM-512": 512,
}


@wycheproof_tests(
    "mlkem_1024_keygen_seed_test.json",
    "mlkem_768_keygen_seed_test.json",
    "mlkem_512_keygen_seed_test.json",
)
def test_mlkem_keygen(wycheproof):
    assert wycheproof.valid

    paramter_set = wycheproof.test_group["parameterSet"]
    level = PARAMETER_SET_MAPPING[paramter_set]

    seed = unhexlify(wycheproof.test_case["seed"])
    expected_ek = unhexlify(wycheproof.test_case["ek"])
    expected_dk = unhexlify(wycheproof.test_case["dk"])

    ek, dk = mlkem.keygen(level, seed)

    assert ek == expected_ek
    assert dk == expected_dk


@wycheproof_tests(
    "mlkem_1024_encaps_test.json",
    "mlkem_768_encaps_test.json",
    "mlkem_512_encaps_test.json",
)
def test_mlkem_encaps(wycheproof):
    paramter_set = wycheproof.test_group["parameterSet"]
    level = PARAMETER_SET_MAPPING[paramter_set]

    ek = unhexlify(wycheproof.test_case["ek"])
    m = unhexlify(wycheproof.test_case["m"])
    expected_ct = unhexlify(wycheproof.test_case["c"])
    expected_ss = unhexlify(wycheproof.test_case["K"])

    if wycheproof.invalid:
        with pytest.raises(ValueError):
            mlkem.encaps(level, ek, m)

    else:
        assert wycheproof.valid

        ct, ss = mlkem.encaps(level, ek, m)

        assert ct == expected_ct
        assert ss == expected_ss


@wycheproof_tests(
    "mlkem_1024_test.json",
    "mlkem_768_test.json",
    "mlkem_512_test.json",
)
def test_mlkem_decaps(wycheproof):
    paramter_set = wycheproof.test_group["parameterSet"]
    level = PARAMETER_SET_MAPPING[paramter_set]

    comment = wycheproof.test_case.get("comment", "")
    seed = unhexlify(wycheproof.test_case["seed"])

    if wycheproof.invalid and comment in (
        "Private key too short",
        "Private key too long",
    ):
        with pytest.raises(ValueError):
            mlkem.keygen(level, seed)
        return

    ct = unhexlify(wycheproof.test_case["c"])
    expected_ek = unhexlify(wycheproof.test_case["ek"])

    ek, dk = mlkem.keygen(level, seed)
    assert ek == expected_ek

    if wycheproof.invalid and comment in (
        "Ciphertext too short",
        "Ciphertext too long",
    ):
        with pytest.raises(ValueError):
            mlkem.decaps(level, ct, dk)
        return

    assert wycheproof.valid

    ct = unhexlify(wycheproof.test_case["c"])
    expected_ek = unhexlify(wycheproof.test_case["ek"])
    expected_ss = unhexlify(wycheproof.test_case["K"])

    ek, dk = mlkem.keygen(level, seed)
    assert ek == expected_ek

    ss = mlkem.decaps(level, ct, dk)
    assert ss == expected_ss
