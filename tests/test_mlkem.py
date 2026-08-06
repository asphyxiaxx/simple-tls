from binascii import unhexlify

import pytest

from simple_tls._crypto import mlkem
from simple_tls.utils.random import get_random_bytes

from .utils import wycheproof_tests


def test_mlkem_end_to_end():
    """Tests the happy path: keygen -> encaps -> decaps"""

    def start(level: int, expected_pk_len: int):
        coins_keygen = get_random_bytes(64)
        coins_encaps = get_random_bytes(32)

        pub_key, priv_key = mlkem.keygen(level, coins_keygen)
        assert len(pub_key) == expected_pk_len

        ct, ss_sender = mlkem.encaps(level, pub_key, coins_encaps)
        assert isinstance(ct, bytes)
        assert isinstance(ss_sender, bytes)
        assert len(ss_sender) == 32  # ML-KEM shared secret is always 32 bytes

        ss_receiver = mlkem.decaps(level, ct, priv_key)

        assert ss_sender == ss_receiver

    start(768, 1184)
    start(1024, 1568)


def test_valid_public_key_lengths():
    """Tests that valid public key lengths are accepted by encaps"""
    coins_32 = b"\x00" * 32

    # Level 768 public key (1184 bytes)
    ct_768, ss_768 = mlkem.encaps(768, b"\x00" * 1184, coins_32)
    assert isinstance(ct_768, bytes)
    assert len(ss_768) == 32

    # Level 1024 public key (1568 bytes)
    ct_1024, ss_1024 = mlkem.encaps(1024, b"\x00" * 1568, coins_32)
    assert isinstance(ct_1024, bytes)
    assert len(ss_1024) == 32


def test_invalid_lengths_and_levels(subtests):
    """Tests that invalid byte lengths or security levels raise ValueError"""
    coins_32 = b"\x00" * 32
    coins_64 = b"\x00" * 64

    with subtests.test(msg="invalid level"):
        with pytest.raises(ValueError):
            mlkem.keygen(999, coins_64)

    with subtests.test(msg="invalid keygen coins length"):
        with pytest.raises(ValueError):
            mlkem.keygen(768, b"\x00" * 32)  # Needs 64 bytes

    with subtests.test(msg="invalid encaps public key length (level 768)"):
        with pytest.raises(ValueError):
            mlkem.encaps(768, b"\x00" * 999, coins_32)

    with subtests.test(msg="invalid encaps public key length (level 1024)"):
        with pytest.raises(ValueError):
            mlkem.encaps(1024, b"\x00" * 999, coins_32)

    with subtests.test(msg="invalid encaps coins length"):
        with pytest.raises(ValueError):
            mlkem.encaps(768, b"\x00" * 1184, b"\x00" * 16)  # Needs 32 bytes


def test_implicit_rejection(subtests):
    """Tests that modifying the ciphertext results in implicit rejection

    (different shared secret rather than crashing)
    """

    def flip_ciphertext(ciphertext: bytes) -> bytes:
        tampered_ct = bytearray(ciphertext)
        tampered_ct[0] ^= 0x01
        return bytes(tampered_ct)

    coins_keygen = b"\x42" * 64
    coins_encaps = b"\x24" * 32

    for level in (768, 1024):
        with subtests.test(level=level):
            pub_key, priv_key = mlkem.keygen(level, coins_keygen)

            ct, original_ss = mlkem.encaps(level, pub_key, coins_encaps)
            tampered_ct = flip_ciphertext(ct)

            # ML-KEM uses implicit rejection: returns a pseudo-random
            # string without raising an exception
            rejected_ss = mlkem.decaps(level, tampered_ct, priv_key)

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
