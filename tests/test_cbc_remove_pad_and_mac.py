import json

import pytest

from simple_tls.utils.constant_time import cbc_remove_pad_and_mac

from .utils import load


def load_test_vectors():
    """loads the JSON once and passes it to any test that asks for it"""
    return json.loads(load("test_vectors", "cbc_mac_pad_kat.json"))


@pytest.mark.parametrize(
    "vector",
    load_test_vectors(),
    ids=lambda v: f"ID:{v['id']}-{v['type']}",
)
def test_cbc_remove_pad_and_mac_constant_time(vector):
    data = bytes.fromhex(vector["data_hex"])
    digest_size = vector["digest_size"]
    block_size = vector["block_size"]

    # Valid Data
    if vector["type"] == "valid":
        # Valid data should extract perfectly, matching the KAT expectations.
        expected_length = vector["expected_length"]
        expected_mac = bytes.fromhex(vector["expected_mac_hex"])

        length, extracted_mac = cbc_remove_pad_and_mac(
            data, digest_size, block_size
        )

        assert length == expected_length, (
            f"Expected length {expected_length}, got {length}"
        )
        assert extracted_mac == expected_mac, (
            "Extracted MAC does not match expected MAC"
        )

    else:
        explicit_error = vector["explicit_error"]
        if explicit_error:
            # This is the ONLY time the function is allowed to raise a
            # ValueError. It is safe because an attacker cannot exploit
            # data shorter than a MAC.
            with pytest.raises(ValueError):
                cbc_remove_pad_and_mac(data, digest_size, block_size)

        else:
            # The KAT file expects a ValueError here (because the padding is
            # mathematically broken). However, a Constant-Time function MUST
            # NOT crash. It must absorb the error and return dummy values to
            # defeat Padding Oracle attacks.
            try:
                length, dummy_mac = cbc_remove_pad_and_mac(
                    data, digest_size, block_size
                )
            except ValueError as e:
                pytest.fail(
                    f"Padding orable vulnerability. Function raised an error "
                    f"instead of returning dummy values: {e}"
                )

            # Verify it returned safe dummy values
            assert 0 <= length <= len(data)
            assert len(dummy_mac) == digest_size, (
                "Dummy MAC must be the exact expected digest size"
            )
