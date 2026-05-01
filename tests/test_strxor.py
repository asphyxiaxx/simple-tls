import pytest
from simple_tls.utils.math import strxor


def test_strxor_success():
    """Test that two identical-length byte strings XOR correctly."""
    b1 = b"\x00\xff\x55"
    b2 = b"\xaa\xaa\xaa"
    expected = b"\xaa\x55\xff"
    result = strxor(b1, b2)

    assert result == expected


def test_strxor_length_mismatch():
    """Test that the function rejects mismatched lengths."""
    b1 = b"\x00\xff"
    b2 = b"\xaa"

    with pytest.raises(ValueError):
        strxor(b1, b2)
