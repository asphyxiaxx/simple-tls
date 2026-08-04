# mypy: ignore-errors

import argparse
import json
from pathlib import Path


def generate_kat_file(outputpath: str | Path) -> None:
    test_vectors = []

    # Test Parameters
    block_sizes = [1, 8, 16, 32, 64]
    digest_sizes = [0, 16, 20, 32, 48, 64]
    plaintext_lengths = [0, 1, 7, 15, 16, 31, 32, 63, 64]

    tc_id = 0

    for bs in block_sizes:
        for ds in digest_sizes:
            for ptl in plaintext_lengths:
                is_stream = bs == 1

                # Generate the Valid Baseline Data
                pt = b"\xaa" * ptl
                mac = b"\xbb" * ds

                if is_stream:
                    data = pt + mac
                else:
                    # Calculate padding to align to the block size
                    rem = (ptl + ds) % bs
                    pad_len = bs - 1 - rem
                    if pad_len < 0:
                        pad_len += bs

                    pad = bytes([pad_len]) * (pad_len + 1)
                    data = pt + mac + pad

                overhead = (0 if bs == 1 else 1) + ds
                if overhead > len(data) or ds == 0:
                    explicit_error = True
                else:
                    explicit_error = False

                # Test Case: Valid Data
                tc_id += 1
                test_vectors.append(
                    {
                        "id": tc_id,
                        "type": "valid",
                        "block_size": bs,
                        "digest_size": ds,
                        "data_hex": data.hex(),
                        "expected_length": len(pt),
                        "expected_mac_hex": mac.hex(),
                        "explicit_error": False,
                    }
                )

                # Test Case: Invalid Padding (Block ciphers only)
                if not is_stream and len(data) > 0:
                    tc_id += 1
                    bad_pad_data = bytearray(data)
                    # Corrupt the very first byte of the padding sequence
                    pad_start_idx = len(data) - (pad_len + 1)
                    bad_pad_data[pad_start_idx] ^= 0xFF

                    test_vectors.append(
                        {
                            "id": tc_id,
                            "type": "invalid_padding_byte",
                            "block_size": bs,
                            "digest_size": ds,
                            "data_hex": bad_pad_data.hex(),
                            "expected_length": None,
                            "expected_mac_hex": None,
                            "explicit_error": explicit_error,
                        }
                    )

                # Test Case: Truncated Data (Pad length exceeds array bounds)
                if not is_stream and len(data) > 0:
                    trunc_data = bytearray(data)
                    # Lie about the padding length so it overruns the buffer
                    fake_pad_len = len(data)
                    if fake_pad_len <= 255:
                        tc_id += 1
                        trunc_data[-1] = fake_pad_len

                        test_vectors.append(
                            {
                                "id": tc_id,
                                "type": "invalid_pad_too_long",
                                "block_size": bs,
                                "digest_size": ds,
                                "data_hex": trunc_data.hex(),
                                "expected_length": None,
                                "expected_mac_hex": None,
                                "explicit_error": explicit_error,
                            }
                        )

                # Test Case: Data shorter than Digest Size
                # We only need to generate this once per digest size
                if ptl == 0 and ds > 0:
                    tc_id += 1
                    short_data = b"\xcc" * (ds - 1)

                    test_vectors.append(
                        {
                            "id": tc_id,
                            "type": "invalid_mac_too_short",
                            "block_size": bs,
                            "digest_size": ds,
                            "data_hex": short_data.hex(),
                            "expected_length": None,
                            "expected_mac_hex": None,
                            "explicit_error": True,
                        }
                    )

    # Ensure parent directories exist if a directory path is provided
    filepath = Path(outputpath)
    filepath.parent.mkdir(parents=True, exist_ok=True)

    with open(filepath, "w") as f:
        json.dump(test_vectors, f, indent=4)

    print(
        f"Successfully generated {len(test_vectors)} test vectors in "
        f"'{filepath}'"
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Generate KAT for cbc_remove_pad_and_mac."
    )
    parser.add_argument(
        "-o",
        "--output-path",
        type=str,
        help="Path to output file",
        required=True,
        metavar="",
    )

    args = parser.parse_args()

    generate_kat_file(args.output_path)
