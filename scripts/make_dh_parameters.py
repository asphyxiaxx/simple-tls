import argparse

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dh


def generate_dh_pem(filename="dhparam.pem", key_size=2048):
    print(
        f"Generating {key_size}-bit DH parameters "
        f"(this may take a few minutes)..."
    )

    # Generate parameters using a standard generator (usually 2)
    parameters = dh.generate_parameters(generator=2, key_size=key_size)

    # Serialize parameters into PEM format
    pem_data = parameters.parameter_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.ParameterFormat.PKCS3,
    )

    # Save to file
    with open(filename, "wb") as f:
        f.write(pem_data)

    print(f"Successfully saved DH parameters to {filename}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate DH parameters.")
    parser.add_argument(
        "-o",
        "--output-path",
        type=str,
        help="Path to output file",
        required=True,
        metavar="",
    )
    parser.add_argument(
        "-s",
        "--key-size",
        type=int,
        help="Key size in bits (default: 2048)",
        default=2048,
        metavar="",
    )

    args = parser.parse_args()

    generate_dh_pem(args.output_path, key_size=args.key_size)
