# mypy: ignore-errors

import argparse
import datetime
import ipaddress
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import (
    dsa,
    ec,
    ed448,
    ed25519,
    rsa,
)
from cryptography.hazmat.primitives.asymmetric.types import (
    CertificateIssuerPrivateKeyTypes,
)
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def write_to_file(filepath: str | Path, data: bytes) -> None:
    with open(filepath, "wb") as f:
        f.write(data)


def write_key_cert(
    private_key: CertificateIssuerPrivateKeyTypes,
    certificates: x509.Certificate | list[x509.Certificate],
    filename_prefix: str,
    output_dir: Path,
) -> None:
    write_to_file(
        output_dir / f"{filename_prefix}.key",
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ),
    )

    if isinstance(certificates, x509.Certificate):
        pem_data = certificates.public_bytes(serialization.Encoding.PEM)
    else:
        pem_data = b"".join(
            c.public_bytes(serialization.Encoding.PEM) for c in certificates
        )

    write_to_file(output_dir / f"{filename_prefix}.crt", pem_data)


def generate_root_ca() -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    print("Generating RSA Root CA...")
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048
    )

    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "State"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "City"),
            x509.NameAttribute(
                NameOID.ORGANIZATION_NAME, "My Test Organization"
            ),
            x509.NameAttribute(NameOID.COMMON_NAME, "My Master RSA Root CA"),
        ]
    )

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(
            datetime.datetime.now(datetime.timezone.utc)
            + datetime.timedelta(days=3650)
        )
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .sign(private_key, hashes.SHA256())
    )

    return private_key, cert


def generate_intermediate_ca(
    root_key: CertificateIssuerPrivateKeyTypes,
    root_cert: x509.Certificate,
) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    print("Generating RSA Intermediate CA...")
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048
    )

    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "State"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "City"),
            x509.NameAttribute(
                NameOID.ORGANIZATION_NAME, "My Test Organization"
            ),
            x509.NameAttribute(NameOID.COMMON_NAME, "My Intermediate RSA CA"),
        ]
    )

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(root_cert.subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(
            datetime.datetime.now(datetime.timezone.utc)
            + datetime.timedelta(days=1825)
        )
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=0),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                root_key.public_key()
            ),
            critical=False,
        )
        .sign(root_key, hashes.SHA256())
    )

    return private_key, cert


def generate_leaf_cert(
    ca_key: CertificateIssuerPrivateKeyTypes,
    ca_cert: x509.Certificate,
    leaf_private_key: CertificateIssuerPrivateKeyTypes,
    extended_key_usages: list[ExtendedKeyUsageOID],
    common_name: str,
    organization_name: str = "Test Server",
    sans: list[x509.GeneralName] | None = None,
) -> x509.Certificate:
    print(f"Generating Leaf Certificate ({common_name})...")

    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "State"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "City"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization_name),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )

    can_encipher = not isinstance(leaf_private_key, dsa.DSAPrivateKey)

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(leaf_private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(
            datetime.datetime.now(datetime.timezone.utc)
            + datetime.timedelta(days=365)
        )
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=can_encipher,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage(extended_key_usages),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                ca_key.public_key()
            ),
            critical=False,
        )
    )

    if sans:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(sans),
            critical=False,
        )

    return builder.sign(ca_key, hashes.SHA256())


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Generate CA, Server Leaf, and Client Leaf Certificates."
    )
    parser.add_argument(
        "output_dir",
        type=Path,
        nargs="?",
        default=Path("."),
        help=(
            "Target directory to save the generated certificates and keys "
            "(default: current directory)"
        ),
    )
    args = parser.parse_args()

    output_dir: Path = args.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    # Generate the Root CA
    root_key, root_cert = generate_root_ca()
    write_key_cert(root_key, root_cert, "root_ca", output_dir)

    # Generate the Intermediate CA (Signed by Root CA)
    int_key, int_cert = generate_intermediate_ca(root_key, root_cert)
    write_key_cert(int_key, int_cert, "intermediate_ca", output_dir)

    # --- SERVER LEAF CERTIFICATES ---
    server_sans = [
        x509.DNSName("localhost"),
        x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
    ]

    rsa_leaf_key = rsa.generate_private_key(65537, 2048)
    rsa_leaf_cert = generate_leaf_cert(
        int_key,
        int_cert,
        rsa_leaf_key,
        extended_key_usages=[ExtendedKeyUsageOID.SERVER_AUTH],
        common_name="localhost-rsa",
        organization_name="Test Server",
        sans=server_sans,
    )
    write_key_cert(
        rsa_leaf_key,
        [rsa_leaf_cert, int_cert],
        "server_rsa",
        output_dir,
    )

    ec_leaf_key = ec.generate_private_key(ec.SECP256R1())
    ec_leaf_cert = generate_leaf_cert(
        int_key,
        int_cert,
        ec_leaf_key,
        extended_key_usages=[ExtendedKeyUsageOID.SERVER_AUTH],
        common_name="localhost-ec",
        organization_name="Test Server",
        sans=server_sans,
    )
    write_key_cert(
        ec_leaf_key,
        [ec_leaf_cert, int_cert],
        "server_ec_secp256r1",
        output_dir,
    )

    dsa_leaf_key = dsa.generate_private_key(key_size=2048)
    dsa_leaf_cert = generate_leaf_cert(
        int_key,
        int_cert,
        dsa_leaf_key,
        extended_key_usages=[ExtendedKeyUsageOID.SERVER_AUTH],
        common_name="localhost-dsa",
        organization_name="Test Server",
        sans=server_sans,
    )
    write_key_cert(
        dsa_leaf_key,
        [dsa_leaf_cert, int_cert],
        "server_dsa",
        output_dir,
    )

    ed25519_leaf_key = ed25519.Ed25519PrivateKey.generate()
    ed25519_leaf_cert = generate_leaf_cert(
        int_key,
        int_cert,
        ed25519_leaf_key,
        extended_key_usages=[ExtendedKeyUsageOID.SERVER_AUTH],
        common_name="localhost-ed25519",
        organization_name="Test Server",
        sans=server_sans,
    )
    write_key_cert(
        ed25519_leaf_key,
        [ed25519_leaf_cert, int_cert],
        "server_ed25519",
        output_dir,
    )

    ed448_leaf_key = ed448.Ed448PrivateKey.generate()
    ed448_leaf_cert = generate_leaf_cert(
        int_key,
        int_cert,
        ed448_leaf_key,
        extended_key_usages=[ExtendedKeyUsageOID.SERVER_AUTH],
        common_name="localhost-ed448",
        organization_name="Test Server",
        sans=server_sans,
    )
    write_key_cert(
        ed448_leaf_key,
        [ed448_leaf_cert, int_cert],
        "server_ed448",
        output_dir,
    )

    # --- CLIENT LEAF CERTIFICATES ---
    rsa_client_key = rsa.generate_private_key(65537, 2048)
    rsa_client_cert = generate_leaf_cert(
        int_key,
        int_cert,
        rsa_client_key,
        extended_key_usages=[ExtendedKeyUsageOID.CLIENT_AUTH],
        common_name="client-rsa-user",
        organization_name="Test Client",
    )
    write_key_cert(
        rsa_client_key,
        [rsa_client_cert, int_cert],
        "client_rsa",
        output_dir,
    )

    # 9. Generate EC Client Certificate
    ec_client_key = ec.generate_private_key(ec.SECP256R1())
    ec_client_cert = generate_leaf_cert(
        int_key,
        int_cert,
        ec_client_key,
        extended_key_usages=[ExtendedKeyUsageOID.CLIENT_AUTH],
        common_name="client-ec-user",
        organization_name="Test Client",
    )
    write_key_cert(
        ec_client_key,
        [ec_client_cert, int_cert],
        "client_ec_secp256r1",
        output_dir,
    )

    dsa_client_key = dsa.generate_private_key(key_size=2048)
    dsa_client_cert = generate_leaf_cert(
        int_key,
        int_cert,
        dsa_client_key,
        extended_key_usages=[ExtendedKeyUsageOID.CLIENT_AUTH],
        common_name="client-dsa-user",
        organization_name="Test Client",
    )
    write_key_cert(
        dsa_client_key,
        [dsa_client_cert, int_cert],
        "client_dsa",
        output_dir,
    )

    ed25519_client_key = ed25519.Ed25519PrivateKey.generate()
    ed25519_client_cert = generate_leaf_cert(
        int_key,
        int_cert,
        ed25519_client_key,
        extended_key_usages=[ExtendedKeyUsageOID.CLIENT_AUTH],
        common_name="client-ed25519-user",
        organization_name="Test Client",
    )
    write_key_cert(
        ed25519_client_key,
        [ed25519_client_cert, int_cert],
        "client_ed25519",
        output_dir,
    )

    ed448_client_key = ed448.Ed448PrivateKey.generate()
    ed448_client_cert = generate_leaf_cert(
        int_key,
        int_cert,
        ed448_client_key,
        extended_key_usages=[ExtendedKeyUsageOID.CLIENT_AUTH],
        common_name="client-ed448-user",
        organization_name="Test Client",
    )
    write_key_cert(
        ed448_client_key,
        [ed448_client_cert, int_cert],
        "client_ed448",
        output_dir,
    )

    print(f"All certificates generated successfully in '{output_dir}'")
