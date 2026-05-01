import datetime
import ipaddress

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import (
    dsa,
    ec,
    rsa,
    ed25519,
    ed448,
)
from cryptography.hazmat.primitives.asymmetric.types import (
    CertificateIssuerPrivateKeyTypes,
)
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def write_to_file(filename: str, data: bytes):
    with open(filename, "wb") as f:
        f.write(data)


def generate_root_ca():
    print("Generating RSA Root CA...")
    # 1. Generate RSA 2048-bit Private Key
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048
    )

    # 2. Build the CA Subject/Issuer Name
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

    # 3. Build the CA Certificate
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(
            # Valid for 10 years
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
):
    print("Generating RSA Intermediate CA...")
    # 1. Generate RSA 2048-bit Private Key for Intermediate
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048
    )

    # 2. Build the Intermediate CA Subject Name
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

    # 3. Build the Intermediate Certificate
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(root_cert.subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(
            # Valid for 5 years
            datetime.datetime.now(datetime.timezone.utc)
            + datetime.timedelta(days=1825)
        )
        .add_extension(
            # path_length=0 means it can sign leaf certs, but cannot sign other CAs
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
                key_cert_sign=True,  # Critical for a CA
                crl_sign=True,  # Critical for a CA
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
    )  # Signed by the Root CA's private key

    return private_key, cert


def generate_leaf_cert(
    ca_key: CertificateIssuerPrivateKeyTypes,
    ca_cert: x509.Certificate,
    leaf_private_key: CertificateIssuerPrivateKeyTypes,
    common_name: str,
    filename_prefix: str,
):
    print(f"Generating Leaf Certificate: {common_name}...")

    # 1. Build the Leaf Subject Name
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "State"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "City"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Server"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )

    # DSA keys can only be used for signatures, not encipherment.
    # RSA and EC can be used for both in TLS.
    can_encipher = not isinstance(leaf_private_key, dsa.DSAPrivateKey)

    # 2. Build the Leaf Certificate
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(leaf_private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(
            # Valid for 1 year
            datetime.datetime.now(datetime.timezone.utc)
            + datetime.timedelta(days=365)
        )
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
                ]
            ),
            critical=False,
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
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                ca_key.public_key()
            ),
            critical=False,
        )
        # Signed by the CA's RSA private key
        .sign(ca_key, hashes.SHA256())
    )

    # 3. Save to files
    write_to_file(
        f"{filename_prefix}.key",
        leaf_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ),
    )

    # Serialize both certificates
    leaf_pem = cert.public_bytes(serialization.Encoding.PEM)
    intermediate_pem = ca_cert.public_bytes(serialization.Encoding.PEM)

    # Write just the leaf certificate (optional, good for debugging)
    write_to_file(
        f"{filename_prefix}.crt",
        leaf_pem,
    )

    # Write the full certificate chain (Leaf first, then Intermediate)
    write_to_file(
        f"{filename_prefix}_chain.crt",
        leaf_pem + intermediate_pem,
    )


if __name__ == "__main__":
    # 1. Generate the Root CA
    root_key, root_cert = generate_root_ca()
    write_to_file(
        "root_ca.key",
        root_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ),
    )
    write_to_file(
        "root_ca.crt",
        root_cert.public_bytes(serialization.Encoding.PEM),
    )

    # 2. Generate the Intermediate CA (Signed by Root CA)
    int_key, int_cert = generate_intermediate_ca(root_key, root_cert)
    write_to_file(
        "intermediate_ca.key",
        int_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ),
    )
    write_to_file(
        "intermediate_ca.crt",
        int_cert.public_bytes(serialization.Encoding.PEM),
    )

    # 3. Generate RSA Leaf (Signed by Intermediate CA)
    rsa_leaf_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048
    )
    generate_leaf_cert(
        int_key,
        int_cert,
        rsa_leaf_key,
        "localhost-rsa",
        "server_rsa",
    )

    # 4. Generate EC Leaf (Signed by Intermediate CA)
    ec_leaf_key = ec.generate_private_key(ec.SECP256R1())
    generate_leaf_cert(
        int_key,
        int_cert,
        ec_leaf_key,
        "localhost-ec",
        "server_ec_secp256r1",
    )

    # 5. Generate DSA Leaf (Signed by Intermediate CA)
    dsa_leaf_key = dsa.generate_private_key(key_size=2048)
    generate_leaf_cert(
        int_key,
        int_cert,
        dsa_leaf_key,
        "localhost-dsa",
        "server_dsa",
    )

    # 5. Generate Ed25519 Leaf (Signed by Intermediate CA)
    ed25519_leaf_key = ed25519.Ed25519PrivateKey.generate()
    generate_leaf_cert(
        int_key,
        int_cert,
        ed25519_leaf_key,
        "localhost-ed25519",
        "server_ed25519",
    )

    # 5. Generate Ed25519 Leaf (Signed by Intermediate CA)
    ed448_leaf_key = ed448.Ed448PrivateKey.generate()
    generate_leaf_cert(
        int_key,
        int_cert,
        ed448_leaf_key,
        "localhost-ed448",
        "server_ed448",
    )

    print("All certificates generated successfully!")
