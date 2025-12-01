# gen_ca.py
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography import x509
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta

print("\n[+] Generating Root CA...\n")

# CA private key
ca_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

# CA certificate
ca_name = x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, u"MyRootCA")
])

ca_cert = (
    x509.CertificateBuilder()
    .subject_name(ca_name)
    .issuer_name(ca_name)        # self-signed
    .public_key(ca_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.utcnow())
    .not_valid_after(datetime.utcnow() + timedelta(days=365))
    .add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True
    )
    .sign(private_key=ca_key, algorithm=hashes.SHA256())
)

# Save files
with open("ca_key.pem", "wb") as f:
    f.write(ca_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()
    ))

with open("ca_cert.pem", "wb") as f:
    f.write(ca_cert.public_bytes(serialization.Encoding.PEM))

print("[+] Root CA created successfully!")
