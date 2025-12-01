# gen_client_cert.py
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta

print("\n[+] Generating Client certificate...\n")

# Load CA
with open("ca_key.pem", "rb") as f:
    ca_key = serialization.load_pem_private_key(f.read(), password=None)
with open("ca_cert.pem", "rb") as f:
    ca_cert = x509.load_pem_x509_certificate(f.read())

# Client key
client_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

client_name = x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, u"WajihaClient")
])

# Sign certificate using CA
client_cert = (
    x509.CertificateBuilder()
    .subject_name(client_name)
    .issuer_name(ca_cert.subject)
    .public_key(client_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.utcnow())
    .not_valid_after(datetime.utcnow() + timedelta(days=365))
    .sign(private_key=ca_key, algorithm=hashes.SHA256())
)

# Save files
with open("client_key.pem", "wb") as f:
    f.write(client_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()
    ))

with open("client_cert.pem", "wb") as f:
    f.write(client_cert.public_bytes(serialization.Encoding.PEM))

print("[+] Client certificate generated!")
