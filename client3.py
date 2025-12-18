# File dari sisi client 
# Lengkapi file ini dengan proses-proses pembuatan private, public key, pembuatan pesan rahasia
# TIPS: Untuk private, public key bisa dibuat di sini lalu disimpan dalam file
# sebelum mengakses laman Swagger API

from cryptography.hazmat.primitives.asymmetric import ec, padding,ed25519
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

from cryptography import x509
from cryptography.x509.oid import NameOID
import datetime
import base64
import os
import hashlib
from pathlib import Path


KEY_DIR = "punkhazard-keys"
os.makedirs(KEY_DIR, exist_ok=True)

PRIVATE_KEY_PATH = os.path.join(KEY_DIR, "najwa_private_key.pem")
PUBLIC_KEY_PATH  = os.path.join(KEY_DIR, "najwa_public_key.pem")

# TODO: Lengkapi proses-proses pembuatan private dan public key
# untuk users yang disimulasikan
# 1. Generate private & public key (ECDSA SECP256K1)
# TODO: Lengkapi proses-proses lain enkripsi simetrik (jika dibutuhkan)
# di mana pesan rahasia tersebut akan ditransmisikan
# 2. Simpan private key ke file

if not os.path.exists(PRIVATE_KEY_PATH):
    priv_key = ec.generate_private_key(ec.SECP256K1())
    pub_key = priv_key.public_key()

    with open(PRIVATE_KEY_PATH, "wb") as f:
        f.write(
            priv_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    with open(PUBLIC_KEY_PATH, "wb") as f:
        f.write(
            pub_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
    print("Kunci privat dan publik berhasil dibuat!")
else:
    with open(PRIVATE_KEY_PATH, "rb") as f:
        priv_key = serialization.load_pem_private_key(
            f.read(), password=None
        )
    print("Kunci sudah ada, tidak dibuat ulang")

pesan = input("Silakan tulis pesan anda disini: ")

# signature (ECDSA + SHA256)
signature = priv_key.sign(
    pesan.encode(),
    ec.ECDSA(hashes.SHA256())
)

# Convert signature ke Base64
signature_b64 = base64.b64encode(signature).decode()

with open("message.txt", "w") as f:
    f.write(pesan)

with open("signature.txt", "w") as f:
    f.write(signature_b64)

print(f"Signature Pesan:\n{signature_b64}")

#PDF
PDF_PATH = "Tabel Kolmogorov Smirnov - One Sample.pdf"

def sign_pdf(pdf_path: str):
    with open(PRIVATE_KEY_PATH, "rb") as f:
            priv_key = serialization.load_pem_private_key(
                f.read(), password=None
            )
    # Baca PDF & hash
    with open(pdf_path, "rb") as f:
        pdf_contents = f.read()

    pdf_hash = hashlib.sha256(pdf_contents).digest()

    # Sign hash
    signature = priv_key.sign(
        pdf_hash,
        ec.ECDSA(hashes.SHA256())
    )

    # Base64
    return base64.b64encode(signature).decode()

signature_b64 = sign_pdf(PDF_PATH)
print("PDF berhasil ditandatangani")
print(f"File   : {PDF_PATH}")
print(f"Signature PDF:\n{signature_b64}")