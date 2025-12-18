# File utama API yang menjadi core logic dari layanan keamanan (security service)
# Peran server dijelaskan pada soal
# TIPS: Gunakan file .txt sederhana untuk menyimpan data-data pengguna

from fastapi import FastAPI, HTTPException, UploadFile, File, Form, Depends, Header, Query
from fastapi.middleware.cors import CORSMiddleware
import os
from datetime import datetime, timedelta
import hashlib
import base64
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.exceptions import InvalidSignature
from cryptography.fernet import Fernet
from jose import jwt, JWTError

app = FastAPI(title="Security Service - Punk Records v1", version="2.0")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Folder penyimpanan server
DATA_DIR = "data"
KEYS_DIR = os.path.join(DATA_DIR, "keys")
INBOX_DIR = os.path.join(DATA_DIR, "inbox")
USERS_FILE = os.path.join(DATA_DIR, "users.txt")
PDF_DIR = os.path.join(DATA_DIR, "pdfs")

os.makedirs(KEYS_DIR, exist_ok=True)
os.makedirs(INBOX_DIR, exist_ok=True)
os.makedirs(PDF_DIR, exist_ok=True)

if not os.path.exists(USERS_FILE):
    open(USERS_FILE, "w").close()

# Symmetric key untuk enkripsi pesan (Fernet)
SYM_KEY_FILE = "data/sym.key"

if os.path.exists(SYM_KEY_FILE):
    SYM_KEY = open(SYM_KEY_FILE, "rb").read()
else:
    SYM_KEY = Fernet.generate_key()
    with open(SYM_KEY_FILE, "wb") as f:
        f.write(SYM_KEY)

fernet = Fernet(SYM_KEY)

#JWT Config
SECRET_KEY = "vegapunk-uas-2025"
ALGORITHM = "HS256"
TOKEN_EXPIRE = 60  # menit

#generate jwt token untuk user
def create_token(username: str):
    expire = datetime.utcnow() + timedelta(minutes=TOKEN_EXPIRE)
    payload = {"sub": username, "exp": expire}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


#verifikasi token di header
def verify_token_header(x_token: str = Header(None, alias="JWT-Token")):
    if x_token is None or not x_token.startswith("Bearer "):
        raise HTTPException(401, "Token tidak sesuai. Gunakan: Bearer <token>")
    token = x_token.split(" ")[1]

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        
        if not username or not isinstance(username, str):
            raise HTTPException(401, "Token payload invalid")
        
        return username
    
    except JWTError:
        raise HTTPException(401, "Token tidak valid / expired")

def verify_user_authorization(current_user: str, requested_user: str):
    if current_user != requested_user:
        raise HTTPException(
            403, 
            f"Anda tidak diizinkan mengakses data {requested_user}. "
            f"Current user: {current_user}"
        )

# Fungsi contoh untuk memeriksa apakah layanan berjalan dengan baik (health check)
@app.get("/health")
async def health_check():
    return {
        "status": "Security Service is running",
        "timestamp": datetime.now().isoformat()
    }

# Fungsi akses pada lokasi "root" atau "index"
@app.get("/")
async def get_index() -> dict:
    return {
        "message": "Punk Records v1 - Security Service",
        "docs": "Please visit http://localhost:8080/docs"
    }


# Login - dapatkan jwt token
@app.post("/login")
async def login(username: str = Form(...)):
    token = create_token(username)
    return {"username": username, "token": token}


# Fungsi untuk mendapatkan public key user dari penyimpanan
def get_user_pubkey(username: str):
    if not os.path.exists(USERS_FILE):
        return None
        
    lines = open(USERS_FILE).read().splitlines()

    for line in reversed(lines):
        if not line.strip():
            continue
        parts = line.split(",", 1)
        if len(parts) != 2:
            continue
        u, fname = parts
        if u == username:
            keypath = os.path.join(KEYS_DIR, fname)
            if os.path.exists(keypath):
                return open(keypath, "rb").read()
    return None

# Fungsi contoh untuk mengunggah file pdf
# Akses API pada URL http://localhost:8080/upload-pdf
@app.post("/upload")
async def upload_file(
    username: str = Form(...),
    signature_b64: str = Form(...),
    file: UploadFile = File(...),
    user=Depends(verify_token_header)
):
    verify_user_authorization(user, username)
    
    if file.content_type != "application/pdf":
        raise HTTPException(400, "Hanya file PDF yang diperbolehkan")

    pdf_path = os.path.join(PDF_DIR, file.filename)
    sig_path = pdf_path + ".sig"

    contents = await file.read()
    with open(pdf_path, "wb") as f:
        f.write(contents)

    with open(sig_path, "w") as f:
        f.write(signature_b64)

    return {
        "message": "PDF dan signature berhasil diunggah",
        "username": username,
        "pdf_saved_as": pdf_path,
        "signature_saved_as": sig_path
    }


@app.post("/store")
async def store_pubkey(
    username: str = Form(...),
    keyfile: UploadFile = File(...),
    user=Depends(verify_token_header)
):
    verify_user_authorization(user, username)
    
    contents = await keyfile.read()

    if not contents.startswith(b"-----BEGIN"):
        raise HTTPException(400, "File bukan PEM")

    if b"PUBLIC KEY" not in contents:
        raise HTTPException(400, "File tidak berisi public key")

    fp = hashlib.sha256(contents).hexdigest()[:16]
    filename = f"{username}_{fp}.pem"

    with open(os.path.join(KEYS_DIR, filename), "wb") as f:
        f.write(contents)

    with open(USERS_FILE, "a") as f:
        f.write(f"{username},{filename}\n")

    return {
        "message": "Public key berhasil disimpan",
        "username": username,
        "stored_file": filename,
        "fingerprint": fp
    }


# Fungsi API untuk memverifikasi signature yang dibuat oleh seorang pengguna
@app.post("/verify")
async def verify(
    username: str = Form(...),
    message: str = Form(...),
    signature_b64: str = Form(...),
    user=Depends(verify_token_header)
):
    pem_data = get_user_pubkey(username)
    if pem_data is None:
        raise HTTPException(404, f"Public key user '{username}' tidak ditemukan")

    try:
        pub = serialization.load_pem_public_key(pem_data)
    except Exception as e:
        raise HTTPException(400, f"Gagal memuat public key: {str(e)}")

    try:
        signature = base64.b64decode(signature_b64)
    except Exception as e:
        raise HTTPException(400, f"Signature base64 tidak valid: {str(e)}")

    try:
        if isinstance(pub, ed25519.Ed25519PublicKey):
            pub.verify(signature, message.encode())
            algo = "Ed25519"
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            pub.verify(signature, message.encode(), ec.ECDSA(hashes.SHA256()))
            algo = "ECDSA"
        else:
            raise HTTPException(400, "Tipe kunci tidak didukung")
    except InvalidSignature:
        raise HTTPException(400, "Signature tidak valid - verifikasi gagal")
    except Exception as e:
        raise HTTPException(400, f"Error saat verifikasi: {str(e)}")

    return {
        "message": f"Signature valid ({algo})",
        "username": username,
        "received_message": message
    }

# Fungsi API untuk memverifikasi signature pada file PDF yang diunggah
@app.post("/verify-pdf")
async def verify_pdf(
    username: str = Form(...),
    pdf_filename: str = Form(...),
    user=Depends(verify_token_header)
):
    pdf_path = os.path.join(PDF_DIR, pdf_filename)
    sig_path = pdf_path + ".sig"

    if not os.path.exists(pdf_path):
        raise HTTPException(404, "File PDF tidak ditemukan")

    if not os.path.exists(sig_path):
        raise HTTPException(404, "Signature PDF tidak ditemukan")

    pem_data = get_user_pubkey(username)
    if pem_data is None:
        raise HTTPException(404, f"Public key user '{username}' tidak ditemukan")

    try:
        pub_key = serialization.load_pem_public_key(pem_data)
    except Exception as e:
        raise HTTPException(400, f"Gagal memuat public key: {str(e)}")

    with open(pdf_path, "rb") as f:
        pdf_data = f.read()

    pdf_hash = hashlib.sha256(pdf_data).digest()

    try:
        with open(sig_path, "r") as f:
            signature = base64.b64decode(f.read())
    except Exception as e:
        raise HTTPException(400, f"Gagal membaca signature: {str(e)}")

    try:
        if isinstance(pub_key, ec.EllipticCurvePublicKey):
            pub_key.verify(
                signature,
                pdf_hash,
                ec.ECDSA(hashes.SHA256())
            )
            algo = "ECDSA"
        elif isinstance(pub_key, ed25519.Ed25519PublicKey):
            pub_key.verify(signature, pdf_hash)
            algo = "Ed25519"
        else:
            raise HTTPException(400, "Tipe key tidak didukung")
    except InvalidSignature:
        raise HTTPException(400, "Signature PDF tidak valid - verifikasi gagal")
    except Exception as e:
        raise HTTPException(400, f"Error saat verifikasi: {str(e)}")

    return {
        "message": f"Signature PDF VALID ({algo})",
        "username": username,
        "pdf": pdf_filename,
        "verified_at": datetime.now().isoformat()
    }


def verify_signature_internal(username: str, message: str, signature_b64: str):
    pem_data = get_user_pubkey(username)
    if pem_data is None:
        raise HTTPException(404, f"Public key user '{username}' tidak ditemukan")

    pub = serialization.load_pem_public_key(pem_data)
    signature = base64.b64decode(signature_b64)

    try:
        if isinstance(pub, ed25519.Ed25519PublicKey):
            pub.verify(signature, message.encode())
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            pub.verify(signature, message.encode(), ec.ECDSA(hashes.SHA256()))
        else:
            raise HTTPException(400, "Tipe kunci tidak didukung")
    except InvalidSignature:
        raise HTTPException(400, "Signature tidak valid")


# Fungsi API untuk relay pesan ke user lain yang terdaftar
@app.post("/relay")
async def relay(
    sender: str = Form(...),
    recipient: str = Form(...),
    message: str = Form(...),
    signature_b64: str = Form(...),
    user=Depends(verify_token_header)
):
    verify_user_authorization(user, sender)
    verify_signature_internal(sender, message, signature_b64)

    ciphertext = fernet.encrypt(message.encode())

    inbox_file = os.path.join(INBOX_DIR, f"inbox_{recipient}.txt")

    with open(inbox_file, "ab") as f:
        f.write(f"[{sender}] ".encode() + ciphertext + b"\n")

    return {
        "message": f"Pesan berhasil dikirim dari {sender} ke {recipient}",
        "from": sender,
        "to": recipient,
        "stored_in": inbox_file
    }


# Fungsi API untuk membaca inbox pesan yang diterima oleh user
@app.get("/inbox")
async def read_inbox(
    username: str = Query(...),
    user=Depends(verify_token_header)
):
    verify_user_authorization(user, username)
    
    inbox_file = os.path.join(INBOX_DIR, f"inbox_{username}.txt")
    if not os.path.exists(inbox_file):
        return {
            "username": username,
            "messages": []
        }

    messages = []
    with open(inbox_file, "rb") as f:
        for line in f:
            try:
                prefix, ciphertext = line.rstrip().split(b"] ", 1)
                sender = prefix[1:].decode()
                plaintext = fernet.decrypt(ciphertext).decode()
                messages.append({
                    "from": sender,
                    "message": plaintext,
                    "timestamp": datetime.now().isoformat()
                })
            except Exception as e:
                continue

    return {
        "username": username,
        "messages": messages
    }