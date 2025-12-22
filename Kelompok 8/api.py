from fastapi import FastAPI, HTTPException, UploadFile, File, Form, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from typing import Dict, Optional
from datetime import datetime, timedelta
import os, json, base64, secrets

from cryptography.hazmat.primitives import serialization, hashes, hmac
from cryptography.hazmat.primitives.asymmetric import ed25519

# CONFIG 
SECRET_JWT = secrets.token_bytes(32)
ALGO_JWT = "HS256"

SERVER_PRIV_KEY_PATH = "punkhazard-keys/priv19.pem"
SERVER_PUB_KEY_PATH  = "punkhazard-keys/pub19.pem"

USERS: Dict[str, Dict[str, str]] = {}
PUBKEYS: Dict[str, ed25519.Ed25519PublicKey] = {}

INBOX_DIR = "inbox"
os.makedirs(INBOX_DIR, exist_ok=True)

# HELPER 
def b64decode_fix(data: str) -> bytes:
    data += "=" * (-len(data) % 4)
    return base64.b64decode(data)

def hash_data(data: bytes) -> bytes:
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    return digest.finalize()

# LOAD SERVER KEY 
def load_server_private():
    try:
        with open(SERVER_PRIV_KEY_PATH, "rb") as f:
            return serialization.load_pem_private_key(f.read(), None)
    except:
        return None

SERVER_PRIV = load_server_private()

# JWT 
def create_token(payload: dict, exp: Optional[timedelta] = None):
    payload = payload.copy()
    payload["exp"] = (datetime.utcnow() + (exp or timedelta(minutes=30))).timestamp()

    header_json = json.dumps({"alg": ALGO_JWT, "typ": "JWT"}).encode()
    header_b64 = base64.urlsafe_b64encode(header_json).rstrip(b"=").decode()

    payload_json = json.dumps(payload).encode()
    payload_b64 = base64.urlsafe_b64encode(payload_json).rstrip(b"=").decode()

    unsigned_token = f"{header_b64}.{payload_b64}".encode()

    hmac_obj = hmac.HMAC(SECRET_JWT, hashes.SHA256())
    hmac_obj.update(unsigned_token)
    signature_b64 = base64.urlsafe_b64encode(
        hmac_obj.finalize()
    ).rstrip(b"=").decode()

    return f"{header_b64}.{payload_b64}.{signature_b64}"

def verify_token(token: str):
    try:
        header_b64, payload_b64, signature_b64 = token.split(".")

        unsigned_token = f"{header_b64}.{payload_b64}".encode()

        payload_json = base64.urlsafe_b64decode(payload_b64 + "==")
        payload = json.loads(payload_json)

        if datetime.fromtimestamp(payload["exp"]) < datetime.utcnow():
            raise Exception

        hmac_obj = hmac.HMAC(SECRET_JWT, hashes.SHA256())
        hmac_obj.update(unsigned_token)
        hmac_obj.verify(base64.urlsafe_b64decode(signature_b64 + "=="))

        return payload["sub"]
    except:
        raise HTTPException(401, "Token tidak valid")

oauth2 = OAuth2PasswordBearer(tokenUrl="login")
def current_user(token: str = Depends(oauth2)):
    return verify_token(token)

# FASTAPI 
app = FastAPI(title="Security Server")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"]
)

@app.get("/health")
async def health():
    return {"status": "OK"}

# AUTH 
@app.post("/register")
async def register(username: str = Form(...), password: str = Form(...)):
    USERS[username] = {"password": password}
    return {"msg": "register ok"}

@app.post("/login")
async def login(username: str = Form(...), password: str = Form(...)):
    user = USERS.get(username)
    if not user or user["password"] != password:
        raise HTTPException(401, "Login gagal")
    return {
        "access_token": create_token({"sub": username}),
        "token_type": "bearer"
    }

# STORE PUBKEY 
@app.post("/store", dependencies=[Depends(current_user)])
async def store_key(username: str = Form(...), file: UploadFile = File(...)):
    data = await file.read()
    try:
        public_key = serialization.load_pem_public_key(data)
    except:
        raise HTTPException(400, "Public key tidak valid")

    PUBKEYS[username] = public_key  
    return {
        "msg": "Public key berhasil disimpan"
    }

# RELAY 
@app.post("/message-relay", dependencies=[Depends(current_user)])
async def relay(
    penerima: str = Form(...),
    pesan: str = Form(...),              
    tanda_tangan_b64: str = Form(...),
    pengirim: str = Depends(current_user)
):
    public_key_pengirim = PUBKEYS.get(pengirim)
    if not public_key_pengirim:
        raise HTTPException(400, "Pengirim belum upload public key")

    pesan_bytes = pesan.encode()         
    signature_bytes = b64decode_fix(tanda_tangan_b64)

    try:
        public_key_pengirim.verify(signature_bytes, pesan_bytes)
    except:
        raise HTTPException(400, "Signature tidak valid")

    with open(f"{INBOX_DIR}/{penerima}.txt", "a") as f:
        f.write(json.dumps({
            "from": pengirim,
            "pesan": pesan,              
            "signature_b64": tanda_tangan_b64
        }) + "\n")

    return {"msg": "Pesan direlay"}

# INBOX 
@app.get("/message-inbox", dependencies=[Depends(current_user)])
async def inbox(user: str = Depends(current_user)):
    path = f"{INBOX_DIR}/{user}.txt"
    if not os.path.exists(path):
        return {"pesan_masuk": []}

    messages = []
    with open(path) as f:
        for line in f:
            messages.append(json.loads(line))
    return {"pesan_masuk": messages}

# SIGN & VERIFY PDF 
@app.post("/sign-pdf", dependencies=[Depends(current_user)])
async def sign_pdf(file: UploadFile = File(...)):
    if not SERVER_PRIV:
        raise HTTPException(500, "Server private key tidak ada")
    data = await file.read()
    signature = SERVER_PRIV.sign(hash_data(data))
    return {"signature_b64": base64.b64encode(signature).decode()}

@app.post("/verify-pdf", dependencies=[Depends(current_user)])
async def verify_pdf(
    file: UploadFile = File(...),
    signature_b64: str = Form(...)
):
    with open(SERVER_PUB_KEY_PATH, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())

    data = await file.read()
    try:
        public_key.verify(b64decode_fix(signature_b64), hash_data(data))
        return {"valid": True}
    except:
        return {"valid": False}