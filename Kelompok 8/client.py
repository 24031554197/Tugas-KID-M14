import requests
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

API_URL = "http://localhost:8080"

# KEY 
PRIV_KEY_PATH = r"punkhazard-keys/priv19.pem"
PUB_KEY_PATH  = r"punkhazard-keys/pub19.pem"

with open(PRIV_KEY_PATH, "rb") as f:
    private_key = serialization.load_pem_private_key(f.read(), password=None)

with open(PUB_KEY_PATH, "rb") as f:
    public_key = serialization.load_pem_public_key(f.read())

# HTTP HELPERS 
def auth_header(token=None):
    return {"Authorization": f"Bearer {token}"} if token else {}

def post_request(url, data=None, files=None, token=None):
    response = requests.post(url, data=data, files=files, headers=auth_header(token))
    try:
        return response.json()
    except:
        return response.text

def get_request(url, token=None):
    response = requests.get(url, headers=auth_header(token))
    try:
        return response.json()
    except:
        return response.text

token = None

# MAIN 
def main():
    username = "herlin"
    password = "1212"
    receiver = "arifin"

    # REGISTER & LOGIN 
    post_request(f"{API_URL}/register", data={"username": username, "password": password})
    login_resp = post_request(f"{API_URL}/login", data={"username": username, "password": password})
    token = login_resp["access_token"]

    # UPLOAD PUBKEY 
    with open(PUB_KEY_PATH, "rb") as f:
        pub_bytes = f.read()
    files = {"file": ("pub19.pem", pub_bytes)}
    post_request(f"{API_URL}/store", data={"username": username}, files=files, token=token)

    # SIGN PESAN 
    pesan = b"Halo ini pesan yg dikirim"
    signature = private_key.sign(pesan)
    signature_b64 = base64.b64encode(signature).decode()
    print("Signature Base64:", signature_b64)

    # SEND MESSAGE 
    payload = {
        "penerima": receiver,
        "pesan": pesan.decode(),
        "tanda_tangan_b64": signature_b64
    }
    resp = post_request(f"{API_URL}/message-relay", data=payload, token=token)
    print("Relay Response:", resp)

    # READ INBOX 
    inbox = get_request(f"{API_URL}/message-inbox", token=token)
    print("Inbox:", inbox)

    # VERIFY CLIENT-SIDE
    from cryptography.exceptions import InvalidSignature
    try:
        public_key.verify(signature, pesan)
        print("Signature valid ")
    except InvalidSignature:
        print("Signature invalid ")

    return token

if __name__ == "__main__":
    token = main()

# SIGN PDF 
PDF_PATH = r"/uploaded_pdfs/Soal-UAS-KID25.pdf"

with open(PDF_PATH, "rb") as f:
    files = {"file": (PDF_PATH.split("\\")[-1], f, "application/pdf")}
    response = requests.post(
        f"{API_URL}/sign-pdf",
        files=files,
        headers={"Authorization": f"Bearer {token}"}
    )

if response.status_code == 200:
    signature_b64_pdf = response.json()["signature_b64"]
    print("=== SIGNATURE PDF ===")
    print(signature_b64_pdf)
else:
    print("Gagal sign PDF:", response.status_code, response.text)