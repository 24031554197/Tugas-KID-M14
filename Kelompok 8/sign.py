from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
import base64

# Path private key pengirim
PRIV_KEY_PATH = r"punkhazard-keys/priv19.pem"

with open(PRIV_KEY_PATH, "rb") as f:
    private_key = serialization.load_pem_private_key(f.read(), password=None)

pesan = b"Halo ini pesan yg dikirim"

signature = private_key.sign(pesan)

signature_b64 = base64.b64encode(signature).decode()
print("Signature (Base64):", signature_b64)

# r2NBWGRoNLlVHPsGGDepjgLenkDNdKo4v4EZbBMolmDEOYI3OH6onkKCParzYXnnkz7N3DFuk2IWA7cpt6LGDA==