# app/utils.py
import os
import io
import numpy as np
from PIL import Image
import face_recognition
from dotenv import load_dotenv

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Load environment variables once
load_dotenv()  # reads .env from project root :contentReference[oaicite:2]{index=2}

# ------------------------------------
# TTP MASTER SECRET DERIVATION (STATIC)
# ------------------------------------
TTP_PASSPHRASE = os.getenv("TTP_PASSPHRASE")
TTP_SALT_HEX   = os.getenv("TTP_SALT_HEX")
if not (TTP_PASSPHRASE and TTP_SALT_HEX):
    raise RuntimeError("Missing TTP_PASSPHRASE or TTP_SALT_HEX in environment")

TTP_SALT = bytes.fromhex(TTP_SALT_HEX)

def get_ttp_master_secret() -> bytes:
    """
    Derive a fixed master secret via PBKDF2-HMAC-SHA256 from
    the passphrase and static salt. Deterministic across restarts.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=TTP_SALT,
        iterations=600000,  # OWASP recommends ≥600k :contentReference[oaicite:3]{index=3}
        backend=default_backend()
    )
    return kdf.derive(TTP_PASSPHRASE.encode())

# ------------------------------------
# IMAGE PROCESSING & EMBEDDING
# ------------------------------------
def load_image(file_bytes: bytes) -> np.ndarray:
    image = Image.open(io.BytesIO(file_bytes))
    return np.array(image)

def get_embedding(image: np.ndarray) -> np.ndarray:
    encs = face_recognition.face_encodings(image)
    if not encs:
        raise ValueError("No face detected")
    return encs[0]

def calculate_hash(embedding: np.ndarray) -> str:
    h = hashes.Hash(hashes.SHA3_512(), backend=default_backend())
    h.update(embedding.tobytes())
    return h.finalize().hex()

# ------------------------------------
# EMBEDDING MATCHING
# ------------------------------------
def cosine_similarity(a: np.ndarray, b: np.ndarray) -> float:
    return float(np.dot(a, b) / (np.linalg.norm(a) * np.linalg.norm(b)))

def euclidean_distance(a: np.ndarray, b: np.ndarray) -> float:
    return float(np.linalg.norm(a - b))

COSINE_THRESHOLD    = 0.90
EUCLIDEAN_THRESHOLD = 0.6

def is_matching(new_emb: np.ndarray, base_emb: np.ndarray) -> bool:
    cos = cosine_similarity(new_emb, base_emb)
    dist = euclidean_distance(new_emb, base_emb)
    print(f"cos={cos:.3f}, dist={dist:.3f}")
    return cos >= COSINE_THRESHOLD and dist <= EUCLIDEAN_THRESHOLD

# ------------------------------------
# DETERMINISTIC IBE KEY PAIR (TTP)
# ------------------------------------
def generate_deterministic_private_key(canonical_hash: str) -> ec.EllipticCurvePrivateKey:
    master = get_ttp_master_secret()
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=canonical_hash.encode(),
        backend=default_backend()
    )
    seed = hkdf.derive(master)
    seed_int = int.from_bytes(seed, "big")
    curve = ec.SECP256R1()
    order = int("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)
    seed_int %= order
    return ec.derive_private_key(seed_int, curve, default_backend())

def simulate_ttp_generate_ibe_key(canonical_hash: str) -> (str, str):
    priv = generate_deterministic_private_key(canonical_hash)
    pub = priv.public_key()
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()
    pub_pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    return priv_pem, pub_pem

# ------------------------------------
# PRIVATE KEY ENCRYPTION (per-request salt)
# ------------------------------------
def derive_encryption_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600000,  # same high iteration count
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_private_key(private_pem: str, password: str) -> (bytes, bytes):
    """
    Encrypts the private PEM with AES-GCM using a password-derived key.
    Returns (nonce  ||  ciphertext, salt).
    """
    salt = os.urandom(16)       # 128-bit random salt per encryption 
    key  = derive_encryption_key(password, salt)
    aes  = AESGCM(key)
    nonce = os.urandom(12)      # 96-bit nonce for AES-GCM
    ct = aes.encrypt(nonce, private_pem.encode(), None)
    return nonce + ct, salt
