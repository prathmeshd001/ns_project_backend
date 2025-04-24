# app/main.py
from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.responses import JSONResponse
import sqlite3, numpy as np
from fastapi.middleware.cors import CORSMiddleware

from app import utils, db

app = FastAPI(title="Secure DH & IBE Demo Backend")

# Replace these with your actual frontend URLs
origins = [
    "*"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,           # or ["*"] during development
    allow_credentials=True,          # if you use cookies/auth headers
    allow_methods=["*"],             # GET, POST, PUT, etc.
    allow_headers=["*"],             # Authorization, Content-Type, etc.
)

@app.on_event("startup")
async def init_db():
    conn = db.create_connection()
    db.create_tables(conn)
    conn.close()

@app.post("/register")
async def register_user(
    email: str = Form(...),
    password: str = Form(...),
    image: UploadFile = File(...)
):
    conn = db.create_connection()
    try:
        # 1. Face embedding
        img = utils.load_image(await image.read())
        emb = utils.get_embedding(img)
        canon_hash = utils.calculate_hash(emb)

        # 2. IBE key pair
        priv_pem, pub_pem = utils.simulate_ttp_generate_ibe_key(canon_hash)

        # 3. Encrypt private key for client
        encrypted_priv, salt = utils.encrypt_private_key(priv_pem, password)
        encrypted_hex = encrypted_priv.hex()
        salt_hex = salt.hex()

        # 4. Store user & IBE data
        db.add_user(conn, email)
        db.add_ibe_data(conn, email, emb.tobytes(), pub_pem, encrypted_hex, salt_hex)
        conn.commit()

        return JSONResponse({
            "message": "Registration successful.",
            "public_key": pub_pem,
            "encrypted_private_key": encrypted_hex,
            "encryption_salt": salt_hex
        })

    except sqlite3.IntegrityError:
        conn.rollback()
        raise HTTPException(400, "User already registered")
    except Exception as e:
        conn.rollback()
        raise HTTPException(400, str(e))
    finally:
        conn.close()

@app.post("/verify")
async def verify_user(
    email: str = Form(...),
    image: UploadFile = File(...)
):
    conn = db.create_connection()
    try:
        data = db.get_ibe_data(conn, email)
        if not data:
            raise HTTPException(400, "Email not registered")

        emb_stored = np.frombuffer(data['embedding'], dtype=np.float64)
        emb_new    = utils.get_embedding(utils.load_image(await image.read()))

        if utils.is_matching(emb_new, emb_stored):
            return JSONResponse({
                "message": "Image verified",
                "public_key": data['public_key']
            })
        else:
            raise HTTPException(400, "Face mismatch")

    except Exception as e:
        raise HTTPException(400, str(e))
    finally:
        conn.close()
