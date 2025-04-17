from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.responses import JSONResponse
from app import utils

app = FastAPI(title="Secure DH & IBE Demo Backend")

# In-memory datastore for demonstration.
users_table = {}  # General user data, keyed by email.
ibe_table = {}    # IBE sensitive data, keyed by email.

@app.post("/register")
async def register_user(
    email: str = Form(...),
    password: str = Form(...),
    image: UploadFile = File(...)
):
    try:
        #logging
        print(f'{email} - {password}');
        # Process the image.
        file_bytes = await image.read()
        img_array = utils.load_image(file_bytes)
        base_embedding = utils.get_embedding(img_array)
        canonical_hash = utils.calculate_hash(base_embedding)
        
        # Check if the email is already registered.
        if email in users_table:
            raise HTTPException(status_code=400, detail="User with this email already registered.")
        
        # Simulate TTP key pair generation.
        private_pem, public_pem = utils.simulate_ttp_generate_ibe_key(canonical_hash)
        
        # Encrypt the private key using the user's password.
        encrypted_private, encryption_salt = utils.encrypt_private_key(private_pem, password)
        
        # Store general user info.
        users_table[email] = {
            "email": email,
            # Additional non-sensitive user data can be stored here.
        }
        
        # Store sensitive IBE data.
        ibe_table[email] = {
            "embedding": base_embedding,          # For internal verification.
            "encrypted_private_key": encrypted_private.hex(),  # Stored as hex string.
            "encryption_salt": encryption_salt.hex(),
            "public_key": public_pem
        }
        
        # Return the public key and encryption details to the client.
        return JSONResponse(content={
            "message": "Registration successful.",
            "public_key": public_pem,
            "encrypted_private_key": encrypted_private.hex(),
            "encryption_salt": encryption_salt.hex()
        })
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/verify")
async def verify_user(
    email: str = Form(...),
    image: UploadFile = File(...)
):
    try:
        # Check if the email is registered.
        if email not in ibe_table:
            raise HTTPException(status_code=400, detail="No registration found for the provided email.")
        
        stored_data = ibe_table[email]
        stored_embedding = stored_data["embedding"]
        
        # Process the new image.
        file_bytes = await image.read()
        img_array = utils.load_image(file_bytes)
        new_embedding = utils.get_embedding(img_array)
        
        # Verify the face embedding against the stored embedding.
        if utils.is_matching(new_embedding, stored_embedding):
            return JSONResponse(content={
                "message": "Image verified successfully.",
                "public_key": stored_data["public_key"]
            })
        else:
            raise HTTPException(status_code=400, detail="Face does not match the registered image.")
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/dh_exchange")
async def dh_exchange():
    # Dummy endpoint for Diffie–Hellman exchange.
    shared_secret = "dummy_shared_secret_value"
    return JSONResponse(content={"shared_secret": shared_secret})
