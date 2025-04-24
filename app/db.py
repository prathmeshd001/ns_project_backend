# app/db.py
import sqlite3
import os

def create_connection():
    conn = sqlite3.connect('database.db', detect_types=sqlite3.PARSE_DECLTYPES)
    conn.execute("PRAGMA foreign_keys=1")
    return conn
#     db_url = os.getenv("DATABASE_URL", "sqlite:///./database.db")
#    # If it’s a sqlite:/// URL, strip the prefix for connect()
#     if db_url.startswith("sqlite:///"):
#         path = db_url.replace("sqlite:///", "")
#         return sqlite3.connect(path, detect_types=sqlite3.PARSE_DECLTYPES)
#    # Otherwise, pass it as a URI
#     return sqlite3.connect(db_url, uri=True, detect_types=sqlite3.PARSE_DECLTYPES)

def create_tables(conn):
    c = conn.cursor()
    c.execute('''
      CREATE TABLE IF NOT EXISTS users (
        email TEXT PRIMARY KEY
      )
    ''')
    c.execute('''
      CREATE TABLE IF NOT EXISTS ibe_data (
        email           TEXT PRIMARY KEY,
        embedding       BLOB NOT NULL,
        public_key      TEXT NOT NULL,
        encrypted_priv  TEXT NOT NULL,
        salt            TEXT NOT NULL,
        FOREIGN KEY(email) REFERENCES users(email) ON DELETE CASCADE
      )
    ''')
    conn.commit()

def add_user(conn, email: str):
    conn.execute('INSERT INTO users (email) VALUES (?)', (email,))

def add_ibe_data(conn, email: str, embedding: bytes, public_key: str,
                 encrypted_priv_hex: str, salt_hex: str):
    conn.execute('''
      INSERT INTO ibe_data (email, embedding, public_key, encrypted_priv, salt)
      VALUES (?, ?, ?, ?, ?)
    ''', (email, embedding, public_key, encrypted_priv_hex, salt_hex))

def get_ibe_data(conn, email: str):
    row = conn.execute('''
      SELECT embedding, public_key, encrypted_priv, salt
      FROM ibe_data WHERE email=?
    ''', (email,)).fetchone()
    if not row:
        return None
    return {
      'embedding': row[0],
      'public_key': row[1],
      'encrypted_priv_hex': row[2],
      'salt_hex': row[3]
    }
