"""Clean application — must produce zero local-gate findings."""
import hashlib
import os
import secrets
import sqlite3
import ssl

API_KEY = os.environ.get("API_KEY")
password = os.environ.get("PASSWORD")


def query_user(conn: sqlite3.Connection, user_id: int) -> None:
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))


def session_token() -> str:
    return secrets.token_hex(32)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def tls_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    return ctx
