"""Deliberately vulnerable Python — local OWASP gate fixtures."""
import hashlib
import random
import sqlite3

password = "hunter2"
api_key = "abcd1234secret"

def run_query(conn, user):
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM users WHERE name = '{user}'")

def run_dynamic(code):
    eval(code)

def weak_hash(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()

def insecure_token():
    return random.randint(1000, 9999)

def leak():
    print(password)
