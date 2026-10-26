"""MiniShop : application FastAPI VOLONTAIREMENT VULNÉRABLE (support du TP Cours 7).

Ne jamais déployer ce code tel quel. Votre mission : le rendre conforme.
Documentation interactive : http://localhost:5000/docs
"""
import ast
import base64
import hashlib
import logging
import os
import pickle
import random
import sqlite3
import subprocess
import traceback

import requests
import uvicorn
import yaml
from fastapi import Body, FastAPI, Request, HTTPException, Depends
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse
from starlette.middleware.sessions import SessionMiddleware
from ipaddress import IPv4Address
from pydantic import BaseModel
from pathlib import Path
import html
from urllib.parse import urlparse
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import secrets

SECRET_KEY = os.environ["SECRET_KEY"]
DB_PATH = os.environ.get("DB_PATH", "shop.db")
UPLOAD_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "uploads")

logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger("minishop")

app = FastAPI(title="MiniShop", debug=True)
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY, https_only=True, same_site="lax")

ph = PasswordHasher()

ROLE_PERMS = {
"admin": {"invoice:read","user:read", "user:delete"},
"user": {"invoice:read"},
}

@app.middleware("http")
async def headers(request, call_next):
    r = await call_next(request)
    r.headers["Content-Security-Policy"] = "default-src 'self'"
    r.headers["X-Content-Type-Options"] = "nosniff"
    r.headers["Strict-Transport-Security"] = "max-age=31536000"
    r.headers["X-Frame-Options"] = "DENY"
    return r


class Profile(BaseModel):
    name: str
    age: int

def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def argon2cffi(value):
    return ph.hash(value)


def init_db():
    conn = db()
    conn.executescript(
        """
        DROP TABLE IF EXISTS users;
        DROP TABLE IF EXISTS products;
        DROP TABLE IF EXISTS invoices;
        CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT UNIQUE,
                            password TEXT, is_admin INTEGER DEFAULT 0);
        CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT, price REAL);
        CREATE TABLE invoices (id INTEGER PRIMARY KEY, owner_id INTEGER,
                               label TEXT, amount REAL);
        """
    )
    conn.execute("INSERT INTO users (username, password, is_admin) VALUES (?, ?, 1)",
                 ("admin", argon2cffi("admin123")))
    conn.execute("INSERT INTO users (username, password) VALUES (?, ?)", ("alice", argon2cffi("alice123")))
    conn.execute("INSERT INTO users (username, password) VALUES (?, ?)", ("bob", argon2cffi("bob123")))
    conn.executemany("INSERT INTO products (name, price) VALUES (?, ?)",
                     [("apple", 1.2), ("banana", 0.8), ("cherry", 3.5)])
    conn.executemany("INSERT INTO invoices (owner_id, label, amount) VALUES (?, ?, ?)",
                     [(2, "Facture Alice", 42.0), (3, "Facture Bob", 99.0)])
    conn.commit()
    conn.close()


@app.exception_handler(Exception)
async def handle_error(request: Request, exc: Exception):
    return HTMLResponse("<pre>" + traceback.format_exc() + "</pre>", status_code=500)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/login")
def login(request: Request, data: dict = Body(...)):
    username, password = data["username"], data["password"]
    log.info(f"login attempt user={username}")
    sql = "SELECT id, username, password FROM users WHERE username=?"
    row = db().execute(sql, (username,)).fetchone()
    if not row:
        return JSONResponse({"error": "bad credentials"}, status_code=401)
    try:
        ph.verify(row["password"], password)
    except VerifyMismatchError:
        return JSONResponse({"error": "bad credentials"}, status_code=401)
    request.session["user_id"] = row["id"]
    request.session["token"] = secrets.token_urlsafe(32)
    return {"status": "logged in", "user": row["username"]}


@app.get("/search")
def search(q: str = ""):
    sql = "SELECT id, name, price FROM products WHERE name LIKE ?"
    rows = db().execute(sql, (f"%{q}%",)).fetchall()
    return [dict(r) for r in rows]


@app.get("/ping")
def ping(host: IPv4Address):
    out = subprocess.run(["ping", "-c", "1", str(host)], text=True, timeout=5, capture_output=True)
    return PlainTextResponse(out.stdout + out.stderr)


@app.get("/hello")
def hello(name: str = ""):
    return HTMLResponse(f"<h1>Bonjour {html.escape(name)}</h1>")


@app.get("/files/{name:path}")
def get_file(name: str):
    BASE = Path(UPLOAD_DIR).resolve()
    p = (BASE / name).resolve()
    if not p.is_relative_to(BASE) or not p.is_file():
        raise HTTPException(status_code=404)
    return FileResponse(p)


@app.post("/calc")
def calc(data: dict = Body(...)):
    try:
        value = ast.literal_eval(data["expr"])
    except (ValueError, SyntaxError, KeyError):
        raise HTTPException(status_code=400)
    return {"result": value}


@app.post("/import-yaml")
async def import_yaml(request: Request):
    cfg = yaml.safe_load(await request.body())
    return {"keys": list(cfg.keys()) if isinstance(cfg, dict) else str(type(cfg))}


@app.post("/import-profile")
async def import_profile(profile: Profile):
    return {"profile": profile.dict()}


@app.get("/fetch")
def fetch(url: str):
    ALLOWED = {"api.partenaire.com"}
    u = urlparse(url)
    if u.scheme != "https" or u.hostname not in ALLOWED:
        raise HTTPException(status_code=400)
    r = requests.get(url, timeout=5, allow_redirects=False, verify=True)
    return PlainTextResponse(r.text[:500])


@app.get("/invoices/{invoice_id}")
def invoice(invoice_id: int, request: Request):
    if "user_id" not in request.session:
        return JSONResponse({"error": "login required"}, status_code=401)
    row = db().execute("SELECT * FROM invoices WHERE id = ? AND owner_id=?", (invoice_id, request.session["user_id"])).fetchone()
    if not row:
        return JSONResponse({"error": "not found"}, status_code=404)
    return dict(row)

def current_user(request: Request):
    user_id = request.session.get("user_id")
    if user_id is None:
        raise HTTPException(status_code=401)
    row = db().execute("SELECT is_admin FROM users WHERE id = ?", (user_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=401)
    role = "admin" if row["is_admin"] else "user"
    return {"id": user_id, "role": role}

def require(perm: str):
    def checker(user=Depends(current_user)):
        if perm not in ROLE_PERMS.get(user["role"], set()):
            raise HTTPException(status_code=403)
        return user
    return checker

@app.get("/admin/users")
def admin_users( _=Depends(require("user:read"))):
    rows = db().execute("SELECT id, username, is_admin FROM users").fetchall()
    return [dict(r) for r in rows]


@app.delete("/users/{user_id}")
def delete_user( user_id: int, _=Depends(require("user:delete"))):
    conn = db()
    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    return {"deleted": user_id}


@app.get("/boom")
def boom():
    return 1 / 0


if __name__ == "__main__":
    init_db()
    uvicorn.run("app:app", host="0.0.0.0", port=5000, reload=True)
