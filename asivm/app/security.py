import base64
import hashlib
import hmac
import os
from datetime import timedelta

import jwt

from .config import settings
from .models import utcnow


def _b(x: bytes) -> str:
    return base64.b64encode(x).decode()


def hash_password(pw: str) -> str:
    salt = os.urandom(16)
    dk = hashlib.scrypt(pw.encode(), salt=salt, n=2**14, r=8, p=1)
    return f"scrypt${_b(salt)}${_b(dk)}"


def verify_password(pw: str, stored: str) -> bool:
    try:
        _, s, d = stored.split("$")
        dk = hashlib.scrypt(pw.encode(), salt=base64.b64decode(s), n=2**14, r=8, p=1)
        return hmac.compare_digest(dk, base64.b64decode(d))
    except Exception:
        return False


def create_token(user) -> str:
    exp = utcnow() + timedelta(minutes=settings.access_token_minutes)
    return jwt.encode({"sub": str(user.id), "org": user.org_id, "role": user.role, "exp": exp},
                      settings.secret_key, algorithm="HS256")


def decode_token(token: str) -> dict:
    return jwt.decode(token, settings.secret_key, algorithms=["HS256"])
