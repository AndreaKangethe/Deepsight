import jwt
from fastapi import Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from .db import get_db
from .models import AuditLog, User
from .security import decode_token

oauth2 = OAuth2PasswordBearer(tokenUrl="/api/auth/login")
RANK = {"viewer": 1, "analyst": 2, "admin": 3}


def current_user(token: str = Depends(oauth2), db: Session = Depends(get_db)) -> User:
    try:
        claims = decode_token(token)
    except jwt.PyJWTError:
        raise HTTPException(401, "Invalid or expired token")
    user = db.get(User, int(claims["sub"]))
    if not user or not user.active:
        raise HTTPException(401, "Unknown or disabled user")
    return user


def require(role: str):
    def dep(user: User = Depends(current_user)) -> User:
        if RANK[user.role] < RANK[role]:
            raise HTTPException(403, f"Requires role '{role}'")
        return user
    return dep


def audit(db: Session, user, action: str, target: str | None = None, detail: dict | None = None):
    db.add(AuditLog(org_id=getattr(user, "org_id", None), actor=getattr(user, "email", str(user)),
                    action=action, target=target, detail=detail or {}))
