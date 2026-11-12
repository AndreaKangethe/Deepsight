import re

from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..db import get_db
from ..deps import audit, current_user, require
from ..models import Organization, User, row
from ..security import create_token, hash_password, verify_password

router = APIRouter(prefix="/api", tags=["auth"])
EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class Bootstrap(BaseModel):
    org_name: str = Field(min_length=2, max_length=200)
    email: str
    password: str = Field(min_length=10)


class NewUser(BaseModel):
    email: str
    password: str = Field(min_length=10)
    role: str = "viewer"


@router.post("/auth/bootstrap", status_code=201)
def bootstrap(b: Bootstrap, db: Session = Depends(get_db)):
    """Create the first organisation and admin. Only works while no users exist."""
    if db.scalar(select(func.count(User.id))):
        raise HTTPException(403, "already initialised")
    if not EMAIL.match(b.email):
        raise HTTPException(422, "invalid email")
    org = Organization(name=b.org_name)
    db.add(org)
    db.flush()
    u = User(org_id=org.id, email=b.email.lower(), password_hash=hash_password(b.password), role="admin")
    db.add(u)
    audit(db, u, "bootstrap", f"org:{org.id}")
    db.commit()
    return {"org_id": org.id, "user_id": u.id}


@router.get("/auth/status")
def status(db: Session = Depends(get_db)):
    return {"initialised": bool(db.scalar(select(func.count(User.id))))}


@router.post("/auth/login")
def login(form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    u = db.scalar(select(User).where(User.email == form.username.lower()))
    if not u or not u.active or not verify_password(form.password, u.password_hash):
        audit(db, form.username, "login_failed")
        db.commit()
        raise HTTPException(401, "Incorrect email or password")
    audit(db, u, "login")
    db.commit()
    return {"access_token": create_token(u), "token_type": "bearer", "role": u.role, "email": u.email}


@router.get("/auth/me")
def me(u: User = Depends(current_user)):
    return row(u, exclude=("password_hash",))


@router.get("/users")
def users(u: User = Depends(require("admin")), db: Session = Depends(get_db)):
    return [row(x, exclude=("password_hash",)) for x in db.scalars(select(User).where(User.org_id == u.org_id))]


@router.post("/users", status_code=201)
def add_user(n: NewUser, u: User = Depends(require("admin")), db: Session = Depends(get_db)):
    if n.role not in ("admin", "analyst", "viewer") or not EMAIL.match(n.email):
        raise HTTPException(422, "invalid role or email")
    if db.scalar(select(User).where(User.email == n.email.lower())):
        raise HTTPException(409, "email already registered")
    x = User(org_id=u.org_id, email=n.email.lower(), password_hash=hash_password(n.password), role=n.role)
    db.add(x)
    audit(db, u, "user_created", n.email, {"role": n.role})
    db.commit()
    return row(x, exclude=("password_hash",))


@router.get("/team")
def team(u: User = Depends(current_user), db: Session = Depends(get_db)):
    """People findings can be assigned to (any signed-in user)."""
    return [{"email": x.email, "role": x.role} for x in db.scalars(
        select(User).where(User.org_id == u.org_id, User.active == True).order_by(User.email))]  # noqa: E712
