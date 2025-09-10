import hashlib
import hmac
import json
import logging
import os
import time

import pyotp
from flask import (
    Blueprint,
    make_response,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from passlib.hash import bcrypt
from sqlalchemy import select

from db import SessionLocal, engine
from device import device_hash
from models import Base, User

bp = Blueprint("auth", __name__)
logger = logging.getLogger("auth")


# Structured JSON logging
class JsonFormatter(logging.Formatter):
    def format(self, record):
        payload = {
            "evt": getattr(record, "evt", record.msg),
            "level": record.levelname,
            "ts": int(time.time()),
            "ip": request.headers.get("X-Forwarded-For", request.remote_addr),
            "ua": request.headers.get("User-Agent"),
            "usr": session.get("user"),
        }
        extra = getattr(record, "extra", None)
        if isinstance(extra, dict):
            payload.update(extra)
        return json.dumps(payload)


handler = logging.StreamHandler()
handler.setFormatter(JsonFormatter())
logger.setLevel(logging.INFO)
logger.addHandler(handler)


@bp.before_app_first_request
def init_db():
    Base.metadata.create_all(bind=engine)


@bp.get("/register")
def register_form():
    return render_template("register.html")


@bp.post("/register")
def register_post():
    email = request.form["email"].lower().strip()
    pw = request.form["password"].strip()
    with SessionLocal() as db:
        if db.scalar(select(User).where(User.email == email)):
            return "Email taken", 400
        u = User(email=email, password_hash=bcrypt.hash(pw))
        db.add(u)
        db.commit()
    return redirect(url_for("auth.login_form"))


@bp.get("/login")
def login_form():
    return render_template("login.html")


@bp.post("/login")
def login_post():
    email = request.form["email"].lower().strip()
    pw = request.form["password"].strip()
    extra = request.form.get("device_data", "")
    dhash = device_hash(extra)

    with SessionLocal() as db:
        u = db.scalar(select(User).where(User.email == email))
        if not u or not bcrypt.verify(pw, u.password_hash):
            logger.info(
                "auth_fail", extra={"evt": "login", "outcome": "fail", "email": email}
            )
            return "Invalid credentials", 401

        # Optional TOTP if enabled
        if u.mfa_enabled:
            code = request.form.get("totp", "")
            if not code or not pyotp.TOTP(u.mfa_secret).verify(code, valid_window=1):
                logger.info(
                    "mfa_fail",
                    extra={"evt": "login", "outcome": "mfa_fail", "email": email},
                )
                return "MFA required/invalid", 401

        # Success: bind session to device hash
        session["user"] = email
        session["device_hash"] = dhash
        session["login_time"] = int(time.time())
        logger.info(
            "auth_success",
            extra={
                "evt": "login",
                "outcome": "success",
                "email": email,
                "device_hash": dhash,
            },
        )
        return redirect(url_for("dashboard"))


@bp.post("/enable_mfa")
def enable_mfa():
    if "user" not in session:
        return "", 401
    secret = pyotp.random_base32()
    with SessionLocal() as db:
        u = db.scalar(select(User).where(User.email == session["user"]))
        u.mfa_secret = secret
        u.mfa_enabled = True
        db.commit()
    return f"MFA enabled. Secret (demo): {secret}", 200


@bp.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("auth.login_form"))


# Admin contain endpoint (called by Azure Function)
@bp.post("/contain/revoke")
def contain_revoke():
    key = os.getenv("ATO_HMAC_SECRET", "")
    sig = request.headers.get("X-ATO-Signature", "")
    body = request.get_data()
    expect = hmac.new(key.encode(), body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expect):
        return "forbidden", 403

    sess_id = request.json.get("session_id")
    if not sess_id:
        return "bad", 400

    # In Flask-Session, server-side keys are internal; simplest is to nuke current session or tag user for force-reauth
    session.clear()
    logger.info(
        "contain_revoke", extra={"evt": "contain", "action": "revoke", "sid": sess_id}
    )
    resp = make_response("ok")
    resp.delete_cookie("session")
    return resp
