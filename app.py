import os

from flask import Flask, render_template, session
from flask_session import Session
from redis import Redis

from auth import bp as auth_bp
from db import Base, engine

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET", os.urandom(16))

# Server-side sessions in Redis
# Prefer TLS URL if present, then fall back to non-TLS or local
redis_url = (
    os.getenv("REDIS_TLS_URL") or os.getenv("REDIS_URL") or "redis://localhost:6379/0"
)

# For some Heroku Redis TLS endpoints, disable cert verification (lab/demo only)
if redis_url.startswith("rediss://") and "ssl_cert_reqs=" not in redis_url:
    redis_url += ("&" if "?" in redis_url else "?") + "ssl_cert_reqs=none"

app.config.update(
    SESSION_TYPE="redis",
    SESSION_REDIS=Redis.from_url(redis_url),  # no 'ssl=' kwarg; rediss:// handles TLS
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE="Lax",
)
Session(app)

app.register_blueprint(auth_bp)


@app.get("/")
def home():
    if "user" in session:
        return render_template("dashboard.html", user=session["user"])
    return render_template("login.html")


@app.get("/dashboard")
def dashboard():
    return render_template("dashboard.html", user=session.get("user"))


@app.get("/__health")
def health():
    return "ok", 200


# Create tables once at startup (idempotent)
try:
    Base.metadata.create_all(bind=engine)
    app.logger.info("db_init_success")
except Exception:
    app.logger.exception("db_init_failed")


@app.context_processor
def inject_env():
    import os

    return dict(
        env={
            "RUM_APP_ID": os.getenv("RUM_APP_ID", ""),
            "RUM_CLIENT_TOKEN": os.getenv("RUM_CLIENT_TOKEN", ""),
            "DD_SITE": os.getenv("DD_SITE", "us5.datadoghq.com"),
        }
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
