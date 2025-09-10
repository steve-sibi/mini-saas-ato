import os
from flask import Flask, render_template, session
from flask_session import Session
from redis import Redis
from auth import bp as auth_bp

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET", os.urandom(16))

# Server-side sessions in Redis
redis_url = os.getenv("REDIS_URL") or os.getenv("REDIS_TLS_URL")
app.config.update(
    SESSION_TYPE="redis",
    SESSION_REDIS=Redis.from_url(redis_url, ssl=redis_url.startswith("rediss://")),
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

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
