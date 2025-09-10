import os, json, hmac, hashlib, logging
import azure.functions as func
import urllib.request

APP_REVOKE_URL = os.getenv("APP_REVOKE_URL")  # https://<app>.herokuapp.com/contain/revoke
ATO_HMAC_SECRET = os.getenv("ATO_HMAC_SECRET")

def main(req: func.HttpRequest) -> func.HttpResponse:
    try:
        body = req.get_json()
    except Exception:
        return func.HttpResponse("bad", status_code=400)

    sid = body.get("sid") or body.get("session_id") or "unknown"
    payload = json.dumps({"session_id": sid}).encode()
    sig = hmac.new(ATO_HMAC_SECRET.encode(), payload, hashlib.sha256).hexdigest()

    req2 = urllib.request.Request(APP_REVOKE_URL, data=payload, headers={
        "Content-Type": "application/json",
        "X-ATO-Signature": sig
    })
    try:
        with urllib.request.urlopen(req2, timeout=10) as resp:
            logging.info("contain_forwarded %s", resp.getcode())
    except Exception as e:
        logging.error("contain_error %s", e)
        return func.HttpResponse("error", status_code=500)

    return func.HttpResponse("ok", status_code=200)
