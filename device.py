import hashlib
from flask import request

IMPORTANT_HEADERS = [
    "User-Agent", "Accept-Language", "Sec-CH-UA-Platform", "Sec-CH-UA",
]

def device_hash(extra_client_data: str = "") -> str:
    parts = [request.headers.get(h, "") for h in IMPORTANT_HEADERS]
    parts.append(request.remote_addr or "")
    if extra_client_data:
        parts.append(extra_client_data)
    raw = "|".join(parts)
    return hashlib.sha256(raw.encode()).hexdigest()
