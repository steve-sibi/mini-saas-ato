from __future__ import annotations

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware

from ato_sentinel.security import compute_device_fingerprint, generate_csrf_token
from ato_sentinel.types import RequestContext


def extract_client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    if request.client:
        return request.client.host
    return "0.0.0.0"


class RequestContextMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        settings = request.app.state.settings
        csrf_token = request.cookies.get(settings.csrf_cookie_name)
        issued_csrf_cookie = csrf_token is None
        if issued_csrf_cookie:
            csrf_token = generate_csrf_token()

        device_entropy = request.cookies.get("device_entropy") or request.headers.get("x-device-entropy", "")
        context = RequestContext(
            ip=extract_client_ip(request),
            user_agent=request.headers.get("user-agent", ""),
            device_entropy=device_entropy,
            device_fingerprint=compute_device_fingerprint(
                {key.lower(): value for key, value in request.headers.items()},
                device_entropy,
            ),
            csrf_token=csrf_token,
            issued_csrf_cookie=issued_csrf_cookie,
        )
        request.state.context = context
        request.state.current_user = None
        request.state.current_session = None

        response = await call_next(request)
        if context.issued_csrf_cookie:
            response.set_cookie(
                settings.csrf_cookie_name,
                context.csrf_token,
                httponly=False,
                samesite="lax",
                secure=settings.use_secure_cookies,
                path="/",
                max_age=60 * 60 * 24 * 30,
            )
        return response
