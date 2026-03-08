from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import Request
from fastapi.templating import Jinja2Templates

TEMPLATES = Jinja2Templates(directory=Path("templates").as_posix())
TEMPLATES.env.globals["bool"] = bool


def template_response(request: Request, name: str, **context: Any):
    current_user = getattr(request.state, "current_user", None)
    current_session = getattr(request.state, "current_session", None)
    settings = request.app.state.settings
    base_context = {
        "request": request,
        "settings": settings,
        "csrf_token": request.state.context.csrf_token,
        "current_user": current_user,
        "current_session": current_session,
        "turnstile_enabled": bool(settings.turnstile_site_key),
    }
    base_context.update(context)
    return TEMPLATES.TemplateResponse(request, name, base_context)
