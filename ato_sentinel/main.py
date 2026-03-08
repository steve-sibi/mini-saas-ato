from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, Request
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles

from ato_sentinel.config import Settings, get_settings
from ato_sentinel.db import build_engine, build_session_factory
from ato_sentinel.deps import AuthenticationRequired, SessionRiskRedirect, get_optional_auth_context
from ato_sentinel.geoip import GeoIPService
from ato_sentinel.middleware import RequestContextMiddleware
from ato_sentinel.routes.account import router as account_router
from ato_sentinel.routes.analyst import router as analyst_router
from ato_sentinel.routes.auth import router as auth_router
from ato_sentinel.routes.internal import router as internal_router
from ato_sentinel.templating import template_response
from ato_sentinel.turnstile import TurnstileVerifier


def create_app(settings: Settings | None = None) -> FastAPI:
    active_settings = settings or get_settings()
    engine = build_engine(active_settings.database_url)
    session_factory = build_session_factory(engine)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.settings = active_settings
        app.state.engine = engine
        app.state.session_factory = session_factory
        app.state.geoip = GeoIPService(active_settings)
        app.state.turnstile = TurnstileVerifier(active_settings)
        yield
        engine.dispose()

    app = FastAPI(title="ATO Sentinel", lifespan=lifespan)
    app.add_middleware(RequestContextMiddleware)
    app.mount("/static", StaticFiles(directory=Path("static")), name="static")

    @app.exception_handler(AuthenticationRequired)
    async def handle_auth_required(request: Request, _: AuthenticationRequired):
        response = RedirectResponse(url="/auth/login", status_code=303)
        response.delete_cookie(request.app.state.settings.session_cookie_name)
        return response

    @app.exception_handler(SessionRiskRedirect)
    async def handle_session_risk(request: Request, exc: SessionRiskRedirect):
        response = RedirectResponse(url=f"/auth/login?error={exc.reason}", status_code=303)
        response.delete_cookie(request.app.state.settings.session_cookie_name)
        return response

    @app.get("/")
    def home(request: Request, auth_context=Depends(get_optional_auth_context)):
        if auth_context:
            return RedirectResponse(url="/account/security", status_code=303)
        return template_response(request, "home.html")

    @app.get("/mitre")
    def mitre_mapping(request: Request):
        mappings = [
            ("ATO-001", "T1110.003", "Password spraying from one IP across many accounts."),
            ("ATO-002", "T1550.004", "Session cookie reuse from a materially different device."),
            ("ATO-003", "T1078 / T1078.004", "Valid-account abuse with impossible travel signals."),
            ("ATO-004", "T1110.004", "Distributed credential stuffing against one account."),
        ]
        return template_response(request, "mitre.html", mappings=mappings)

    @app.get("/healthz")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    app.include_router(auth_router)
    app.include_router(account_router)
    app.include_router(analyst_router)
    app.include_router(internal_router)
    return app


app = create_app()
