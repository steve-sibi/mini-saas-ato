from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from ato_sentinel.models import User, UserSession


@dataclass
class GeoContext:
    country_code: str | None = None
    city: str | None = None
    latitude: float | None = None
    longitude: float | None = None
    asn: str | None = None
    status: str = "disabled"


@dataclass
class RequestContext:
    ip: str
    user_agent: str
    device_entropy: str
    device_fingerprint: str
    csrf_token: str
    issued_csrf_cookie: bool


@dataclass
class AuthenticatedContext:
    user: User
    session: UserSession
    geo: GeoContext


@dataclass
class TicketPayload:
    user_id: int
    email: str
    device_fingerprint: str
    source_ip: str
    issued_at: datetime
