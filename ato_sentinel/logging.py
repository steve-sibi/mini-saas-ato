from __future__ import annotations

import json
import logging
from datetime import datetime
from decimal import Decimal

from ato_sentinel.config import Settings

logger = logging.getLogger("ato_sentinel.events")


def configure_logging() -> None:
    if logger.handlers:
        return
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    logger.setLevel(logging.INFO)


def _default(value: object) -> str | float:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, Decimal):
        return float(value)
    return str(value)


def emit_log(settings: Settings, payload: dict[str, object]) -> None:
    configure_logging()
    enriched = {
        "service": settings.dd_service,
        "env": settings.dd_env,
        **payload,
    }
    logger.info(json.dumps(enriched, default=_default, separators=(",", ":")))
