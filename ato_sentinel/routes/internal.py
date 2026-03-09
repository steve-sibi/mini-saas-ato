from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from ato_sentinel.deps import get_db
from ato_sentinel.schemas import ContainmentWebhookPayload
from ato_sentinel.security import verify_webhook_signature
from ato_sentinel.services.detections import apply_webhook_containment

router = APIRouter(tags=["internal"])


@router.post("/internal/datadog/contain")
async def datadog_contain(request: Request, db: Session = Depends(get_db)):
    settings = request.app.state.settings
    body = await request.body()
    token = request.headers.get("X-ATO-Webhook-Token", "")
    timestamp = request.headers.get("X-ATO-Timestamp", "")
    signature = request.headers.get("X-ATO-Signature", "")

    authorized = False
    if timestamp and signature:
        authorized = verify_webhook_signature(
            settings.datadog_webhook_secret,
            timestamp,
            body,
            signature,
            settings.hmac_tolerance_seconds,
        )
    elif token and token == settings.datadog_webhook_secret:
        authorized = True

    if not authorized:
        raise HTTPException(status_code=403, detail="Invalid webhook signature")

    payload = ContainmentWebhookPayload.model_validate_json(body)
    if not timestamp and (datetime.now(timezone.utc) - payload.occurred_at).total_seconds() > settings.webhook_fallback_tolerance_seconds:
        raise HTTPException(status_code=400, detail="Fallback webhook payload is too old")

    action, idempotent = apply_webhook_containment(
        db,
        detection_type=payload.detection_type,
        entity_type=payload.entity_type,
        entity_value=payload.entity_value,
        external_id=payload.alert_id,
        monitor_name=payload.monitor_name,
        occurred_at=payload.occurred_at,
    )
    db.commit()
    return JSONResponse({"status": "ok", "action_id": action.id, "idempotent": idempotent})
