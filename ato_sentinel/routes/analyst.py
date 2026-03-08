from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from ato_sentinel.deps import get_db, require_authenticated
from ato_sentinel.models import AuthEvent, ContainmentAction, Detection
from ato_sentinel.templating import template_response

router = APIRouter(prefix="/analyst", tags=["analyst"])


@router.get("/detections")
def list_detections(
    request: Request,
    db: Session = Depends(get_db),
    _auth_context=Depends(require_authenticated),
):
    detections = db.scalars(select(Detection).order_by(Detection.occurred_at.desc()).limit(100)).all()
    return template_response(request, "analyst/detections.html", detections=detections)


@router.get("/detections/{detection_id}")
def detection_detail(
    request: Request,
    detection_id: int,
    db: Session = Depends(get_db),
    _auth_context=Depends(require_authenticated),
):
    detection = db.get(Detection, detection_id)
    if not detection:
        raise HTTPException(status_code=404, detail="Detection not found")

    auth_event = db.get(AuthEvent, detection.auth_event_id) if detection.auth_event_id else None
    actions = db.scalars(
        select(ContainmentAction).where(ContainmentAction.detection_id == detection.id).order_by(ContainmentAction.created_at.desc())
    ).all()
    return template_response(
        request,
        "analyst/detection_detail.html",
        detection=detection,
        auth_event=auth_event,
        actions=actions,
    )
