from datetime import datetime, timezone

from pydantic import BaseModel, Field


class ContainmentWebhookPayload(BaseModel):
    alert_id: str
    detection_type: str
    entity_type: str
    entity_value: str
    occurred_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    monitor_name: str
