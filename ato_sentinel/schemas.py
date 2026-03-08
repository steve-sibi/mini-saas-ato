from datetime import datetime

from pydantic import BaseModel, Field


class ContainmentWebhookPayload(BaseModel):
    alert_id: str
    detection_type: str
    entity_type: str
    entity_value: str
    occurred_at: datetime = Field(default_factory=datetime.utcnow)
    monitor_name: str
