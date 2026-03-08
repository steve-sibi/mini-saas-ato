from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from ato_sentinel.config import Settings
from ato_sentinel.main import create_app
from ato_sentinel.models import Base


@pytest.fixture
def client(tmp_path: Path):
    settings = Settings(
        database_url=f"sqlite+pysqlite:///{tmp_path / 'ato-sentinel.db'}",
        app_secret_key="test-app-secret",
        csrf_secret_key="test-csrf-secret",
        datadog_webhook_secret="test-webhook-secret",
        dd_env="dev",
        dd_service="ato-sentinel-test",
    )
    app = create_app(settings)
    with TestClient(app) as client:
        Base.metadata.create_all(bind=client.app.state.engine)
        yield client
        Base.metadata.drop_all(bind=client.app.state.engine)
