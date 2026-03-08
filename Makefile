UV ?= uv

.PHONY: db dev test migrate geoip

db:
	docker compose up db

dev:
	$(UV) run uvicorn app:app --reload --host 0.0.0.0 --port 8000

migrate:
	$(UV) run alembic upgrade head

test:
	$(UV) run pytest

geoip:
	$(UV) run python scripts/download_geoip.py
