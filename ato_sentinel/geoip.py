from __future__ import annotations

import io
import tarfile
from pathlib import Path

import httpx
from geoip2 import database
from geoip2.errors import AddressNotFoundError

from ato_sentinel.config import Settings
from ato_sentinel.types import GeoContext


class GeoIPService:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.reader: database.Reader | None = None
        self.status = "disabled"
        self._load_reader()

    def _load_reader(self) -> None:
        path = Path(self.settings.geoip_db_path)
        if path.exists():
            self.reader = database.Reader(path.as_posix())
            self.status = "ready"
            return

        if not self.settings.maxmind_license_key:
            self.status = "disabled"
            return

        try:
            runtime_path = Path("/tmp/GeoLite2-City.mmdb")
            self._download_city_db(runtime_path)
            self.reader = database.Reader(runtime_path.as_posix())
            self.status = "downloaded"
        except Exception:
            self.reader = None
            self.status = "download_failed"

    def _download_city_db(self, destination: Path) -> None:
        destination.parent.mkdir(parents=True, exist_ok=True)
        url = (
            "https://download.maxmind.com/app/geoip_download"
            f"?edition_id=GeoLite2-City&license_key={self.settings.maxmind_license_key}&suffix=tar.gz"
        )
        with httpx.Client(timeout=20) as client:
            response = client.get(url)
            response.raise_for_status()
        with tarfile.open(fileobj=io.BytesIO(response.content), mode="r:gz") as archive:
            member = next(item for item in archive.getmembers() if item.name.endswith("GeoLite2-City.mmdb"))
            with archive.extractfile(member) as stream:
                if stream is None:
                    raise RuntimeError("GeoLite2 archive missing GeoLite2-City.mmdb")
                destination.write_bytes(stream.read())

    def lookup(self, ip: str, headers: dict[str, str]) -> GeoContext:
        if self.settings.allow_debug_geo_overrides and headers.get("x-debug-country"):
            latitude = headers.get("x-debug-latitude")
            longitude = headers.get("x-debug-longitude")
            return GeoContext(
                country_code=headers.get("x-debug-country"),
                city=headers.get("x-debug-city"),
                latitude=float(latitude) if latitude else None,
                longitude=float(longitude) if longitude else None,
                asn=headers.get("x-debug-asn"),
                status="debug",
            )

        if not self.reader:
            return GeoContext(status=self.status)

        try:
            city_response = self.reader.city(ip)
            asn = None
            try:
                asn = str(getattr(city_response.traits, "autonomous_system_number", "") or "")
            except Exception:
                asn = None
            return GeoContext(
                country_code=city_response.country.iso_code,
                city=city_response.city.name,
                latitude=city_response.location.latitude,
                longitude=city_response.location.longitude,
                asn=asn or None,
                status=self.status,
            )
        except AddressNotFoundError:
            return GeoContext(status="not_found")
        except Exception:
            return GeoContext(status="lookup_failed")
