from pathlib import Path
import sys

from ato_sentinel.config import get_settings
from ato_sentinel.geoip import GeoIPService


def main() -> int:
    settings = get_settings()
    if not settings.maxmind_license_key:
        print("MAXMIND_LICENSE_KEY is required to download GeoLite2-City.")
        return 1

    destination = Path(settings.geoip_db_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    service = GeoIPService(settings)
    service._download_city_db(destination)  # noqa: SLF001 - shared helper for local setup.
    print(f"Downloaded GeoLite2-City to {destination}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
