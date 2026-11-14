"""Client for querying FIRST.org Exploit Prediction Scoring System (EPSS) API."""

import logging

import requests

from .schemas import EpssData

logger = logging.getLogger(__name__)

EPSS_API_URL = "https://api.first.org/data/v1/epss"


class EpssClient:
    """Client for fetching and caching EPSS probability and percentile data."""

    def __init__(self, timeout_seconds: int = 10):
        self.timeout_seconds = timeout_seconds
        self._cache: dict[str, EpssData] = {}

    def get_epss(self, cve_id: str) -> EpssData:
        """Fetch EPSS data for a specific CVE ID.

        Falls back to 0.0 probability if the CVE is unrecorded or network fails.
        """
        cve_upper = cve_id.strip().upper()
        if cve_upper in self._cache:
            return self._cache[cve_upper]

        try:
            response = requests.get(
                EPSS_API_URL,
                params={"cve": cve_upper},
                timeout=self.timeout_seconds,
                headers={"Accept": "application/json"},
            )
            response.raise_for_status()
            payload = response.json()
            data = payload.get("data", [])

            if data:
                entry = data[0]
                result = EpssData(
                    cve_id=cve_upper,
                    epss_score=float(entry.get("epss", 0.0)),
                    percentile=float(entry.get("percentile", 0.0)),
                    date=str(entry.get("date", "")),
                )
            else:
                logger.warning(
                    "No EPSS entry returned for %s; defaulting to 0.0", cve_upper
                )
                result = EpssData(cve_id=cve_upper, epss_score=0.0, percentile=0.0)

        except (requests.RequestException, ValueError, KeyError, OSError) as err:
            logger.error(
                "Failed to fetch EPSS for %s: %s; using safe defaults", cve_upper, err
            )
            result = EpssData(cve_id=cve_upper, epss_score=0.0, percentile=0.0)

        self._cache[cve_upper] = result
        return result
