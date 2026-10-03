import logging
import requests
from typing import Dict, Any
from config import SETTINGS

logger = logging.getLogger("AbuseIPDBClient")

class AbuseIPDBClient:
    def __init__(self):
        self.api_key = SETTINGS.get("ABUSEIPDB_API_KEY")
        self.base_url = "https://api.abuseipdb.com/api/v2"
        
        self.session = requests.Session()
        # AbuseIPDB uses 'Key' instead of 'x-apikey'
        if self.api_key:
            self.session.headers.update({
                "Key": self.api_key,
                "Accept": "application/json"
            })

    def check_ip(self, ip_address: str, max_age_days: int = 90) -> Dict[str, Any]:
        """
        Queries the AbuseIPDB /check endpoint for an IP address.
        """
        # Failsafe if the user didn't configure the API key
        if not self.api_key or self.api_key == "your_abuseipdb_api_key_here":
            logger.debug("AbuseIPDB API key not configured. Skipping.")
            return {"abuse_confidence_score": 0, "total_reports": 0}

        endpoint = f"{self.base_url}/check"
        params = {
            "ipAddress": ip_address,
            "maxAgeInDays": max_age_days
        }

        try:
            logger.info(f"Querying AbuseIPDB for IP: {ip_address}")
            response = self.session.get(endpoint, params=params, timeout=10)

            if response.status_code == 200:
                data = response.json().get("data", {})
                return {
                    "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                    "total_reports": data.get("totalReports", 0)
                }
            elif response.status_code == 429:
                logger.warning("AbuseIPDB Rate Limit Exceeded (HTTP 429).")
            elif response.status_code == 401:
                logger.error("AbuseIPDB Unauthorized. Check your API key.")
            else:
                logger.warning(f"AbuseIPDB returned unexpected status {response.status_code} for {ip_address}")

        except requests.RequestException as e:
            logger.error(f"AbuseIPDB network request failed: {e}")

        # Return default safe values if the request fails
        return {"abuse_confidence_score": 0, "total_reports": 0}