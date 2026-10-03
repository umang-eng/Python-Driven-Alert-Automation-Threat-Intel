import time
import logging
import requests
from typing import Dict, Any
from requests.exceptions import Timeout, RequestException

# Import settings from our config module
from config import SETTINGS

logger = logging.getLogger("VirusTotalAPI")

# ---------------------------------------------------------
# Custom Exceptions
# ---------------------------------------------------------
class RateLimitExceeded(Exception):
    """Raised when the VirusTotal API rate limit (HTTP 429) is repeatedly hit."""
    pass

class APIAuthenticationError(Exception):
    """Raised when the API key is invalid or unauthorized (HTTP 401)."""
    pass

class ConnectionTimeout(Exception):
    """Raised when the connection to the VirusTotal API times out."""
    pass

class VTServerError(Exception):
    """Raised when VirusTotal returns persistent 5xx errors."""
    pass

# ---------------------------------------------------------
# API Client
# ---------------------------------------------------------
class VirusTotalClient:
    def __init__(self):
        self.api_key = SETTINGS.get("VT_API_KEY")
        self.base_url = "https://www.virustotal.com/api/v3"
        
        # Implement connection pooling for performance
        self.session = requests.Session()
        self.session.headers.update({
            "x-apikey": self.api_key,
            "Accept": "application/json"
        })
        
        # Strict rate limiter for free tier (4 req/min = 1 req every 15s)
        self.rate_limit_delay = 15.0 

    def _make_request(self, endpoint: str) -> Dict[str, Any]:
        """
        Internal method to execute API requests with exponential backoff.
        """
        url = f"{self.base_url}/{endpoint}"
        max_retries = 3
        backoff_time = 2.0

        for attempt in range(1, max_retries + 1):
            try:
                logger.info(f"Querying VirusTotal: {url}")
                response = self.session.get(url, timeout=10)
                
                # Enforce strict rate limiting regardless of response success
                time.sleep(self.rate_limit_delay)
                
                if response.status_code == 200:
                    return response.json()
                
                elif response.status_code == 401:
                    logger.critical("Unauthorized API Key.")
                    raise APIAuthenticationError("Invalid or unauthorized VirusTotal API Key.")
                
                elif response.status_code == 429:
                    logger.warning(f"Rate limit hit on attempt {attempt}. Applying extended backoff...")
                    if attempt == max_retries:
                        raise RateLimitExceeded("Exceeded maximum retries for HTTP 429 Too Many Requests.")
                    time.sleep(self.rate_limit_delay * 2)
                    continue
                
                elif response.status_code == 404:
                    # IoC not found in VirusTotal database (not necessarily an error)
                    logger.info(f"IoC not found in VT database: {endpoint}")
                    return {}
                
                elif response.status_code >= 500:
                    logger.warning(f"VT Server Error ({response.status_code}). Retrying in {backoff_time}s...")
                    time.sleep(backoff_time)
                    backoff_time *= 2
                    continue
                
                else:
                    # Handle other unexpected HTTP errors
                    response.raise_for_status()

            except Timeout:
                logger.error(f"Timeout on attempt {attempt} for {url}")
                if attempt == max_retries:
                    raise ConnectionTimeout(f"Connection timeout to VT API for {url}")
                time.sleep(backoff_time)
                backoff_time *= 2
                
            except RequestException as e:
                logger.error(f"Network request failed: {e}")
                return {}

        raise VTServerError("Exceeded maximum retries due to persistent server errors.")

    def _parse_stats(self, ioc_value: str, raw_response: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extracts only the required malicious and suspicious counts from the raw JSON payload.
        """
        if not raw_response or "data" not in raw_response:
            return {
                "ioc": ioc_value, 
                "malicious": 0, 
                "suspicious": 0, 
                "found": False
            }
        
        stats = raw_response["data"]["attributes"].get("last_analysis_stats", {})
        
        return {
            "ioc": ioc_value,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "found": True
        }

    def get_ip_reputation(self, ip_address: str) -> Dict[str, Any]:
        """
        Queries the IP address endpoint and returns parsed threat intelligence.
        """
        endpoint = f"ip_addresses/{ip_address}"
        response = self._make_request(endpoint)
        return self._parse_stats(ip_address, response)

    def get_hash_reputation(self, file_hash: str) -> Dict[str, Any]:
        """
        Queries the file hash endpoint and returns parsed threat intelligence.
        """
        endpoint = f"files/{file_hash}"
        response = self._make_request(endpoint)
        return self._parse_stats(file_hash, response)