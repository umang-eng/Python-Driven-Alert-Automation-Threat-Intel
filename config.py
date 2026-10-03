import os
import logging
from typing import Dict, Union
from dotenv import load_dotenv

# ---------------------------------------------------------
# Logging Configuration
# ---------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(name)s | %(levelname)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("PipelineConfig")

# ---------------------------------------------------------
# Custom Exceptions
# ---------------------------------------------------------
class MissingConfigurationError(Exception):
    """Exception raised when critical environment variables are missing."""
    pass

# ---------------------------------------------------------
# Configuration Loader
# ---------------------------------------------------------
def load_config() -> Dict[str, Union[str, int]]:
    """
    Loads environment variables from the .env file and validates them.
    
    Returns:
        dict: A dictionary containing the validated configuration keys.
        
    Raises:
        MissingConfigurationError: If critical configurations are missing or invalid.
    """
    logger.info("Initializing configuration and loading environment variables.")
    
    # Load .env file into os.environ
    load_dotenv()

    # Retrieve variables
    vt_api_key = os.getenv("VT_API_KEY")
    risk_score_str = os.getenv("RISK_SCORE_THRESHOLD", "3")  # Defaults to 3 if omitted
    abuse_api_key = os.getenv("ABUSEIPDB_API_KEY", "")

    # Validate VirusTotal API Key
    if not vt_api_key or vt_api_key.strip() == "your_virustotal_api_key_here":
        logger.critical("VT_API_KEY is missing or set to the default placeholder.")
        raise MissingConfigurationError("FATAL: VT_API_KEY is not configured.")

    # Validate Risk Score Threshold
    try:
        risk_score = int(risk_score_str)
    except ValueError:
        logger.critical("RISK_SCORE_THRESHOLD must be a valid integer. Received: %s", risk_score_str)
        raise MissingConfigurationError(f"FATAL: Invalid RISK_SCORE_THRESHOLD: {risk_score_str}")

    logger.info("Configuration validated successfully.")
    
    return {
        "VT_API_KEY": vt_api_key,
        "ABUSEIPDB_API_KEY": abuse_api_key,
        "RISK_SCORE_THRESHOLD": risk_score
    }

# ---------------------------------------------------------
# Global Config Export
# ---------------------------------------------------------
try:
    SETTINGS = load_config()
except MissingConfigurationError as e:
    logger.critical("Application halting due to configuration failure.")
    raise SystemExit(1)