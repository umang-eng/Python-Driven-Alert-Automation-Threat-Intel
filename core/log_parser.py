import json
import logging
from typing import Dict, Iterator, Tuple, Any, Set
from core.ioc_extractor import extract_iocs

logger = logging.getLogger("LogParser")

def yield_log_lines(file_path: str) -> Iterator[Tuple[str, str]]:
    """
    A generator that reads a JSON log file line-by-line to minimize memory consumption.
    Extracts a contextual identifier (timestamp or ID) alongside the raw JSON string.
    
    Args:
        file_path (str): The absolute or relative path to the log file.
        
    Yields:
        Tuple[str, str]: A tuple containing the (log_id_or_timestamp, raw_json_string).
    """
    logger.info(f"Opening log file for stream processing: {file_path}")
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, start=1):
                line = line.strip()
                if not line:
                    continue
                
                try:
                    data = json.loads(line)
                    # Attempt to extract 'timestamp' or 'id'. Fall back to line number if missing.
                    log_id = str(data.get("timestamp", data.get("id", f"line_{line_num}")))
                    yield log_id, line
                except json.JSONDecodeError:
                    logger.warning(f"Malformed JSON skipped on line {line_num} in {file_path}")
                    continue
    except FileNotFoundError:
        logger.error(f"File not found: {file_path}")
        raise

def parse_and_extract(file_path: str) -> Dict[str, Dict[str, Any]]:
    """
    Processes a log file, returning a deduplicated mapping of IoCs to their occurrences.
    
    Args:
        file_path (str): Path to the log file.
        
    Returns:
        Dict[str, Dict[str, Any]]: A dictionary where the key is the IoC value (e.g., '8.8.8.8') 
        and the value is metadata containing the IoC type and a set of log IDs where it was seen.
    """
    # Structure: { "8.8.8.8": {"type": "ip", "seen_in": {"2023-10-24T12:00:00Z", "line_45"}} }
    deduplicated_iocs: Dict[str, Dict[str, Any]] = {}
    
    # Iterate through the file without holding it in memory
    for log_id, raw_line in yield_log_lines(file_path):
        extracted = extract_iocs(raw_line)
        
        # Helper function to map extracted IoCs into our deduplicated dictionary
        def map_ioc(ioc_list: List[str], ioc_type: str):
            for ioc in ioc_list:
                if ioc not in deduplicated_iocs:
                    deduplicated_iocs[ioc] = {
                        "type": ioc_type,
                        "seen_in": set()
                    }
                deduplicated_iocs[ioc]["seen_in"].add(log_id)

        map_ioc(extracted["ips"], "ip")
        map_ioc(extracted["md5"], "md5")
        map_ioc(extracted["sha256"], "sha256")

    total_unique = len(deduplicated_iocs)
    logger.info(f"Finished parsing {file_path}. Extracted {total_unique} unique actionable IoCs.")
    
    return deduplicated_iocs