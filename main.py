import os
import sys
import glob
import argparse
import logging
from typing import List, Dict, Any

from core.log_parser import parse_and_extract
from core.report_builder import ReportBuilder
from integrations.virustotal import VirusTotalClient
from integrations.abuseipdb import AbuseIPDBClient

# ---------------------------------------------------------
# Master Orchestrator Logging setup
# ---------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(name)s | %(levelname)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("TriageOrchestrator")

def main():
    # CLI Argument Parsing
    parser = argparse.ArgumentParser(description="Automated Alert Triage & Threat Intel Pipeline")
    parser.add_argument(
        "--input", 
        type=str, 
        default="data/input_logs/", 
        help="Directory containing raw JSON security logs."
    )
    args = parser.parse_args()

    input_dir = args.input
    if not os.path.isdir(input_dir):
        logger.critical(f"Input directory does not exist: {input_dir}")
        sys.exit(1)

    log_files = glob.glob(os.path.join(input_dir, "*.json"))
    if not log_files:
        logger.warning(f"No JSON logs found in {input_dir}. Exiting.")
        sys.exit(0)

    logger.info(f"Pipeline starting. Found {len(log_files)} log file(s) for processing.")

    # Initialize Modules
    vt_client = VirusTotalClient()
    abuse_client = AbuseIPDBClient()
    report_builder = ReportBuilder()
    all_enriched_data: List[Dict[str, Any]] = []

    # 1. Ingestion & Extraction Phase
    for log_file in log_files:
        try:
            logger.info(f"Initiating extraction for: {log_file}")
            extracted_iocs = parse_and_extract(log_file)
        except Exception as e:
            logger.error(f"Failed to parse {log_file}: {e}")
            continue

        # 2. Enrichment Phase
        for ioc_value, metadata in extracted_iocs.items():
            ioc_type = metadata["type"]
            seen_in = metadata["seen_in"]
            
            # Master Exception Handler: Ensure one bad IoC query doesn't crash the pipeline
            try:
                if ioc_type == "ip":
                    # Query VirusTotal
                    vt_result = vt_client.get_ip_reputation(ioc_value)
                    
                    # Query AbuseIPDB for additional enrichment
                    abuse_result = abuse_client.check_ip(ioc_value)
                    
                    if vt_result:
                        vt_result["type"] = ioc_type
                        vt_result["seen_in"] = seen_in
                        # Merge the AbuseIPDB scores into the final dict
                        vt_result["abuse_confidence_score"] = abuse_result.get("abuse_confidence_score", 0)
                        vt_result["abuse_total_reports"] = abuse_result.get("total_reports", 0)
                        
                        all_enriched_data.append(vt_result)

                elif ioc_type in ["md5", "sha256"]:
                    vt_result = vt_client.get_hash_reputation(ioc_value)
                    
                    if vt_result:
                        vt_result["type"] = ioc_type
                        vt_result["seen_in"] = seen_in
                        # Hashes don't apply to AbuseIPDB, so we set defaults
                        vt_result["abuse_confidence_score"] = 0 
                        vt_result["abuse_total_reports"] = 0
                        
                        all_enriched_data.append(vt_result)
                else:
                    logger.warning(f"Unknown IoC type extracted: {ioc_type}")
                    continue
                    
            except Exception as e:
                logger.error(f"Unhandled error while querying APIs for {ioc_type} ({ioc_value}): {e}")
                continue

    # 3. Reporting Phase
    if all_enriched_data:
        logger.info("Enrichment complete. Compiling final triage report...")
        try:
            report_path = report_builder.generate_csv_report(all_enriched_data)
            if report_path:
                logger.info(f"SUCCESS: High-risk alerts have been triaged and saved.")
        except Exception as e:
            logger.critical(f"Failed to compile final report: {e}")
            sys.exit(1)
    else:
        logger.info("No active IoCs successfully processed. Pipeline terminating cleanly.")

if __name__ == "__main__":
    main()