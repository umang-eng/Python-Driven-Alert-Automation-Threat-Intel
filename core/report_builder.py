import os
import csv
import logging
from datetime import datetime
from typing import List, Dict, Any

from config import SETTINGS

logger = logging.getLogger("ReportBuilder")

class ReportBuilder:
    def __init__(self, output_dir: str = "data/output_reports"):
        """
        Initializes the ReportBuilder and ensures the output directory exists.
        """
        self.output_dir = output_dir
        self.threshold = SETTINGS.get("RISK_SCORE_THRESHOLD", 3)
        
        # Ensure the directory structure exists before attempting to write
        os.makedirs(self.output_dir, exist_ok=True)

    def _determine_action(self, malicious_score: int) -> str:
        """
        Determines the required SOC action based on the VT malicious score.
        """
        if malicious_score >= self.threshold:
            return "Block"
        elif malicious_score > 0:
            return "Investigate"
        return "Clean"

    def generate_csv_report(self, enriched_iocs: List[Dict[str, Any]], report_prefix: str = "triage_report") -> str:
        """
        Generates a CSV report containing only non-benign IoCs.
        
        Args:
            enriched_iocs (List[Dict[str, Any]]): The list of dictionaries containing IoC and VT data.
            report_prefix (str): Prefix for the generated CSV filename.
            
        Returns:
            str: The filepath of the generated CSV report.
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{report_prefix}_{timestamp}.csv"
        filepath = os.path.join(self.output_dir, filename)
        
        fieldnames = ["Timestamp", "IoC Type", "IoC Value", "VT Malicious Score", "Action Required", "Log Source IDs"]
        
        # Filter out benign IoCs (Score of 0) to ensure the report is strictly actionable
        actionable_iocs = [ioc for ioc in enriched_iocs if ioc.get("malicious", 0) > 0]
        
        if not actionable_iocs:
            logger.info("No malicious or suspicious IoCs found. Report not generated.")
            return ""

        try:
            with open(filepath, mode="w", newline="", encoding="utf-8") as csv_file:
                writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
                writer.writeheader()
                
                for ioc in actionable_iocs:
                    score = ioc.get("malicious", 0)
                    writer.writerow({
                        "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "IoC Type": str(ioc.get("type", "unknown")).upper(),
                        "IoC Value": ioc.get("ioc", ""),
                        "VT Malicious Score": score,
                        "Action Required": self._determine_action(score),
                        # Convert the set of log IDs into a readable string, truncating if excessively long
                        "Log Source IDs": " | ".join(list(ioc.get("seen_in", [])))[:150]
                    })
            
            logger.info(f"Actionable CSV report successfully written to: {filepath}")
            return filepath
            
        except IOError as e:
            logger.error(f"Failed to write report to {filepath}: {e}")
            raise