"""JSON output formatting."""

import json
from typing import List, Dict, Any


class JsonReporter:
    """Format scan results as JSON."""
    
    @staticmethod
    def report_file(result: Dict) -> str:
        """Convert file scan result to JSON."""
        return json.dumps(result, indent=2)
    
    @staticmethod
    def report_batch(batch_result: Dict) -> str:
        """Convert batch results to JSON."""
        return json.dumps(batch_result, indent=2)
    
    @staticmethod
    def report_compact(batch_result: Dict) -> str:
        """Convert to compact JSON (no indent)."""
        return json.dumps(batch_result, separators=(',', ':'))
