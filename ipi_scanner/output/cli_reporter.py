"""CLI output formatting with colors and clear reporting."""

from typing import List, Dict


class CliReporter:
    """Format scan results for terminal output."""
    
    # Color codes for terminal
    RED = '\033[91m'
    ORANGE = '\033[38;5;208m'
    YELLOW = '\033[93m'
    GREEN = '\033[92m'
    BLUE = '\033[94m'
    BOLD = '\033[1m'
    RESET = '\033[0m'
    
    @staticmethod
    def _colorize(text: str, color: str) -> str:
        """Add color to text."""
        return f"{color}{text}{CliReporter.RESET}"
    
    @staticmethod
    def report_file(result: Dict) -> str:
        """Format single file scan result."""
        output = []
        
        if result['status'] == 'error':
            output.append(
                CliReporter._colorize(f"❌ {result['file']}", CliReporter.RED)
            )
            output.append(f"   Error: {result.get('error', 'Unknown error')}")
            return "\n".join(output)
        
        if result['status'] == 'empty':
            output.append(
                CliReporter._colorize(f"⚪ {result['file']}", CliReporter.BLUE)
            )
            output.append("   File is empty")
            return "\n".join(output)
        
        # Successful scan
        assessment = result['risk_assessment']
        score = assessment['score']
        level = assessment['level']
        
        # Choose icon and color by level
        if level == 'Red':
            icon = '🔴'
            color = CliReporter.RED
        elif level == 'Orange':
            icon = '🟠'
            color = CliReporter.ORANGE
        elif level == 'Yellow':
            icon = '🟡'
            color = CliReporter.YELLOW
        else:  # Green
            icon = '✅'
            color = CliReporter.GREEN
        
        # File header
        output.append(
            CliReporter._colorize(f"{icon} {result['file']}", CliReporter.BOLD)
        )
        
        # Risk score
        output.append(
            CliReporter._colorize(
                f"   Risk Score: {score}/100 ({level})",
                color
            )
        )
        
        # File info
        if 'size_bytes' in result:
            size_kb = result['size_bytes'] / 1024
            output.append(f"   Size: {size_kb:.1f} KB")
        
        output.append(f"   Type: {result['doc_type']}")
        
        # Detections
        if result['detections']:
            output.append(f"   Threats ({len(result['detections'])} detected):")
            for det in result['detections']:
                confidence_pct = int(det['confidence'] * 100)
                threat_name = det['category'].replace('_', ' ').title()
                output.append(
                    f"      • {threat_name} ({confidence_pct}%) @ {det['location']}"
                )
                # Show match preview (truncated)
                match_preview = det['match'][:80].replace('\n', ' ')
                output.append(f"        → \"{match_preview}...\"")
        else:
            output.append("   No threats detected ✓")
        
        # Recommendation
        output.append(f"   {assessment['recommendation']}")
        
        return "\n".join(output)
    
    @staticmethod
    def report_batch(batch_result: Dict) -> str:
        """Format batch scan results."""
        output = []
        summary = batch_result['summary']
        
        # Summary header
        output.append(CliReporter._colorize("=" * 60, CliReporter.BOLD))
        output.append(CliReporter._colorize("IPI-SCANNER BATCH RESULTS", CliReporter.BOLD))
        output.append(CliReporter._colorize("=" * 60, CliReporter.RESET))
        output.append("")
        
        # Statistics
        output.append(CliReporter._colorize("SUMMARY", CliReporter.BOLD))
        output.append(f"  Total files: {summary['total_files']}")
        output.append(f"  Successfully scanned: {summary['scanned']}")
        output.append(f"  Errors: {summary['errors']}")
        output.append(f"  High-risk files: {summary['high_risk_count']}")
        output.append(f"  Total detections: {summary['total_detections']}")
        output.append("")
        
        # High risk files
        if batch_result['high_risk_files']:
            output.append(CliReporter._colorize("HIGH-RISK FILES", CliReporter.BOLD))
            for file_path, score in batch_result['high_risk_files']:
                output.append(
                    CliReporter._colorize(
                        f"  ⚠️  {file_path}: {score}/100",
                        CliReporter.RED if score >= 75 else CliReporter.ORANGE
                    )
                )
            output.append("")
        
        # Detailed results
        output.append(CliReporter._colorize("DETAILED RESULTS", CliReporter.BOLD))
        output.append("")
        
        for result in batch_result['detailed_results']:
            output.append(CliReporter.report_file(result))
            output.append("")
        
        return "\n".join(output)
    
    @staticmethod
    def report_summary(batch_result: Dict) -> str:
        """Format brief summary only."""
        summary = batch_result['summary']
        
        output = []
        output.append("")
        output.append(CliReporter._colorize("SCAN SUMMARY", CliReporter.BOLD))
        output.append(f"  Scanned: {summary['scanned']}/{summary['total_files']}")
        output.append(f"  High-risk: {summary['high_risk_count']}")
        output.append(f"  Detections: {summary['total_detections']}")
        
        if batch_result['high_risk_files']:
            output.append("")
            output.append("High-risk files:")
            for file_path, score in batch_result['high_risk_files']:
                output.append(f"  • {file_path}: {score}/100")
        
        return "\n".join(output)
