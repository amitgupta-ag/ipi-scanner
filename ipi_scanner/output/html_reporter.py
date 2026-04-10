"""HTML dashboard output formatting."""

import json
from typing import Dict
from datetime import datetime


class HtmlReporter:
    """Generate HTML dashboard for scan results."""
    
    @staticmethod
    def report_file(result: Dict) -> str:
        """Generate HTML for single file scan."""
        return HtmlReporter._generate_html([result])
    
    @staticmethod
    def report_batch(batch_result: Dict) -> str:
        """Generate HTML dashboard for batch results."""
        return HtmlReporter._generate_html(batch_result['detailed_results'])
    
    @staticmethod
    def _generate_html(results: list) -> str:
        """Generate complete HTML page."""
        html = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>IPI-Scanner Report</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: #f5f5f5;
            color: #333;
            padding: 20px;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        
        header {
            background: white;
            padding: 30px;
            border-radius: 8px;
            margin-bottom: 30px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        
        h1 {
            color: #2c3e50;
            margin-bottom: 10px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .timestamp {
            color: #7f8c8d;
            font-size: 14px;
        }
        
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-top: 30px;
        }
        
        .summary-card {
            background: #ecf0f1;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
        }
        
        .summary-card .number {
            font-size: 32px;
            font-weight: bold;
            color: #2c3e50;
        }
        
        .summary-card .label {
            color: #7f8c8d;
            margin-top: 8px;
            font-size: 14px;
        }
        
        .file-results {
            display: grid;
            gap: 20px;
        }
        
        .file-card {
            background: white;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        
        .file-header {
            padding: 20px;
            border-left: 5px solid;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .file-header.red {
            border-left-color: #e74c3c;
            background: #fadbd8;
        }
        
        .file-header.orange {
            border-left-color: #e67e22;
            background: #fdebd0;
        }
        
        .file-header.yellow {
            border-left-color: #f39c12;
            background: #fef5e7;
        }
        
        .file-header.green {
            border-left-color: #27ae60;
            background: #d5f4e6;
        }
        
        .file-info h3 {
            margin-bottom: 8px;
            color: #2c3e50;
        }
        
        .file-path {
            font-family: 'Courier New', monospace;
            font-size: 12px;
            color: #7f8c8d;
            margin-top: 5px;
            word-break: break-all;
        }
        
        .risk-badge {
            display: flex;
            align-items: center;
            gap: 10px;
            font-weight: bold;
        }
        
        .score {
            font-size: 24px;
            font-weight: bold;
        }
        
        .level {
            font-size: 14px;
            padding: 4px 8px;
            border-radius: 4px;
            background: rgba(0,0,0,0.1);
        }
        
        .file-body {
            padding: 20px;
            border-top: 1px solid #ecf0f1;
        }
        
        .detections {
            margin-bottom: 15px;
        }
        
        .detection-item {
            margin-bottom: 12px;
            padding: 12px;
            background: #f8f9f9;
            border-radius: 4px;
            border-left: 3px solid #3498db;
        }
        
        .detection-category {
            font-weight: bold;
            color: #2c3e50;
            margin-bottom: 4px;
        }
        
        .detection-match {
            font-family: 'Courier New', monospace;
            font-size: 12px;
            color: #7f8c8d;
            margin-top: 4px;
            padding: 8px;
            background: white;
            border-radius: 4px;
            word-break: break-all;
            max-height: 100px;
            overflow: hidden;
        }
        
        .recommendation {
            padding: 12px;
            border-radius: 4px;
            font-weight: bold;
            margin-top: 15px;
        }
        
        .recommendation.red {
            background: #e74c3c;
            color: white;
        }
        
        .recommendation.orange {
            background: #e67e22;
            color: white;
        }
        
        .recommendation.yellow {
            background: #f39c12;
            color: white;
        }
        
        .recommendation.green {
            background: #27ae60;
            color: white;
        }
        
        .no-detections {
            color: #27ae60;
            font-weight: bold;
            padding: 12px;
            text-align: center;
        }
        
        .error-card {
            background: #fadbd8;
            border-left-color: #e74c3c;
        }
        
        .error-message {
            color: #c0392b;
            padding: 20px;
            font-family: 'Courier New', monospace;
            font-size: 12px;
        }
        
        footer {
            text-align: center;
            color: #7f8c8d;
            margin-top: 40px;
            padding: 20px;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔒 IPI-Scanner Report</h1>
            <p class="timestamp">Generated: """ + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + """</p>
"""
        
        # Add summary if available
        summary_stats = {
            'total': len(results),
            'high_risk': sum(1 for r in results if r.get('status') == 'success' and r.get('risk_assessment', {}).get('score', 0) >= 50),
            'errors': sum(1 for r in results if r.get('status') == 'error'),
            'safe': sum(1 for r in results if r.get('status') == 'success' and r.get('risk_assessment', {}).get('score', 0) < 25)
        }
        
        html += """
            <div class="summary-grid">
                <div class="summary-card">
                    <div class="number">""" + str(summary_stats['total']) + """</div>
                    <div class="label">Total Files</div>
                </div>
                <div class="summary-card">
                    <div class="number">""" + str(summary_stats['high_risk']) + """</div>
                    <div class="label">High Risk</div>
                </div>
                <div class="summary-card">
                    <div class="number">""" + str(summary_stats['safe']) + """</div>
                    <div class="label">Safe</div>
                </div>
                <div class="summary-card">
                    <div class="number">""" + str(summary_stats['errors']) + """</div>
                    <div class="label">Errors</div>
                </div>
            </div>
        </header>
        
        <div class="file-results">
"""
        
        # Add file results
        for result in results:
            html += HtmlReporter._generate_file_html(result)
        
        html += """
        </div>
        
        <footer>
            <p>IPI-Scanner v0.1.0 | Detect Indirect Prompt Injection Attacks</p>
            <p><a href="https://github.com/username/ipi-scanner">GitHub</a> | <a href="https://github.com/username/ipi-scanner/blob/main/README.md">Documentation</a></p>
        </footer>
    </div>
</body>
</html>
"""
        return html
    
    @staticmethod
    def _generate_file_html(result: Dict) -> str:
        """Generate HTML for single file result."""
        if result['status'] == 'error':
            return f"""
        <div class="file-card error-card">
            <div class="file-header red">
                <div class="file-info">
                    <h3>❌ {result['file']}</h3>
                </div>
            </div>
            <div class="file-body">
                <div class="error-message">Error: {result.get('error', 'Unknown error')}</div>
            </div>
        </div>
"""
        
        assessment = result.get('risk_assessment', {})
        score = assessment.get('score', 0)
        level = assessment.get('level', 'Unknown')
        
        # Determine level class
        level_class = level.lower() if level else 'green'
        
        # Icon by level
        icons = {'red': '🔴', 'orange': '🟠', 'yellow': '🟡', 'green': '✅'}
        icon = icons.get(level_class, '❓')
        
        html = f"""
        <div class="file-card">
            <div class="file-header {level_class}">
                <div class="file-info">
                    <h3>{icon} {result['file']}</h3>
                    <div class="file-path">{result.get('doc_type', 'unknown')} | {result.get('size_bytes', 0)} bytes</div>
                </div>
                <div class="risk-badge">
                    <div class="score">{score}</div>
                    <div class="level">{level}</div>
                </div>
            </div>
            <div class="file-body">
"""
        
        # Detections
        detections = result.get('detections', [])
        if detections:
            html += '<div class="detections">'
            for det in detections:
                html += f"""
                <div class="detection-item">
                    <div class="detection-category">{det['category'].replace('_', ' ').title()} ({int(det['confidence']*100)}%)</div>
                    <div class="detection-match">{det['match']}</div>
                    <div style="font-size: 12px; color: #7f8c8d; margin-top: 4px;">{det['location']}</div>
                </div>
"""
            html += '</div>'
        else:
            html += '<div class="no-detections">✓ No threats detected</div>'
        
        # Recommendation
        rec = assessment.get('recommendation', '')
        rec_class = level_class if level else 'green'
        html += f"""
                <div class="recommendation {rec_class}">{rec}</div>
            </div>
        </div>
"""
        
        return html
