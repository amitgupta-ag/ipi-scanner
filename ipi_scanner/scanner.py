"""
Main IPI-Scanner orchestrator.

Coordinates pattern detection, document parsing, and risk scoring.
"""

from pathlib import Path
from typing import Dict, List, Optional
from dataclasses import asdict

from ipi_scanner.parsers.document_parser import DocumentParser
from ipi_scanner.detectors.pattern_detector import PatternDetector
from ipi_scanner.scoring.risk_scorer import RiskScorer


class Scanner:
    """Main scanner orchestrating the detection pipeline."""
    
    def __init__(self, patterns_file: Optional[str] = None, mode: str = 'balanced'):
        """
        Initialize scanner.
        
        Args:
            patterns_file: Path to patterns.json
            mode: Detection sensitivity - 'strict', 'balanced', 'permissive'
        """
        self.mode = mode
        self.parser = DocumentParser()
        self.detector = PatternDetector(patterns_file)
        self.scorer = RiskScorer()
    
    def scan_file(
        self,
        file_path: str,
        context: Optional[Dict] = None
    ) -> Dict:
        """
        Scan a single file for IPI attacks.
        
        Args:
            file_path: Path to document
            context: Context for risk scoring
            
        Returns:
            Dictionary with scan results
        """
        try:
            # Parse document
            content, doc_type = self.parser.parse(file_path)
            
            if not content or not content.strip():
                return {
                    'file': file_path,
                    'doc_type': doc_type,
                    'status': 'empty',
                    'risk_assessment': {
                        'score': 0,
                        'level': 'Green',
                        'recommendation': 'File is empty'
                    }
                }
            
            # Detect patterns
            detections = self.detector.detect(content)
            
            # Apply sensitivity filter
            detections = self._apply_mode_filter(detections)
            
            # Score risk
            assessment = self.scorer.score(detections, context or {})
            
            return {
                'file': str(file_path),
                'doc_type': doc_type,
                'size_bytes': len(content),
                'risk_assessment': asdict(assessment),
                'detections': [
                    {
                        'pattern': d.pattern,
                        'category': d.category,
                        'confidence': d.confidence,
                        'match': d.match_text[:100],  # First 100 chars
                        'location': d.location
                    }
                    for d in detections
                ],
                'status': 'success'
            }
        
        except Exception as e:
            return {
                'file': str(file_path),
                'status': 'error',
                'error': str(e),
                'error_type': type(e).__name__
            }
    
    def scan_directory(
        self,
        directory: str,
        context: Optional[Dict] = None,
        recursive: bool = True
    ) -> List[Dict]:
        """
        Scan all documents in a directory.
        
        Args:
            directory: Directory path
            context: Context for risk scoring
            recursive: Scan subdirectories
            
        Returns:
            List of scan results
        """
        results = []
        path = Path(directory)
        
        if not path.exists():
            return [{
                'error': f'Directory not found: {directory}',
                'status': 'error'
            }]
        
        # Find all supported files
        if recursive:
            files = path.rglob('*')
        else:
            files = path.glob('*')
        
        for file in files:
            if file.is_file() and file.suffix.lower() in DocumentParser.SUPPORTED_EXTENSIONS:
                result = self.scan_file(str(file), context)
                results.append(result)
        
        return results
    
    def scan_text(
        self,
        content: str,
        context: Optional[Dict] = None
    ) -> Dict:
        """
        Scan raw text content for IPI attacks.
        
        Perfect for scanning concatenated prompts from multiple sources:
        - Concatenated prompts (system + context + user input)
        - OCR'd image text
        - Tool outputs
        - RAG chunks
        - Any string content
        
        Args:
            content: Text content to scan
            context: Optional context for risk multipliers
            
        Returns:
            Dictionary with risk assessment
            
        Example:
            ```python
            scanner = Scanner()
            final_prompt = f"{system_prompt}\\n{rag_context}\\n{user_query}"
            result = scanner.scan_text(final_prompt, context={
                "agent_tool_access": True,
                "rag_pipeline": True
            })
            print(result['score'])  # 0-100 risk score
            ```
        """
        if not content or not content.strip():
            return {
                'status': 'empty',
                'risk_assessment': {
                    'score': 0,
                    'level': 'Green',
                    'recommendation': 'Content is empty'
                },
                'detections': []
            }
        
        # Detect patterns
        detections = self.detector.detect(content)
        
        # Apply sensitivity filter
        detections = self._apply_mode_filter(detections)
        
        # Score risk
        assessment = self.scorer.score(detections, context or {})
        
        return {
            'status': 'success',
            'risk_assessment': asdict(assessment),
            'detections': [
                {
                    'pattern': d.pattern,
                    'category': d.category,
                    'confidence': d.confidence,
                    'match': d.match_text[:100],
                    'location': d.location
                }
                for d in detections
            ]
        }
    
    def _apply_mode_filter(self, detections):
        """Filter detections based on sensitivity mode."""
        if self.mode == 'strict':
            # Keep all detections
            return detections
        elif self.mode == 'permissive':
            # Keep only high confidence (critical + high severity)
            return [
                d for d in detections
                if d.confidence >= 0.80
            ]
        else:  # balanced (default)
            # Keep moderate and high confidence
            return [
                d for d in detections
                if d.confidence >= 0.65
            ]
    
    def batch_scan(
        self,
        files: List[str],
        context: Optional[Dict] = None
    ) -> Dict:
        """
        Scan multiple files and aggregate results.
        
        Args:
            files: List of file paths
            context: Context for risk scoring
            
        Returns:
            Dictionary with aggregated results
        """
        results = []
        high_risk = []
        stats = {
            'total_files': len(files),
            'scanned': 0,
            'errors': 0,
            'high_risk_count': 0,
            'total_detections': 0,
        }
        
        for file_path in files:
            result = self.scan_file(file_path, context)
            results.append(result)
            
            if result['status'] == 'success':
                stats['scanned'] += 1
                risk_score = result['risk_assessment']['score']
                if risk_score >= 50:
                    high_risk.append((file_path, risk_score))
                    stats['high_risk_count'] += 1
                stats['total_detections'] += len(result['detections'])
            elif result['status'] == 'error':
                stats['errors'] += 1
        
        return {
            'summary': stats,
            'high_risk_files': sorted(high_risk, key=lambda x: x[1], reverse=True),
            'detailed_results': results
        }
