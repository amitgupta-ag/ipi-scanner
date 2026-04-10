"""
Pattern-based IPI detection (Tier 1).

Fast, deterministic detection using regex patterns. No LLM needed.
Expected accuracy: 60-80% on diverse attacks.
"""

import re
import json
from pathlib import Path
from dataclasses import dataclass
from typing import List, Dict, Optional


@dataclass
class Detection:
    """A single pattern match detection."""
    pattern: str
    category: str
    confidence: float
    match_text: str
    location: str  # line number or position


class PatternDetector:
    """Detects IPI attacks using regex pattern matching."""
    
    def __init__(self, patterns_file: Optional[str] = None):
        """
        Initialize detector with patterns.
        
        Args:
            patterns_file: Path to patterns.json. If None, uses default.
        """
        if patterns_file is None:
            # Try to find patterns.json in package directory
            current_dir = Path(__file__).parent.parent
            patterns_file = current_dir / "patterns.json"
        
        self.patterns_file = patterns_file
        self.patterns = self._load_patterns()
        self._compiled_patterns = self._compile_patterns()
    
    def _load_patterns(self) -> Dict:
        """Load patterns from JSON file."""
        try:
            with open(self.patterns_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            raise FileNotFoundError(
                f"Patterns file not found: {self.patterns_file}\n"
                "Download patterns.json from the project."
            )
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in patterns file: {e}")
    
    def _compile_patterns(self) -> Dict[str, List]:
        """Pre-compile all regex patterns for performance."""
        compiled = {}
        for category, config in self.patterns.items():
            compiled[category] = {
                'severity': config['severity'],
                'base_score': config['base_score'],
                'patterns': [
                    re.compile(pattern, re.IGNORECASE | re.MULTILINE)
                    for pattern in config['patterns']
                ]
            }
        return compiled
    
    def detect(self, text: str) -> List[Detection]:
        """
        Find all pattern matches in text.
        
        Args:
            text: Text to scan for IPI patterns
            
        Returns:
            List of Detection objects found
        """
        detections = []
        
        for category, config in self._compiled_patterns.items():
            for idx, compiled_pattern in enumerate(config['patterns']):
                try:
                    matches = compiled_pattern.finditer(text)
                    for match in matches:
                        # Get confidence based on severity
                        confidence = self._get_confidence(config['severity'])
                        
                        # Get location info
                        line_num = text[:match.start()].count('\n') + 1
                        
                        # Get the original pattern string for reference
                        pattern_str = self.patterns[category]['patterns'][idx]
                        
                        detection = Detection(
                            pattern=pattern_str,
                            category=category,
                            confidence=confidence,
                            match_text=match.group(),
                            location=f"line {line_num}"
                        )
                        detections.append(detection)
                
                except re.error as e:
                    # Skip invalid patterns but log them
                    print(f"Warning: Invalid regex pattern in {category}: {e}")
        
        return detections
    
    def _get_confidence(self, severity: str) -> float:
        """Map severity to baseline confidence."""
        confidence_map = {
            'critical': 0.95,
            'high': 0.80,
            'medium': 0.65,
            'low': 0.50
        }
        return confidence_map.get(severity, 0.50)
    
    def detect_by_category(self, text: str, category: str) -> List[Detection]:
        """
        Detect patterns in specific category only.
        
        Args:
            text: Text to scan
            category: Pattern category to check
            
        Returns:
            List of detections in that category
        """
        if category not in self._compiled_patterns:
            raise ValueError(f"Unknown category: {category}")
        
        detections = []
        config = self._compiled_patterns[category]
        
        for idx, compiled_pattern in enumerate(config['patterns']):
            matches = compiled_pattern.finditer(text)
            for match in matches:
                confidence = self._get_confidence(config['severity'])
                line_num = text[:match.start()].count('\n') + 1
                pattern_str = self.patterns[category]['patterns'][idx]
                
                detection = Detection(
                    pattern=pattern_str,
                    category=category,
                    confidence=confidence,
                    match_text=match.group(),
                    location=f"line {line_num}"
                )
                detections.append(detection)
        
        return detections
    
    def get_categories(self) -> List[str]:
        """Get all available pattern categories."""
        return list(self.patterns.keys())
