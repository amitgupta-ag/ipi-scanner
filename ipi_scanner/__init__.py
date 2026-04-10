"""
IPI-Scanner: Detect Indirect Prompt Injection Attacks

A production-ready tool that detects hidden attack instructions in documents
before they reach your LLM. Uses a 3-tier detection system:
1. Pattern matching (fast, deterministic)
2. Semantic analysis (accurate, slower)
3. Simulation (proves attacks work, expensive)

Version: 0.1.0
License: MIT
"""

__version__ = "0.1.0"
__author__ = "IPI-Scanner Contributors"
__license__ = "MIT"

from ipi_scanner.scanner import Scanner
from ipi_scanner.detectors.pattern_detector import PatternDetector
from ipi_scanner.scoring.risk_scorer import RiskAssessment

__all__ = ["Scanner", "PatternDetector", "RiskAssessment"]
