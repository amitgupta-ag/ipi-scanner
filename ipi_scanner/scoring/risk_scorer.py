"""
Risk scoring for IPI detections.

Converts pattern matches into 0-100 risk scores with context multipliers.
"""

from dataclasses import dataclass
from typing import List, Dict, Optional
from ipi_scanner.detectors.pattern_detector import Detection


@dataclass
class RiskAssessment:
    """Assessment result with risk score and recommendations."""
    score: int  # 0-100
    level: str  # Red, Orange, Yellow, Green
    threats: List[str]  # Threat descriptions
    confidence: float  # Average confidence
    recommendation: str  # What to do
    details: Dict  # Extra details


class RiskScorer:
    """Calculate risk scores from detections."""
    
    # Severity weights (base points)
    SEVERITY_WEIGHTS = {
        'critical': 40,
        'high': 25,
        'medium': 10,
        'low': 5
    }
    
    # Context multipliers
    MULTIPLIERS = {
        'untrusted_source': 1.3,      # Email, web, external
        'rag_pipeline': 1.5,           # Being ingested into RAG
        'agent_tool_access': 2.0,      # Agent can execute tools
        'agent_api_access': 2.5,       # Agent can make API calls
    }
    
    def score(
        self,
        detections: List[Detection],
        context: Optional[Dict] = None
    ) -> RiskAssessment:
        """
        Calculate risk assessment from detections.
        
        Args:
            detections: List of detections found
            context: Context dictionary with multiplier flags
                - untrusted_source (bool)
                - rag_pipeline (bool)
                - agent_tool_access (bool)
                - agent_api_access (bool)
            
        Returns:
            RiskAssessment with score 0-100
        """
        context = context or {}
        
        if not detections:
            return RiskAssessment(
                score=0,
                level='Green',
                threats=[],
                confidence=0.0,
                recommendation='Safe: Proceed normally',
                details={}
            )
        
        # Calculate base score from detections
        base_score = 0
        threat_list = []
        confidence_scores = []
        
        for detection in detections:
            # Get severity from the detection's category
            severity = self._get_severity(detection.category)
            weight = self.SEVERITY_WEIGHTS.get(severity, 5)
            base_score += weight
            
            # Add to threat list
            threat_list.append(
                f"{detection.category.replace('_', ' ').title()} "
                f"({detection.confidence:.0%} confidence) @ {detection.location}"
            )
            confidence_scores.append(detection.confidence)
        
        # Calculate context multiplier
        multiplier = 1.0
        active_contexts = []
        for context_type, has_context in context.items():
            if has_context and context_type in self.MULTIPLIERS:
                multiplier *= self.MULTIPLIERS[context_type]
                active_contexts.append(context_type)
        
        # Calculate final score
        final_score = min(100, int(base_score * multiplier))
        
        # Calculate average confidence
        avg_confidence = (
            sum(confidence_scores) / len(confidence_scores)
            if confidence_scores else 0
        )
        
        # Determine level and recommendation
        level = self._score_to_level(final_score)
        recommendation = self._get_recommendation(level)
        
        return RiskAssessment(
            score=final_score,
            level=level,
            threats=threat_list,
            confidence=avg_confidence,
            recommendation=recommendation,
            details={
                'base_score': base_score,
                'multiplier': round(multiplier, 2),
                'active_contexts': active_contexts,
                'detection_count': len(detections),
                'categories_detected': list(set(d.category for d in detections))
            }
        )
    
    def _get_severity(self, category: str) -> str:
        """Map category to severity."""
        severity_map = {
            'data_exfiltration': 'critical',
            'credential_exfiltration': 'critical',
            'sensitive_file_access': 'critical',
            'instruction_override': 'high',
            'context_manipulation': 'high',
            'auth_bypass': 'high',
            'url_fragment_injection': 'medium',
            'hidden_instruction': 'medium',
            'policy_override': 'medium',
            'social_engineering': 'medium',
            'tool_execution_manipulation': 'medium',
            'memory_poisoning': 'medium',
            'citation_injection': 'low',
            'reasoning_manipulation': 'low',
            'temporal_conditional_override': 'low',
            'suspicious_external_ref': 'low',
        }
        return severity_map.get(category, 'low')
    
    def _score_to_level(self, score: int) -> str:
        """Convert numeric score to risk level."""
        if score >= 75:
            return 'Red'
        elif score >= 50:
            return 'Orange'
        elif score >= 25:
            return 'Yellow'
        else:
            return 'Green'
    
    def _get_recommendation(self, level: str) -> str:
        """Get recommendation based on risk level."""
        recommendations = {
            'Red': '🔴 BLOCK: Do not feed this document to your LLM',
            'Orange': '🟠 REVIEW: Check before RAG ingestion',
            'Yellow': '🟡 CAUTION: Monitor for suspicious behavior',
            'Green': '✅ SAFE: Proceed normally',
        }
        return recommendations.get(level, 'Unknown')
