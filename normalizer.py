"""Result normalizer - transforms Kev responses into structured analysis results."""

import logging
from typing import Dict, Any

from .models import (
    KevRawResponse,
    PhishingAssessment,
    MaliciousAssessment,
    ThreatTypeAssessment,
    RiskAssessment,
    AnalysisResult,
)
from .exceptions import KevInvalidResponseError

logger = logging.getLogger(__name__)


class ResultNormalizer:
    """Normalizes Kev responses into structured analysis results.
    
    Responsible for parsing raw Kev responses and extracting relevant
    security assessment data. Does not calculate risk scores (that's
    RiskAssessment's job).
    """
    
    def normalize(self, kev_response: KevRawResponse) -> AnalysisResult:
        """Normalize Kev response into analysis result.
        
        Args:
            kev_response: Raw response from Kev
            
        Returns:
            Structured analysis result
            
        Raises:
            KevInvalidResponseError: If response is missing required answers
        """
        logger.debug(
            "Normalizing Kev response",
            extra={"num_answers": len(kev_response.answers)}
        )
        
        answers = kev_response.answers
        
        try:
            phishing_assessment = self._extract_phishing(answers)
            malicious_assessment = self._extract_malicious(answers)
            threat_type_assessment = self._extract_threat_type(answers)
            risk_assessment = self._extract_risk(answers)
            
            result = AnalysisResult(
                is_phishing=phishing_assessment,
                is_malicious=malicious_assessment,
                threat_type=threat_type_assessment,
                risk=risk_assessment,
                raw_response=kev_response,
                latency_ms=kev_response.latency_ms,
            )
            
            logger.info(
                "Analysis result normalized",
                extra={
                    "phishing_prob": phishing_assessment.probability,
                    "malicious_prob": malicious_assessment.probability,
                    "threat_type": threat_type_assessment.value,
                    "risk_score": risk_assessment.score,
                }
            )
            
            return result
            
        except KeyError as e:
            raise KevInvalidResponseError(
                f"Missing required answer in Kev response: {str(e)}"
            )
        except Exception as e:
            raise KevInvalidResponseError(
                f"Failed to normalize Kev response: {str(e)}"
            )
    
    def _extract_phishing(self, answers: Dict[str, Any]) -> PhishingAssessment:
        """Extract phishing assessment from answers."""
        if "is_phishing" not in answers:
            raise KeyError("is_phishing")
        
        answer = answers["is_phishing"]
        
        if answer.get("type") != "noul":
            raise ValueError(f"is_phishing should be noul type, got {answer.get('type')}")
        
        return PhishingAssessment(probability=answer["noul"])
    
    def _extract_malicious(self, answers: Dict[str, Any]) -> MaliciousAssessment:
        """Extract malicious content assessment from answers."""
        if "is_malicious" not in answers:
            raise KeyError("is_malicious")
        
        answer = answers["is_malicious"]
        
        if answer.get("type") != "noul":
            raise ValueError(f"is_malicious should be noul type, got {answer.get('type')}")
        
        return MaliciousAssessment(probability=answer["noul"])
    
    def _extract_threat_type(self, answers: Dict[str, Any]) -> ThreatTypeAssessment:
        """Extract threat type classification from answers."""
        if "threat_type" not in answers:
            raise KeyError("threat_type")
        
        answer = answers["threat_type"]
        
        if answer.get("type") != "choice":
            raise ValueError(f"threat_type should be choice type, got {answer.get('type')}")
        
        return ThreatTypeAssessment(
            value=answer["choice"],
            confidence=answer["confidence"],
            probabilities=answer["probabilities"],
        )
    
    def _extract_risk(self, answers: Dict[str, Any]) -> RiskAssessment:
        """Extract risk assessment from answers."""
        if "risk_level" not in answers:
            raise KeyError("risk_level")
        
        answer = answers["risk_level"]
        
        if answer.get("type") != "score":
            raise ValueError(f"risk_level should be score type, got {answer.get('type')}")
        
        score_value = answer["score"]
        max_level = len(answer["legend"]) - 1
        
        normalized_score = score_value / max_level if max_level > 0 else 0.0
        normalized_score = max(0.0, min(1.0, normalized_score))
        
        return RiskAssessment(score=normalized_score)
