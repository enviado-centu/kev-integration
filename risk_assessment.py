"""Risk assessment - combines multiple signals for comprehensive risk evaluation."""

import logging
from typing import Optional
from .models import AnalysisResult, RiskAssessment

logger = logging.getLogger(__name__)


class RiskCalculator:
    """Calculates comprehensive risk scores from analysis results.
    
    This layer is separate from the normalizer to allow future extension
    with additional risk signals (domain reputation, URL heuristics, etc.)
    without modifying the Kev integration.
    """
    
    def calculate(
        self,
        analysis: AnalysisResult,
        domain_reputation: Optional[float] = None,
        url_heuristics: Optional[float] = None,
    ) -> RiskAssessment:
        """Calculate comprehensive risk score.
        
        Currently uses Kev signals only. Future versions can incorporate:
        - Domain reputation scores
        - URL heuristic analysis
        - External threat intelligence
        - Historical data
        
        Args:
            analysis: Normalized analysis result from Kev
            domain_reputation: Optional domain reputation score (0-1, higher = more risky)
            url_heuristics: Optional URL heuristic risk score (0-1)
            
        Returns:
            Updated risk assessment
        """
        kev_risk = analysis.risk.score
        phishing_prob = analysis.is_phishing.probability
        malicious_prob = analysis.is_malicious.probability
        
        kev_composite = (
            0.4 * kev_risk +
            0.3 * phishing_prob +
            0.3 * malicious_prob
        )
        
        if domain_reputation is not None:
            kev_composite = 0.7 * kev_composite + 0.3 * domain_reputation
            logger.debug(
                "Incorporated domain reputation",
                extra={"domain_reputation": domain_reputation}
            )
        
        if url_heuristics is not None:
            kev_composite = 0.8 * kev_composite + 0.2 * url_heuristics
            logger.debug(
                "Incorporated URL heuristics",
                extra={"url_heuristics": url_heuristics}
            )
        
        final_risk = max(0.0, min(1.0, kev_composite))
        
        logger.info(
            "Risk score calculated",
            extra={
                "kev_risk": kev_risk,
                "phishing_prob": phishing_prob,
                "malicious_prob": malicious_prob,
                "final_risk": final_risk,
            }
        )
        
        return RiskAssessment(score=final_risk)
