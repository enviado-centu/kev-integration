"""Main Kev service - orchestrates the complete analysis workflow."""

import logging
from typing import Optional

from .config import KevConfig
from .models import PageAnalysisRequest, AnalysisResult
from .state_builder import StateBuilder
from .questions import QuestionConfig
from .client import KevClient
from .normalizer import ResultNormalizer
from .risk_assessment import RiskCalculator

logger = logging.getLogger(__name__)


class KevService:
    """Main service for phishing and threat detection using Kev.
    
    Orchestrates the complete analysis workflow:
    1. Build state from page data
    2. Prepare questions
    3. Call Kev API
    4. Normalize response
    5. Calculate risk score
    
    This is the main interface for the backend. The backend should not
    need to know about Kev's API details, payload format, or response parsing.
    """
    
    def __init__(self, config: Optional[KevConfig] = None):
        """Initialize Kev service.
        
        Args:
            config: Kev configuration. If None, loads from environment variables.
        """
        self.config = config or KevConfig.from_env()
        self.config.validate()
        
        self.state_builder = StateBuilder()
        self.question_config = QuestionConfig()
        self.client = KevClient(self.config)
        self.normalizer = ResultNormalizer()
        self.risk_calculator = RiskCalculator()
        
        logger.info(
            "KevService initialized",
            extra={
                "base_url": self.config.base_url,
                "model": self.config.model,
            }
        )
    
    def analyze(
        self,
        request: PageAnalysisRequest,
        domain_reputation: Optional[float] = None,
        url_heuristics: Optional[float] = None,
    ) -> AnalysisResult:
        """Analyze a page for phishing and threats.
        
        This is the main entry point for the backend. It takes a page analysis
        request and returns a structured analysis result.
        
        Args:
            request: Page data to analyze
            domain_reputation: Optional domain reputation score (0-1, higher = more risky)
            url_heuristics: Optional URL heuristic risk score (0-1)
            
        Returns:
            Structured analysis result with phishing/malicious assessments,
            threat type classification, and risk score
            
        Example:
            >>> service = KevService()
            >>> request = PageAnalysisRequest(
            ...     url="https://example.com",
            ...     domain="example.com",
            ...     title="Login",
            ...     visible_text="Enter your credentials..."
            ... )
            >>> result = service.analyze(request)
            >>> print(result.is_phishing.probability)
            0.91
        """
        logger.info(
            "Starting page analysis",
            extra={"url": request.url, "domain": request.domain}
        )
        
        state = self.state_builder.build(request)
        
        questions = self.question_config.get_questions()
        
        kev_response = self.client.analyze(state, questions)
        
        analysis = self.normalizer.normalize(kev_response)
        
        if domain_reputation is not None or url_heuristics is not None:
            enhanced_risk = self.risk_calculator.calculate(
                analysis,
                domain_reputation=domain_reputation,
                url_heuristics=url_heuristics,
            )
            analysis = analysis.model_copy(update={"risk": enhanced_risk})
        
        logger.info(
            "Page analysis completed",
            extra={
                "url": request.url,
                "is_phishing": analysis.is_phishing.probability,
                "is_malicious": analysis.is_malicious.probability,
                "threat_type": analysis.threat_type.value,
                "risk_score": analysis.risk.score,
                "latency_ms": analysis.latency_ms,
            }
        )
        
        return analysis
