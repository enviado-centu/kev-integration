"""Data models for Kev integration."""

from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field


class PageAnalysisRequest(BaseModel):
    """Request model for page analysis.
    
    Contains all relevant information about a page to be analyzed for phishing/threats.
    """
    
    url: str = Field(..., description="Full URL of the page")
    domain: str = Field(..., description="Domain name")
    title: Optional[str] = Field(None, description="Page title")
    visible_text: Optional[str] = Field(None, description="Visible text content")
    page_content: Optional[str] = Field(None, description="Full page content/HTML")
    links: Optional[List[str]] = Field(None, description="List of links found on page")
    metadata: Optional[Dict[str, Any]] = Field(None, description="Additional metadata")
    
    def to_state(self) -> Dict[str, Any]:
        """Convert to Kev state format.
        
        Creates a structured state object with all relevant page information.
        """
        state = {
            "url": self.url,
            "domain": self.domain,
        }
        
        if self.title:
            state["title"] = self.title
        
        if self.visible_text:
            state["visible_text"] = self.visible_text
        
        if self.page_content:
            state["page_content"] = self.page_content
        
        if self.links:
            state["links"] = self.links
        
        if self.metadata:
            state["metadata"] = self.metadata
        
        return state


class NoulAnswer(BaseModel):
    """Answer for a noul (yes/no) question."""
    
    type: str = "noul"
    noul: float = Field(..., ge=0, le=1, description="Probability of yes")


class ChoiceAnswer(BaseModel):
    """Answer for a choice question."""
    
    type: str = "choice"
    choice: str = Field(..., description="Selected option")
    confidence: float = Field(..., ge=0, le=1, description="Confidence score")
    probabilities: Dict[str, float] = Field(..., description="Probability distribution")


class ScoreAnswer(BaseModel):
    """Answer for a score question."""
    
    type: str = "score"
    score: float = Field(..., description="Mean level index")
    legend: Dict[str, str] = Field(..., description="Level descriptions")
    probabilities: Dict[str, float] = Field(..., description="Probability distribution")
    confidence: float = Field(..., ge=0, le=1, description="Confidence score")


class KevRawResponse(BaseModel):
    """Raw response from Kev API."""
    
    model: str
    answers: Dict[str, Any]
    usage: Dict[str, int]
    latency_ms: float


class PhishingAssessment(BaseModel):
    """Phishing detection assessment."""
    
    probability: float = Field(..., ge=0, le=1, description="Probability of phishing")


class MaliciousAssessment(BaseModel):
    """Malicious content assessment."""
    
    probability: float = Field(..., ge=0, le=1, description="Probability of malicious content")


class ThreatTypeAssessment(BaseModel):
    """Threat type classification."""
    
    value: str = Field(..., description="Most likely threat type")
    confidence: float = Field(..., ge=0, le=1, description="Confidence in classification")
    probabilities: Dict[str, float] = Field(..., description="Probability distribution across threat types")


class RiskAssessment(BaseModel):
    """Overall risk assessment."""
    
    score: float = Field(..., ge=0, le=1, description="Risk score (0-1)")


class AnalysisResult(BaseModel):
    """Complete analysis result returned to the caller."""
    
    is_phishing: PhishingAssessment
    is_malicious: MaliciousAssessment
    threat_type: ThreatTypeAssessment
    risk: RiskAssessment
    raw_response: Optional[KevRawResponse] = Field(None, description="Raw Kev response (for debugging)")
    latency_ms: Optional[float] = Field(None, description="Total latency in milliseconds")
