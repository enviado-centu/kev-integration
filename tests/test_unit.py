"""Unit tests for kev_integration module."""

import pytest
from unittest.mock import Mock, patch, MagicMock
import httpx

from kev_integration import (
    KevService,
    PageAnalysisRequest,
    KevConfig,
    KevConnectionError,
    KevTimeoutError,
    KevRequestError,
    KevInvalidResponseError,
)
from kev_integration.state_builder import StateBuilder
from kev_integration.questions import QuestionConfig
from kev_integration.client import KevClient
from kev_integration.normalizer import ResultNormalizer
from kev_integration.risk_assessment import RiskCalculator
from kev_integration.models import KevRawResponse


class TestStateBuilder:
    """Tests for StateBuilder."""
    
    def test_build_basic_request(self):
        """Test building state from basic request."""
        builder = StateBuilder()
        request = PageAnalysisRequest(
            url="https://example.com",
            domain="example.com",
        )
        
        state = builder.build(request)
        
        assert state["url"] == "https://example.com"
        assert state["domain"] == "example.com"
        assert "title" not in state
        assert "visible_text" not in state
    
    def test_build_full_request(self):
        """Test building state from full request."""
        builder = StateBuilder()
        request = PageAnalysisRequest(
            url="https://example.com/login",
            domain="example.com",
            title="Login Page",
            visible_text="Enter your credentials",
            page_content="<html>...</html>",
            links=["https://example.com/about"],
            metadata={"ssl": True},
        )
        
        state = builder.build(request)
        
        assert state["url"] == "https://example.com/login"
        assert state["domain"] == "example.com"
        assert state["title"] == "Login Page"
        assert state["visible_text"] == "Enter your credentials"
        assert state["page_content"] == "<html>...</html>"
        assert state["links"] == ["https://example.com/about"]
        assert state["metadata"] == {"ssl": True}


class TestQuestionConfig:
    """Tests for QuestionConfig."""
    
    def test_get_questions(self):
        """Test getting all questions."""
        config = QuestionConfig()
        questions = config.get_questions()
        
        assert "is_phishing" in questions
        assert "is_malicious" in questions
        assert "threat_type" in questions
        assert "risk_level" in questions
        
        assert questions["is_phishing"]["type"] == "noul"
        assert questions["is_malicious"]["type"] == "noul"
        assert questions["threat_type"]["type"] == "choice"
        assert questions["risk_level"]["type"] == "score"
    
    def test_threat_type_criteria(self):
        """Test threat type has correct criteria."""
        config = QuestionConfig()
        questions = config.get_questions()
        
        threat_type = questions["threat_type"]
        assert "criteria" in threat_type
        assert "phishing" in threat_type["criteria"]
        assert "malware" in threat_type["criteria"]
        assert "scam" in threat_type["criteria"]
        assert "benign" in threat_type["criteria"]
        assert "other" in threat_type["criteria"]


class TestKevClient:
    """Tests for KevClient."""
    
    @patch("kev_integration.client.httpx.Client")
    def test_analyze_success(self, mock_client_class):
        """Test successful analysis."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "model": "kev-latest",
            "answers": {
                "is_phishing": {"type": "noul", "noul": 0.9},
                "is_malicious": {"type": "noul", "noul": 0.8},
                "threat_type": {
                    "type": "choice",
                    "choice": "phishing",
                    "confidence": 0.9,
                    "probabilities": {"phishing": 0.9, "malware": 0.05, "scam": 0.03, "benign": 0.01, "other": 0.01},
                },
                "risk_level": {
                    "type": "score",
                    "score": 3.5,
                    "legend": {"0": "Safe", "1": "Low", "2": "Medium", "3": "High", "4": "Critical"},
                    "probabilities": {"0": 0.0, "1": 0.0, "2": 0.1, "3": 0.6, "4": 0.3},
                    "confidence": 0.8,
                },
            },
            "usage": {"input_tokens": 100, "output_tokens": 50},
            "latency_ms": 495.0,
        }
        
        mock_client = Mock()
        mock_client.post.return_value = mock_response
        mock_client.__enter__ = Mock(return_value=mock_client)
        mock_client.__exit__ = Mock(return_value=None)
        mock_client_class.return_value = mock_client
        
        config = KevConfig(base_url="http://localhost:8009")
        client = KevClient(config)
        
        state = {"url": "https://example.com"}
        questions = {"is_phishing": {"type": "noul", "instructions": "..."}}
        
        result = client.analyze(state, questions)
        
        assert result.model == "kev-latest"
        assert "is_phishing" in result.answers
        assert result.latency_ms == 495.0
    
    @patch("kev_integration.client.httpx.Client")
    def test_analyze_connection_error(self, mock_client_class):
        """Test connection error handling."""
        mock_client = Mock()
        mock_client.post.side_effect = httpx.ConnectError("Connection refused")
        mock_client.__enter__ = Mock(return_value=mock_client)
        mock_client.__exit__ = Mock(return_value=None)
        mock_client_class.return_value = mock_client
        
        config = KevConfig(base_url="http://localhost:8009")
        client = KevClient(config)
        
        with pytest.raises(KevConnectionError):
            client.analyze({"url": "test"}, {})
    
    @patch("kev_integration.client.httpx.Client")
    def test_analyze_timeout_error(self, mock_client_class):
        """Test timeout error handling."""
        mock_client = Mock()
        mock_client.post.side_effect = httpx.TimeoutException("Timeout")
        mock_client.__enter__ = Mock(return_value=mock_client)
        mock_client.__exit__ = Mock(return_value=None)
        mock_client_class.return_value = mock_client
        
        config = KevConfig(base_url="http://localhost:8009")
        client = KevClient(config)
        
        with pytest.raises(KevTimeoutError):
            client.analyze({"url": "test"}, {})
    
    @patch("kev_integration.client.httpx.Client")
    def test_analyze_http_error(self, mock_client_class):
        """Test HTTP error handling."""
        mock_response = Mock()
        mock_response.status_code = 500
        mock_response.text = "Internal server error"
        
        mock_client = Mock()
        mock_client.post.return_value = mock_response
        mock_client.__enter__ = Mock(return_value=mock_client)
        mock_client.__exit__ = Mock(return_value=None)
        mock_client_class.return_value = mock_client
        
        config = KevConfig(base_url="http://localhost:8009")
        client = KevClient(config)
        
        with pytest.raises(KevRequestError) as exc_info:
            client.analyze({"url": "test"}, {})
        
        assert exc_info.value.status_code == 500


class TestResultNormalizer:
    """Tests for ResultNormalizer."""
    
    def test_normalize_success(self):
        """Test successful normalization."""
        normalizer = ResultNormalizer()
        
        kev_response = KevRawResponse(
            model="kev-latest",
            answers={
                "is_phishing": {"type": "noul", "noul": 0.9},
                "is_malicious": {"type": "noul", "noul": 0.8},
                "threat_type": {
                    "type": "choice",
                    "choice": "phishing",
                    "confidence": 0.9,
                    "probabilities": {"phishing": 0.9, "malware": 0.05, "scam": 0.03, "benign": 0.01, "other": 0.01},
                },
                "risk_level": {
                    "type": "score",
                    "score": 3.5,
                    "legend": {"0": "Safe", "1": "Low", "2": "Medium", "3": "High", "4": "Critical"},
                    "probabilities": {"0": 0.0, "1": 0.0, "2": 0.1, "3": 0.6, "4": 0.3},
                    "confidence": 0.8,
                },
            },
            usage={"input_tokens": 100, "output_tokens": 50},
            latency_ms=495.0,
        )
        
        result = normalizer.normalize(kev_response)
        
        assert result.is_phishing.probability == 0.9
        assert result.is_malicious.probability == 0.8
        assert result.threat_type.value == "phishing"
        assert result.threat_type.confidence == 0.9
        assert result.risk.score == 0.875  # 3.5 / 4
    
    def test_normalize_missing_answer(self):
        """Test normalization with missing answer."""
        normalizer = ResultNormalizer()
        
        kev_response = KevRawResponse(
            model="kev-latest",
            answers={
                "is_phishing": {"type": "noul", "noul": 0.9},
            },
            usage={"input_tokens": 100, "output_tokens": 50},
            latency_ms=495.0,
        )
        
        with pytest.raises(KevInvalidResponseError):
            normalizer.normalize(kev_response)


class TestRiskCalculator:
    """Tests for RiskCalculator."""
    
    def test_calculate_basic(self):
        """Test basic risk calculation."""
        from kev_integration.models import (
            AnalysisResult,
            PhishingAssessment,
            MaliciousAssessment,
            ThreatTypeAssessment,
            RiskAssessment,
        )
        
        calculator = RiskCalculator()
        
        analysis = AnalysisResult(
            is_phishing=PhishingAssessment(probability=0.9),
            is_malicious=MaliciousAssessment(probability=0.8),
            threat_type=ThreatTypeAssessment(
                value="phishing",
                confidence=0.9,
                probabilities={"phishing": 0.9},
            ),
            risk=RiskAssessment(score=0.8),
        )
        
        result = calculator.calculate(analysis)
        
        assert 0 <= result.score <= 1
        assert result.score > 0.7  # Should be high risk
    
    def test_calculate_with_external_signals(self):
        """Test risk calculation with external signals."""
        from kev_integration.models import (
            AnalysisResult,
            PhishingAssessment,
            MaliciousAssessment,
            ThreatTypeAssessment,
            RiskAssessment,
        )
        
        calculator = RiskCalculator()
        
        analysis = AnalysisResult(
            is_phishing=PhishingAssessment(probability=0.5),
            is_malicious=MaliciousAssessment(probability=0.5),
            threat_type=ThreatTypeAssessment(
                value="benign",
                confidence=0.6,
                probabilities={"benign": 0.6},
            ),
            risk=RiskAssessment(score=0.5),
        )
        
        result = calculator.calculate(
            analysis,
            domain_reputation=0.9,
            url_heuristics=0.8,
        )
        
        assert result.score > 0.5  # Should increase with external signals


class TestKevService:
    """Tests for KevService."""
    
    @patch("kev_integration.client.httpx.Client")
    def test_analyze_full_workflow(self, mock_client_class):
        """Test full analysis workflow."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "model": "kev-latest",
            "answers": {
                "is_phishing": {"type": "noul", "noul": 0.91},
                "is_malicious": {"type": "noul", "noul": 0.87},
                "threat_type": {
                    "type": "choice",
                    "choice": "phishing",
                    "confidence": 0.91,
                    "probabilities": {"phishing": 0.91, "malware": 0.04, "scam": 0.03, "benign": 0.01, "other": 0.01},
                },
                "risk_level": {
                    "type": "score",
                    "score": 3.44,
                    "legend": {"0": "Safe", "1": "Low", "2": "Medium", "3": "High", "4": "Critical"},
                    "probabilities": {"0": 0.0, "1": 0.0, "2": 0.1, "3": 0.6, "4": 0.3},
                    "confidence": 0.85,
                },
            },
            "usage": {"input_tokens": 100, "output_tokens": 50},
            "latency_ms": 495.0,
        }
        
        mock_client = Mock()
        mock_client.post.return_value = mock_response
        mock_client.__enter__ = Mock(return_value=mock_client)
        mock_client.__exit__ = Mock(return_value=None)
        mock_client_class.return_value = mock_client
        
        config = KevConfig(base_url="http://localhost:8009")
        service = KevService(config)
        
        request = PageAnalysisRequest(
            url="https://example.com",
            domain="example.com",
            title="Login",
            visible_text="Enter your credentials",
        )
        
        result = service.analyze(request)
        
        assert result.is_phishing.probability == 0.91
        assert result.is_malicious.probability == 0.87
        assert result.threat_type.value == "phishing"
        assert result.risk.score > 0.8
        assert result.latency_ms == 495.0
