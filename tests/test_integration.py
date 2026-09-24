"""Integration tests for kev_integration module.

These tests require a running Kev server.
Run with: KEV_BASE_URL=http://localhost:8009 pytest tests/test_integration.py -v
"""

import os
import pytest

from kev_integration import KevService, PageAnalysisRequest, KevConfig, KevConnectionError


pytestmark = pytest.mark.integration


@pytest.fixture
def kev_service():
    """Create KevService with test configuration."""
    base_url = os.environ.get("KEV_BASE_URL", "http://localhost:8009")
    config = KevConfig(base_url=base_url, timeout=60)
    return KevService(config)


def test_analyze_phishing_page(kev_service):
    """Test analysis of a suspicious phishing page."""
    request = PageAnalysisRequest(
        url="https://secure-login-bank.com/verify",
        domain="secure-login-bank.com",
        title="Secure Bank Login - Verify Your Account",
        visible_text="Your account has been suspended. Enter your username, password, and SSN to verify your identity. Failure to verify within 24 hours will result in permanent account closure.",
    )
    
    result = kev_service.analyze(request)
    
    assert 0 <= result.is_phishing.probability <= 1
    assert 0 <= result.is_malicious.probability <= 1
    assert result.threat_type.value in ["phishing", "malware", "scam", "benign", "other"]
    assert 0 <= result.threat_type.confidence <= 1
    assert 0 <= result.risk.score <= 1
    assert result.latency_ms > 0
    
    print(f"\nPhishing page analysis:")
    print(f"  Phishing: {result.is_phishing.probability:.2%}")
    print(f"  Malicious: {result.is_malicious.probability:.2%}")
    print(f"  Threat type: {result.threat_type.value} ({result.threat_type.confidence:.2%})")
    print(f"  Risk: {result.risk.score:.2%}")


def test_analyze_benign_page(kev_service):
    """Test analysis of a benign page."""
    request = PageAnalysisRequest(
        url="https://example.com",
        domain="example.com",
        title="Example Domain",
        visible_text="This domain is for use in illustrative examples in documents.",
    )
    
    result = kev_service.analyze(request)
    
    assert 0 <= result.is_phishing.probability <= 1
    assert 0 <= result.is_malicious.probability <= 1
    assert result.threat_type.value in ["phishing", "malware", "scam", "benign", "other"]
    assert 0 <= result.risk.score <= 1
    
    print(f"\nBenign page analysis:")
    print(f"  Phishing: {result.is_phishing.probability:.2%}")
    print(f"  Malicious: {result.is_malicious.probability:.2%}")
    print(f"  Threat type: {result.threat_type.value} ({result.threat_type.confidence:.2%})")
    print(f"  Risk: {result.risk.score:.2%}")


def test_analyze_with_metadata(kev_service):
    """Test analysis with additional metadata."""
    request = PageAnalysisRequest(
        url="https://example.com/login",
        domain="example.com",
        title="Login",
        visible_text="Enter your credentials to access your account.",
        links=[
            "https://example.com/about",
            "https://example.com/contact",
            "https://example.com/privacy",
        ],
        metadata={
            "response_time_ms": 250,
            "ssl_valid": True,
            "server": "nginx",
        },
    )
    
    result = kev_service.analyze(request)
    
    assert result.is_phishing.probability is not None
    assert result.threat_type.value is not None
    assert result.risk.score is not None
    
    print(f"\nPage with metadata analysis:")
    print(f"  Phishing: {result.is_phishing.probability:.2%}")
    print(f"  Threat type: {result.threat_type.value}")
    print(f"  Risk: {result.risk.score:.2%}")


def test_analyze_with_external_signals(kev_service):
    """Test analysis with external risk signals."""
    request = PageAnalysisRequest(
        url="https://example.com",
        domain="example.com",
        title="Example",
        visible_text="Some content here.",
    )
    
    result = kev_service.analyze(
        request,
        domain_reputation=0.2,
        url_heuristics=0.3,
    )
    
    assert 0 <= result.risk.score <= 1
    
    print(f"\nAnalysis with external signals:")
    print(f"  Risk: {result.risk.score:.2%}")


def test_connection_error():
    """Test connection error when Kev is not available."""
    config = KevConfig(base_url="http://localhost:9999", timeout=5)
    service = KevService(config)
    
    request = PageAnalysisRequest(
        url="https://example.com",
        domain="example.com",
    )
    
    with pytest.raises(KevConnectionError):
        service.analyze(request)
