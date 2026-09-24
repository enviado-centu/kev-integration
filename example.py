"""Example usage of kev_integration module."""

import logging
from kev_integration import KevService, PageAnalysisRequest, KevConfig

logging.basicConfig(level=logging.INFO)


def main():
    config = KevConfig(
        base_url="http://localhost:8009",
        model="kev-latest",
        timeout=30,
    )
    
    service = KevService(config)
    
    print("=" * 60)
    print("Ejemplo 1: Página sospechosa de phishing")
    print("=" * 60)
    
    phishing_request = PageAnalysisRequest(
        url="https://secure-bank-login.com/verify",
        domain="secure-bank-login.com",
        title="Secure Bank Login - Verify Your Account",
        visible_text=(
            "Your account has been suspended due to suspicious activity. "
            "Enter your username, password, and security questions to verify your identity. "
            "Failure to verify within 24 hours will result in permanent account closure."
        ),
    )
    
    try:
        result = service.analyze(phishing_request)
        
        print(f"\nResultados:")
        print(f"  Phishing: {result.is_phishing.probability:.2%}")
        print(f"  Malicioso: {result.is_malicious.probability:.2%}")
        print(f"  Tipo de amenaza: {result.threat_type.value}")
        print(f"  Confianza: {result.threat_type.confidence:.2%}")
        print(f"  Risk score: {result.risk.score:.2%}")
        print(f"  Latencia: {result.latency_ms:.1f}ms")
        
        print(f"\nDistribución de tipos de amenaza:")
        for threat, prob in result.threat_type.probabilities.items():
            print(f"  {threat}: {prob:.2%}")
        
    except Exception as e:
        print(f"Error: {e}")
    
    print("\n" + "=" * 60)
    print("Ejemplo 2: Página legítima")
    print("=" * 60)
    
    benign_request = PageAnalysisRequest(
        url="https://example.com",
        domain="example.com",
        title="Example Domain",
        visible_text="This domain is for use in illustrative examples in documents.",
    )
    
    try:
        result = service.analyze(benign_request)
        
        print(f"\nResultados:")
        print(f"  Phishing: {result.is_phishing.probability:.2%}")
        print(f"  Malicioso: {result.is_malicious.probability:.2%}")
        print(f"  Tipo de amenaza: {result.threat_type.value}")
        print(f"  Confianza: {result.threat_type.confidence:.2%}")
        print(f"  Risk score: {result.risk.score:.2%}")
        print(f"  Latencia: {result.latency_ms:.1f}ms")
        
    except Exception as e:
        print(f"Error: {e}")
    
    print("\n" + "=" * 60)
    print("Ejemplo 3: Con señales externas")
    print("=" * 60)
    
    request_with_signals = PageAnalysisRequest(
        url="https://suspicious-site.com",
        domain="suspicious-site.com",
        title="Free Prize Winner",
        visible_text="Congratulations! You've won a $1000 gift card. Click here to claim your prize now!",
    )
    
    try:
        result = service.analyze(
            request_with_signals,
            domain_reputation=0.8,
            url_heuristics=0.7,
        )
        
        print(f"\nResultados:")
        print(f"  Phishing: {result.is_phishing.probability:.2%}")
        print(f"  Malicioso: {result.is_malicious.probability:.2%}")
        print(f"  Tipo de amenaza: {result.threat_type.value}")
        print(f"  Risk score: {result.risk.score:.2%}")
        print(f"  (Incluye domain reputation: 0.80, URL heuristics: 0.70)")
        
    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    main()
