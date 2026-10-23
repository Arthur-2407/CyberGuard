import pytest
from backend.config import get_settings
from backend.analysis.phishing_analyzer import PhishingAnalyzer
from backend.analysis.url_analyzer import URLAnalyzer
from backend.threats.models import RiskLevel, ThreatCategory

def test_phishing_analyzer():
    config = get_settings()
    analyzer = PhishingAnalyzer(config)
    
    # Safe text
    event_safe = analyzer.analyze("Hello, are we still meeting for lunch today?")
    assert event_safe.severity == RiskLevel.SAFE
    
    # Phishing text
    event_phish = analyzer.analyze("URGENT: Your account suspended. Please verify your account and enter your password immediately.")
    assert event_phish.severity in [RiskLevel.HIGH, RiskLevel.CRITICAL]
    assert event_phish.threat_category == ThreatCategory.PHISHING

@pytest.mark.asyncio
async def test_url_analyzer():
    config = get_settings()
    analyzer = URLAnalyzer(config)
    
    # Safe URL
    event_safe = await analyzer.analyze("https://www.google.com/search?q=test")
    assert event_safe.severity == RiskLevel.SAFE
    
    # Suspicious URL
    event_sus = await analyzer.analyze("http://192.168.1.100/login/secure/verify")
    assert event_sus.severity in [RiskLevel.HIGH, RiskLevel.CRITICAL]
    assert event_sus.threat_category == ThreatCategory.MALICIOUS_URL
