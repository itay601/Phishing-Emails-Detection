from src.parser.email_parser import ParsedEmail, LinkInfo, parse_email
from src.detection.analyzer import PhishingAnalyzer


class TestPhishingAnalyzer:
    def setup_method(self):
        self.analyzer = PhishingAnalyzer()

    def test_safe_email(self):
        email = ParsedEmail(
            sender="colleague@company.com",
            sender_name="Jane Smith",
            subject="Meeting Notes",
            body_text="Here are the notes from today's meeting.",
        )
        result = self.analyzer.analyze(email)
        assert result.classification == "Safe"
        assert result.confidence_score < 0.4

    def test_obvious_phishing(self):
        email = ParsedEmail(
            sender="security@paypa1.com",
            sender_name="PayPal Security",
            subject="URGENT: Account Suspended",
            body_text="Immediate action required. Verify your account or it will be permanently deleted.",
            links=[
                LinkInfo(
                    href="http://evil.com/steal",
                    display_text="http://paypal.com/verify",
                    is_mismatched=True,
                )
            ],
        )
        result = self.analyzer.analyze(email)
        assert result.classification == "Phishing"
        assert result.confidence_score >= 0.7
        assert len(result.heuristic_results) == 4

    def test_suspicious_email(self):
        email = ParsedEmail(
            sender="noreply@somecompany.com",
            sender_name="Some Company",
            subject="Verify your account",
            body_text="Please confirm your information by clicking the link below.",
            links=[
                LinkInfo(href="http://bit.ly/verify123", display_text="Verify Now")
            ],
        )
        result = self.analyzer.analyze(email)
        assert result.classification in ("Suspicious", "Phishing")
        assert result.confidence_score >= 0.3


class TestEmailParser:
    def test_parse_basic(self):
        data = {
            "from": "test@example.com",
            "from_name": "Test User",
            "subject": "Hello",
            "body_text": "Hi there",
            "body_html": "",
        }
        parsed = parse_email(data)
        assert parsed.sender == "test@example.com"
        assert parsed.subject == "Hello"

    def test_parse_links(self):
        data = {
            "from": "test@example.com",
            "body_html": '<a href="http://example.com">Click here</a>',
            "body_text": "",
            "subject": "",
        }
        parsed = parse_email(data)
        assert len(parsed.links) == 1
        assert parsed.links[0].href == "http://example.com"

    def test_link_mismatch(self):
        data = {
            "from": "test@example.com",
            "body_html": '<a href="http://evil.com">http://paypal.com</a>',
            "body_text": "",
            "subject": "",
        }
        parsed = parse_email(data)
        assert len(parsed.links) == 1
        assert parsed.links[0].is_mismatched is True
