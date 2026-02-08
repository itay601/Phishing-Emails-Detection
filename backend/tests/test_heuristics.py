from src.parser.email_parser import ParsedEmail, LinkInfo
from src.detection.heuristics.link_analyzer import LinkAnalyzer
from src.detection.heuristics.domain_analyzer import DomainAnalyzer
from src.detection.heuristics.language_analyzer import LanguageAnalyzer
from src.detection.heuristics.sender_analyzer import SenderAnalyzer


class TestLinkAnalyzer:
    def setup_method(self):
        self.analyzer = LinkAnalyzer()

    def test_clean_email(self):
        email = ParsedEmail(links=[])
        result = self.analyzer.analyze(email)
        assert result.score == 0.0
        assert result.indicators == []

    def test_url_shortener(self):
        email = ParsedEmail(
            links=[LinkInfo(href="http://bit.ly/abc123", display_text="Click here")]
        )
        result = self.analyzer.analyze(email)
        assert result.score >= 0.5
        assert any("shortener" in i.lower() for i in result.indicators)

    def test_url_mismatch(self):
        email = ParsedEmail(
            links=[LinkInfo(
                href="http://evil.com/steal",
                display_text="http://paypal.com/secure",
                is_mismatched=True,
            )]
        )
        result = self.analyzer.analyze(email)
        assert result.score >= 0.8
        assert any("mismatch" in i.lower() for i in result.indicators)

    def test_ip_based_url(self):
        email = ParsedEmail(
            links=[LinkInfo(href="http://192.168.1.1/login", display_text="Login")]
        )
        result = self.analyzer.analyze(email)
        assert result.score >= 0.7
        assert any("IP" in i for i in result.indicators)

    def test_suspicious_tld(self):
        email = ParsedEmail(
            links=[LinkInfo(href="http://freeprize.xyz/claim", display_text="Claim")]
        )
        result = self.analyzer.analyze(email)
        assert result.score >= 0.4
        assert any(".xyz" in i for i in result.indicators)


class TestDomainAnalyzer:
    def setup_method(self):
        self.analyzer = DomainAnalyzer()

    def test_clean_domain(self):
        email = ParsedEmail(sender="user@google.com")
        result = self.analyzer.analyze(email)
        assert result.score == 0.0

    def test_typosquatting(self):
        email = ParsedEmail(sender="support@paypa1.com")
        result = self.analyzer.analyze(email)
        assert result.score >= 0.8
        assert any("paypal" in i.lower() for i in result.indicators)

    def test_homograph(self):
        email = ParsedEmail(sender="alert@g00gle.com")
        result = self.analyzer.analyze(email)
        assert result.score >= 0.8
        assert any("google" in i.lower() for i in result.indicators)


class TestLanguageAnalyzer:
    def setup_method(self):
        self.analyzer = LanguageAnalyzer()

    def test_clean_text(self):
        email = ParsedEmail(subject="Meeting tomorrow", body_text="See you at 3pm.")
        result = self.analyzer.analyze(email)
        assert result.score == 0.0

    def test_urgency_phrases(self):
        email = ParsedEmail(
            subject="URGENT: Account Suspended",
            body_text="Immediate action required. Verify your account within 24 hours.",
        )
        result = self.analyzer.analyze(email)
        assert result.score >= 0.5
        assert len(result.indicators) >= 2

    def test_threatening_language(self):
        email = ParsedEmail(
            subject="Final Warning",
            body_text="Legal action will be taken. Your account will be permanently deleted.",
        )
        result = self.analyzer.analyze(email)
        assert result.score >= 0.5
        assert any("threat" in i.lower() or "legal" in i.lower() for i in result.indicators)


class TestSenderAnalyzer:
    def setup_method(self):
        self.analyzer = SenderAnalyzer()

    def test_clean_sender(self):
        email = ParsedEmail(sender="friend@gmail.com", sender_name="John Doe")
        result = self.analyzer.analyze(email)
        assert result.score == 0.0

    def test_free_email_impersonation(self):
        email = ParsedEmail(
            sender="paypal.security@gmail.com",
            sender_name="PayPal Security",
        )
        result = self.analyzer.analyze(email)
        assert result.score >= 0.7
        assert any("brand" in i.lower() or "free email" in i.lower() for i in result.indicators)

    def test_reply_to_mismatch(self):
        email = ParsedEmail(
            sender="support@company.com",
            sender_name="Support",
            headers={"reply-to": "scammer@evil.com"},
        )
        result = self.analyzer.analyze(email)
        assert result.score >= 0.6
        assert any("reply" in i.lower() for i in result.indicators)

    def test_display_name_email(self):
        email = ParsedEmail(
            sender="attacker@evil.com",
            sender_name="ceo@company.com",
        )
        result = self.analyzer.analyze(email)
        assert result.score >= 0.6
        assert any("display name" in i.lower() for i in result.indicators)
