import re

from src.detection.heuristics.base import BaseHeuristic, HeuristicResult
from src.parser.email_parser import ParsedEmail

FREE_EMAIL_PROVIDERS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
    "aol.com", "mail.com", "protonmail.com", "icloud.com",
    "yandex.com", "zoho.com",
}

BRAND_KEYWORDS = [
    "paypal", "apple", "microsoft", "google", "amazon", "netflix",
    "facebook", "instagram", "support", "security", "admin",
    "helpdesk", "service", "billing", "account",
]


class SenderAnalyzer(BaseHeuristic):
    def analyze(self, email: ParsedEmail) -> HeuristicResult:
        indicators = []
        score = 0.0

        sender = email.sender.lower()
        sender_name = email.sender_name.lower()

        # Extract domain from sender
        domain_match = re.search(r"@([\w.-]+)", sender)
        sender_domain = domain_match.group(1) if domain_match else ""

        # Free email impersonating a company
        if sender_domain in FREE_EMAIL_PROVIDERS:
            for keyword in BRAND_KEYWORDS:
                if keyword in sender_name:
                    indicators.append(
                        f"Free email ({sender_domain}) with brand name in display: \"{email.sender_name}\""
                    )
                    score = max(score, 0.8)
                    break

        # Display name spoofing: name contains an email address
        if re.search(r"[\w.-]+@[\w.-]+\.\w+", sender_name):
            indicators.append(f"Display name contains email address: \"{email.sender_name}\"")
            score = max(score, 0.7)

        # Reply-to mismatch
        reply_to = email.headers.get("reply-to", "").lower()
        if reply_to and reply_to != sender:
            reply_domain_match = re.search(r"@([\w.-]+)", reply_to)
            reply_domain = reply_domain_match.group(1) if reply_domain_match else ""
            if reply_domain and reply_domain != sender_domain:
                indicators.append(f"Reply-To domain ({reply_domain}) differs from sender ({sender_domain})")
                score = max(score, 0.7)

        return HeuristicResult(name="sender_analysis", score=score, indicators=indicators)
