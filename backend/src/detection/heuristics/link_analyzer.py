import re

from src.detection.heuristics.base import BaseHeuristic, HeuristicResult
from src.parser.email_parser import ParsedEmail

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "short.link", "rebrand.ly", "cutt.ly",
}

SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".club", ".work", ".click", ".loan", ".win",
    ".gq", ".ml", ".cf", ".tk", ".ga", ".buzz", ".icu",
}

IP_URL_PATTERN = re.compile(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")

SUSPICIOUS_URL_KEYWORDS = {
    "login", "verify", "account", "secure", "update", "confirm",
    "signin", "banking", "password", "credential",
}


class LinkAnalyzer(BaseHeuristic):
    def analyze(self, email: ParsedEmail) -> HeuristicResult:
        indicators = []
        score = 0.0

        for link in email.links:
            href = link.href.lower()

            # URL shortener
            for shortener in URL_SHORTENERS:
                if shortener in href:
                    indicators.append(f"URL shortener detected: {shortener}")
                    score = max(score, 0.6)
                    break

            # Display/href mismatch
            if link.is_mismatched:
                indicators.append(f"URL mismatch: displays '{link.display_text}' but links to '{link.href}'")
                score = max(score, 0.9)

            # IP-based URL
            if IP_URL_PATTERN.search(link.href):
                indicators.append(f"IP-based URL: {link.href}")
                score = max(score, 0.8)

            # Suspicious TLD
            for tld in SUSPICIOUS_TLDS:
                if href.endswith(tld) or (tld + "/") in href:
                    indicators.append(f"Suspicious TLD: {tld}")
                    score = max(score, 0.5)
                    break

            # Suspicious keywords in URL (e.g. fake-bank-login.com/verify)
            for keyword in SUSPICIOUS_URL_KEYWORDS:
                if keyword in href:
                    indicators.append(f"Suspicious keyword in URL: \"{keyword}\"")
                    score = max(score, 0.5)
                    break

        # Check body text for raw URLs too
        body = email.body_text + " " + email.body_html
        if IP_URL_PATTERN.search(body) and not any("IP-based" in i for i in indicators):
            indicators.append("IP-based URL found in email body")
            score = max(score, 0.7)

        return HeuristicResult(name="link_analysis", score=score, indicators=indicators)
