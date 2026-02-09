import re

import tldextract

from src.detection.heuristics.base import BaseHeuristic, HeuristicResult
from src.parser.email_parser import ParsedEmail

KNOWN_BRANDS = [
    "paypal", "apple", "microsoft", "google", "amazon", "netflix",
    "facebook", "instagram", "whatsapp", "linkedin", "twitter",
    "dropbox", "chase", "wellsfargo", "bankofamerica", "citibank",
    "ups", "fedex", "dhl", "usps", "bank", "secure", "login",
]

# Common homograph characters (look-alike substitutions)
HOMOGRAPH_MAP = {
    "0": "o", "1": "l", "l": "i", "rn": "m",
    "vv": "w", "cl": "d", "nn": "m",
}


class DomainAnalyzer(BaseHeuristic):
    def analyze(self, email: ParsedEmail) -> HeuristicResult:
        indicators = []
        score = 0.0

        # Analyze sender domain
        sender_domain = self._get_domain(email.sender)
        if sender_domain:
            typo_result = self._check_typosquatting(sender_domain)
            if typo_result:
                indicators.append(f"Typosquatting: {sender_domain} resembles {typo_result}")
                score = max(score, 0.85)

            homograph = self._check_homograph(sender_domain)
            if homograph:
                indicators.append(f"Homograph attack: {sender_domain} uses look-alike characters for {homograph}")
                score = max(score, 0.9)

        # Analyze link domains
        for link in email.links:
            link_domain = self._get_domain(link.href)
            if not link_domain:
                continue

            typo_result = self._check_typosquatting(link_domain)
            if typo_result:
                indicators.append(f"Typosquatting in link: {link_domain} resembles {typo_result}")
                score = max(score, 0.85)

            brand_in_domain = self._check_brand_in_domain(link_domain)
            if brand_in_domain:
                indicators.append(
                    f"Brand name \"{brand_in_domain}\" embedded in link domain: {link_domain}"
                )
                score = max(score, 0.6)

        # Also check sender domain for embedded brand
        if sender_domain:
            brand_in_sender = self._check_brand_in_domain(sender_domain)
            if brand_in_sender:
                indicators.append(
                    f"Brand name \"{brand_in_sender}\" embedded in sender domain: {sender_domain}"
                )
                score = max(score, 0.6)

        return HeuristicResult(name="domain_analysis", score=score, indicators=indicators)

    def _get_domain(self, address: str) -> str | None:
        """Extract domain from email address or URL."""
        # Handle email addresses
        if "@" in address:
            address = address.split("@")[-1].strip(">").strip()
        extracted = tldextract.extract(address)
        if extracted.domain:
            return f"{extracted.domain}.{extracted.suffix}"
        return None

    def _check_typosquatting(self, domain: str) -> str | None:
        """Check if domain is a typosquat of a known brand using Levenshtein distance."""
        extracted = tldextract.extract(domain)
        domain_name = extracted.domain.lower()

        for brand in KNOWN_BRANDS:
            if domain_name == brand:
                continue  # Exact match, not a typosquat
            distance = self._levenshtein(domain_name, brand)
            if 0 < distance <= 2:
                return brand
        return None

    def _check_brand_in_domain(self, domain: str) -> str | None:
        """Check if a known brand name appears as a substring in the domain."""
        extracted = tldextract.extract(domain)
        domain_name = extracted.domain.lower()

        for brand in KNOWN_BRANDS:
            if brand in domain_name and domain_name != brand:
                return brand
        return None

    def _check_homograph(self, domain: str) -> str | None:
        """Check for homograph character substitutions."""
        extracted = tldextract.extract(domain)
        domain_name = extracted.domain.lower()

        normalized = domain_name
        for fake, real in HOMOGRAPH_MAP.items():
            normalized = normalized.replace(fake, real)

        if normalized != domain_name:
            for brand in KNOWN_BRANDS:
                if normalized == brand:
                    return brand
        return None

    def _levenshtein(self, s1: str, s2: str) -> int:
        """Compute Levenshtein distance between two strings."""
        if len(s1) < len(s2):
            return self._levenshtein(s2, s1)
        if len(s2) == 0:
            return len(s1)

        prev_row = list(range(len(s2) + 1))
        for i, c1 in enumerate(s1):
            curr_row = [i + 1]
            for j, c2 in enumerate(s2):
                cost = 0 if c1 == c2 else 1
                curr_row.append(min(
                    curr_row[j] + 1,
                    prev_row[j + 1] + 1,
                    prev_row[j] + cost,
                ))
            prev_row = curr_row
        return prev_row[-1]
