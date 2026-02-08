import re

from src.detection.heuristics.base import BaseHeuristic, HeuristicResult
from src.parser.email_parser import ParsedEmail

URGENCY_PHRASES = [
    r"immediate\s+action\s+required",
    r"act\s+now",
    r"urgent",
    r"account\s+(has\s+been\s+)?(suspended|locked|compromised|disabled)",
    r"verify\s+your\s+(account|identity|information)",
    r"confirm\s+your\s+(account|identity|information)",
    r"unauthorized\s+(access|activity|transaction)",
    r"click\s+(here\s+)?immediately",
    r"within\s+\d+\s+hours?",
    r"your\s+account\s+will\s+be\s+(closed|terminated|deleted)",
    r"failure\s+to\s+(respond|verify|confirm)",
    r"security\s+alert",
    r"unusual\s+(activity|sign-?in|login)",
    r"limited\s+time",
    r"won\s+a?\s*(prize|lottery|gift|reward)",
    r"congratulations",
]

THREAT_PHRASES = [
    r"legal\s+action",
    r"law\s+enforcement",
    r"arrest\s+warrant",
    r"criminal\s+charges",
    r"permanent(ly)?\s+(ban|block|suspend|delete)",
]

COMPILED_URGENCY = [re.compile(p, re.IGNORECASE) for p in URGENCY_PHRASES]
COMPILED_THREATS = [re.compile(p, re.IGNORECASE) for p in THREAT_PHRASES]


class LanguageAnalyzer(BaseHeuristic):
    def analyze(self, email: ParsedEmail) -> HeuristicResult:
        indicators = []
        score = 0.0

        text = f"{email.subject} {email.body_text}"

        # Check urgency phrases
        urgency_count = 0
        for pattern in COMPILED_URGENCY:
            match = pattern.search(text)
            if match:
                indicators.append(f"Urgency phrase: \"{match.group()}\"")
                urgency_count += 1

        # Check threat phrases
        threat_count = 0
        for pattern in COMPILED_THREATS:
            match = pattern.search(text)
            if match:
                indicators.append(f"Threatening language: \"{match.group()}\"")
                threat_count += 1

        # Score based on findings
        if threat_count > 0:
            score = max(score, min(0.5 + threat_count * 0.15, 0.9))
        if urgency_count > 0:
            score = max(score, min(0.3 + urgency_count * 0.15, 0.9))
        if urgency_count >= 3:
            score = max(score, 0.8)

        return HeuristicResult(name="language_analysis", score=score, indicators=indicators)
