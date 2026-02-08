import re


def extract_features(subject: str, body_text: str, link_count: int) -> dict:
    """Extract structural features from an email for ML prediction."""
    text = f"{subject} {body_text}"
    return {
        "text": text.lower(),
        "link_count": link_count,
        "has_html": False,  # set by caller if needed
        "subject_length": len(subject),
        "body_length": len(body_text),
        "exclamation_count": text.count("!"),
        "question_count": text.count("?"),
        "uppercase_ratio": _uppercase_ratio(text),
    }


def _uppercase_ratio(text: str) -> float:
    """Ratio of uppercase characters to total alphabetic characters."""
    alpha = [c for c in text if c.isalpha()]
    if not alpha:
        return 0.0
    upper = sum(1 for c in alpha if c.isupper())
    return upper / len(alpha)
