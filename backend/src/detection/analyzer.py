import logging
from dataclasses import dataclass, field

from src.config import settings
from src.detection.heuristics.base import HeuristicResult
from src.detection.heuristics.domain_analyzer import DomainAnalyzer
from src.detection.heuristics.language_analyzer import LanguageAnalyzer
from src.detection.heuristics.link_analyzer import LinkAnalyzer
from src.detection.heuristics.sender_analyzer import SenderAnalyzer
from src.detection.ml.model import MLPrediction, PhishingMLModel
from src.detection.ml.preprocessor import extract_features
from src.parser.email_parser import ParsedEmail

logger = logging.getLogger(__name__)


@dataclass
class AnalysisResult:
    classification: str  # "Phishing", "Suspicious", "Safe"
    confidence_score: float
    summary: str
    heuristic_results: list[HeuristicResult] = field(default_factory=list)
    ml_prediction: MLPrediction | None = None


class PhishingAnalyzer:
    def __init__(self):
        self.heuristics = [
            LinkAnalyzer(),
            DomainAnalyzer(),
            LanguageAnalyzer(),
            SenderAnalyzer(),
        ]
        self.ml_model = PhishingMLModel(settings.model_path)

    def analyze(self, email: ParsedEmail) -> AnalysisResult:
        # Run all heuristics
        heuristic_results = [h.analyze(email) for h in self.heuristics]
        scores = [r.score for r in heuristic_results]

        # Run ML model if available
        ml_prediction = None
        if self.ml_model.is_available:
            features = extract_features(
                email.subject, email.body_text, len(email.links)
            )
            ml_prediction = self.ml_model.predict(features["text"])

        # Compute final score
        if scores:
            max_score = max(scores)
            avg_score = sum(scores) / len(scores)
        else:
            max_score = avg_score = 0.0

        if ml_prediction:
            final_score = (
                0.4 * max_score
                + 0.3 * avg_score
                + 0.3 * ml_prediction.confidence
            )
        else:
            final_score = 0.5 * max_score + 0.5 * avg_score

        # Classify
        if final_score >= 0.7:
            classification = "Phishing"
        elif final_score >= 0.4:
            classification = "Suspicious"
        else:
            classification = "Safe"

        # Build summary
        all_indicators = []
        for r in heuristic_results:
            all_indicators.extend(r.indicators)

        if classification == "Phishing":
            summary = f"High-risk: {len(all_indicators)} phishing indicator(s) detected"
        elif classification == "Suspicious":
            summary = f"Medium-risk: {len(all_indicators)} suspicious indicator(s) found"
        else:
            summary = "No significant phishing indicators detected"

        return AnalysisResult(
            classification=classification,
            confidence_score=round(final_score, 2),
            summary=summary,
            heuristic_results=heuristic_results,
            ml_prediction=ml_prediction,
        )
