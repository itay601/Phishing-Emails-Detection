import logging
import os
import pickle
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class MLPrediction:
    is_phishing: bool
    confidence: float


class PhishingMLModel:
    def __init__(self, model_path: str):
        self.model = None
        self.vectorizer = None
        self._load(model_path)

    def _load(self, model_path: str) -> None:
        if not os.path.exists(model_path):
            logger.warning("ML model not found at %s — running in heuristics-only mode", model_path)
            return
        try:
            with open(model_path, "rb") as f:
                data = pickle.load(f)
            self.model = data["model"]
            self.vectorizer = data["vectorizer"]
            logger.info("ML model loaded from %s", model_path)
        except Exception:
            logger.exception("Failed to load ML model from %s", model_path)

    @property
    def is_available(self) -> bool:
        return self.model is not None and self.vectorizer is not None

    def predict(self, text: str) -> MLPrediction | None:
        if not self.is_available:
            return None
        try:
            features = self.vectorizer.transform([text])
            proba = self.model.predict_proba(features)[0]
            phishing_prob = float(proba[1]) if len(proba) > 1 else float(proba[0])
            return MLPrediction(
                is_phishing=phishing_prob >= 0.5,
                confidence=phishing_prob,
            )
        except Exception:
            logger.exception("ML prediction failed")
            return None
