from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from src.parser.email_parser import ParsedEmail


@dataclass
class HeuristicResult:
    name: str
    score: float  # 0.0 (safe) to 1.0 (phishing)
    indicators: list[str] = field(default_factory=list)


class BaseHeuristic(ABC):
    @abstractmethod
    def analyze(self, email: ParsedEmail) -> HeuristicResult:
        ...
