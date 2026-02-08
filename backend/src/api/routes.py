from fastapi import APIRouter, Header, HTTPException

from src.api.schemas import (
    AnalysisDetails,
    AnalyzeRequest,
    AnalyzeResponse,
    HeuristicDetail,
    MLDetail,
)
from src.config import settings
from src.detection.analyzer import PhishingAnalyzer
from src.parser.email_parser import parse_email

router = APIRouter()
analyzer = PhishingAnalyzer()


@router.post("/analyze", response_model=AnalyzeResponse)
def analyze_email(
    request: AnalyzeRequest,
    x_api_key: str = Header(default=None),
):
    if settings.api_key and x_api_key != settings.api_key:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")

    # Build email data dict for the parser
    email_data = {
        "from": request.email_content.from_address,
        "from_name": request.email_content.from_name,
        "to": request.email_content.to,
        "subject": request.email_content.subject,
        "body_text": request.email_content.body_text,
        "body_html": request.email_content.body_html,
        "headers": request.email_content.headers,
    }

    parsed = parse_email(email_data)
    result = analyzer.analyze(parsed)

    heuristic_details = [
        HeuristicDetail(name=h.name, score=h.score, indicators=h.indicators)
        for h in result.heuristic_results
    ]

    ml_detail = None
    if result.ml_prediction:
        ml_detail = MLDetail(
            is_phishing=result.ml_prediction.is_phishing,
            confidence=result.ml_prediction.confidence,
        )

    return AnalyzeResponse(
        classification=result.classification,
        confidence_score=result.confidence_score,
        summary=result.summary,
        details=AnalysisDetails(
            heuristics=heuristic_details,
            ml_prediction=ml_detail,
        ),
    )
