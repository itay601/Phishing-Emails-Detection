from pydantic import BaseModel


class EmailContent(BaseModel):
    model_config = {"populate_by_name": True}

    from_address: str = ""
    from_name: str = ""
    to: str = ""
    subject: str = ""
    body_text: str = ""
    body_html: str = ""
    headers: dict = {}


class AnalyzeRequest(BaseModel):
    email_content: EmailContent


class HeuristicDetail(BaseModel):
    name: str
    score: float
    indicators: list[str]


class MLDetail(BaseModel):
    is_phishing: bool
    confidence: float


class AnalysisDetails(BaseModel):
    heuristics: list[HeuristicDetail]
    ml_prediction: MLDetail | None = None


class AnalyzeResponse(BaseModel):
    classification: str
    confidence_score: float
    summary: str
    details: AnalysisDetails
