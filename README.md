# Phishing Email Detection

A real-time phishing email detection system that combines rule-based heuristics with machine learning to classify emails as **Phishing**, **Suspicious**, or **Safe**. Deployed as a FastAPI backend with a Gmail Add-on frontend that lets users scan emails directly from their inbox.

## Architecture

```
Gmail Inbox
    │
    ▼
┌──────────────────┐         HTTPS / JSON           ┌──────────────────────────────┐
│  Gmail Add-on    │  ──────────────────────────►   │  FastAPI Backend             │
│  (Apps Script)   │  ◄──────────────────────────   │                              │
│                  │     classification result      │  ┌────────────────────────┐  │
│  • Scan button   │                                │  │  Heuristic Analyzers   │  │
│  • Result card   │                                │  │  • Link analysis       │  │
│  • Risk icons    │                                │  │  • Domain analysis     │  │
└──────────────────┘                                │  │  • Language analysis   │  │
                                                    │  │  • Sender analysis     │  │
                                                    │  └────────────────────────┘  │
                                                    │  ┌────────────────────────┐  │
                                                    │  │  ML Model              │  │
                                                    │  │  TF-IDF + LogReg       │  │
                                                    │  └────────────────────────┘  │
                                                    │                              │
                                                    │  Scoring: 0.4×max + 0.3×avg  │
                                                    │           + 0.3×ML conf      │
                                                    └──────────────────────────────┘
```

## Tech Stack

| Layer        | Technology                                   |
|--------------|----------------------------------------------|
| Backend      | Python 3.11, FastAPI, Uvicorn                |
| ML           | scikit-learn (TF-IDF + Logistic Regression)  |
| Heuristics   | BeautifulSoup4, tldextract, regex            |
| Frontend     | Google Apps Script (Gmail Add-on)            |
| Deployment   | Docker, Docker Compose                       |

## Project Structure

```
.
├── backend/
│   ├── src/
│   │   ├── api/
│   │   │   ├── routes.py          # POST /api/v1/analyze endpoint
│   │   │   └── schemas.py         # Pydantic request/response models
│   │   ├── detection/
│   │   │   ├── analyzer.py        # Orchestrates heuristics + ML scoring
│   │   │   ├── heuristics/
│   │   │   │   ├── base.py        # BaseHeuristic ABC
│   │   │   │   ├── link_analyzer.py
│   │   │   │   ├── domain_analyzer.py
│   │   │   │   ├── language_analyzer.py
│   │   │   │   └── sender_analyzer.py
│   │   │   └── ml/
│   │   │       ├── model.py       # Loads and runs the sklearn model
│   │   │       └── preprocessor.py
│   │   ├── parser/
│   │   │   └── email_parser.py    # Normalizes raw email into ParsedEmail
│   │   ├── config.py              # Settings via pydantic-settings
│   │   └── main.py                # FastAPI app entry point
│   ├── tests/
│   │   ├── test_api.py
│   │   ├── test_analyzer.py
│   │   └── test_heuristics.py
│   ├── Dockerfile
│   └── requirements.txt
├── gmail-addon/
│   ├── Code.gs                    # Add-on entry point & email extraction
│   ├── ApiClient.gs               # HTTP calls to backend API
│   ├── CardUI.gs                  # Result card rendering
│   └── appsscript.json            # Manifest
├── models/
│   ├── model.ipynb                # Training notebook
│   └── phishing_model.pkl         # Serialized TF-IDF vectorizer + classifier
├── datasets/
│   └── CEAS_08.csv                # Training dataset
└── docker-compose.yml
```

## Detection Engine

### Heuristic Analyzers

Each analyzer returns a score (0.0 = safe, 1.0 = phishing) and a list of human-readable indicators.

| Analyzer            | What it checks                                                                    |
|---------------------|-----------------------------------------------------------------------------------|
| **LinkAnalyzer**    | URL shorteners, display/href mismatches, IP-based URLs, suspicious TLDs/keywords  |
| **DomainAnalyzer**  | Typosquatting (Levenshtein distance), homograph attacks, brand names in domains    |
| **LanguageAnalyzer**| Urgency phrases ("act now", "account suspended"), threatening language             |
| **SenderAnalyzer**  | Free-email brand impersonation, brand keywords in sender domain, Reply-To mismatch|

### ML Model

- **Algorithm**: TF-IDF (7,000 features, unigrams + bigrams) + Logistic Regression
- **Dataset**: CEAS_08 (1,487 emails, subject + body combined)
- **Performance**: 97% accuracy, 0.97 macro F1 (3-fold cross-validation mean F1: 0.966)

### Scoring Logic

The final confidence score is a weighted combination:

**With ML model available:**
```
final_score = 0.4 * max_heuristic + 0.3 * avg_active_heuristics + 0.3 * ml_confidence
```

**Heuristics-only fallback:**
```
final_score = 0.6 * max_heuristic + 0.4 * avg_active_heuristics
```

Classification thresholds:
- **Phishing**: score >= 0.7
- **Suspicious**: score >= 0.4
- **Safe**: score < 0.4

## API Reference

### `POST /api/v1/analyze`

Analyze an email for phishing indicators.

**Headers:**
| Header         | Required | Description       |
|----------------|----------|-------------------|
| `Content-Type` | Yes      | `application/json`|
| `X-API-Key`    | Yes      | API key from env  |

**Request body:**
```json
{
  "email_content": {
    "from_address": "suspicious@fake-bank.com",
    "from_name": "Bank Security",
    "to": "victim@gmail.com",
    "subject": "Urgent: Verify your account now!",
    "body_text": "Click here to verify your account...",
    "body_html": "<p>Click <a href='http://evil.com'>here</a></p>",
    "headers": { "reply-to": "other@domain.com" }
  }
}
```

**Response:**
```json
{
  "classification": "Phishing",
  "confidence_score": 0.85,
  "summary": "High-risk: 5 phishing indicator(s) detected",
  "details": {
    "heuristics": [
      {
        "name": "link_analysis",
        "score": 0.9,
        "indicators": ["Suspicious keyword in URL: \"verify\""]
      }
    ],
    "ml_prediction": {
      "is_phishing": true,
      "confidence": 0.92
    }
  }
}
```

### `GET /health`

Returns `{"status": "ok"}` when the service is running.

## Gmail Add-on

The `gmail-addon/` directory contains a Google Apps Script project that found in Goggle app script:

1. When a user opens an email, the add-on shows a **"Scan for Phishing"** button
2. Clicking the button extracts the email's sender, subject, body, and headers
3. The data is sent to the backend API via `UrlFetchApp`
4. Results are displayed in a color-coded card with risk level, summary, heuristic details, and ML prediction

**Setup:** In the Apps Script project, set these script properties:
- `API_URL` — your backend endpoint (e.g. `https://your-domain.com/api/v1/analyze`)
- `API_KEY` — the same key configured in `PHISHING_API_KEY`

## Getting Started

### Prerequisites

- Docker and Docker Compose
- A `PHISHING_API_KEY` environment variable

### Run with Docker

```bash
export PHISHING_API_KEY="your-secret-key"
docker compose up --build
```

The API will be available at `http://localhost:8000`.

### Run Locally (without Docker)

```bash
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

export PHISHING_API_KEY="your-secret-key"
uvicorn src.main:app --reload --port 8000
```

### Environment Variables

| Variable               | Description                              | Default                    |
|------------------------|------------------------------------------|----------------------------|
| `PHISHING_API_KEY`     | API key for authenticating requests      | *(required)*               |
| `PHISHING_MODEL_PATH`  | Path to the serialized ML model          | `models/phishing_model.pkl`|
| `PHISHING_DEBUG`       | Enable debug mode                        | `false`                    |

### Run Tests

```bash
cd backend
pytest
```

## ML Model Training

The training notebook is at `models/model.ipynb`. To retrain:

1. Place `CEAS_08.csv` in `datasets/`
2. Open the notebook and run all cells
3. The trained model is saved to `models/phishing_model.pkl`

The pickle file contains both the TF-IDF vectorizer and the Logistic Regression classifier, loaded at backend startup.

## Quick Test (using ngrok for development)

```bash
cat <<'JSONEOF' > /tmp/test_payload.json
{
  "email_content": {
    "from_address": "suspicious@fake-bank.com",
    "from_name": "Bank Security",
    "to": "victim@gmail.com",
    "subject": "Urgent: Verify your account now!",
    "body_text": "Click here to verify your account immediately or it will be suspended. http://fake-bank-login.com/verify",
    "body_html": "",
    "headers": {}
  }
}
JSONEOF


curl -s -X POST https://nonexpediently-nonenumerated-santa.ngrok-free.dev/api/v1/analyze \
     -H "Content-Type: application/json" \
     -H "X-API-Key: $PHISHING_API_KEY" \
     -d @/tmp/test_payload.json | jq .



-------------------------------
          --Docker--
-------------------------------
docker run -d -p 8000:8000 -e PHISHING_API_KEY=my-secret-123 -e PHISHING_MODEL_PATH=../models/phishing_model.pkl --name phishing-email phishing-email

      |
      V 

ngrok http 8000

      |
      V

check-in-emails
-------------------------------

```