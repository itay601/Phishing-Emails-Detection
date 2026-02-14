# Backend Structure Description - Phishing Email Detection

## What the Backend Does
A FastAPI-based REST API that analyzes emails and classifies them as **Phishing**, **Suspicious**, or **Safe** using a hybrid approach: 4 rule-based heuristics + an ML model.

---

## Directory Structure (Only the Files That Matter)

```
backend/
├── .env                    # API key + model path config
├── requirements.txt        # Python dependencies
├── Dockerfile              # Docker deployment config
└── src/
    ├── main.py             # App entry point - creates FastAPI, CORS, /health
    ├── config.py           # Reads .env vars (api_key, model_path, debug)
    ├── api/
    │   ├── routes.py       # Single endpoint: POST /api/v1/analyze
    │   └── schemas.py      # Pydantic models (request/response shapes)
    ├── detection/
    │   ├── analyzer.py     # Orchestrator - runs all heuristics + ML, calculates final score
    │   ├── heuristics/
    │   │   ├── base.py              # Abstract base class (score 0-1 + indicators)
    │   │   ├── link_analyzer.py     # Checks URLs: shorteners, mismatches, IP URLs, suspicious TLDs
    │   │   ├── domain_analyzer.py   # Checks domains: typosquatting, homograph attacks, brand spoofing
    │   │   ├── language_analyzer.py # Checks text: urgency phrases, threats
    │   │   └── sender_analyzer.py   # Checks sender: free email spoofing, reply-to mismatch
    │   └── ml/
    │       ├── model.py        # Loads sklearn pickle model, returns prediction
    │       └── preprocessor.py # Extracts features (text, link count, uppercase ratio, etc.)
    └── parser/
        └── email_parser.py  # Parses email, extracts links from HTML, detects URL mismatches
```

---

## How a Request Flows (Step by Step)

```
Client → POST /api/v1/analyze (with X-API-Key header)
  │
  ├─ routes.py: validates API key → 401 if bad
  ├─ routes.py: validates request body via Pydantic schemas
  │
  ├─ email_parser.py: parses email, extracts links from HTML
  │
  ├─ analyzer.py: runs all 4 heuristics on the parsed email
  │   ├─ LinkAnalyzer     → score + indicators
  │   ├─ DomainAnalyzer   → score + indicators
  │   ├─ LanguageAnalyzer → score + indicators
  │   └─ SenderAnalyzer   → score + indicators
  │
  ├─ analyzer.py: runs ML model (if available)
  │   └─ preprocessor.py extracts features → model.py predicts
  │
  ├─ analyzer.py: combines scores
  │   With ML:    0.4 * max_heuristic + 0.3 * avg_active + 0.3 * ml_confidence
  │   Without ML: 0.6 * max_heuristic + 0.4 * avg_active
  │
  └─ Classification:  >= 0.7 → "Phishing"  |  >= 0.4 → "Suspicious"  |  < 0.4 → "Safe"
```

---

## The 6 Most Important Files (and Why)

| File | Role |
|------|------|
| `src/main.py` | Creates the app, sets up CORS, mounts routes at `/api/v1` |
| `src/api/routes.py` | The only endpoint - receives email, orchestrates parsing + analysis, returns result |
| `src/api/schemas.py` | Defines the exact shape of requests and responses (Pydantic) |
| `src/detection/analyzer.py` | The brain - runs all detection methods and calculates the final score |
| `src/detection/heuristics/*.py` | 4 rule-based detectors (links, domains, language, sender) |
| `src/parser/email_parser.py` | Converts raw email into structured data, extracts links |

---

## Key Tech Stack

- **FastAPI** - web framework
- **Pydantic** - request/response validation
- **scikit-learn** - ML model (optional, degrades gracefully if missing)
- **BeautifulSoup4** - HTML link extraction
- **tldextract** - domain parsing
- **Uvicorn** - ASGI server

---

## Key Design Decisions

1. **Hybrid detection**: Heuristics always run; ML is optional (works without a trained model)
2. **Pluggable heuristics**: Each heuristic is an independent class inheriting from `BaseHeuristic` - easy to add/remove
3. **Explainable results**: Response includes per-heuristic scores and human-readable indicators, not just a yes/no
4. **Single endpoint**: One POST route does everything - simple API surface
5. **API key auth**: Simple header-based authentication via `X-API-Key`
