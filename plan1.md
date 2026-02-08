Phishing Email Detection System - Implementation Plan  

 Overview                                               

 Build a phishing email detection system with:
 - Backend: Python/FastAPI with heuristic + ML detection
 - Frontend: Gmail Add-on (Google Apps Script)
 - Deployment: Docker for local development

 ---
 Project Structure

 Phishing-Emails-Detection/
 ├── README.md
 ├── .gitignore
 ├── docker-compose.yml
 │
 ├── backend/
 │   ├── Dockerfile
 │   ├── requirements.txt
 │   ├── src/
 │   │   ├── __init__.py
 │   │   ├── main.py                    # FastAPI entry point
 │   │   ├── config.py                  # Configuration
 │   │   ├── api/
 │   │   │   ├── __init__.py
 │   │   │   ├── routes.py              # /analyze endpoint
 │   │   │   └── schemas.py             # Pydantic models
 │   │   ├── detection/
 │   │   │   ├── __init__.py
 │   │   │   ├── analyzer.py            # Detection orchestrator
 │   │   │   ├── heuristics/
 │   │   │   │   ├── __init__.py
 │   │   │   │   ├── base.py            # Abstract base class
 │   │   │   │   ├── link_analyzer.py   # Suspicious links
 │   │   │   │   ├── sender_analyzer.py # Sender legitimacy
 │   │   │   │   ├── language_analyzer.py # Urgent language
 │   │   │   │   └── domain_analyzer.py # Domain spoofing
 │   │   │   └── ml/
 │   │   │       ├── __init__.py
 │   │   │       ├── model.py           # ML model wrapper
 │   │   │       └── preprocessor.py    # Feature extraction
 │   │   └── parser/
 │   │       ├── __init__.py
 │   │       └── email_parser.py        # Email content
 extraction
 │   ├── tests/
 │   │   ├── conftest.py
 │   │   ├── test_heuristics.py
 │   │   ├── test_analyzer.py
 │   │   └── test_api.py
 │   ├── models/                        # Trained ML models
 (.pkl)
 │   └── data/                          # Training data
 (gitignored)
 │
 ├── gmail-addon/
 │   ├── appsscript.json               # Manifest
 │   ├── Code.gs                       # Main entry point
 │   ├── CardUI.gs                     # UI components
 │   └── ApiClient.gs                  # Backend communication
 │
 └── scripts/
     └── train_model.py                # ML training script

 ---
 Technology Stack
 ┌─────────────────┬──────────────────┬─────────────────────────┐
 │    Component    │    Technology    │         Purpose         │
 ├─────────────────┼──────────────────┼─────────────────────────┤
 │ Backend         │ FastAPI          │ Async API with          │
 │ Framework       │                  │ auto-docs               │
 ├─────────────────┼──────────────────┼─────────────────────────┤
 │ Data Validation │ Pydantic v2      │ Request/response        │
 │                 │                  │ schemas                 │
 ├─────────────────┼──────────────────┼─────────────────────────┤
 │ ML Framework    │ scikit-learn     │ Text classification     │
 │                 │                  │ model                   │
 ├─────────────────┼──────────────────┼─────────────────────────┤
 │ NLP             │ spaCy / regex    │ Language pattern        │
 │                 │                  │ detection               │
 ├─────────────────┼──────────────────┼─────────────────────────┤
 │ Domain Parsing  │ tldextract       │ Extract domain          │
 │                 │                  │ components              │
 ├─────────────────┼──────────────────┼─────────────────────────┤
 │ Testing         │ pytest           │ Unit + integration      │
 │                 │                  │ tests                   │
 ├─────────────────┼──────────────────┼─────────────────────────┤
 │ Server          │ uvicorn          │ ASGI server             │
 ├─────────────────┼──────────────────┼─────────────────────────┤
 │ Gmail Add-on    │ Google Apps      │ Gmail integration       │
 │                 │ Script           │                         │
 └─────────────────┴──────────────────┴─────────────────────────┘
 ---
 API Design

 POST /api/v1/analyze

 Request:
 {
   "email_content": {
     "from": "security@paypa1.com",
     "from_name": "PayPal Security",
     "to": "user@example.com",
     "subject": "URGENT: Account Suspended",
     "body_text": "Click here immediately...",
     "body_html": "<html>...</html>",
     "headers": {}
   },
   "options": { "include_details": true }
 }

 Response:
 {
   "classification": "Phishing",
   "confidence_score": 0.87,
   "summary": "High-risk email with multiple phishing
 indicators",
   "details": {
     "heuristics": [
       {"name": "link_analysis", "score": 0.9, "indicators":
 ["URL mismatch detected"]},
       {"name": "language_analysis", "score": 0.8, "indicators":
 ["Urgency phrase found"]}
     ],
     "ml_prediction": {"is_phishing": true, "confidence": 0.82}
   }
 }

 ---
 Detection Logic

 Heuristics (Rule-Based)
 Analyzer: LinkAnalyzer
 Checks For: Suspicious URLs
 Risk Signals: URL shorteners, display/actual mismatch, IP
   addresses, suspicious TLDs
 ────────────────────────────────────────
 Analyzer: SenderAnalyzer
 Checks For: Sender legitimacy
 Risk Signals: Free email impersonating companies, display name
   spoofing, reply-to mismatch
 ────────────────────────────────────────
 Analyzer: LanguageAnalyzer
 Checks For: Urgency patterns
 Risk Signals: "Immediate action", "suspended", threatening
   language
 ────────────────────────────────────────
 Analyzer: DomainAnalyzer
 Checks For: Domain spoofing
 Risk Signals: Typosquatting (paypa1.com), homograph attacks,
   lookalike domains
 ML Model

 - Algorithm: RandomForest or LogisticRegression
 - Features: TF-IDF text vectors + structural features (link
 count, attachment presence)
 - Dataset: Kaggle phishing email dataset
 - Output: Probability score combined with heuristics

 Scoring Algorithm

 final_score = (
     0.4 * max(heuristic_scores) +      # Highest heuristic risk
     0.3 * avg(heuristic_scores) +       # Average heuristic risk
     0.3 * ml_confidence                  # ML model confidence
 )

 classification:
   >= 0.7 → "Phishing"
   >= 0.4 → "Suspicious"
   < 0.4  → "Safe"

 ---
 Implementation Order

 Phase 1: Project Setup

 1. Create directory structure
 2. Set up requirements.txt with dependencies
 3. Create .gitignore (ignore data/, models/*.pkl, .env)
 4. Create basic FastAPI app with health endpoint

 Phase 2: Email Parser

 5. Implement ParsedEmail dataclass
 6. Build link extraction from HTML (BeautifulSoup)
 7. Parse email headers
 8. Unit tests for parser

 Phase 3: Heuristic Detection

 9. Create BaseHeuristic abstract class with HeuristicResult
 10. Implement LinkAnalyzer (highest impact)
 11. Implement DomainAnalyzer
 12. Implement LanguageAnalyzer
 13. Implement SenderAnalyzer
 14. Unit tests for each heuristic

 Phase 4: ML Model

 15. Create training script (scripts/train_model.py)
 16. Download Kaggle dataset, preprocess
 17. Train and save model to models/
 18. Implement PhishingMLModel wrapper
 19. Create feature preprocessor

 Phase 5: Detection Orchestrator

 20. Implement PhishingAnalyzer combining all components
 21. Create scoring algorithm
 22. Integration tests

 Phase 6: API Layer

 23. Define Pydantic schemas (AnalyzeRequest, AnalyzeResponse)
 24. Implement /analyze endpoint
 25. Add error handling middleware
 26. API tests

 Phase 7: Docker Setup

 27. Create Dockerfile for backend
 28. Create docker-compose.yml
 29. Test containerized deployment

 Phase 8: Gmail Add-on

 30. Create appsscript.json manifest
 31. Implement buildAddOn() entry point
 32. Create "Scan for Phishing" button UI
 33. Implement ApiClient.gs for backend calls
 34. Create result display cards with color-coded status

 Phase 9: Documentation

 35. Write comprehensive README
 36. Add inline code documentation

 ---
 Key Files to Create

 Critical (Must Have)

 - /backend/src/main.py - FastAPI app
 - /backend/src/api/routes.py - Analyze endpoint
 - /backend/src/api/schemas.py - Request/response models
 - /backend/src/detection/analyzer.py - Core orchestrator
 - /backend/src/detection/heuristics/link_analyzer.py - Link
 detection
 - /backend/src/parser/email_parser.py - Email parsing
 - /gmail-addon/Code.gs - Add-on entry point
 - /gmail-addon/appsscript.json - Add-on manifest

 High Priority

 - /backend/src/detection/heuristics/domain_analyzer.py
 - /backend/src/detection/heuristics/language_analyzer.py
 - /backend/src/detection/heuristics/sender_analyzer.py
 - /backend/src/detection/ml/model.py
 - /gmail-addon/CardUI.gs
 - /gmail-addon/ApiClient.gs
 - /backend/Dockerfile
 - /docker-compose.yml

 ---
 Verification Plan

 Unit Tests

 cd backend && pytest tests/ -v

 Manual API Testing

 # Start server
 docker-compose up

 # Test analyze endpoint
 curl -X POST http://localhost:8000/api/v1/analyze \
   -H "Content-Type: application/json" \
   -d '{
     "email_content": {
       "from": "security@paypa1.com",
       "subject": "URGENT: Account suspended",
       "body_text": "Click http://bit.ly/xyz immediately"
     }
   }'

 Gmail Add-on Testing

 1. Deploy to Google Apps Script editor
 2. Test deployment → Gmail
 3. Open test email, click "Scan for Phishing"
 4. Verify results display correctly

 ---
 Dependencies (requirements.txt)

 fastapi>=0.104.0
 uvicorn>=0.24.0
 pydantic>=2.5.0
 scikit-learn>=1.3.0
 beautifulsoup4>=4.12.0
 tldextract>=5.1.0
 python-dotenv>=1.0.0
 httpx>=0.25.0
 pytest>=7.4.0
 pytest-asyncio>=0.21.0

 ---
 Limitations & Future Improvements

 Current Limitations

 - ML model trained on public dataset (may not cover all phishing
  patterns)
 - No real-time threat intelligence integration
 - Gmail Add-on requires manual API URL configuration

 Future Enhancements

 - Integration with VirusTotal API for URL scanning
 - Add attachment analysis (malware detection)
 - User feedback loop to improve ML model
 - Multi-language support for language analysis.


 ----------------------------------
 ● Here are my thoughts on your plan:                              
   
  What's Good                                                     
                      
  - Clean project structure - well-organized separation of
  concerns (parser, heuristics, ML, API, Gmail addon)
  - Phased implementation order - makes sense to build bottom-up
  (parser -> heuristics -> ML -> orchestrator -> API -> addon)
  - Scoring algorithm - the weighted combination of heuristics +
  ML is a solid approach
  - API design - the request/response schema is well thought out
  and covers the key fields
  - Heuristic coverage - the 4 analyzers (link, sender, language,
  domain) cover the main phishing signals

  Suggestions & Concerns

  1. Google Colab for Training - Yes, Do It

  Your instinct is correct. Train on Colab, then export the .pkl
  model file into the project. Benefits:
  - Free GPU/better resources for experimenting with different
  models
  - You can iterate on the model (try different algorithms,
  hyperparameters) without cluttering the project
  - Keep scripts/train_model.py as a reference, but add a Colab
  notebook (notebooks/train_model.ipynb) as the primary training
  artifact
  - Just commit the final trained model to models/ (or better, use
   Git LFS or provide a download script if the model is large)

  2. spaCy is Overkill

  You list spaCy for language pattern detection, but your
  LanguageAnalyzer is just matching urgency phrases like
  "immediate action", "suspended", etc. Plain regex or keyword
  lists are sufficient here. spaCy adds ~500MB of dependencies for
   something you don't need. Drop it.

  3. ML Model Choice

  - LogisticRegression + TF-IDF is the better choice over
  RandomForest for text classification - it's faster, smaller, and
   typically performs equally well or better on TF-IDF features
  - Consider also trying Naive Bayes (MultinomialNB) - it's a
  classic for spam/phishing and trains in seconds

  4. Deployment Gap

  Your task says the backend should be a service outside Gmail,
  and you have Docker for local dev. But how will the Gmail Add-on
   reach your backend in production? You need to address this:
  - Google Cloud Run or Cloud Functions would be the natural
  choice (free tier available)
  - Without a publicly accessible endpoint, the Gmail Add-on can't
   call your API
  - Add this to your plan, even if it's a "future step"

  5. Scoring Formula Tweak

  Your current formula:
  0.4 * max(heuristic_scores) + 0.3 * avg(heuristic_scores) + 0.3
  * ml_confidence
  Consider: what happens when ML model is not available (model
  file missing, loading error)? Add a fallback that uses
  heuristics-only scoring. Also, using max() means a single
  high-scoring heuristic dominates - this is generally fine, but
  document that design choice.

  6. Missing from the Plan

  - CORS configuration - the Gmail Add-on (Apps Script) will call
  your API via UrlFetchApp. If you ever test from a browser,
  you'll need CORS. Worth noting.
  - API authentication - your endpoint is wide open. At minimum,
  add an API key check so random people can't hit your /analyze
  endpoint.
  - Rate limiting - even a simple in-memory rate limiter protects
  against abuse.
  - Graceful ML fallback - if the model file isn't present, the
  system should still work with heuristics only.

  7. Simplification Opportunity

  - You probably don't need httpx in backend dependencies - that's
   an HTTP client, but your backend is a server. Unless you plan
  to make outbound calls (like checking URLs), you can remove it.
  - python-dotenv is fine but FastAPI's pydantic-settings handles
  env vars natively - one less dependency.

  Recommended Revised Phase Order

  I'd suggest swapping Phases 4 and 7:

  1. Project Setup
  2. Email Parser
  3. Heuristic Detection
  4. Detection Orchestrator (heuristics-only first - get a working
   system early)
  5. API Layer + Docker (now you have something deployable and
  testable end-to-end)
  6. Gmail Add-on (connect to your running API)
  7. ML Model (train on Colab, add to the project, improve
  accuracy)
  8. Documentation

  This way you have a working end-to-end system faster using just
  heuristics, and ML becomes an enhancement rather than a blocker.

  Bottom Line

  The plan is solid overall. The main adjustments: drop spaCy,
  train on Colab (add a notebook), plan for cloud deployment, add
  basic API security, and reorder phases to get a working system
  sooner before adding ML.