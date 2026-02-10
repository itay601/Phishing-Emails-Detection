● Here's my full analysis of your project. The key points:        
                                                                  
  What it is: A phishing email detection system with a FastAPI    
  backend (heuristics + optional ML) and a Gmail Add-on frontend. 
  Well-structured with 26/26 tests passing.                       
                                                                  
  Strengths:                                                      
  - Clean architecture with good separation of concerns           
  - 4 heuristic analyzers covering major phishing techniques (URL 
  tricks, typosquatting, urgency language, sender spoofing)       
  - Graceful ML fallback - works without a trained model          
  - Good test coverage                                            
  - Dockerized deployment                                         

  Top problems to be aware of:
  1. Performance bug: PhishingAnalyzer is re-created per request,
  reloading the ML model from disk every time
  2. Recursive Levenshtein without memoization (O(3^n) - textbook
  algorithm mistake)
  3. Security shortcuts: hardcoded "dev-api-key", CORS *,
  plaintext API key in addon
  4. No ML training pipeline exists - the model is referenced but
  never actually trained
  5. No evaluation metrics - no way to prove accuracy, false
  positive rate, etc.
  6. Arbitrary scoring weights (0.4/0.3/0.3) not derived from data

  I also included a section on questions reviewers might ask you
  and how to answer them. The full analysis is in the plan file -
  take a look and let me know if you want me to dive deeper into
  any specific area.

──────────────────────────────────────────────────────────────────
 Ready to code?
                                                                  
 Here is Claude's plan:
╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌
 Phishing Email Detection - Full Project Analysis                 

 What The Project Is

 A phishing email detection system with two components:
 1. FastAPI Backend - Analyzes emails using rule-based heuristics
  + optional ML model
 2. Gmail Add-on (Google Apps Script) - UI inside Gmail with a
 "Scan for Phishing" button that calls the backend

 Tech Stack: Python 3.11, FastAPI, Pydantic v2, scikit-learn,
 BeautifulSoup4, tldextract, Docker, Google Apps Script

 ---
 Architecture Overview

 Gmail Inbox
     │
     ▼
 Gmail Add-on (Google Apps Script)
     │  Extracts: sender, subject, body, headers, links
     │  POST /api/v1/analyze  (X-API-Key auth)
     ▼
 FastAPI Backend (Docker container, port 8000)
     │
     ├── Email Parser ──► extracts links, detects URL/display
 mismatches
     │
     ├── 4 Heuristic Analyzers (rule-based, each returns score
 0.0–1.0)
     │   ├── LinkAnalyzer      – URL shorteners, IP URLs,
 suspicious TLDs, mismatches
     │   ├── DomainAnalyzer    – Typosquatting (Levenshtein),
 homograph attacks
     │   ├── LanguageAnalyzer  – Urgency phrases, threatening
 language
     │   └── SenderAnalyzer    – Free-email impersonation,
 reply-to mismatch
     │
     ├── ML Model (optional) ──► scikit-learn .pkl, text
 vectorization + metadata features
     │
     └── Scoring Engine
          With ML:    0.4 * max_heuristic + 0.3 * avg_heuristic +
  0.3 * ml_score
          Without ML: 0.5 * max_heuristic + 0.5 * avg_heuristic

 ─────────────────────────────────────────────────────────
          >= 0.7  → "Phishing"
          >= 0.4  → "Suspicious"
          < 0.4   → "Safe"

 ---
 Key Files to Know
 File: backend/src/main.py
 Purpose: FastAPI app setup, CORS, health endpoint
 ────────────────────────────────────────
 File: backend/src/config.py
 Purpose: Settings via env vars (PHISHING_API_KEY, MODEL_PATH)
 ────────────────────────────────────────
 File: backend/src/api/routes.py
 Purpose: POST /api/v1/analyze endpoint + API key validation
 ────────────────────────────────────────
 File: backend/src/api/schemas.py
 Purpose: Pydantic request/response models
 ────────────────────────────────────────
 File: backend/src/parser/email_parser.py
 Purpose: ParsedEmail dataclass, HTML link extraction, mismatch
   detection
 ────────────────────────────────────────
 File: backend/src/detection/analyzer.py
 Purpose: Core orchestrator - runs all heuristics, combines
   scores, classifies
 ────────────────────────────────────────
 File: backend/src/detection/heuristics/base.py
 Purpose: Abstract base class for heuristics
 ────────────────────────────────────────
 File: backend/src/detection/heuristics/link_analyzer.py
 Purpose: Detects: shorteners, IP URLs, suspicious TLDs,
   display/href mismatch
 ────────────────────────────────────────
 File: backend/src/detection/heuristics/domain_analyzer.py
 Purpose: Detects: typosquatting (Levenshtein distance),
 homograph
    attacks (0→o, 1→l, rn→m)
 ────────────────────────────────────────
 File: backend/src/detection/heuristics/language_analyzer.py
 Purpose: Detects: 23+ urgency/threat phrases via regex
 ────────────────────────────────────────
 File: backend/src/detection/heuristics/sender_analyzer.py
 Purpose: Detects: free-email impersonation, display name
   spoofing, reply-to mismatch
 ────────────────────────────────────────
 File: backend/src/detection/ml/model.py
 Purpose: Loads .pkl model, graceful fallback if missing
 ────────────────────────────────────────
 File: backend/src/detection/ml/preprocessor.py
 Purpose: Feature extraction (text, link_count, uppercase_ratio,
   etc.)
 ────────────────────────────────────────
 File: gmail-addon/Code.gs
 Purpose: Entry point, extracts email data from Gmail API
 ────────────────────────────────────────
 File: gmail-addon/CardUI.gs
 Purpose: Renders color-coded result cards (red/yellow/green)
 ────────────────────────────────────────
 File: gmail-addon/ApiClient.gs
 Purpose: HTTP calls to backend with API key header
 ────────────────────────────────────────
 File: docker-compose.yml
 Purpose: Backend service on port 8000, mounts models/ volume
 ---
 How Each Heuristic Works (Detail)

 LinkAnalyzer

 - Checks links against 10 known URL shorteners (bit.ly, tinyurl,
  etc.) → score 0.6
 - Detects display/href mismatch (e.g., shows "paypal.com" but
 links to "evil.com") → score 0.9
 - Detects IP-based URLs (http://192.168.1.1/...) → score 0.8
 - Flags 14 suspicious TLDs (.xyz, .tk, .buzz, etc.) → score 0.5

 DomainAnalyzer

 - Typosquatting: Computes Levenshtein edit distance between
 sender domain and 20 known brands (paypal, google, amazon...).
 Distance ≤ 2 = suspicious → score 0.85
 - Homograph attacks: Normalizes characters (0→o, 1→l, rn→m,
 vv→w) then checks if it matches a brand → score 0.9
 - Also checks link domains for typosquatting

 LanguageAnalyzer

 - Scans body text with regex for urgency phrases: "immediate
 action", "account suspended", "verify your account", "within 24
 hours", etc.
 - Score: 0.3 + (count * 0.15) capped at 0.9; 3+ phrases forces
 minimum 0.8
 - Threat phrases: "legal action", "law enforcement", "arrest
 warrant"
 - Score: 0.5 + (count * 0.15) capped at 0.9

 SenderAnalyzer

 - Free-email impersonation: Sender uses @gmail.com but display
 name contains "PayPal" → score 0.8
 - Display name spoofing: Display name contains an email address
 → score 0.7
 - Reply-To mismatch: Reply-To domain differs from sender domain
 → score 0.7

 ---
 Testing: 26/26 Tests Passing

 - test_heuristics.py - Unit tests for each of the 4 heuristic
 analyzers
 - test_analyzer.py - Integration tests: safe emails, phishing
 emails, suspicious emails, parser
 - test_api.py - API tests: health check, phishing detection,
 safe detection, auth (valid/invalid/missing key)

 ---
 Design Decisions Worth Explaining in Review

 1. Heuristics-first, ML-optional: System works fully without a
 trained model. ML enhances accuracy but isn't required. This is
 pragmatic - avoids dependency on training data.
 2. Weighted ensemble scoring: Max heuristic score prevents a
 single strong signal from being diluted by averaging. The
 40/30/30 split balances between "worst signal" and "overall
 picture".
 3. Three-tier classification: Not binary (phishing/safe) but
 adds "Suspicious" tier to reduce false positives.
 4. Regex over spaCy for NLP: Deliberate choice to avoid heavy
 dependency; 23+ regex patterns are sufficient for known phishing
  language.
 5. Graceful ML degradation: Model fails silently with a warning,
  system continues with heuristics only.

 ---
 Problems and Mistakes to Be Aware Of

 Critical Issues
 #: 1
 Issue: Hardcoded default API key "dev-api-key"
 Where: config.py
 Why It Matters: Anyone can call the API if not overridden.
 Should
    be mandatory, no default.
 ────────────────────────────────────────
 #: 2
 Issue: CORS allows all origins allow_origins=["*"]
 Where: main.py
 Why It Matters: Any website can call your API. Should whitelist
   specific origins in production.
 ────────────────────────────────────────
 #: 3
 Issue: API key in plaintext in Gmail addon
 Where: ApiClient.gs
 Why It Matters: Visible to anyone with script editor access.
   Should use Google PropertiesService or Secret
   Manager.
 Architecture/Logic Problems
 #: 4
 Issue: PhishingAnalyzer re-created per request
 Where: routes.py
 Why It Matters: ML model reloaded from disk on EVERY API call.
   Should be a singleton/global instance. This is a
   major performance bug.
 ────────────────────────────────────────
 #: 5
 Issue: Recursive Levenshtein without memoization
 Where: domain_analyzer.py
 Why It Matters: O(3^n) worst case. Works because domain names
 are
    short, but it's a textbook algorithm mistake.
   Should use iterative DP or python-Levenshtein
   library.
 ────────────────────────────────────────
 #: 6
 Issue: Scoring formula is arbitrary
 Where: analyzer.py
 Why It Matters: The 0.4/0.3/0.3 weights weren't derived from
   data. No justification for why these specific
   weights. Should ideally be tuned on a validation
   set.
 ────────────────────────────────────────
 #: 7
 Issue: No input size limits
 Where: schemas.py
 Why It Matters: No max_length on body_text/body_html. A 50MB
   email body could crash the server.
 ────────────────────────────────────────
 #: 8
 Issue: No rate limiting
 Where: routes.py
 Why It Matters: No protection against abuse or DoS.
 ────────────────────────────────────────
 #: 9
 Issue: ML model loaded from relative path
 Where: config.py
 Why It Matters: "models/phishing_model.pkl" is relative; breaks
   if CWD changes. Works in Docker only because
   WORKDIR is set.
 ────────────────────────────────────────
 #: 10
 Issue: Only Reply-To header extracted in addon
 Where: Code.gs
 Why It Matters: Missing SPF, DKIM, DMARC, X-Originating-IP
   headers that are critical for phishing detection.
 Missing Features
 #: 11
 What's Missing: No logging in detection logic
 Impact: Can't debug false positives/negatives
 ────────────────────────────────────────
 #: 12
 What's Missing: No caching of scan results
 Impact: Same email re-analyzed every click
 ────────────────────────────────────────
 #: 13
 What's Missing: No ML model training pipeline
 Impact: Model .pkl referenced but no training code exists
 ────────────────────────────────────────
 #: 14
 What's Missing: No monitoring/metrics
 Impact: No visibility into classification distribution or
   accuracy
 ────────────────────────────────────────
 #: 15
 What's Missing: Homograph map is incomplete
 Impact: Missing: 5→S, 8→B, @→a, etc.
 ────────────────────────────────────────
 #: 16
 What's Missing: No loading indicator in addon
 Impact: User sees nothing while waiting for API response
 Code Quality Nits
 #: 17
 Issue: Inconsistent case normalization - some heuristics
   lowercase input, others use re.IGNORECASE
 Where: Multiple heuristic files
 ────────────────────────────────────────
 #: 18
 Issue: Broad except Exception catches mask real bugs
 Where: model.py
 ────────────────────────────────────────
 #: 19
 Issue: dict type hints without key/value types
 Where: email_parser.py
 ---
 What Reviewers Might Ask You

 1. "Why these specific heuristic weights (0.4/0.3/0.3)?" -
 Honest answer: they're heuristic-based, not data-driven. The max
  score gets highest weight because a single strong phishing
 signal (like a mismatched URL at 0.9) should dominate.
 2. "Why not use a pre-trained NLP model instead of regex?" -
 Trade-off: regex is fast, lightweight, zero dependencies beyond
 Python stdlib. spaCy/transformers would add ~500MB+ to the
 Docker image for marginal gains on known patterns.
 3. "How does the system handle novel phishing techniques?" - It
 doesn't, unless the ML model is trained on them. The heuristics
 only catch known patterns. This is the main limitation.
 4. "What's the false positive rate?" - Unknown. There's no
 evaluation dataset or metrics tracking. This would be the top
 priority for a production system.
 5. "Why Google Apps Script instead of a Chrome extension?" -
 Apps Script is the official Gmail add-on SDK, works on mobile
 Gmail too, and has first-class access to email content via
 GmailApp API.

 --
 Summary for Your Review Presentation

 The project is a well-structured phishing detection system with
 clean separation of concerns (parser → heuristics → scorer → API
  → UI). The heuristic analyzers cover the major phishing
 techniques (URL tricks, domain spoofing, social engineering
 language, sender impersonation). The architecture is sound
 (FastAPI + Docker + Gmail Add-on).

 The main weaknesses are: (1) no trained ML model exists so it's
 heuristics-only in practice, (2) the analyzer is re-created per
 request which is a performance bug, (3) security shortcuts
 (hardcoded API key, wildcard CORS, plaintext credentials in
 addon), and (4) no evaluation metrics to prove the system
 actually works well.

 It's a solid prototype/MVP but would need the issues above
 addressed for production use.