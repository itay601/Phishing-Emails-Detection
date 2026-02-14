Home Task: Phishing Email Detection and  

Gmail Add-on Development  

Objective  

The goal of this task is to develop a system that detects phishing emails using a combination of rule-based techniques and machine learning, and then integrate this functionality into a Gmail Add-on that allows users to scan emails upon request.  

Task Breakdown  

1. Phishing Email Detection System  

Develop a program that analyzes an email and determines if it is a phishing attempt. The system should include:  

Basic heuristics (e.g., checking for suspicious links, unusual sender addresses, urgent language, or misleading domains).  

Machine learning (optional): Train a simple model using existing phishing datasets (e.g., Kaggle’s phishing emails dataset).  

Integration with an email parser to extract relevant email components (headers, body, links).  

Output: A confidence score or a classification (e.g., "Phishing", "Suspicious", "Safe").  

The implementation can be written in Python or Java, and should follow clean coding principles with appropriate documentation.  

2. Gmail Add-on for Email Scanning  

Build a Google Apps Script Add-on for Gmail that allows users to scan an email for phishing upon request.  

Requirements:  

UI Element: Add a "Scan for Phishing" button in Gmail.  

Backend Service (Optional): While a backend service can be used for additional processing, it is not mandatory. The detection logic can be implemented directly within the Google Apps Script or as a lightweight client-side script.  

Backend Logic: When clicked, the email content should be sent to the phishing detection system - should be implemented as a backhand service out of Gmail.  

Results Display: Show the phishing confidence score or classification within the Gmail UI.  

Implementation Considerations:  

○ Use Google Apps Script for Gmail API interactions.  

○ If a backend service is used, it can communicate with the phishing detection model via a cloud-based API (e.g., Flask or Spring Boot server running on Google Cloud Functions).  

Deliverables  

Phishing detection code (Python or Java).  

Gmail Add-on code (Google Apps Script file).  

A brief README explaining:  

○ How the detection model works.  

○ How to install and use the Gmail Add-on.  

○ Any limitations or future improvements.  

Evaluation Criteria  

Accuracy and effectiveness of phishing detection.  

Proper implementation and integration with Gmail.  

Clean, modular, and well-documented code. ● User-friendly interface in Gmail.    
-----------------------------------------------------------
  Connection Method: Direct HTTP API Call (not OAuth, not Webhook)                
                 
  The add-on uses a simple REST API call with an API key — specifically           
  UrlFetchApp.fetch() from Google Apps Script. Here's the flow:                   

  How it works

  1. User clicks "Scan for Phishing" in Gmail (Code.gs:81-83)
  2. Code.gs reads the email via GmailApp.getMessageById() (this part uses Gmail
  OAuth scopes)
  3. ApiClient.gs:73 sends a POST request via UrlFetchApp.fetch() to your backend
  at POST /api/v1/analyze
  4. Auth: The X-Api-Key header is attached if configured (ApiClient.gs:67-69)
  5. Backend validates the key (routes.py:23-24) and returns the analysis result

  So it's:

  - Not OAuth between add-on and backend — it's a static API key (X-Api-Key
  header)
  - Not a webhook — the add-on initiates the call on user click, backend doesn't
  push to the add-on
  - OAuth is only used for the add-on to access Gmail itself (the 4 scopes in
  appsscript.json:6-11)

  Configuration

  The API URL and key are stored in Google Apps Script Properties
  (ApiClient.gs:6-7):
  API_URL: PropertiesService.getScriptProperties().getProperty("API_URL")
  API_KEY: PropertiesService.getScriptProperties().getProperty("API_KEY")

  Summary

  Gmail Add-on  --[HTTP POST + X-Api-Key header]--> FastAPI Backend
       ↑                                                  |
       |                                                  |
       +--------[JSON response]---------------------------+

  The add-on reads the email (via Gmail OAuth), then makes a plain HTTP request to
   your backend with a shared API key. Simple and straightforward.



     Logging configuration (main.py)                               
                  
  - Centralized setup with logging.basicConfig — respects the   
  debug setting from .env (INFO by default, DEBUG when          
  PHISHING_DEBUG=true)                                          
  - Request/response middleware — logs every HTTP request with
  method, path, status code, and duration in ms
  - Startup log — confirms the server started and shows debug
  mode status

  Per-module logging

  routes.py — logs:
  - Unauthorized access attempts (warning)
  - Each analyze request (sender + subject)
  - Final classification result with score and indicator count

  analyzer.py — logs:
  - Each heuristic name, score, and indicators found
  - ML model prediction result (or that it's unavailable)
  - Score breakdown (max, avg_active, final) at DEBUG level
  - Final classification summary

  email_parser.py — logs:
  - Mismatched links detected (warning with details)
  - Parse summary (link count, subject) at DEBUG level

  Log output format

  2026-02-14 12:00:00 | INFO     | src.api.routes | Analyze
  request — from: user@example.com, subject: Verify your account
  2026-02-14 12:00:00 | INFO     | src.detection.analyzer |
  Starting analysis for email from 'user@example.com'
  2026-02-14 12:00:00 | INFO     | src.detection.analyzer |
  Heuristic link_analysis        score=0.65  indicators=['URL
  shortener detected', 'Suspicious TLD']
  2026-02-14 12:00:00 | INFO     | src.detection.analyzer |
  Analysis complete — Suspicious (score 0.45)
  2026-02-14 12:00:00 | INFO     | phishing_detector | <<< POST
  /api/v1/analyze — 200 (42.3ms)

  Set PHISHING_DEBUG=true in your .env to get even more verbose
  output (score breakdowns, parse details).