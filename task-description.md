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