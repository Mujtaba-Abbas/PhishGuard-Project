# PhishGuard
**Web-Based Phishing Detection and Security Awareness System**

Academic project built with HTML, CSS, JavaScript, Python Flask, and SQLite, aligned with the submitted Web Technologies proposal.

## Features
- URL scanner with rule-based indicators
- Email content analyzer with phishing indicators
- Risk score (0–100) and threat levels: Safe, Low, Medium, High, Critical
- Explanations for detected indicators
- Risk-based security recommendations
- SQLite scan history and dashboard statistics
- Security awareness tips and project details

## Run locally
1. Install Python 3.10 or later.
2. Open a terminal in the `PhishGuard` folder.
3. Create and activate a virtual environment (recommended):
   - Windows: `python -m venv .venv` then `.venv\\Scripts\\activate`
   - macOS/Linux: `python3 -m venv .venv` then `source .venv/bin/activate`
4. Install dependencies: `pip install -r requirements.txt`
5. Start the app: `python app.py`
6. Open `http://127.0.0.1:5000` in your browser.

The SQLite database `phishguard.db` is created automatically at first run.

## Important scope note
PhishGuard is an educational, rule-based assessment tool. It does not query live threat-intelligence feeds and cannot guarantee that a URL or email is safe or malicious. Do not paste real passwords, OTPs, or confidential messages into the demo. Do not visit suspicious links to test them.

## Project workflow
User Input → URL/Email Analysis → Indicator Detection → Risk Score Calculation → Threat Classification → Explanation & Recommendation
