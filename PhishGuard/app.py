from flask import Flask, render_template, request, jsonify
import sqlite3
from urllib.parse import urlparse
from datetime import datetime
import re
import os

app = Flask(__name__)
DB_PATH = os.path.join(os.path.dirname(__file__), "phishguard.db")

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_type TEXT NOT NULL,
                input_text TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                threat_level TEXT NOT NULL,
                indicators TEXT NOT NULL,
                scanned_at TEXT NOT NULL
            )
        """)

def assess_url(raw_url):
    text = raw_url.strip()
    candidate = text if "://" in text else "http://" + text
    parsed = urlparse(candidate)
    host = (parsed.hostname or "").lower()
    path = parsed.path or ""
    score, indicators = 0, []

    def flag(points, label, explanation):
        nonlocal score
        score += points
        indicators.append({"label": label, "explanation": explanation, "points": points})

    if not text:
        return {"score": 0, "level": "Safe", "indicators": [], "recommendations": ["Enter a URL to analyze."]}

    if len(text) > 100:
        flag(10, "Unusually long URL", "Long URLs can be used to hide the real destination.")
    if re.search(r'\d{1,3}(?:\.\d{1,3}){3}', host):
        flag(25, "IP-based address", "The hostname is an IP address rather than a conventional domain.")
    if host.count(".") >= 3:
        flag(10, "Multiple subdomains", "Several subdomain levels may make a destination harder to recognize.")
    if "@" in text:
        flag(20, "At-sign in URL", "An at-sign can make part of a URL look like the destination when it is not.")
    if any(word in text.lower() for word in ["login", "verify", "update", "secure", "account", "password", "banking", "confirm"]):
        flag(10, "Sensitive-action keyword", "The URL contains words commonly used in account or verification lures.")
    if any(ch in text for ch in ["%", "~", "\\\\"]):
        flag(5, "Unusual special characters", "Special characters can sometimes obfuscate a URL.")
    if not candidate.lower().startswith("https://"):
        flag(10, "HTTPS not detected", "The URL does not use HTTPS. This alone does not prove phishing.")
    if host.startswith("xn--") or ".xn--" in host:
        flag(15, "Internationalized domain", "Punycode domains can sometimes be used to imitate familiar names.")
    if re.search(r'(^|\.)\d{1,3}(?:\.\d{1,3}){3}($|:)', host):
        pass
    if not host or "." not in host:
        flag(10, "Unusual domain structure", "A recognizable public domain could not be identified in the input.")
    if len(indicators) == 0:
        indicators.append({"label": "No obvious rule-based indicators", "explanation": "The configured checks did not find common warning signs. This does not guarantee the URL is safe.", "points": 0})

    score = min(score, 100)
    level = "Safe" if score < 10 else "Low" if score < 25 else "Medium" if score < 50 else "High" if score < 75 else "Critical"
    recs = recommendations(level)
    return {"score": score, "level": level, "indicators": indicators, "recommendations": recs}

def assess_email(content):
    text = content.strip()
    lower = text.lower()
    score, indicators = 0, []

    def flag(points, label, explanation):
        nonlocal score
        score += points
        indicators.append({"label": label, "explanation": explanation, "points": points})

    if not text:
        return {"score": 0, "level": "Safe", "indicators": [], "recommendations": ["Paste email text to analyze."]}

    urgency = ["immediately", "urgent", "act now", "within 24 hours", "account suspended", "final warning", "limited time"]
    credential = ["password", "verify your account", "login", "sign in", "bank details", "credit card", "social security"]
    prize = ["you have won", "winner", "claim your prize", "free gift", "lottery"]
    links = re.findall(r'https?://\S+|www\.\S+', text, re.I)

    if any(term in lower for term in urgency):
        flag(15, "Urgent or threatening language", "The message pressures the reader to act quickly.")
    if any(term in lower for term in credential):
        flag(20, "Sensitive information request", "The message mentions account access or sensitive personal/financial information.")
    if any(term in lower for term in prize):
        flag(15, "Prize or reward language", "Unexpected prizes and rewards are commonly used in scam messages.")
    if links:
        flag(10, "Link included in message", f"Found {len(links)} link(s). Inspect destinations carefully before opening.")
        for link in links[:3]:
            url_result = assess_url(link)
            if url_result["score"] >= 25:
                flag(15, "Potentially suspicious link", f"One included link triggered several URL warning signs: {link[:90]}")
                break
    if "dear customer" in lower or "dear user" in lower:
        flag(5, "Generic greeting", "Generic greetings can be a warning sign when a message claims to be from a service you use.")
    if re.search(r'\b(send|share|reply with)\b.{0,35}\b(password|pin|otp|code)\b', lower):
        flag(25, "Request for password, PIN, or code", "Legitimate services generally should not ask you to send secret authentication codes by email.")
    if len(indicators) == 0:
        indicators.append({"label": "No obvious rule-based indicators", "explanation": "The configured checks did not find common warning signs. Review the sender and context carefully.", "points": 0})

    score = min(score, 100)
    level = "Safe" if score < 10 else "Low" if score < 25 else "Medium" if score < 50 else "High" if score < 75 else "Critical"
    return {"score": score, "level": level, "indicators": indicators, "recommendations": recommendations(level)}

def recommendations(level):
    advice = {
        "Safe": ["No common warning signs were detected by these rules.", "Check the sender and destination independently before sharing sensitive information."],
        "Low": ["Proceed carefully and verify the website or sender through an official channel.", "Do not enter passwords or payment details unless you are sure of the destination."],
        "Medium": ["Avoid clicking links until you verify the sender and destination.", "Visit the service by typing its official address yourself.", "Never share one-time passcodes or passwords by email."],
        "High": ["Do not open links or attachments from this message.", "Verify the request using a known official phone number or website.", "Report the message to your email provider or security team."],
        "Critical": ["Treat this content as highly suspicious and do not interact with it.", "Do not enter credentials, payment details, or authentication codes.", "Report the content and delete it after preserving evidence if needed."]
    }
    return advice.get(level, advice["Medium"])

def save_scan(scan_type, input_text, result):
    with get_db() as conn:
        conn.execute(
            "INSERT INTO scans (scan_type, input_text, risk_score, threat_level, indicators, scanned_at) VALUES (?, ?, ?, ?, ?, ?)",
            (scan_type, input_text[:2000], result["score"], result["level"],
             " | ".join(item["label"] for item in result["indicators"]),
             datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        )

@app.route("/")
def index():
    with get_db() as conn:
        total = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        threats = conn.execute("SELECT COUNT(*) FROM scans WHERE threat_level IN ('High','Critical')").fetchone()[0]
        high_risk = conn.execute("SELECT COUNT(*) FROM scans WHERE threat_level IN ('Medium','High','Critical')").fetchone()[0]
        recent = conn.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 5").fetchall()
    return render_template("index.html", total=total, threats=threats, high_risk=high_risk, recent=recent)

@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json(silent=True) or request.form
    scan_type = data.get("scan_type", "url")
    content = (data.get("content") or "").strip()
    if not content:
        return jsonify({"error": "Please enter content to analyze."}), 400
    if scan_type == "email":
        result = assess_email(content)
    else:
        result = assess_url(content)
    save_scan(scan_type, content, result)
    return jsonify(result)

@app.route("/history")
def history():
    with get_db() as conn:
        scans = conn.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 100").fetchall()
    return render_template("history.html", scans=scans)

@app.route("/awareness")
def awareness():
    return render_template("awareness.html")

@app.route("/about")
def about():
    return render_template("about.html")

@app.route("/api/stats")
def stats():
    with get_db() as conn:
        rows = conn.execute("SELECT threat_level, COUNT(*) AS count FROM scans GROUP BY threat_level").fetchall()
    return jsonify({row["threat_level"]: row["count"] for row in rows})

init_db()

if __name__ == "__main__":
    app.run(debug=True)
