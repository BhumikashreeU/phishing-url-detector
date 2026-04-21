from flask import Flask, render_template, request
import re
from urllib.parse import urlparse
from datetime import datetime
import whois

app = Flask(__name__)

def analyze_url(url):
    score = 0
    reasons = []

    # Long URL
    if len(url) > 60:
        score += 30
        reasons.append("Long URL detected")

    # IP address
    if re.search(r"(http[s]?://)?(\d{1,3}\.){3}\d{1,3}", url):
        score += 40
        reasons.append("IP address used instead of domain")

    # Suspicious words
    if any(word in url.lower() for word in ["login", "verify", "secure", "account", "update", "bank"]):
        score += 30
        reasons.append("Suspicious keywords found")

    # Subdomains
    domain = urlparse(url).netloc
    if domain.count(".") > 3:
        score += 20
        reasons.append("Too many subdomains")

    # Domain age
    try:
        info = whois.whois(domain)
        creation_date = info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        age = (datetime.now() - creation_date).days
        if age < 180:
            score += 30
            reasons.append("Domain is recently created")
    except:
        score += 10
        reasons.append("Domain information not found")

    # Result classification
    if score < 20:
        result = "🟢 Safe"
    elif score < 50:
        result = "🟠 Suspicious"
    else:
        result = "🔴 High Risk"

    # Precautions
    if result == "🟢 Safe":
        precautions = [
            "Always verify the URL before entering sensitive data",
            "Check for HTTPS and valid certificates",
            "Avoid clicking unknown links"
        ]

    elif result == "🟠 Suspicious":
        precautions = [
            "Do not enter personal or banking details",
            "Verify the website manually before proceeding",
            "Avoid clicking links from unknown emails"
        ]

    else:
        precautions = [
            "Do NOT open this link",
            "Do not enter any credentials",
            "Report this URL as phishing",
            "Use antivirus or browser security tools"
        ]

    return score, result, reasons, precautions


@app.route("/", methods=["GET", "POST"])
def home():
    score = None
    result = None
    reasons = None
    precautions = None
    url = ""

    if request.method == "POST":
        url = request.form["url"]
        score, result, reasons, precautions = analyze_url(url)

    return render_template(
        "index.html",
        score=score,
        result=result,
        reasons=reasons,
        precautions=precautions,
        url=url
    )


if __name__ == "__main__":
    app.run(debug=True)