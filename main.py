from flask import Flask, request, render_template
import socket
from urllib.parse import urlparse
import requests
import time

API_KEY = "4fba3e14a48633995f6e6d47fbe5ab49bdf50a0e5b7ce8be023696fab64ce0bc"

app = Flask(__name__)


@app.route('/')
def home():
    return render_template("index.html")


@app.route('/submit', methods=['POST'])
def submit():

    text = request.form['user_text']

    malicious = 0
    suspicious = 0
    harmless = 0
    threat = "Unknown"

    try:
        # Extract domain
        parsed = urlparse(text)

        if parsed.hostname:
            domain = parsed.hostname
        else:
            domain = text.split("/")[0]

        # Get IP address
        try:
            ip = socket.gethostbyname(domain)
        except:
            ip = "IP not found"

        # ---------- VIRUSTOTAL SCAN ----------

        submit_url = "https://www.virustotal.com/api/v3/urls"

        headers = {
            "x-apikey": API_KEY
        }

        data = {
            "url": text
        }

        # Submit URL
        submit_response = requests.post(submit_url, headers=headers, data=data)
        submit_result = submit_response.json()

        if "data" in submit_result:

            analysis_id = submit_result["data"]["id"]

            # wait for scan
            time.sleep(3)

            report_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"

            report_response = requests.get(report_url, headers=headers)
            report_result = report_response.json()

            if "data" in report_result:

                stats = report_result["data"]["attributes"]["stats"]

                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                harmless = stats.get("harmless", 0)

    except Exception as e:
        ip = f"Error: {e}"

    # ---------- THREAT LEVEL ----------

    if malicious > 0:
        threat = "Malicious"
    elif suspicious > 0:
        threat = "Suspicious"
    else:
        threat = "Safe"

    return render_template(
        "result.html",
        ip=ip,
        malicious=malicious,
        suspicious=suspicious,
        harmless=harmless,
        threat=threat
    )


if __name__ == "__main__":
    app.run(debug=True)