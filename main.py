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

    try:
        parsed = urlparse(text)

        if parsed.hostname:
            domain = parsed.hostname
        else:
            domain = text.split("/")[0]

        try:
            ip = socket.gethostbyname(domain)
        except:
            ip = "IP not found"

        headers = {
            "x-apikey": API_KEY
        }

        # Submit URL to VirusTotal
        submit_url = "https://www.virustotal.com/api/v3/urls"

        data = {"url": text}

        submit_response = requests.post(submit_url, headers=headers, data=data)
        submit_result = submit_response.json()

        if "data" not in submit_result:
            raise Exception(submit_result)

        analysis_id = submit_result["data"]["id"]

        time.sleep(3)

        # Get analysis report
        report_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"

        report_response = requests.get(report_url, headers=headers)
        report_result = report_response.json()

        if "data" not in report_result:
            raise Exception(report_result)

        stats = report_result["data"]["attributes"]["stats"]

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)

    except Exception as e:
        ip = f"Error: {e}"
        malicious = 0
        suspicious = 0
        harmless = 0

    return render_template(
        "result.html",
        ip=ip,
        malicious=malicious,
        suspicious=suspicious,
        harmless=harmless
    )


if __name__ == "__main__":
    app.run(debug=True)