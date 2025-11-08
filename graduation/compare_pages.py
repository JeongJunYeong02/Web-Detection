# compare_pages.py
from web_forgery_detector import WebForgeryDetector
import pathlib
import json

def load_html(path):
    return pathlib.Path(path).read_text(encoding='utf-8')

if __name__ == "__main__":
    legitimate_html = load_html("normal.html")
    suspicious_html = load_html("malicious.html")

    # Create detector without CSV
    detector = WebForgeryDetector(whitelist_csv_path=None)

    # Provide example URLs (도메인 비교용)
    legit_url = "https://www.acme-bank.com"
    malicious_url = "http://acme-bank.login-security.xyz"

    results = detector.analyze_webpage(suspicious_html, legitimate_html, malicious_url, legit_url)
    print(json.dumps(results, indent=2, ensure_ascii=False))