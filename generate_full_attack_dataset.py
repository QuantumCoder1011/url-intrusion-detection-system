"""
Generate a deterministic full-coverage CSV dataset for the URL IDS.

The dashboard only needs timestamp, source_ip, and url. Extra expected_* columns
are included so the same file can also be used for manual validation.
"""

import csv
from datetime import datetime, timedelta
from pathlib import Path


BASE_TIME = datetime(2026, 4, 21, 9, 0, 0)


def rows():
    data = []

    def add(source_ip, url, expected_attack_type, expected_source, severity, note):
        idx = len(data)
        data.append(
            {
                "timestamp": (BASE_TIME + timedelta(seconds=idx * 37)).strftime("%Y-%m-%d %H:%M:%S"),
                "source_ip": source_ip,
                "url": url,
                "expected_attack_type": expected_attack_type,
                "expected_detection_source": expected_source,
                "expected_severity": severity,
                "test_note": note,
            }
        )

    # Safe/benign traffic
    safe_urls = [
        "/",
        "/index.html",
        "/about",
        "/contact",
        "/login",
        "/dashboard",
        "/settings",
        "/profile?user=vansh",
        "/api/users?id=123",
        "/products?category=books&page=2",
        "/search?q=hello",
        "/assets/style.css",
        "/images/logo.png",
        "/download?file=report.pdf",
        "/api/data?sort=created_at",
    ]
    for i, url in enumerate(safe_urls, start=1):
        add(f"203.0.113.{i}", url, "None", "None", "None", "Benign baseline")

    # Strong rule-based SQL injection
    sql_rule_urls = [
        "/login?user=admin' OR 1=1",
        "/item?id=1' OR 1=1#",
        "/search?q=test' UNION SELECT * FROM users--",
        "/reports?query=SELECT password FROM users",
        "/api?id=1; DROP TABLE users--",
        "/delete?item=1;--",
        "/login?name=admin%27%20OR%201%3D1",
        "/lookup?u=admin'%20--",
    ]
    for i, url in enumerate(sql_rule_urls, start=20):
        add(f"192.168.10.{i}", url, "SQL Injection", "Rule", "High", "Rule SQLi")

    # Strong rule-based XSS
    xss_rule_urls = [
        "/search?q=<script>alert(1)</script>",
        "/comment?text=<img src=x onerror=alert(document.cookie)>",
        "/profile?name=<svg onload=alert(1)>",
        "/?ref=javascript:alert(1)",
        "/frame?next=<iframe src=http://evil.test></iframe>",
        "/link?x=vbscript:msgbox(1)",
        "/page?x=%3Cscript%20src%3D//evil.test/x.js%3E%3C/script%3E",
        "/button?label=test&onclick=alert(1)",
    ]
    for i, url in enumerate(xss_rule_urls, start=40):
        add(f"198.51.100.{i}", url, "XSS", "Rule", "High", "Rule XSS")

    # Strong rule-based directory traversal
    traversal_rule_urls = [
        "/download?file=../../../etc/passwd",
        "/view?path=..%2f..%2f..%2fetc%2fpasswd",
        "/static/..%252f..%252f..%252fetc/passwd",
        r"/api/file?path=..\..\..\windows\system32\config\sam",
        "/read?name=../../etc/shadow",
        "/assets/../../../../var/log/auth.log",
        "/open?target=..%5c..%5cboot.ini",
        "/docs?file=..%255c..%255csecret.txt",
    ]
    for i, url in enumerate(traversal_rule_urls, start=60):
        add(f"10.0.20.{i}", url, "Directory Traversal", "Rule", "Medium", "Rule traversal")

    # Strong rule-based command injection
    command_rule_urls = [
        "/run?cmd=; ls -la",
        "/run?cmd=; whoami",
        "/api?q=test | cat /etc/passwd",
        "/shell?c=&& netstat -an",
        "/process?x=|| id",
        "/debug?cmd=$(uname -a)",
        "/backup?target=`whoami`",
        "/chmod?file=x; chmod 777 x",
    ]
    for i, url in enumerate(command_rule_urls, start=80):
        add(f"172.16.30.{i}", url, "Command Injection", "Rule", "High", "Rule command injection")

    # Low-severity rule fallback
    suspicious_rule_urls = [
        "/note?text=single%27quote",
        "/name?value=o%27reilly",
        "/book?title=reader%27s-choice",
        "/literal?mark=apostrophe%27",
        "/search?q=customer%27s+receipt",
        "/profile?nickname=pilot%27s-log",
        "/docs?title=admin%27s-guide",
        "/ticket?message=operator%27s-note",
    ]
    for i, url in enumerate(suspicious_rule_urls, start=100):
        add(f"192.0.2.{i}", url, "Suspicious Activity", "Rule", "Low", "Low-severity rule fallback")

    # ML-oriented cases: designed to avoid the explicit regex rules but resemble
    # classes in backend/train_model.py. They require backend/train_model.py to
    # have been run so backend/models/url_detector_model.pkl exists.
    ml_urls = [
        ("/exec?command=id", "Command Injection", "ML command style from training data"),
        ("/search?q=script alert", "XSS", "XSS vocabulary without literal tags"),
        ("/login?user=admin' OR '1'='1", "SQL Injection", "SQLi shape not covered by strong SQL regex"),
        (r"/api/file?path=windows\system32\config\sam", "Directory Traversal", "Sensitive Windows path without traversal token"),
        ("/shell?command=netstat", "Command Injection", "Command keyword without rule delimiter"),
        ("/profile?name=javascriptalert", "XSS", "JavaScript vocabulary without javascript: scheme"),
        ("/comment?text=alert cookie", "SQL Injection", "Model false-positive/regression guard"),
        ("/view?path=etc/passwd", "Directory Traversal", "Sensitive Unix path without leading slash"),
    ]
    for i, (url, attack_type, note) in enumerate(ml_urls, start=120):
        add(f"10.10.40.{i}", url, attack_type, "ML", "Medium", note)

    return data


def main():
    out_path = Path(__file__).resolve().parent / "full_attack_test_dataset.csv"
    data = rows()
    with out_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "timestamp",
                "source_ip",
                "url",
                "expected_attack_type",
                "expected_detection_source",
                "expected_severity",
                "test_note",
            ],
        )
        writer.writeheader()
        writer.writerows(data)
    print(f"Wrote {len(data)} rows to {out_path}")


if __name__ == "__main__":
    main()
