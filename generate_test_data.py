"""
Generate real-world style test data: CSV log file and PCAP with HTTP traffic.
Includes normal traffic and all attack types detected by the URL IDS.
Run from project root: python generate_test_data.py
"""
import csv
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

# CSV: realistic web server log rows (timestamp, source_ip, url)
def generate_csv(out_path: str) -> None:
    base_ts = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=1)
    rows = []

    # Helper to add a row
    def add(ip: str, url: str, ts: datetime = None):
        t = (ts or base_ts) + timedelta(seconds=random.randint(0, 86400))
        rows.append({
            "timestamp": t.strftime("%Y-%m-%d %H:%M:%S"),
            "source_ip": ip,
            "url": url,
        })

    # --- Legitimate / edge cases ---
    ips_legit = ["203.0.113.10", "198.51.100.22", "192.0.2.5", "10.0.0.101", "172.16.1.50"]
    for ip in ips_legit:
        add(ip, "/")
        add(ip, "/index.html")
        add(ip, "/search?q=hello")
        add(ip, "/api/users?id=123")
        add(ip, "/login")
        add(ip, "/assets/style.css")
        add(ip, "/products?category=books&page=2")
        add(ip, "/view?file=report.pdf")

    # --- SQL Injection ---
    ips_sqli = ["192.168.1.100", "10.0.0.205", "203.0.113.99"]
    sqli_urls = [
        "/login?user=admin' OR '1'='1",
        "/api?id=1; DROP TABLE users--",
        "/search?q=test' UNION SELECT * FROM users--",
        "/page?id=1 AND 1=1--",
        "/item?id=1' OR 1=1#",
        "/filter?order=id; INSERT INTO log VALUES(1)",
        "/report?from=1&to=2; DELETE FROM orders",
        "/user?name=admin'--",
        "/?id=1%27%20OR%20%271%27%3D%271",
    ]
    for ip in ips_sqli:
        for url in random.sample(sqli_urls, min(4, len(sqli_urls))):
            add(ip, url)

    # --- XSS ---
    ips_xss = ["198.51.100.77", "192.168.2.33"]
    xss_urls = [
        "/search?q=<script>alert(1)</script>",
        "/comment?text=<img src=x onerror=alert(document.cookie)>",
        "/profile?name=<svg onload=alert(1)>",
        "/?ref=javascript:alert(1)",
        "/page?x=<body onload=alert(1)>",
        "/form?input=document.write('<img src=x>')",
        "/?q=<iframe src=javascript:alert(1)>",
        "/search?q=test%22%3E%3Cscript%3Ealert(1)%3C/script%3E",
    ]
    for ip in ips_xss:
        for url in random.sample(xss_urls, min(4, len(xss_urls))):
            add(ip, url)

    # --- Directory / Path Traversal ---
    ips_trav = ["10.0.0.50", "172.16.0.100"]
    trav_urls = [
        "/download?file=../../../etc/passwd",
        "/view?path=..%2f..%2f..%2fetc%2fpasswd",
        "/doc?name=....//....//....//etc/shadow",
        "/static/..%252f..%252f..%252fetc/passwd",
        "/api/file?path=..\\..\\..\\windows\\system32\\config\\sam",
        "/read?f=....//....//....//etc/passwd",
    ]
    for ip in ips_trav:
        for url in trav_urls:
            add(ip, url)

    # --- Command Injection ---
    ips_cmd = ["203.0.113.55", "192.168.5.10"]
    cmd_urls = [
        "/run?cmd=; ls -la",
        "/exec?command=id",
        "/api?q=test | cat /etc/passwd",
        "/run?cmd=; whoami",
        "/shell?c=&& netstat -an",
        "/run?cmd=; rm -rf /tmp/x",
        "/api?x=$(id)",
        "/run?cmd=; chmod 777 /var/www",
    ]
    for ip in ips_cmd:
        for url in random.sample(cmd_urls, min(4, len(cmd_urls))):
            add(ip, url)

    # --- SSRF ---
    ips_ssrf = ["198.51.100.200", "10.0.0.99"]
    ssrf_urls = [
        "/fetch?url=http://127.0.0.1/admin",
        "/proxy?target=http://localhost:8080",
        "/api/callback?url=http://169.254.169.254/latest/meta-data/",
        "/import?url=file:///etc/passwd",
        "/get?url=http://192.168.1.1/admin",
        "/fetch?url=http://10.0.0.1/internal",
        "/proxy?u=gopher://127.0.0.1:25/",
        "/fetch?url=dict://127.0.0.1:11211/",
    ]
    for ip in ips_ssrf:
        for url in random.sample(ssrf_urls, min(4, len(ssrf_urls))):
            add(ip, url)

    # --- File Inclusion (LFI/RFI) ---
    fi_urls = [
        "/include?page=....//....//....//etc/passwd",
        "/view?file=php://filter/convert.base64-encode/resource=index.php",
        "/?page=php://input",
        "/load?f=expect://id",
        "/doc?path=phar:///var/www/uploads/evil.phar",
    ]
    for url in fi_urls:
        add("192.168.10.20", url)

    # --- LDAP Injection ---
    ldap_urls = [
        "/search?user=*)(uid=*))(|(uid=*",
        "/auth?name=admin)(|(password=*",
        "/ldap?filter=(&(cn=*)(objectClass=*))",
        "/query?q=*)(&",
    ]
    for url in ldap_urls:
        add("172.16.2.15", url)

    # --- XXE (in URL-encoded form) ---
    xxe_urls = [
        "/api/xml?data=%3C!ENTITY%20xxe%20SYSTEM%20%22file:///etc/passwd%22%3E",
        "/submit?xml=%3C!DOCTYPE%20x%20[%3C!ENTITY%20y%20SYSTEM%20%22http://evil.com%22%3E]%3E",
    ]
    for url in xxe_urls:
        add("203.0.113.66", url)

    # Shuffle for realistic order
    random.shuffle(rows)

    with open(out_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["timestamp", "source_ip", "url"])
        w.writeheader()
        w.writerows(rows)

    print(f"Written {len(rows)} rows to {out_path}")


def generate_pcap(out_path: str) -> None:
    try:
        from scapy.all import Ether, IP, TCP, Raw, wrpcap
    except ImportError:
        print("Scapy not found. Install with: pip install scapy")
        print("Skipping PCAP generation.")
        return

    packets = []
    server_ip = "192.168.1.100"
    client_ips = [
        "203.0.113.10", "198.51.100.22", "192.168.1.50", "10.0.0.101",
        "172.16.1.20", "192.168.2.100", "203.0.113.55", "198.51.100.77",
    ]

    def make_http_request(client_ip: str, path_query: str, method: str = "GET"):
        raw = f"{method} {path_query} HTTP/1.1\r\nHost: example.com\r\nUser-Agent: TestClient/1.0\r\n\r\n"
        pkt = (
            Ether(dst="02:00:00:00:00:01", src="02:00:00:00:00:02")
            / IP(src=client_ip, dst=server_ip)
            / TCP(sport=random.randint(40000, 65535), dport=80, flags="PA")
            / Raw(load=raw.encode("utf-8"))
        )
        packets.append(pkt)

    # Normal
    for ip in client_ips[:4]:
        make_http_request(ip, "/")
        make_http_request(ip, "/index.html")
        make_http_request(ip, "/search?q=test")
        make_http_request(ip, "/api/users?id=1")

    # SQL Injection
    make_http_request("192.168.1.50", "/login?user=admin' OR '1'='1")
    make_http_request("10.0.0.101", "/api?id=1; DROP TABLE users--")
    make_http_request("172.16.1.20", "/search?q=1 UNION SELECT * FROM users")

    # XSS
    make_http_request("198.51.100.77", "/search?q=<script>alert(1)</script>")
    make_http_request("192.168.2.100", "/?x=<img src=x onerror=alert(1)>")

    # Directory traversal
    make_http_request("203.0.113.55", "/download?file=../../../etc/passwd")
    make_http_request("10.0.0.101", "/view?path=..%2f..%2f..%2fetc%2fpasswd")

    # Command injection
    make_http_request("192.168.1.50", "/run?cmd=; ls -la")
    make_http_request("172.16.1.20", "/exec?command=id")

    # SSRF
    make_http_request("198.51.100.77", "/fetch?url=http://127.0.0.1/admin")
    make_http_request("203.0.113.55", "/proxy?target=http://169.254.169.254/")

    # File inclusion
    make_http_request("192.168.2.100", "/include?page=php://filter/read=string.rot13/resource=index.php")

    # LDAP
    make_http_request("10.0.0.101", "/search?user=*)(uid=*))(|(uid=*")

    try:
        wrpcap(out_path, packets)
        print(f"Written {len(packets)} packets to {out_path}")
    except Exception as e:
        print(f"Could not write PCAP ({e}). CSV is ready; use test_data.csv for testing.")


def main():
    root = Path(__file__).resolve().parent
    csv_path = root / "test_data.csv"
    pcap_path = root / "test_traffic.pcap"

    generate_csv(str(csv_path))
    generate_pcap(str(pcap_path))
    print("Done. Use test_data.csv and test_traffic.pcap in the dashboard.")


if __name__ == "__main__":
    main()
