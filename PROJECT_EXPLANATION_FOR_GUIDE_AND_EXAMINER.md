# URL-based Intrusion Detection System  
## Complete Explanation for Project Guide & External Examiner

**Student:** Vansh Shah  
**Roll No.:** MCA2547  
**Mentor:** Prof. Puja Devgun  
**Purpose:** Detailed reference for project explanation, viva, and evaluation.

---

# Part 1: What Is Built (Project Overview)

## 1.1 In One Sentence

A **full-stack web application** that takes **CSV log files** or **PCAP network captures**, extracts URLs from them, runs each URL through **rule-based (regex) attack detection**, stores results in a database, and presents them on an **interactive dashboard** with charts, filters, file history, and export (CSV/JSON).

## 1.2 What the System Does Step by Step

1. **User uploads a file** (CSV or PCAP) via the web interface.
2. **Backend receives the file**, validates type and size (e.g. max 16 MB), and saves it temporarily.
3. **Data ingestion**  
   - **CSV:** Uses Pandas to read the file, finds URL-like columns (e.g. `url`, `request`, `path`) and optional `source_ip`, `timestamp`, and extracts a list of `{url, source_ip, timestamp}`.  
   - **PCAP:** Uses Scapy to read packets, finds TCP payloads that look like HTTP request lines (GET/POST etc.), and extracts URL, source IP (from packet), and packet timestamp.
4. **Detection:** For each URL, the **detector** decodes percent-encoding (e.g. `%27` → `'`), then checks the URL against **compiled regex patterns** in a **fixed priority order**: Command Injection → Directory Traversal → XSS → SQL Injection → Low-severity “Suspicious Activity”. **At most one** attack type is reported per URL. A **confidence score** (0–100) is computed from how many patterns matched and whether the URL was encoded.
5. **Storage:** Each detection is stored in **SQLite** along with which file it came from (`file_analysis` table). File metadata (name, type, upload time, total attacks) is also stored.
6. **Dashboard:** The **React** frontend fetches detections and statistics from the **Flask API**, shows:  
   - Summary (total detections, attack types count, unique IPs),  
   - Pie chart (by attack type), bar charts (by severity, top attacking IPs),  
   - Analyst summary and recommendations,  
   - File analysis history (click to see stats for that file only),  
   - Events table with sortable columns and filters (attack type, source IP, severity),  
   - Export filtered/overall detections as CSV or JSON (including **pattern_matched**),  
   - Light/dark theme.
7. **Cleanup:** Uploaded files are **deleted** from disk after processing.

## 1.3 Main Deliverables

| Component | What It Is |
|-----------|------------|
| **Backend API** | Flask app with routes: health, upload, detections (with filters), statistics, top-IPs, file-history, clear-database, export CSV/JSON. |
| **Detector** | Priority-based, one-result-per-URL module using regex patterns from `patterns.py`; returns attack type, severity, confidence score, and **matched pattern** (regex string). |
| **Data ingestion** | CSV (Pandas, flexible column mapping) and PCAP (Scapy, HTTP line parsing) to produce a list of URL records. |
| **Database** | SQLite with `file_analysis` and `detections` tables; supports filtering by file, attack type, IP, severity. |
| **Frontend** | React app: FileUpload, Dashboard (stats + charts + analyst summary + file history), EventsTable (filters, sort, export). |

---

# Part 2: Real-World Applications

## 2.1 Where Such a System Is Used

- **Security Operations Center (SOC):** Analysts receive log files or packet captures from firewalls, proxies, or WAFs. They need to quickly see which URLs contained attack patterns (e.g. SQL injection, XSS, command injection). This project mimics that workflow: upload → analyze → view by file, filter by type/IP → export for reports or SIEM.
- **Incident response:** After a suspected breach or attack, logs are exported (often as CSV) or network traffic is captured (PCAP). Offline analysis of URLs helps identify which endpoints were targeted and what kind of attacks were attempted.
- **Compliance and auditing:** Organizations may need to demonstrate that they analyze web traffic for malicious patterns. An offline URL-IDS provides evidence of “what was looked for” and “what was found.”
- **Security research and training:** Researchers and students can test attack samples (e.g. from OWASP) against a rule set, compare results, and extend patterns without dealing with live traffic.

## 2.2 How It Fits in the Security Landscape

- It is a **signature-based** (rule-based) **intrusion detection** system focused on **URLs** only (not full HTTP body or headers, not other protocols).
- It does **not** block traffic; it **detects and reports**. Blocking would be the job of a WAF or firewall; this tool supports **analysis and reporting** that can feed into those systems (e.g. via exported CSV/JSON or future SIEM integration).

---

# Part 3: Limitations (Honest Boundaries)

1. **Offline only:** No real-time monitoring. Analysis happens only after a file is uploaded. Live traffic would require integration with a proxy, WAF log stream, or packet capture pipeline.
2. **Rule-based only:** Detection is entirely regex/signature-based. Sophisticated obfuscation, zero-day payloads, or behavior-based attacks are not covered. No machine learning or anomaly detection.
3. **One classification per URL:** If a URL matches multiple categories (e.g. both SQL and command injection), only the **highest-priority** one is reported.
4. **CSV format dependency:** The system assumes the CSV has (or allows inferring) URL-like data and optional IP/timestamp. Column names are heuristics (e.g. `url`, `request`, `path`); unusual formats may need preprocessing.
5. **PCAP limitations:** Only **plain HTTP** is parsed (no TLS decryption). URLs are taken from the first line of TCP payload; fragmented or multi-packet requests are not reassembled.
6. **False positives/negatives:** Regex rules can miss encoded or novel payloads (false negatives) or flag benign but odd URLs (false positives). Tuning and maintenance of rules is required.
7. **No authentication/authorization:** The UI and API are open to anyone who can reach the server. Not suitable for multi-user or production deployment without adding login and access control.
8. **Single-node:** One backend, one SQLite database. No clustering, replication, or high availability.
9. **No automatic response:** The system does not block IPs, alert external systems, or push to SIEM by itself; export and API are the integration points.

---

# Part 4: Future Enhancements

- **Real-time IDS:** Use the same `detect_attack()` in a middleware or log tailer so every incoming request URL is analyzed before/after forwarding; store or stream results to the same (or another) backend.
- **SIEM/alerting integration:** Push detections to syslog, Splunk, or other SIEMs; or trigger alerts when severity/count exceeds a threshold.
- **Rule management:** Load patterns from a config file or external feed; support hot-reload so new rules apply without restarting the app.
- **Authentication and roles:** Add user login and role-based access so only authorized analysts can upload, view, or clear data.
- **More attack types:** Add first-class patterns (and priority) for SSRF, XXE, LDAP injection, etc., in `patterns.py` and `detector.py`.
- **Better PCAP handling:** Full HTTP parsing, optional TLS decryption (with keys), reassembly of fragmented requests.
- **Machine learning (optional):** Use ML as a second layer (e.g. on top of rule-based results) for anomaly detection or reduced false positives.

---

# Part 5: Scope (Formal)

## 5.1 In Scope

- Input: CSV and PCAP files only.  
- Detection: Command Injection, Directory Traversal, XSS, SQL Injection, and low-severity “Suspicious Activity” with priority-based, single result per URL.  
- Output: Stored detections (with pattern_matched), REST API, React dashboard, filtering, file-level context, export CSV/JSON, theme.  
- No real-time traffic, no ML, no blocking, no auth in current version.

## 5.2 Out of Scope

- Real-time monitoring, TLS decryption, non-HTTP protocols, ML-based detection, user authentication, automatic blocking/remediation, distributed deployment.

---

# Part 6: Technology Stack — What Is Used and Why (Detailed)

## 6.1 Backend

| Technology | Where / What For | Why This Choice |
|------------|------------------|------------------|
| **Python 3.x** | Entire backend logic, detection, ingestion, DB, API. | Mature ecosystem for security tooling, regex, file handling, and quick prototyping; widely used in SOC/DevSecOps. |
| **Flask** | Web framework: routes, request handling, file upload, JSON/CSV responses. | Lightweight, easy to understand, minimal boilerplate; sufficient for a REST API and file upload; no need for a full MVC framework. |
| **Flask-CORS** | Allow frontend (different origin, e.g. localhost:3000) to call backend (localhost:5000). | Browsers block cross-origin requests by default; CORS middleware enables the React app to talk to the API during development and optional production. |
| **Pandas** | CSV parsing: read file, detect columns, extract URL/IP/timestamp. | Handles different delimiters, missing values, and column mapping; standard for tabular log analysis in Python. |
| **Scapy** | PCAP reading: load packets, access IP/TCP/Raw layers, extract HTTP request line. | Industry-standard for packet manipulation and analysis; allows low-level access without writing C. |
| **SQLite** | Single-file database for `file_analysis` and `detections`. | No separate server, zero config, file-based; ideal for single-user/desktop and academic projects; easy to backup and inspect. |
| **re (regex)** | In `patterns.py` and `detector.py`: compile and match attack patterns. | Built-in, fast, and sufficient for signature-based URL inspection; patterns are maintainable in one module. |

## 6.2 Frontend

| Technology | Where / What For | Why This Choice |
|------------|------------------|------------------|
| **React 18** | UI structure: App, Header, FileUpload, Dashboard, EventsTable. | Component-based, large ecosystem, good for dashboards and stateful UIs; widely taught and used in industry. |
| **Chart.js / react-chartjs-2** | Pie chart (attack types), bar charts (severity, top IPs). | Simple API, good defaults, responsive; react-chartjs-2 integrates cleanly with React state. |
| **Axios** | HTTP client: GET/POST to Flask API (detections, statistics, upload, export, clear). | Promise-based, supports file upload and query params; clearer than raw fetch for this use case. |
| **CSS (App.css)** | Theming (light/dark), layout, cards, tables, buttons. | Full control over look and feel; CSS variables for theme switching without extra libraries. |

## 6.3 Per-Module Rationale

- **patterns.py:** Centralizing all regex in one module makes it easy for a security analyst or examiner to see “what is being detected” and to add new rules without touching detector logic.
- **detector.py:** Single function `detect_attack(url)` and explicit priority order keep behavior predictable and testable; same function can later be called from a real-time pipeline.
- **data_ingestion.py:** Separating CSV vs PCAP logic allows adding new formats (e.g. JSON logs) without changing the rest of the pipeline.
- **database.py:** Abstracting SQLite behind a small API (insert, get_detections, get_statistics, etc.) keeps app.py clean and makes it easier to swap to PostgreSQL/MySQL later if needed.
- **React components:** FileUpload, Dashboard, EventsTable, Header are reusable and testable; file-level context (selecting a file from history) improves analyst workflow.

---

# Part 7: How the Project Helps

- **Analysts:** Quickly see which URLs in uploaded logs/captures triggered which rules; filter by attack type, IP, severity; export for reports or SIEM; view stats per file.
- **Learning:** Demonstrates full stack (backend API, DB, frontend), signature-based IDS concepts, regex-based detection, and separation of concerns (ingestion vs detection vs storage vs UI).
- **Extension base:** Clear modules and documented extension points (real-time IDS, SIEM, new patterns) so the project can grow without rewriting from scratch.

---

# Part 8: Possible Questions & Answers (Guide / External Examiner)

**Q1: What is an intrusion detection system (IDS)?**  
**A:** An IDS monitors network or host activity to identify malicious or policy-violating behavior. It typically **detects and reports** (and sometimes alerts); it does not necessarily block. This project is a **URL-based** IDS: it looks at URL strings in logs/captures and flags those that match known attack patterns.

**Q2: Why URL-based only?**  
**A:** Many web attacks (SQL injection, XSS, command injection, path traversal) show up in the **URL** (query string, path). Focusing on URLs keeps the scope manageable and the rules interpretable; body and headers can be added later.

**Q3: What is the difference between this and a WAF?**  
**A:** A WAF (Web Application Firewall) usually sits in front of the application and **blocks** or modifies requests in real time. This project **does not block**; it **analyzes** offline files (CSV/PCAP) and produces a report. Its output could be used to tune a WAF or to feed a SIEM.

**Q4: Why priority-based detection (one result per URL)?**  
**A:** A single URL can match multiple rule categories (e.g. semicolon + “select” could look like both command and SQL injection). Reporting one category per URL avoids duplicate/confusing entries and gives a clear “primary” classification. Priority order (e.g. Command Injection before SQL Injection) is chosen so the more dangerous or specific class wins.

**Q5: Why SQLite and not PostgreSQL/MySQL?**  
**A:** SQLite needs no separate server or configuration; it is a single file, easy to backup and share. For a single-user or academic project it is sufficient. For multi-user or production, one would consider PostgreSQL/MySQL and connection pooling.

**Q6: Why Flask and not Django?**  
**A:** This project is API-centric (REST endpoints, file upload, no server-rendered HTML). Flask is lightweight and enough for that; Django would add more structure than needed for the current scope.

**Q7: How do you handle encoded URLs?**  
**A:** Before matching, the detector **decodes** the URL using `urllib.parse.unquote` (up to a few passes) so that patterns like `%27` (single quote) or `%2f` (slash) are recognized. The matched **pattern** and **confidence** can still reflect that encoding was present (e.g. higher confidence if raw ≠ decoded).

**Q8: What if the CSV has different column names?**  
**A:** The ingestion code looks for common names (e.g. `url`, `URL`, `request`, `path`; `ip`, `source_ip`; `timestamp`, `time`). If the CSV uses other names, the code might not find URLs unless they appear in a text-like column; for production, configurable column mapping would help.

**Q9: Why is the uploaded file deleted after processing?**  
**A:** To avoid storing sensitive log/capture data on disk and to reduce storage and privacy risk. Results are already in the database; the original file is no longer needed.

**Q10: What is “pattern_matched” in the export?**  
**A:** It is the **regex pattern string** that matched the URL (e.g. `r"'?\s*or\s*1\s*=\s*1"` for a simple SQL injection rule). It helps analysts and examiners see **which exact rule** fired for each detection.

**Q11: Can this run in real time?**  
**A:** Not in the current build. The same `detect_attack()` function could be called from a proxy or log tailer so that every request URL is analyzed as it arrives; the current app only processes uploaded files.

**Q12: How would you reduce false positives?**  
**A:** Options: tighten regex (e.g. more context), add allowlists for known-good paths, use severity/confidence thresholds, and optionally add a second layer (e.g. ML or manual review) for borderline cases.

**Q13: What is the confidence score?**  
**A:** A 0–100 value computed from (1) how many patterns in that attack category matched the URL and (2) whether the URL was encoded (suggesting obfuscation). It helps analysts prioritize which detections to review first.

**Q14: Why React for the frontend?**  
**A:** React fits dashboard-style UIs with dynamic data (stats, charts, tables, filters). Component reuse (FileUpload, Dashboard, EventsTable) keeps the code organized and maintainable.

**Q15: How do you ensure security of the application itself?**  
**A:** Current measures: file type/size validation, secure filename handling, deletion of uploads after processing. Not yet implemented: authentication, rate limiting, input sanitization for any admin features, and HTTPS in production—these would be part of future hardening.

---

*End of document. Use this for preparation with your project guide and for the external examiner viva.*
