# Expected Output for Test Files

Use this to verify your dashboard results when you upload **test_data.csv** and **test_traffic.pcap**.

---

## 1. test_data.csv

| Metric | Expected value |
|--------|----------------|
| **Total URLs processed** | 99 |
| **Total detections** | 67 |

### By attack type

| Attack type | Count |
|-------------|-------|
| Command Injection | 1 |
| Directory Traversal | 12 |
| File Inclusion | 6 |
| LDAP Injection | 3 |
| Path Traversal | 11 |
| SQL Injection | 15 |
| SSRF | 9 |
| XSS | 3 |
| XXE | 7 |

### By severity

| Severity | Count |
|----------|-------|
| High | 41 |
| Medium | 26 |

---

## 2. test_traffic.pcap

| Metric | Expected value |
|--------|----------------|
| **Total URLs processed** | 29 |
| **Total detections** | 16 |

### By attack type

| Attack type | Count |
|-------------|-------|
| Directory Traversal | 2 |
| File Inclusion | 2 |
| LDAP Injection | 1 |
| Path Traversal | 2 |
| SQL Injection | 4 |
| SSRF | 2 |
| XSS | 1 |
| XXE | 2 |

### By severity

| Severity | Count |
|----------|-------|
| High | 11 |
| Medium | 5 |

---

## How to match when testing

1. **Upload** the file in the dashboard (Upload & Analyze).
2. **Success message** should show:
   - **test_data.csv:** `total_urls: 99`, `detected_attacks: 67`
   - **test_traffic.pcap:** `total_urls: 29`, `detected_attacks: 16`
3. **Dashboard summary:**
   - “Total Detections” = 67 (after CSV) or 16 (after PCAP), or the sum if you uploaded both without clearing.
4. **Pie chart “Detections by Attack Type”** should match the “By attack type” tables above (for the file you just uploaded).
5. **Bar chart “Detections by Severity”** should match the “By severity” tables.
6. **Events table:** number of rows = total detections for the uploaded file(s).
7. **Filters:** use “Attack type” and “Source IP” and check that counts match the tables.

---

## Regenerating test files

If you run `python generate_test_data.py` again, the CSV uses random sampling, so **exact counts may change** for **test_data.csv**. To get the expected output for your current files, run:

```bash
python expected_output.py
```

That prints the expected totals and breakdown for the **current** test_data.csv and test_traffic.pcap in your project folder.
