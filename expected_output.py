"""
Run this to get the EXPECTED output when you upload test_data.csv and test_traffic.pcap.
Usage (from project root):  python expected_output.py

Uses the same backend logic (DataIngestion + detector.detect_attack) as the running app.
One URL produces at most one detection (priority-based).
"""
import sys
from pathlib import Path
from collections import defaultdict

root = Path(__file__).resolve().parent
sys.path.insert(0, str(root / "backend"))

from data_ingestion import DataIngestion
from detector import detect_attack


def process_file(filepath: Path, file_type: str, ingestion: DataIngestion):
    """Process one file and return (urls_list, detections_list). One detection per URL."""
    urls = ingestion.process_file(str(filepath), file_type)
    detections = []
    for u in urls:
        url = u.get("url", "")
        attack = detect_attack(url)
        if attack:
            detections.append({
                "url": url[:80] + ("..." if len(url) > 80 else ""),
                "source_ip": u.get("source_ip", "Unknown"),
                "attack_type": attack["attack_type"],
                "severity": attack["severity"],
            })
    return urls, detections


def main():
    csv_path = root / "test_data.csv"
    pcap_path = root / "test_traffic.pcap"

    ingestion = DataIngestion()

    def summarize(name: str, urls: list, detections: list):
        by_type = defaultdict(int)
        by_severity = defaultdict(int)
        for d in detections:
            by_type[d["attack_type"]] += 1
            by_severity[d["severity"]] += 1
        print(f"\n{'='*60}")
        print(f"  EXPECTED OUTPUT: {name}")
        print(f"{'='*60}")
        print(f"  Total URLs processed:     {len(urls)}")
        print(f"  Total detections:        {len(detections)}")
        print(f"\n  By attack type:")
        for k in sorted(by_type.keys()):
            print(f"    - {k}: {by_type[k]}")
        print(f"\n  By severity:")
        for k in sorted(by_severity.keys()):
            print(f"    - {k}: {by_severity[k]}")
        print()
        return by_type, by_severity

    if not csv_path.exists():
        print(f"File not found: {csv_path}")
        print("Run: python generate_test_data.py")
        return
    urls_csv, det_csv = process_file(csv_path, "csv", ingestion)
    summarize("test_data.csv", urls_csv, det_csv)

    if not pcap_path.exists():
        print(f"File not found: {pcap_path}")
        print("Run: python generate_test_data.py (PCAP may fail on some systems)")
    else:
        urls_pcap, det_pcap = process_file(pcap_path, "pcap", ingestion)
        summarize("test_traffic.pcap", urls_pcap, det_pcap)

    print("\n" + "="*60)
    print("  HOW TO MATCH WHEN TESTING")
    print("="*60)
    print("  1. Upload the file in the dashboard.")
    print("  2. Check the success message: total_urls and detected_attacks.")
    print("  3. On Dashboard: Total Detections and pie chart should match")
    print("     the 'Total detections' and 'By attack type' above.")
    print("  4. Events table row count = Total detections.")
    print("  5. Filter by attack type and compare counts.")
    print()


if __name__ == "__main__":
    main()
