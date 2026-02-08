"""Run this script to verify all backend Python dependencies are installed."""
import sys

REQUIRED = [
    ('flask', 'Flask'),
    ('flask_cors', 'Flask-CORS'),
    ('pandas', 'pandas'),
    ('scapy', 'scapy'),
    ('dotenv', 'python-dotenv'),
]

def main():
    missing = []
    for module_name, pip_name in REQUIRED:
        try:
            __import__(module_name)
            print(f"  OK: {pip_name}")
        except ImportError:
            print(f"  MISSING: {pip_name}")
            missing.append(pip_name)

    if missing:
        print("\nInstall missing packages with:")
        print("  pip install " + " ".join(missing))
        sys.exit(1)
    print("\nAll backend dependencies are installed.")
    return 0

if __name__ == "__main__":
    print("Checking backend dependencies...\n")
    sys.exit(main())
