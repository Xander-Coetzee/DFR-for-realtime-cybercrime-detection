# gather_samples.py
import csv
import hashlib
import os
import time

import requests

# --- Configuration ---
# PhishTank CSV can be downloaded from: https://data.phishtank.com/data/online-valid.csv.gz
PHISHTANK_CSV = "verified_online.csv"

# Tranco top sites list can be downloaded from: https://tranco-list.eu/
TRANCO_CSV = "tranco_7NZVX.csv"  # <-- IMPORTANT: Change to your Tranco file name

POSITIVE_DIR = "benchmark_data/positive_samples"
NEGATIVE_DIR = "benchmark_data/negative_samples"
NUM_POSITIVE_SAMPLES = 500
NUM_NEGATIVE_SAMPLES = 500


def setup_directories():
    os.makedirs(POSITIVE_DIR, exist_ok=True)
    os.makedirs(NEGATIVE_DIR, exist_ok=True)


def download_html(url, save_path):
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        }
        response = requests.get(url, headers=headers, timeout=10, allow_redirects=True)
        if response.status_code == 200 and response.text:
            with open(save_path, "w", encoding="utf-8", errors="ignore") as f:
                f.write(response.text)
            print(f"  [SUCCESS] Saved {url}")
            return True
        else:
            print(f"  [FAILED] Status {response.status_code} for {url}")
            return False
    except requests.exceptions.RequestException as e:
        print(f"  [ERROR] Could not download {url}: {e}")
        return False
    except Exception as e:
        print(f"  [UNEXPECTED ERROR] for {url}: {e}")
        return False


def gather_positive_samples():
    print("\n--- Gathering Positive Samples (Phishing) ---")
    if not os.path.exists(PHISHTANK_CSV):
        print(f"ERROR: PhishTank file '{PHISHTANK_CSV}' not found.")
        print(
            "Please download it from https://data.phishtank.com/data/online-valid.csv.gz"
        )
        return
    count = 0
    with open(PHISHTANK_CSV, "r", encoding="utf-8") as f:
        reader = csv.reader(f)
        next(reader)  # Skip header row
        for row in reader:
            if count >= NUM_POSITIVE_SAMPLES:
                break
            url = row[1]
            filename = hashlib.md5(url.encode()).hexdigest() + ".txt"
            save_path = os.path.join(POSITIVE_DIR, filename)
            print(f"Processing ({count + 1}/{NUM_POSITIVE_SAMPLES}): {url}")
            if download_html(url, save_path):
                count += 1
            time.sleep(0.5)


def gather_negative_samples():
    print("\n--- Gathering Negative Samples (Benign) ---")
    if not os.path.exists(TRANCO_CSV):
        print(f"ERROR: Tranco file '{TRANCO_CSV}' not found.")
        print("Please download a top sites list from https://tranco-list.eu/")
        return
    count = 0
    with open(TRANCO_CSV, "r", encoding="utf-8") as f:
        reader = csv.reader(f)
        for row in reader:
            if count >= NUM_NEGATIVE_SAMPLES:
                break
            domain = row[1]
            # Try HTTPS first, then HTTP
            urls_to_try = [f"https://{domain}", f"http://{domain}"]
            filename = hashlib.md5(domain.encode()).hexdigest() + ".txt"
            save_path = os.path.join(NEGATIVE_DIR, filename)

            success = False
            for url in urls_to_try:
                print(f"Processing ({count + 1}/{NUM_NEGATIVE_SAMPLES}): {url}")
                if download_html(url, save_path):
                    count += 1
                    success = True
                    break  # Move to the next domain if download succeeds

            if success:
                time.sleep(0.5)


if __name__ == "__main__":
    setup_directories()
    gather_positive_samples()
    gather_negative_samples()
    print("\n--- Sample Gathering Complete! ---")
