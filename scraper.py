import argparse
import base64
import hashlib
import json
import logging
import os
import sqlite3
import time
from datetime import datetime

import nltk
import psutil
import requests
from bs4 import BeautifulSoup
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from bert_classifier import BertClassifier

DB_FILE = "threats.db"


# General logger

logger = logging.getLogger(__name__)

logger.setLevel(logging.INFO)


# Metrics logger

metrics_logger = logging.getLogger("metrics")

metrics_logger.setLevel(logging.INFO)


# File handler for scraper.log

file_handler = logging.FileHandler("scraper.log")

formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")

file_handler.setFormatter(formatter)

logger.addHandler(file_handler)


# File handler for metrics.log

metrics_file_handler = logging.FileHandler("metrics.log")

metrics_file_handler.setFormatter(formatter)

metrics_logger.addHandler(metrics_file_handler)


# Console handler for terminal output

console_handler = logging.StreamHandler()

console_handler.setFormatter(formatter)

logger.addHandler(console_handler)

metrics_logger.addHandler(console_handler)


# Keyword effectiveness logger

keyword_logger = logging.getLogger("keyword_effectiveness")

keyword_logger.setLevel(logging.INFO)

keyword_file_handler = logging.FileHandler("keyword_effectiveness.log")

keyword_file_handler.setFormatter(formatter)

keyword_logger.addHandler(keyword_file_handler)

keyword_logger.addHandler(console_handler)


def log_resource_usage(stage="default"):
    process = psutil.Process(os.getpid())

    memory_info = process.memory_info()

    cpu_percent = psutil.cpu_percent(interval=1)

    metrics_logger.info(
        f"ResourceUsage - Stage: {stage}, CPU: {cpu_percent}%, Memory: {memory_info.rss / 1024 / 1024:.2f} MB"
    )


def get_encryption_key(password, salt=None):
    if not password:
        raise ValueError("A password is required for encryption.")
    if salt is None:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key, salt


def init_db():
    try:
        con = sqlite3.connect(DB_FILE)
        cur = con.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS threats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                url TEXT NOT NULL,
                keywords TEXT, -- Encrypted
                http_headers TEXT, -- Encrypted
                article_content TEXT, -- Encrypted
                raw_html TEXT, -- Encrypted
                content_hash TEXT NOT NULL,
                previous_hash TEXT,
                is_phishing TEXT, -- Encrypted
                salt BLOB NOT NULL
            )
        """)
        cur.execute("SELECT COUNT(*) FROM threats")
        if cur.fetchone()[0] == 0:
            genesis_hash = "00" * 32
            salt = b"\x00" * 16
            # Since we don't have a fernet object here, we can't encrypt.
            # We will store placeholder values for the encrypted fields.
            encrypted_keywords = b"[]"
            encrypted_headers = b"{}"
            encrypted_content = b""
            encrypted_raw_html = b""
            encrypted_is_phishing = b""
            cur.execute(
                "INSERT INTO threats (timestamp, url, keywords, http_headers, article_content, raw_html, content_hash, previous_hash, is_phishing, salt) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    datetime.now().isoformat(),
                    "genesis",
                    encrypted_keywords,
                    encrypted_headers,
                    encrypted_content,
                    encrypted_raw_html,
                    genesis_hash,
                    "0" * 64,
                    encrypted_is_phishing,
                    salt,
                ),
            )
        con.commit()
        con.close()
        logger.info(f"Database '{DB_FILE}' initialized successfully.")
    except sqlite3.Error as e:
        logger.error(f"Database initialization error: {e}")
        raise


def download_nltk_data():
    try:
        nltk.data.find("tokenizers/punkt")
    except LookupError:
        nltk.download("punkt")
    try:
        nltk.data.find("corpora/stopwords")
    except LookupError:
        nltk.download("stopwords")


def load_config():
    try:
        with open("config.json", "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return None


def send_email_notification(threat_data):
    pass  # Not relevant for this test


def save_threat_to_db(threat_data, fernet):
    try:
        con = sqlite3.connect(DB_FILE)
        cur = con.cursor()

        cur.execute("SELECT content_hash FROM threats ORDER BY id DESC LIMIT 1")
        last_hash = cur.fetchone()[0]

        raw_html_bytes = threat_data["raw_html"].encode("utf-8")
        content_hash = hashlib.sha256(raw_html_bytes).hexdigest()

        encrypted_keywords = fernet.encrypt(
            json.dumps(threat_data["keywords"]).encode()
        )
        encrypted_headers = fernet.encrypt(
            json.dumps(threat_data["http_headers"]).encode()
        )
        encrypted_content = fernet.encrypt(threat_data["article_content"].encode())
        encrypted_raw_html = fernet.encrypt(raw_html_bytes)
        encrypted_is_phishing = fernet.encrypt(
            json.dumps(threat_data["is_phishing"]).encode()
        )

        # Data Reduction Ratio Calculation
        original_size = len(raw_html_bytes)
        stored_size = (
            len(encrypted_keywords)
            + len(encrypted_headers)
            + len(encrypted_content)
            + len(encrypted_raw_html)
            + len(encrypted_is_phishing)
        )
        reduction_ratio = (
            (1 - (stored_size / original_size)) * 100 if original_size > 0 else 0
        )
        metrics_logger.info(
            f"DataReduction - URL: {threat_data['url']}, Original Size: {original_size} bytes, Stored Size: {stored_size} bytes, Reduction: {reduction_ratio:.2f}%"
        )

        cur.execute(
            """
            INSERT INTO threats (timestamp, url, keywords, http_headers, article_content, raw_html, content_hash, previous_hash, is_phishing, salt)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (
                threat_data["timestamp"],
                threat_data["url"],
                encrypted_keywords,
                encrypted_headers,
                encrypted_content,
                encrypted_raw_html,
                content_hash,
                last_hash,
                encrypted_is_phishing,
                threat_data["salt"],
            ),
        )
        con.commit()
        con.close()
        logger.info(f"Encrypted threat data saved to DB for URL: {threat_data['url']}")
    except sqlite3.Error as e:
        logger.error(f"Database save error: {e}")


def analyze_text(text, suspicious_keywords):
    text_lower = text.lower()
    found_keywords = []
    if isinstance(suspicious_keywords, dict):
        for category, keywords in suspicious_keywords.items():
            for keyword in keywords:
                if keyword in text_lower:
                    found_keywords.append(keyword)
    return found_keywords


def fetch_page(url, max_retries=3, backoff_factor=2):
    retries = 0
    delay = 1
    while retries < max_retries:
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            return response
        except requests.exceptions.RequestException:
            time.sleep(delay)
            retries += 1
            delay *= backoff_factor
    return None


def process_page(response, suspicious_keywords, classifier, password, keyword_stats):
    page_start_time = time.time()
    if not response:
        return
    url = response.url
    soup = BeautifulSoup(response.content, "html.parser")
    articles = soup.find_all("article")
    logger.info(f"Found {len(articles)} articles on {url}")

    for article in articles:
        article_text = article.get_text()
        logger.info(f"Processing article text: {article_text[:100]}...")
        found_keywords = analyze_text(article_text, suspicious_keywords)
        logger.info(f"Found keywords: {found_keywords}")
        if found_keywords:
            prediction = classifier.classify(article_text)
            logger.info(f"Classification result for {url}: {prediction}")

            # Update keyword_stats
            for keyword in found_keywords:
                if keyword in keyword_stats:
                    keyword_stats[keyword]["found_count"] += 1
                    if prediction and prediction["label"] == "Not Safe":
                        keyword_stats[keyword]["notsafe_count"] += 1

            key, salt = get_encryption_key(password)
            fernet = Fernet(key)

            threat_data = {
                "timestamp": datetime.now().isoformat(),
                "url": url,
                "keywords": found_keywords,
                "http_headers": dict(response.headers),
                "article_content": article.get_text(strip=True),
                "raw_html": str(article),
                "is_phishing": prediction,
                "salt": salt,
                "explanation_path": None,
            }
            save_threat_to_db(threat_data, fernet)
            send_email_notification(threat_data)

            page_end_time = time.time()
            latency = page_end_time - page_start_time
            metrics_logger.info(f"Latency - URL: {url}, Latency: {latency:.2f}s")
            log_resource_usage(f"process_page_{url}")


def main():
    parser = argparse.ArgumentParser(description="Scrape websites for threats.")

    parser.add_argument(
        "--password", required=True, help="Password for database encryption."
    )

    args = parser.parse_args()

    logger.info("Scraper starting...")

    log_resource_usage("main_start")

    start_time = time.time()

    try:
        get_encryption_key(args.password)

    except ValueError as e:
        logger.error(e)

        return

    init_db()

    download_nltk_data()

    config = load_config()

    if not config:
        return

    urls = config.get("urls_to_scrape", [])

    keywords = config.get("phishing_keywords", {})
    all_keywords = [kw for sublist in keywords.values() for kw in sublist]
    keyword_stats = {kw: {"found_count": 0, "notsafe_count": 0} for kw in all_keywords}

    total_urls = len(urls)

    successful_scrapes = 0

    classifier = BertClassifier()

    for url in urls:
        response = fetch_page(url)

        if response:
            successful_scrapes += 1

            process_page(response, keywords, classifier, args.password, keyword_stats)

    end_time = time.time()

    total_time = end_time - start_time

    throughput = total_urls / total_time if total_time > 0 else 0

    success_rate = (successful_scrapes / total_urls) * 100 if total_urls > 0 else 0

    metrics_logger.info(
        f"OverallStats - Total Time: {total_time:.2f}s, Throughput: {throughput:.2f} pages/s, Success Rate: {success_rate:.2f}%"
    )

    # Keyword Effectiveness Analysis
    keyword_logger.info("Keyword Effectiveness Analysis:")
    effectiveness = {}
    for keyword, stats in keyword_stats.items():
        if stats["found_count"] > 0:
            effectiveness[keyword] = (
                stats["notsafe_count"] / stats["found_count"]
            ) * 100
        else:
            effectiveness[keyword] = 0

    sorted_effectiveness = sorted(
        effectiveness.items(), key=lambda item: item[1], reverse=True
    )

    for keyword, eff in sorted_effectiveness:
        stats = keyword_stats[keyword]
        keyword_logger.info(
            f'- Keyword: "{keyword}"\n'
            f"  - Effectiveness: {eff:.2f}%\n"
            f"  - Found Count: {stats['found_count']}\n"
            f"  - 'Not Safe' Count: {stats['notsafe_count']}"
        )

    log_resource_usage("main_end")

    logger.info("Scraper finished.")


if __name__ == "__main__":
    main()
