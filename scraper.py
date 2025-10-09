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
import requests
from bs4 import BeautifulSoup
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from bert_classifier import BertClassifier

DB_FILE = "threats.db"

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# File handler for scraper.log
file_handler = logging.FileHandler("scraper.log")
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

# Console handler for terminal output
console_handler = logging.StreamHandler()
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)


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
                salt BLOB NOT NULL,
                explanation_path TEXT
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
                "INSERT INTO threats (timestamp, url, keywords, http_headers, article_content, raw_html, content_hash, previous_hash, is_phishing, salt, explanation_path) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
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
                    None,
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

        cur.execute(
            """
            INSERT INTO threats (timestamp, url, keywords, http_headers, article_content, raw_html, content_hash, previous_hash, is_phishing, salt, explanation_path)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                threat_data["explanation_path"],
            ),
        )
        con.commit()
        con.close()
        logger.info(f"Encrypted threat data saved to DB for URL: {threat_data['url']}")
    except sqlite3.Error as e:
        logger.error(f"Database save error: {e}")


def analyze_text(text, suspicious_keywords):
    text_lower = text.lower()
    found_keywords = [kw for kw in suspicious_keywords if kw in text_lower]
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


def process_page(response, suspicious_keywords, classifier, password):
    if not response:
        return
    url = response.url
    soup = BeautifulSoup(response.content, "html.parser")
    articles = soup.find_all("article")
    logger.info(f"Found {len(articles)} articles on {url}")

    explanations_dir = "explanations"
    os.makedirs(explanations_dir, exist_ok=True)

    for article in articles:
        article_text = article.get_text()
        logger.info(f"Processing article text: {article_text[:100]}...")
        found_keywords = analyze_text(article_text, suspicious_keywords)
        logger.info(f"Found keywords: {found_keywords}")
        if found_keywords:
            prediction = classifier.classify(article_text)
            logger.info(f"Classification result for {url}: {prediction}")
            key, salt = get_encryption_key(password)
            fernet = Fernet(key)

            explanation_path = None
            if prediction and prediction["label"] == "Not Safe":
                logger.info("Generating LIME explanation (this may take a moment)...")
                explanation = classifier.explain(article_text)
                logger.info("LIME explanation generated.")
                if explanation:
                    timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
                    explanation_filename = f"explanation_{timestamp_str}.html"
                    explanation_path = os.path.join(explanations_dir, explanation_filename)
                    explanation.save_to_file(explanation_path)
                    logger.info(f"Explanation saved to {explanation_path}")
                    explanation_list = explanation.as_list(label=1)
                    logger.info(f"LIME Explanation (Top features for 'Not Safe'): {explanation_list}")

            threat_data = {
                "timestamp": datetime.now().isoformat(),
                "url": url,
                "keywords": found_keywords,
                "http_headers": dict(response.headers),
                "article_content": article.get_text(strip=True),
                "raw_html": str(article),
                "is_phishing": prediction,
                "salt": salt,
                "explanation_path": explanation_path,
            }
            save_threat_to_db(threat_data, fernet)
            send_email_notification(threat_data)


def main():
    parser = argparse.ArgumentParser(description="Scrape websites for threats.")
    parser.add_argument(
        "--password", required=True, help="Password for database encryption."
    )
    args = parser.parse_args()

    logger.info("Scraper starting...")
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
    keywords = config.get("suspicious_keywords", [])

    classifier = BertClassifier()

    for url in urls:
        response = fetch_page(url)
        process_page(response, keywords, classifier, args.password)

    logger.info("Scraper finished.")


if __name__ == "__main__":
    main()
