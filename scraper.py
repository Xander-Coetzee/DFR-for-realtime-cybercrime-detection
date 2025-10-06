import requests
from bs4 import BeautifulSoup
import json
from datetime import datetime
import smtplib
import os
import nltk
from nltk.tokenize import word_tokenize
from nltk.stem import PorterStemmer
from nltk.corpus import stopwords
import logging
import time
import sqlite3
import hashlib
import base64
import argparse
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from bert_classifier import BertClassifier

DB_FILE = "threats.db"

logging.basicConfig(filename='scraper.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def get_encryption_key(password):
    if not password:
        raise ValueError("A password is required for encryption.")
    salt = b'\x00' * 16
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

def init_db(fernet):
    try:
        con = sqlite3.connect(DB_FILE)
        cur = con.cursor()
        cur.execute('''
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
                is_phishing TEXT -- Encrypted
            )
        ''')
        cur.execute("SELECT COUNT(*) FROM threats")
        if cur.fetchone()[0] == 0:
            genesis_hash = '00' * 32
            encrypted_keywords = fernet.encrypt(b"[]")
            encrypted_headers = fernet.encrypt(b"{}")
            encrypted_content = fernet.encrypt(b"")
            encrypted_raw_html = fernet.encrypt(b"")
            encrypted_is_phishing = fernet.encrypt(b"")
            cur.execute("INSERT INTO threats (timestamp, url, keywords, http_headers, article_content, raw_html, content_hash, previous_hash, is_phishing) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (datetime.now().isoformat(), "genesis", encrypted_keywords, encrypted_headers, encrypted_content, encrypted_raw_html, genesis_hash, '0' * 64, encrypted_is_phishing))
        con.commit()
        con.close()
        logging.info(f"Database '{DB_FILE}' initialized successfully.")
    except sqlite3.Error as e:
        logging.error(f"Database initialization error: {e}")
        raise

def download_nltk_data():
    try:
        nltk.data.find('tokenizers/punkt')
    except LookupError:
        nltk.download('punkt')
    try:
        nltk.data.find('corpora/stopwords')
    except LookupError:
        nltk.download('stopwords')

def load_config():
    try:
        with open('config.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return None

def send_email_notification(threat_data):
    pass # Not relevant for this test

def save_threat_to_db(threat_data, fernet):
    try:
        con = sqlite3.connect(DB_FILE)
        cur = con.cursor()

        cur.execute("SELECT content_hash FROM threats ORDER BY id DESC LIMIT 1")
        last_hash = cur.fetchone()[0]

        raw_html_bytes = threat_data['raw_html'].encode('utf-8')
        content_hash = hashlib.sha256(raw_html_bytes).hexdigest()
        
        encrypted_keywords = fernet.encrypt(json.dumps(threat_data['keywords']).encode())
        encrypted_headers = fernet.encrypt(json.dumps(threat_data['http_headers']).encode())
        encrypted_content = fernet.encrypt(threat_data['article_content'].encode())
        encrypted_raw_html = fernet.encrypt(raw_html_bytes)
        encrypted_is_phishing = fernet.encrypt(json.dumps(threat_data['is_phishing']).encode())

        cur.execute("""
            INSERT INTO threats (timestamp, url, keywords, http_headers, article_content, raw_html, content_hash, previous_hash, is_phishing)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            threat_data['timestamp'],
            threat_data['url'],
            encrypted_keywords,
            encrypted_headers,
            encrypted_content,
            encrypted_raw_html,
            content_hash,
            last_hash,
            encrypted_is_phishing
        ))
        con.commit()
        con.close()
        logging.info(f"Encrypted threat data saved to DB for URL: {threat_data['url']}")
    except sqlite3.Error as e:
        logging.error(f"Database save error: {e}")

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
        except requests.exceptions.RequestException as e:
            time.sleep(delay)
            retries += 1
            delay *= backoff_factor
    return None

def process_page(response, suspicious_keywords, fernet, classifier):
    if not response:
        return
    url = response.url
    soup = BeautifulSoup(response.content, 'html.parser')
    articles = soup.find_all('article')
    logging.info(f"Found {len(articles)} articles on {url}")
    for article in articles:
        article_text = article.get_text()
        logging.info(f"Processing article text: {article_text[:100]}...")
        found_keywords = analyze_text(article_text, suspicious_keywords)
        logging.info(f"Found keywords: {found_keywords}")
        if found_keywords:
            prediction = classifier.classify(article_text)
            logging.info(f"Classification result for {url}: {prediction}")
            threat_data = {
                'timestamp': datetime.now().isoformat(),
                'url': url,
                'keywords': found_keywords,
                'http_headers': dict(response.headers),
                'article_content': article.get_text(strip=True),
                'raw_html': str(article),
                'is_phishing': prediction
            }
            save_threat_to_db(threat_data, fernet)
            send_email_notification(threat_data)

def main():
    parser = argparse.ArgumentParser(description='Scrape websites for threats.')
    parser.add_argument('--password', required=True, help='Password for database encryption.')
    args = parser.parse_args()

    logging.info("Scraper starting...")
    try:
        key = get_encryption_key(args.password)
        fernet = Fernet(key)
    except ValueError as e:
        logging.error(e)
        return

    init_db(fernet)
    download_nltk_data()
    config = load_config()
    if not config:
        return

    urls = config.get("urls_to_scrape", [])
    keywords = config.get("suspicious_keywords", [])

    classifier = BertClassifier()

    for url in urls:
        response = fetch_page(url)
        process_page(response, keywords, fernet, classifier)
    
    logging.info("Scraper finished.")

if __name__ == '__main__':
    main()
