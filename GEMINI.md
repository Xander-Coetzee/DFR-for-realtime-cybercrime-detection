# Project: Real-time Phishing Detection with Deep Feature Representation

## Project Overview

This project is a real-time phishing detection system. It actively scrapes specified websites, analyzes their content for phishing-related keywords, and uses a BERT-based transformer model to classify the content as safe or malicious.

The core components are:
- **Web Scraper (`scraper.py`):** A Python script that fetches content from URLs defined in `config.json`. It uses BeautifulSoup for parsing HTML and a custom BERT classifier for analysis.
- **BERT Classifier (`bert_classifier.py`):** A class that wraps a fine-tuned BERT model from Hugging Face (`shogun-the-great/finetuned-bert-phishing-site-classification`) to perform text classification.
- **Encrypted Database (`threats.db`):** A SQLite database where findings are stored. Key fields in the database are encrypted using a password-derived key. The database also implements a blockchain-like chain of evidence by linking each new entry to the hash of the previous one.
- **Flask Web Server (`test_website/app.py`):** A simple web application that serves as a testbed for the scraper. It contains pages with varying levels of threat indicators.
- **Configuration (`config.json`):** A JSON file that specifies the target URLs to scrape and the phishing-related keywords to search for.

The system is designed with security and auditability in mind, featuring encryption at rest for sensitive data and a chained-hash mechanism to ensure the integrity of the collected evidence. It also performs detailed logging of its operations and performance metrics.

## Key Files

- `scraper.py`: The main script for scraping and analyzing web pages.
- `bert_classifier.py`: Contains the logic for classifying text using the BERT model.
- `test_website/app.py`: A Flask application to serve test pages.
- `config.json`: Configuration file for the scraper, including URLs and keywords.
- `requirements.txt`: A list of Python dependencies for the project.
- `threats.db`: The SQLite database where threat data is stored (will be created on first run).
- `metrics.log`: Logs performance metrics like CPU/memory usage, latency, and data reduction ratios.
- `scraper.log`: Logs the operational details of the scraper script.
- `verify_db.py`: A script to verify the integrity of the database chain.

## Building and Running

### 1. Installation

First, install the required Python packages from the `requirements.txt` file. It is recommended to do this in a virtual environment.

```bash
pip install -r requirements.txt
```

The scraper also requires NLTK data. This will be downloaded automatically on the first run of the scraper.

### 2. Running the System

The system has two main parts: the test web server and the scraper. You should run them in separate terminals.

**A. Start the Test Web Server:**

This server provides the local web pages that the scraper will analyze by default.

```bash
python test_website/app.py
```
The web server will start on `http://127.0.0.1:5000`.

**B. Run the Scraper:**

The scraper requires a password to be provided via the command line. This password is used to generate the encryption key for the database. **Choose a secure password.**

```bash
python scraper.py --password YOUR_SECRET_PASSWORD
```

The scraper will then fetch the URLs from `config.json`, analyze them, and store any findings in the `threats.db` database.

### 3. Verifying the Database

After the scraper has run, you can verify the integrity of the database chain using the `verify_db.py` script. This script also requires the password used for encryption.

```bash
python verify_db.py --password YOUR_SECRET_PASSWORD
```

## Development Conventions

- **Linting:** The project appears to use `ruff` for linting, as indicated by the `.ruff_cache` directory.
- **Logging:** The application uses two separate loggers:
    - A general logger for operational messages, which outputs to both the console and `scraper.log`.
    - A metrics logger for performance data, which outputs to both the console and `metrics.log`.
- **Encryption:** All sensitive data stored in `threats.db` is encrypted. The encryption key is derived from the password provided at runtime. This means the database cannot be read without the correct password.
- **Data Integrity:** The database uses a content hash and a previous hash to create a chain of entries, making it possible to detect tampering.
