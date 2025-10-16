# Real-time Phishing Detection with Deep Feature Representation

## Project Overview

This project is a real-time phishing detection system designed for academic research. It actively scrapes websites, analyzes their content for phishing-related keywords, and uses a fine-tuned BERT transformer model to classify the content as safe or malicious. The findings are stored in a secure, encrypted SQLite database that features a blockchain-inspired hash chain for data integrity.

The system also includes a comprehensive framework for evaluating the model's performance, including scripts to automatically gather a benchmark dataset and calculate key efficacy metrics such as Precision, Recall, F1-Score, and False Positive Rate.

### Core Components:

- **Web Scraper (`scraper.py`):** The main application that takes a list of URLs, fetches their content, and orchestrates the analysis and storage process.
- **BERT Classifier (`bert_classifier.py`):** A class that wraps a pre-trained BERT model from Hugging Face (`shogun-the-great/finetuned-bert-phishing-site-classification`) to perform the core classification task.
- **Encrypted Database (`threats.db`):** A SQLite database where findings are stored. All sensitive data is encrypted, and each entry is linked to the previous one via a content hash, ensuring a verifiable chain of evidence.
- **Evaluation Framework:**
  - **`gather_samples.py`:** A script to automatically download hundreds of verified phishing (from PhishTank) and benign (from the Tranco top sites list) web pages to build a benchmark dataset.
  - **`evaluate_model.py`:** A script that runs the classifier against the benchmark dataset and generates a detailed performance report with key academic metrics.
- **Test Server (`test_website/app.py`):** A simple Flask web application that serves local pages with varying threat levels for testing purposes.

## Building and Running

### 1. Installation

First, install the required Python packages from the `requirements.txt` file. It is recommended to do this in a virtual environment.

```bash
pip install -r requirements.txt
```

The scraper also requires NLTK data, which will be downloaded automatically on the first run.

### 2. Running the Scraper

The system has two main parts that should be run in separate terminals: the test web server and the scraper.

**A. Start the Test Web Server:**

This server provides local web pages for quick tests.

```bash
python test_website/app.py
```

**B. Run the Scraper:**

The scraper requires a password to be provided via the command line. This password is used to generate the encryption key for the database.

```bash
python scraper.py --password YOUR_SECRET_PASSWORD
```

### 3. Verifying the Database

After the scraper has run, you can verify the integrity of the database's hash chain and decrypt its contents using the `verify_db.py` script.

```bash
python verify_db.py --password YOUR_SECRET_PASSWORD
```

## Model Evaluation

The project includes a framework for robust, academic-style model evaluation.

### 1. Gather Benchmark Data

Before evaluating, you need to download a dataset of positive and negative samples.

1.  **Download PhishTank Data:** Get the latest verified phishing URLs from [https://data.phishtank.com/data/online-valid.csv.gz](https://data.phishtank.com/data/online-valid.csv.gz). Unzip it and place the `online-valid.csv` file in the project root.
2.  **Download Tranco Data:** Get a top sites list from [https://tranco-list.eu/](https://tranco-list.eu/). Place the CSV file in the project root.
3.  **Run the Script:** Execute the `gather_samples.py` script. Make sure the CSV filenames in the script match the ones you downloaded.

```bash
python gather_samples.py
```

### 2. Run Evaluation

Once you have a populated `benchmark_data` directory, you can run the evaluation script:

```bash
python evaluate_model.py
```

This will output a classification report with Precision, Recall, F1-Score, and the False Positive Rate.

## Development Conventions

- **Linting:** The project appears to use `ruff` for linting, as indicated by the `.ruff_cache` directory.
- **Logging:** The application uses multiple log files for different purposes:
    - `scraper.log`: General operational messages.
    - `metrics.log`: Performance data (CPU/memory usage, latency, etc.).
    - `keyword_effectiveness.log`: Analysis of which keywords are most effective.
- **Security:** All sensitive data in `threats.db` is encrypted at rest. The database cannot be read without the correct password.
- **Data Integrity:** The database uses a content hash and a previous hash to create a verifiable chain of entries, making it possible to detect tampering.
