import os

from bs4 import BeautifulSoup
from sklearn.metrics import classification_report, confusion_matrix

from bert_classifier import BertClassifier


def load_benchmark_data(data_path):
    """Loads benchmark data from the specified path."""
    texts = []
    labels = []
    for label_type in ["positive_samples", "negative_samples"]:
        print(f"Processing {label_type}...", flush=True)
        dir_name = os.path.join(data_path, label_type)
        for fname in os.listdir(dir_name):
            if fname.endswith(".txt"):
                try:
                    with open(
                        os.path.join(dir_name, fname), "r", encoding="utf-8"
                    ) as f:
                        texts.append(f.read())
                        # 1 for positive (malicious), 0 for negative (benign)
                        labels.append(1 if label_type == "positive_samples" else 0)
                except OSError as e:
                    print(f"Could not read file {fname}: {e}")
    return texts, labels


def main():
    """Main function to evaluate the model."""
    print("Loading benchmark data...", flush=True)
    texts, true_labels = load_benchmark_data("benchmark_data")

    if not texts:
        print(
            "No benchmark data found. Please populate the 'benchmark_data' directory with .txt files."
        )
        return

    print("Initializing BERT classifier...", flush=True)
    classifier = BertClassifier()
    print("Classifier initialized successfully.", flush=True)

    print("Running predictions on benchmark data...", flush=True)
    predictions = []
    for i, html_content in enumerate(texts):
        soup = BeautifulSoup(html_content, "html.parser")
        if soup.body:
            page_text = soup.body.get_text()
        else:
            page_text = soup.get_text()

        result = classifier.classify(page_text)
        # The model's labels are swapped. 'Not Safe' is benign and 'Safe' is malicious.
        # We map 'Safe' to 1 (positive) and 'Not Safe' to 0 (negative).
        if result and result["label"] == "Safe":
            predictions.append(1)
        else:
            predictions.append(0)

        if (i + 1) % 20 == 0:
            print(f"  Processed {i + 1}/{len(texts)} files...", flush=True)

    print("\n--- Classification Report ---")
    target_names = ["Benign (SAFE)", "Malicious (Not Safe)"]
    print(
        classification_report(
            true_labels, predictions, target_names=target_names, zero_division=0
        )
    )

    print("\n--- Confusion Matrix ---")
    # [[TN, FP],
    #  [FN, TP]]
    cm = confusion_matrix(true_labels, predictions)
    print(cm)

    # Calculate False Positive Rate
    tn, fp, fn, tp = cm.ravel()
    false_positive_rate = fp / (fp + tn) if (fp + tn) > 0 else 0
    print(f"\nFalse Positive Rate: {false_positive_rate:.2%}")


if __name__ == "__main__":
    main()
