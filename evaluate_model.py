import os
from sklearn.metrics import classification_report, confusion_matrix
from bert_classifier import BertClassifier

def load_benchmark_data(data_path):
    """Loads benchmark data from the specified path."""
    texts = []
    labels = []
    for label_type in ['positive_samples', 'negative_samples']:
        dir_name = os.path.join(data_path, label_type)
        for fname in os.listdir(dir_name):
            if fname.endswith('.txt'):
                with open(os.path.join(dir_name, fname), 'r', encoding='utf-8') as f:
                    texts.append(f.read())
                    # 1 for positive (malicious), 0 for negative (benign)
                    labels.append(1 if label_type == 'positive_samples' else 0)
    return texts, labels

def main():
    """Main function to evaluate the model."""
    print("Loading benchmark data...")
    texts, true_labels = load_benchmark_data('benchmark_data')

    if not texts:
        print("No benchmark data found. Please populate the 'benchmark_data' directory with .txt files.")
        return

    print("Initializing BERT classifier...")
    classifier = BertClassifier()

    print("Running predictions on benchmark data...")
    predictions = []
    for text in texts:
        result = classifier.classify(text)
        # The model returns 'Not Safe' for malicious and 'SAFE' for benign.
        # We map 'Not Safe' to 1 (positive) and 'SAFE' to 0 (negative).
        if result and result['label'] == 'Not Safe':
            predictions.append(1)
        else:
            predictions.append(0)

    print("\n--- Classification Report ---")
    target_names = ['Benign (SAFE)', 'Malicious (Not Safe)']
    print(classification_report(true_labels, predictions, target_names=target_names, zero_division=0))

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
