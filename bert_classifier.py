from transformers import pipeline

class BertClassifier:
    def __init__(self):
        self.classifier = pipeline(
            "text-classification",
            model="shogun-the-great/finetuned-bert-phishing-site-classification",
            framework="pt"  # Use PyTorch
        )

    def classify(self, text):
        """
        Classifies the given text as phishing or not.
        """
        if not text:
            return {"label": "SAFE", "score": 1.0} # Or handle as an error

        # The model expects a certain input length, truncation is handled by the pipeline
        try:
            results = self.classifier(text, truncation=True, max_length=512)
            # The pipeline returns a list of dictionaries
            return results[0] if results else None
        except Exception as e:
            print(f"Error during classification: {e}")
            return None

# Example usage:
if __name__ == '__main__':
    classifier = BertClassifier()
    
    # Example with a benign text
    benign_text = "This is a regular news article about technology."
    prediction = classifier.classify(benign_text)
    print(f"Prediction for benign text: {prediction}")

    # Example with a potentially malicious text
    malicious_text = "Congratulations! You've won a $1,000,000 lottery. Click here to claim your prize now."
    prediction = classifier.classify(malicious_text)
    print(f"Prediction for malicious text: {prediction}")
