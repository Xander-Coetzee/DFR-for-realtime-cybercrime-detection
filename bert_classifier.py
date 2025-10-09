import numpy as np
from lime.lime_text import LimeTextExplainer
from transformers import pipeline


class BertClassifier:
    def __init__(self):
        self.classifier = pipeline(
            "text-classification",
            model="shogun-the-great/finetuned-bert-phishing-site-classification",
            framework="pt",  # Use PyTorch
        )
        # The model's labels are {'Not Safe': 1, 'SAFE': 0}
        self.explainer = LimeTextExplainer(class_names=["SAFE", "Not Safe"])

    def predictor(self, texts):
        try:
            # The pipeline returns a list of dicts, e.g., [{'label': 'Not Safe', 'score': 0.9...}]
            predictions = self.classifier(texts, truncation=True, max_length=512)
            probs = []
            for p in predictions:
                # LIME expects probabilities for each class, e.g., [P(SAFE), P(Not Safe)]
                if p["label"] == "Not Safe":
                    probs.append([1 - p["score"], p["score"]])
                else:  # SAFE
                    probs.append([p["score"], 1 - p["score"]])
            return np.array(probs)
        except Exception as e:
            print(f"Error during prediction for LIME: {e}")
            return np.array([[0.5, 0.5]] * len(texts))

    def classify(self, text):
        """
        Classifies the given text.
        """
        if not text:
            return {"label": "SAFE", "score": 1.0}

        try:
            results = self.classifier(text, truncation=True, max_length=512)
            return results[0] if results else None
        except Exception as e:
            print(f"Error during classification: {e}")
            return None

    def explain(self, text):
        """
        Generates an explanation for the classification of the given text.
        """
        if not text:
            return None
        try:
            # We want to explain the 'Not Safe' class, which is at index 1
            # Reducing num_samples from the default of 5000 to 1000 for performance.
            explanation = self.explainer.explain_instance(
                text, self.predictor, num_features=10, labels=(1,), num_samples=1000
            )
            return explanation
        except Exception as e:
            print(f"Error during explanation: {e}")
            return None


# Example usage:
if __name__ == "__main__":
    classifier = BertClassifier()

    benign_text = "This is a regular news article about technology."
    prediction = classifier.classify(benign_text)
    print(f"Prediction for benign text: {prediction}")

    malicious_text = "Congratulations! You've won a $1,000,000 lottery. Click here to claim your prize now."
    prediction = classifier.classify(malicious_text)
    print(f"Prediction for malicious text: {prediction}")

    if prediction and prediction["label"] == "Not Safe":
        explanation = classifier.explain(malicious_text)
        if explanation:
            explanation.save_to_file("explanation.html")
            print("Explanation saved to explanation.html")
            print(explanation.as_list(label=1))
