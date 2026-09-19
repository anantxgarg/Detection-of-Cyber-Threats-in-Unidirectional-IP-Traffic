import joblib
import pandas as pd
import numpy as np
import math
import re
from scipy.sparse import hstack
import json
import os

# Get the folder where dga_detector.py is located
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Paths to saved model files
MODEL_PATH = os.path.join(BASE_DIR, "combined_dga_model.pkl")
VECTORIZER_PATH = os.path.join(BASE_DIR, "ngram_vectorizer.pkl")

# Load the trained model
combined_model = joblib.load(MODEL_PATH)

# Load the fitted n-gram vectorizer
vectorizer = joblib.load(VECTORIZER_PATH)

print("DGA model loaded successfully!")
print("N-gram vectorizer loaded successfully!")

FEATURE_COLUMNS = [
    "domain_length",
    "num_labels",
    "longest_label_length",
    "entropy",
    "digit_ratio",
    "vowel_ratio",
    "hyphen_ratio",
    "unique_character_ratio",
    "max_consecutive_consonants"
]


def preprocess_domain(domain):
    """
    Clean and normalize the input domain.
    """
    domain = str(domain).lower().strip()
    domain = re.sub(r"^https?://", "", domain)
    domain = domain.split("/")[0]
    return domain


def calculate_entropy(domain):
    """
    Calculate Shannon entropy of the domain.
    """
    if not domain:
        return 0

    counts = {}

    for char in domain:
        counts[char] = counts.get(char, 0) + 1

    entropy = 0

    for count in counts.values():
        probability = count / len(domain)
        entropy -= probability * math.log2(probability)

    return entropy


def calculate_digit_ratio(domain):
    """
    Calculate the ratio of digits in the domain.
    """
    if not domain:
        return 0

    digit_count = sum(char.isdigit() for char in domain)

    return digit_count / len(domain)


def calculate_vowel_ratio(domain):
    """
    Calculate the ratio of vowels in the domain.
    """
    if not domain:
        return 0

    vowels = "aeiou"
    vowel_count = sum(char in vowels for char in domain)

    return vowel_count / len(domain)


def calculate_hyphen_ratio(domain):
    """
    Calculate the ratio of hyphens in the domain.
    """
    if not domain:
        return 0

    hyphen_count = domain.count("-")

    return hyphen_count / len(domain)


def calculate_unique_character_ratio(domain):
    """
    Calculate the ratio of unique characters.
    """
    if not domain:
        return 0

    return len(set(domain)) / len(domain)


def calculate_max_consecutive_consonants(domain):
    """
    Find the maximum number of consecutive consonants.
    """
    vowels = "aeiou"

    max_count = 0
    current_count = 0

    for char in domain:
        if char.isalpha() and char not in vowels:
            current_count += 1
            max_count = max(max_count, current_count)
        else:
            current_count = 0

    return max_count




def extract_handcrafted_features(domain):
    """
    Extract the same 9 handcrafted features
    used while training the model.
    """

    # Preprocess domain first
    clean_domain = preprocess_domain(domain)

    # Split domain into labels
    labels = clean_domain.split(".")

    # Create features in the EXACT SAME ORDER
    features = {
        "domain_length": len(clean_domain),

        "num_labels": len(labels),

        "longest_label_length": max(
            len(label) for label in labels
        ) if labels else 0,

        "entropy": calculate_entropy(clean_domain),

        "digit_ratio": calculate_digit_ratio(clean_domain),

        "vowel_ratio": calculate_vowel_ratio(clean_domain),

        "hyphen_ratio": calculate_hyphen_ratio(clean_domain),

        "unique_character_ratio": calculate_unique_character_ratio(
            clean_domain
        ),

        "max_consecutive_consonants":
            calculate_max_consecutive_consonants(clean_domain)
    }

    return features

def get_suspicion_level(dga_score):

    if dga_score < 0.30:
        return "Low"

    elif dga_score < 0.70:
        return "Medium"

    else:
        return "High"


def detect_dga(domain, context=None):
    """
    Analyze a domain using the trained DGA detection model.
    """

    # 1. Preprocess the incoming domain
    clean_domain = preprocess_domain(domain)

    # 2. Extract the 9 handcrafted features
    handcrafted_features = extract_handcrafted_features(clean_domain)

    # Convert dictionary values into a DataFrame
    handcrafted_df = pd.DataFrame(
      [handcrafted_features],
      columns=FEATURE_COLUMNS
    )

    # 3. Extract character n-gram features
    ngram_features = vectorizer.transform(
        [clean_domain]
    )

    # 4. Combine n-gram + handcrafted features
    combined_features = hstack([
        ngram_features,
        handcrafted_df
    ])

    # 5. Get prediction
    prediction = combined_model.predict(
        combined_features
    )[0]

    # 6. Get probability scores
    probabilities = combined_model.predict_proba(
        combined_features
    )[0]

    # Class 1 = DGA
    dga_score = float(probabilities[1])

    suspicion_level = get_suspicion_level(dga_score)

    # Convert numeric prediction into readable output
    prediction_label = (
        "DGA" if prediction == 1 else "Legit"
    )

    if context is None:
        context = {}

    return {
        "detector_name": "DGA_Detector",

        "entity": {
            "type": "domain",
            "value": clean_domain
        },

        "result": {
            "prediction": prediction_label,
            "dga_score": dga_score,
            "suspicion_level": suspicion_level
        },

        "evidence": {
            "features": handcrafted_features
        },

        "context": context
    }   



if __name__ == "__main__":

    test_domains = [
        "google.com",
        "mokaaldobcfkafbf.com",
        "xj7qk9mzab.com"
    ]

    for domain in test_domains:
        result = detect_dga(domain)

        print("\n" + "=" * 50)
        print(json.dumps(result, indent=4))