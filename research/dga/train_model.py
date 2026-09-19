import pandas as pd
from sklearn.model_selection import train_test_split
from xgboost import XGBClassifier
from sklearn.metrics import accuracy_score
from sklearn.metrics import classification_report
from sklearn.metrics import confusion_matrix
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.feature_extraction.text import TfidfVectorizer
from scipy.sparse import hstack
import joblib

# Load the dataset
df = pd.read_csv(
    "data/dga_domains_sample.csv",
    header=None,
    names=["label", "source", "domain"]
)

# Show the first 5 rows
print(df.head())



def preprocess_domain(domain):
    domain = domain.strip()       # Remove spaces before/after
    domain = domain.lower()       # Convert everything to lowercase
    domain = domain.rstrip(".")   # Remove a trailing dot
    return domain

print("\nPreprocessing test:")
print(preprocess_domain("  Example.COM.  "))

# Apply preprocessing to every domain
df["clean_domain"] = df["domain"].apply(preprocess_domain)

# Show original and cleaned domains
print("\nOriginal vs Cleaned:")
print(df[["domain", "clean_domain"]].head())


def parse_domain(domain):
    return domain.split(".")

print("\nDomain parsing test:")
print(parse_domain("cvyh1po636avyrsxebwbkn7.ddns.net"))


# Extract simple domain features
df["domain_length"] = df["clean_domain"].apply(len)

df["num_labels"] = df["clean_domain"].apply(
    lambda x: len(parse_domain(x))
)

df["longest_label_length"] = df["clean_domain"].apply(
    lambda x: max(len(label) for label in parse_domain(x))
)

# Show the extracted features
print("\nSimple domain features:")
print(
    df[
        [
            "clean_domain",
            "domain_length",
            "num_labels",
            "longest_label_length"
        ]
    ].head()
)


import math
from collections import Counter

def calculate_entropy(domain):
    # Count how many times each character appears
    counts = Counter(domain)

    # Total number of characters
    length = len(domain)

    # Calculate Shannon entropy
    entropy = 0

    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy

print("\nEntropy test:")
print("google.com:", calculate_entropy("google.com"))
print("xj7qk9mzab.com:", calculate_entropy("xj7qk9mzab.com"))


# Calculate entropy for every domain
df["entropy"] = df["clean_domain"].apply(calculate_entropy)

# Show domains with their entropy
print("\nDomain entropy:")
print(df[["clean_domain", "entropy"]].head())

def calculate_digit_ratio(domain):
    if len(domain) == 0:
        return 0

    digit_count = sum(char.isdigit() for char in domain)
    return digit_count / len(domain)

print("\nDigit ratio test:")
print("google.com:", calculate_digit_ratio("google.com"))
print("abc123xyz.com:", calculate_digit_ratio("abc123xyz.com"))


# Calculate digit ratio for every domain
df["digit_ratio"] = df["clean_domain"].apply(calculate_digit_ratio)

# Show domains with their digit ratio
print("\nDomain digit ratios:")
print(df[["clean_domain", "digit_ratio"]].head())


def calculate_vowel_ratio(domain):
    letters = [char for char in domain if char.isalpha()]

    if len(letters) == 0:
        return 0

    vowels = "aeiou"
    vowel_count = sum(char in vowels for char in letters)

    return vowel_count / len(letters)

print("\nVowel ratio test:")
print("google.com:", calculate_vowel_ratio("google.com"))
print("xj7qk9mzab.com:", calculate_vowel_ratio("xj7qk9mzab.com"))


df["vowel_ratio"] = df["clean_domain"].apply(calculate_vowel_ratio)

print("\nDomain vowel ratios:")
print(df[["clean_domain", "vowel_ratio"]].head())


# Compare average feature values for DGA and legitimate domains
# A longer domain + high entropy + low vowel ratio + digits could be suspicious.
#basically creating the baseline

features = [
    "domain_length",
    "num_labels",
    "longest_label_length",
    "entropy",
    "digit_ratio",
    "vowel_ratio"
]

print("\nAverage features by label:")
print(df.groupby("label")[features].mean())



def calculate_hyphen_ratio(domain):
    if len(domain) == 0:
        return 0

    hyphen_count = domain.count("-")
    return hyphen_count / len(domain)

print("\nHyphen ratio test:")
print("google.com:", calculate_hyphen_ratio("google.com"))
print("my-test-domain.com:", calculate_hyphen_ratio("my-test-domain.com"))



df["hyphen_ratio"] = df["clean_domain"].apply(calculate_hyphen_ratio)

print("\nDomain hyphen ratios:")
print(df[["clean_domain", "hyphen_ratio"]].head())

\
def calculate_unique_character_ratio(domain):
    if len(domain) == 0:
        return 0

    unique_characters = len(set(domain))
    return unique_characters / len(domain)

print("\nUnique character ratio test:")
print("google.com:", calculate_unique_character_ratio("google.com"))
print("xj7qk9mzab.com:", calculate_unique_character_ratio("xj7qk9mzab.com"))

# Calculate unique character ratio for every domain
df["unique_character_ratio"] = df["clean_domain"].apply(
    calculate_unique_character_ratio
)

print("\nDomain unique character ratios:")
print(df[["clean_domain", "unique_character_ratio"]].head())

print("\nTotal rows with unique character ratio:")
print(df["unique_character_ratio"].count())


def max_consecutive_consonants(domain):
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

print("\nConsecutive consonants test:")
print("google.com:", max_consecutive_consonants("google.com"))
print("xjkrpt.com:", max_consecutive_consonants("xjkrpt.com"))


# Calculate maximum consecutive consonants for every domain
df["max_consecutive_consonants"] = df["clean_domain"].apply(
    max_consecutive_consonants
)

print("\nMaximum consecutive consonants:")
print(
    df[["clean_domain", "max_consecutive_consonants"]].head()
)

print("\nTotal rows with consecutive consonant values:")
print(df["max_consecutive_consonants"].count())


# Select the features for the ML model
feature_columns = [
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

# X contains the input features
X = df[feature_columns]

# y contains the correct labels
y = df["label"].map({
    "legit": 0,
    "dga": 1
})

print("\nX - Input features:")
print(X.head())

print("\ny - Labels:")
print(y.head())


# Split the dataset into training and testing data
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y
)

print("\nTraining data:")
print(X_train.shape)

print("\nTesting data:")
print(X_test.shape)

print("\nTraining label counts:")
print(y_train.value_counts())

print("\nTesting label counts:")
print(y_test.value_counts())


# Create the XGBoost model
model = XGBClassifier(
    random_state=42
)

# Train the model
model.fit(X_train, y_train)
print("\nModel training completed successfully!")


# Make predictions on unseen test data
y_pred = model.predict(X_test)

print("\nPredictions completed!")


# Calculate model accuracy
accuracy = accuracy_score(y_test, y_pred)

print("\nModel Accuracy:")
print(accuracy)


print("\nClassification Report:")
print(
    classification_report(
        y_test,
        y_pred,
        target_names=["Legit", "DGA"]
    )
)

# Create confusion matrix
cm = confusion_matrix(y_test, y_pred)

print("\nConfusion Matrix:")
print(cm)


# Create character n-gram vectorizer
vectorizer = CountVectorizer(
    analyzer="char",
    ngram_range=(2, 3)
)

# Learn character bigrams and trigrams from TRAINING domains only
X_train_ngrams = vectorizer.fit_transform(
    df.loc[X_train.index, "clean_domain"]
)


# Transform testing domains using the same learned vocabulary
X_test_ngrams = vectorizer.transform(
    df.loc[X_test.index, "clean_domain"]
)

print("\nN-gram training feature shape:")
print(X_train_ngrams.shape)

print("\nN-gram testing feature shape:")
print(X_test_ngrams.shape)

print("\nFirst 20 learned n-grams:")
print(vectorizer.get_feature_names_out()[:20])



# Create the Logistic Regression model
ngram_model = LogisticRegression(
    max_iter=1000,
    random_state=42
)

# Train the model using n-gram features
ngram_model.fit(X_train_ngrams, y_train)

print("\nN-gram Logistic Regression model training completed!")


# Make predictions using the n-gram model
y_pred_ngram = ngram_model.predict(X_test_ngrams)

print("\nN-gram predictions completed!")


#comapre the performance 
print("\nN-gram Model Accuracy:")
ngram_accuracy = accuracy_score(y_test, y_pred_ngram)
print(ngram_accuracy)

print("\nN-gram Classification Report:")
print(
    classification_report(
        y_test,
        y_pred_ngram,
        target_names=["Legit", "DGA"]
    )
)

print("\nN-gram Confusion Matrix:")
print(confusion_matrix(y_test, y_pred_ngram))


# Create TF-IDF character n-gram vectorizer
tfidf_vectorizer = TfidfVectorizer(
    analyzer="char",
    ngram_range=(2, 3)
)


# Learn n-grams and TF-IDF weights from training domains only
X_train_tfidf = tfidf_vectorizer.fit_transform(
    df.loc[X_train.index, "clean_domain"]
)

# Transform test domains using the same learned vocabulary
X_test_tfidf = tfidf_vectorizer.transform(
    df.loc[X_test.index, "clean_domain"]
)

print("\nTF-IDF training feature shape:")
print(X_train_tfidf.shape)

print("\nTF-IDF testing feature shape:")
print(X_test_tfidf.shape)


# Create Logistic Regression model for TF-IDF features
tfidf_model = LogisticRegression(
    max_iter=1000,
    random_state=42
)

# Train using TF-IDF n-gram features
tfidf_model.fit(X_train_tfidf, y_train)

print("\nTF-IDF Logistic Regression model training completed!")



# Make predictions using the TF-IDF model
y_pred_tfidf = tfidf_model.predict(X_test_tfidf)

print("\nTF-IDF predictions completed!")



print("\nTF-IDF Model Accuracy:")
tfidf_accuracy = accuracy_score(y_test, y_pred_tfidf)
print(tfidf_accuracy)

print("\nTF-IDF Classification Report:")
print(
    classification_report(
        y_test,
        y_pred_tfidf,
        target_names=["Legit", "DGA"]
    )
)

print("\nTF-IDF Confusion Matrix:")
print(confusion_matrix(y_test, y_pred_tfidf))


# Get handcrafted features for training data
X_train_handcrafted = X_train

# Get handcrafted features for testing data
X_test_handcrafted = X_test

print("\nHandcrafted training feature shape:")
print(X_train_handcrafted.shape)

print("\nHandcrafted testing feature shape:")
print(X_test_handcrafted.shape)



# Combine n-gram features with handcrafted features
X_train_combined = hstack([
    X_train_ngrams,
    X_train_handcrafted
])

X_test_combined = hstack([
    X_test_ngrams,
    X_test_handcrafted
])

print("\nCombined training feature shape:")
print(X_train_combined.shape)

print("\nCombined testing feature shape:")
print(X_test_combined.shape)


# Create Logistic Regression model for combined features
combined_model = LogisticRegression(
    max_iter=1000,
    random_state=42
)

# Train using n-grams + handcrafted features
combined_model.fit(X_train_combined, y_train)

print("\nCombined model training completed!")


# Make predictions using the combined model
y_pred_combined = combined_model.predict(X_test_combined)

print("\nCombined model predictions completed!")


print("\nCombined Model Accuracy:")
combined_accuracy = accuracy_score(y_test, y_pred_combined)
print(combined_accuracy)

print("\nCombined Classification Report:")
print(
    classification_report(
        y_test,
        y_pred_combined,
        target_names=["Legit", "DGA"]
    )
)

print("\nCombined Confusion Matrix:")
print(confusion_matrix(y_test, y_pred_combined))

# Get probability scores from the combined model
y_prob_combined = combined_model.predict_proba(X_test_combined)

print("\nFirst 5 probability outputs:")
print(y_prob_combined[:5])



# Save the best trained model
joblib.dump(combined_model, "combined_dga_model.pkl")

# Save the fitted n-gram vectorizer
joblib.dump(vectorizer, "ngram_vectorizer.pkl")

print("\nFinal model and vectorizer saved successfully!")