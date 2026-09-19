import pandas as pd

# Load dataset
df = pd.read_csv("data/dataset_final.csv")

# DNS tunnel related features
features = [
    "dns_query_length",
    "dns_query_entropy",
    "dns_subdomain_count",
    "dns_numerical_ratio",
    "src2dst_bytes",
    "dst2src_bytes",
]

# Derived feature: request/response byte ratio
df["request_response_ratio"] = (
    df["src2dst_bytes"] / (df["dst2src_bytes"] + 1)
)

features.append("request_response_ratio")

print("\n===== FEATURE ANALYSIS =====\n")

# Compare statistics for benign vs exfiltration
summary = df.groupby("label")[features].agg(
    ["mean", "median", "std"]
)

print(summary)

print("\n===== CLASS COUNTS =====")
print(df["label"].value_counts())

print("\n===== FEATURE RANGES =====")

for feature in features:
    print(f"\n{feature}")
    print("  Benign:")
    print(df[df["label"] == 0][feature].describe())

    print("  Exfiltration:")
    print(df[df["label"] == 1][feature].describe())