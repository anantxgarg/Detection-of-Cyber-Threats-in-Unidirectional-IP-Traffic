import pandas as pd

df = pd.read_csv("data/dataset_final.csv")

print("LABEL DISTRIBUTION")
print("=" * 40)
print(df["label"].value_counts())

print("\nLABEL PERCENTAGE")
print("=" * 40)
print((df["label"].value_counts(normalize=True) * 100).round(2))

print("\nLABEL 0 EXAMPLES")
print("=" * 40)
print(df[df["label"] == 0].head(3))

print("\nLABEL 1 EXAMPLES")
print("=" * 40)
print(df[df["label"] == 1].head(3))