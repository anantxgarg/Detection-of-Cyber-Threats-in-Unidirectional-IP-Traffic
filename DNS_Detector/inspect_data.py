import pandas as pd

# Dataset path
DATA_PATH = "data/dataset_final.csv"

print("=" * 60)
print("DNS TUNNEL DATASET INSPECTION")
print("=" * 60)

# Load dataset
df = pd.read_csv(DATA_PATH)

# Basic information
print("\n1. DATASET SHAPE")
print("-" * 40)
print("Rows:", df.shape[0])
print("Columns:", df.shape[1])

# Column names
print("\n2. COLUMN NAMES")
print("-" * 40)
for column in df.columns:
    print(column)

# First 5 rows
print("\n3. FIRST 5 ROWS")
print("-" * 40)
print(df.head())

# Data types
print("\n4. DATA TYPES")
print("-" * 40)
print(df.dtypes)

# Missing values
print("\n5. MISSING VALUES")
print("-" * 40)
print(df.isnull().sum())

# Duplicate rows
print("\n6. DUPLICATE ROWS")
print("-" * 40)
print("Duplicates:", df.duplicated().sum())

# Unique values
print("\n7. UNIQUE VALUES PER COLUMN")
print("-" * 40)
for column in df.columns:
    print(f"{column}: {df[column].nunique()}")

print("\n" + "=" * 60)
print("INSPECTION COMPLETE")
print("=" * 60)