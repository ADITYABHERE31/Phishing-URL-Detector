import pandas as pd

file_path = "ml/PhiUSIIL_Phishing_URL_Dataset.csv"

df = pd.read_csv(file_path)

print("Dataset shape:", df.shape)

print("\nColumn names:")
print(df.columns.tolist())

print("\nFirst 5 rows:")
print(df.head())

print("\nLabel distribution:")
print(df["label"].value_counts())

print("\nMissing values:")
print(df.isnull().sum())