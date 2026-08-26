import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, roc_auc_score
import joblib

# Load dataset
print("Loading dataset...")
df = pd.read_csv("ml/PhiUSIIL_Phishing_URL_Dataset.csv")

print("Dataset:", df.shape)

# Remove duplicate URLs
before = len(df)
df = df.drop_duplicates(subset=["URL"])
print("Duplicate URLs removed:", before - len(df))
print("Remaining samples:", len(df))

# Dataset feature columns
dataset_features = [
    "URLLength",
    "DomainLength",
    "IsDomainIP",
    "NoOfSubDomain",
    "NoOfLettersInURL",
    "NoOfDegitsInURL",
    "NoOfEqualsInURL",
    "NoOfQMarkInURL",
    "NoOfAmpersandInURL",
    "NoOfOtherSpecialCharsInURL",
    "SpacialCharRatioInURL",
    "IsHTTPS",
    "NoOfURLRedirect",
    "NoOfSelfRedirect",
    "HasObfuscation",
    "LetterRatioInURL",
    "DegitRatioInURL",
    "TLDLength",
    "NoOfObfuscatedChar",
    "ObfuscationRatio",
    "CharContinuationRate",
]

# These are the names expected by the API/extractor.
model_features = [
    "url_length",
    "domain_length",
    "is_ip",
    "subdomain_count",
    "digit_count",
    "special_char_count",
    "has_at",
    "hyphen_count",
    "query_count",
    "equals_count",
    "ampersand_count",
    "encoded_count",
    "is_https",
    "suspicious_keyword_count",
    "suspicious_tld",
    "has_port",
    "path_length",
    "query_length",
    "digit_ratio",
    "letter_ratio",
    "max_character_run",
]

# IMPORTANT:
# The dataset's 21 columns do NOT correspond exactly to the current
# extractor's 21 definitions.
#
# Therefore, do NOT train this model using dataset columns directly.
# We will create the exact same features used by the API.

from feature_extractor import extract_features

print("Extracting features using feature_extractor.py...")

X = pd.DataFrame(
    [extract_features(url) for url in df["URL"]]
)

# Ensure exact feature order
X = X[model_features]

y = df["label"]

print("Features:", X.shape)
print("Feature columns:", list(X.columns))
print("Labels:", y.shape)

print("\nLabel distribution:")
print(y.value_counts())

# Split
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)

print("\nTraining data:", X_train.shape)
print("Testing data:", X_test.shape)

# Model
model = RandomForestClassifier(
    n_estimators=200,
    max_depth=12,
    min_samples_leaf=5,
    random_state=42,
    n_jobs=-1
)

print("\nTraining model...")
model.fit(X_train, y_train)

print("Model training completed.")

# Evaluation
y_pred = model.predict(X_test)
y_prob = model.predict_proba(X_test)[:, 1]

accuracy = accuracy_score(y_test, y_pred)
roc_auc = roc_auc_score(y_test, y_prob)

print("\n==============================")
print("MODEL EVALUATION")
print("==============================")
print(f"Accuracy: {accuracy:.4f}")
print(f"ROC-AUC: {roc_auc:.4f}")

print("\nClassification Report:")
print(
    classification_report(
        y_test,
        y_pred,
        target_names=["Phishing", "Legitimate"]
    )
)

print("\nConfusion Matrix:")
print(confusion_matrix(y_test, y_pred))

# Save model
joblib.dump(model, "ml/phishing_model.pkl")

print("\nModel saved to: ml/phishing_model.pkl")
print("Model features:")
print(list(model.feature_names_in_))