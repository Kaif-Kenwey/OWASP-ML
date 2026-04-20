import os
import joblib
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import Pipeline
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_PATH = os.path.join(BASE_DIR, "data", "processed.csv")
MODEL_DIR = os.path.join(BASE_DIR, "models")
os.makedirs(MODEL_DIR, exist_ok=True)

print("\n--- Loading Data ---")

df = pd.read_csv(DATA_PATH)

print("Dataset shape:", df.shape)

# Remove missing values
df = df.dropna()

# ========================
# TARGET
# ========================
target_column = "risk"

if target_column not in df.columns:
    raise Exception("Target column 'risk' not found!")

# ========================
# FEATURES
# ========================
feature_columns = ["confidence", "cweid", "method", "url_length"]

for col in feature_columns:
    if col not in df.columns:
        raise Exception(f"Missing feature column: {col}")

X = df[feature_columns]
y = df[target_column]

# Encode target
label_encoder = LabelEncoder()
y_encoded = label_encoder.fit_transform(y)

# ========================
# Train/Test Split
# ========================
X_train, X_test, y_train, y_test = train_test_split(
    X, y_encoded,
    test_size=0.25,
    stratify=y_encoded,
    random_state=42
)

print("Training samples:", len(X_train))
print("Testing samples:", len(X_test))

# ========================
# Preprocessing
# ========================

categorical_features = ["confidence", "cweid", "method"]
numeric_features = ["url_length"]

preprocessor = ColumnTransformer(
    transformers=[
        ("cat", OneHotEncoder(handle_unknown="ignore"), categorical_features),
        ("num", "passthrough", numeric_features)
    ]
)

# ========================
# Model
# ========================

model = Pipeline(steps=[
    ("preprocessor", preprocessor),
    ("classifier", RandomForestClassifier(
        n_estimators=200,
        max_depth=15,
        random_state=42
    ))
])

print("\n--- Training Model ---")
model.fit(X_train, y_train)

# ========================
# Evaluation
# ========================

y_pred = model.predict(X_test)

print("\n--- Evaluation ---")
print(classification_report(y_test, y_pred))
print("\nConfusion Matrix:")
print(confusion_matrix(y_test, y_pred))

# ========================
# Save Model
# ========================

joblib.dump(model, os.path.join(MODEL_DIR, "model.pkl"))
joblib.dump(label_encoder, os.path.join(MODEL_DIR, "label_encoder.pkl"))

print("\nModel saved successfully.")
