import os
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report
import joblib

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_PATH = os.path.join(BASE_DIR, "data", "processed.csv")
MODEL_PATH = os.path.join(BASE_DIR, "models", "model.pkl")

if not os.path.exists(DATA_PATH):
    print("Processed file not found.")
    exit()

df = pd.read_csv(DATA_PATH)

if df.empty:
    print("Dataset is empty. Nothing to train.")
    exit()

le = LabelEncoder()
df["risk_encoded"] = le.fit_transform(df["risk"])

X = df[["confidence", "cweid", "url_length"]].copy()
X["confidence"] = X["confidence"].astype(str)

X = pd.get_dummies(X)

y = df["risk_encoded"]

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.3, random_state=42
)

model = RandomForestClassifier()
model.fit(X_train, y_train)

pred = model.predict(X_test)

print(classification_report(y_test, pred))

os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
joblib.dump(model, MODEL_PATH)

print("Model saved to:", MODEL_PATH)
