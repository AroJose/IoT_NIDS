# train_model.py

import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
import joblib
import os

CSV_IN = "iot_traffic.csv"
MODEL_DIR = "model_assets"
os.makedirs(MODEL_DIR, exist_ok=True)

def load_data(csv_path):
    df = pd.read_csv(csv_path)
    expected = {"timestamp","src_port","dst_port","protocol","packet_size","label"}
    if not expected.issubset(set(df.columns)):
        raise RuntimeError(f"CSV missing expected columns: {expected - set(df.columns)}")
    return df

def preprocess(df):
    df2 = df.copy()
    # Encode protocol
    le_proto = LabelEncoder()
    df2["protocol"] = le_proto.fit_transform(df2["protocol"].astype(str))
    # Features and label
    X = df2[["src_port","dst_port","protocol","packet_size"]].astype(float)
    y = df2["label"].astype(int)
    # Scale numeric features
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    return X_scaled, y, scaler, le_proto

def train_and_save(X, y, scaler, le_proto):
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    model = RandomForestClassifier(n_estimators=150, random_state=42)
    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)
    print("\nAccuracy on test set:", accuracy_score(y_test, y_pred))
    print("\nClassification report:\n", classification_report(y_test, y_pred))
    # Save artifacts
    joblib.dump(model, os.path.join(MODEL_DIR, "rf_model.joblib"))
    joblib.dump(scaler, os.path.join(MODEL_DIR, "scaler.joblib"))
    joblib.dump({"proto": le_proto}, os.path.join(MODEL_DIR, "encoders.joblib"))
    print(f"\n[✓] Saved model, scaler and encoders to '{MODEL_DIR}/'")

if __name__ == "__main__":
    print("[+] Loading CSV:", CSV_IN)
    df = load_data(CSV_IN)
    X_scaled, y, scaler, le_proto = preprocess(df)
    train_and_save(X_scaled, y, scaler, le_proto)
