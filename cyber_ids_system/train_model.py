import numpy as np
import pandas as pd
from sklearn.datasets import fetch_kddcup99
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
import joblib
import os

def create_directories():
    dirs = ['models', 'logs', 'reports']
    for d in dirs:
        os.makedirs(d, exist_ok=True)

def load_dataset():
    print("Loading KDDCup99 dataset...")
    data = fetch_kddcup99(subset="SA", percent10=True, as_frame=True)
    
    X = data.data
    y = data.target
    
    X.columns = [col.replace(":", "_") for col in X.columns]
    
    for col in X.select_dtypes(include=["object"]).columns:
        X.loc[:, col] = LabelEncoder().fit_transform(X[col])
    
    y = LabelEncoder().fit_transform(y)
    
    return train_test_split(X, y, test_size=0.2, random_state=42)

def federated_training(num_clients=3, rounds=5):
    X_train, X_test, y_train, y_test = load_dataset()
    
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    client_splits = np.array_split(range(len(X_train_scaled)), num_clients)
    
    global_model = RandomForestClassifier(n_estimators=100, random_state=42)
    
    print(f"\nStarting Federated Learning with {num_clients} clients for {rounds} rounds...")
    
    for rnd in range(rounds):
        client_models = []
        for c in range(num_clients):
            idx = client_splits[c]
            X_c, y_c = X_train_scaled[idx], y_train[idx]
            
            clf = RandomForestClassifier(n_estimators=30, random_state=42+c)
            clf.fit(X_c, y_c)
            client_models.append(clf)
        
        preds = np.array([clf.predict(X_test_scaled) for clf in client_models])
        final_pred = np.apply_along_axis(lambda x: np.bincount(x).argmax(), axis=0, arr=preds)
        
        print(f"\n{'='*60}")
        print(f"Round {rnd+1}/{rounds} Results:")
        print(f"{'='*60}")
        print(classification_report(y_test, final_pred, zero_division=0))
    
    print("\nTraining final global model...")
    global_model.fit(X_train_scaled, y_train)
    
    final_predictions = global_model.predict(X_test_scaled)
    print(f"\n{'='*60}")
    print("Final Model Performance:")
    print(f"{'='*60}")
    print(classification_report(y_test, final_predictions, zero_division=0))
    
    os.makedirs('models', exist_ok=True)
    joblib.dump(global_model, "models/fl_ids_model.pkl")
    joblib.dump(scaler, "models/scaler.pkl")
    
    feature_names = X_train.columns.tolist()
    joblib.dump(feature_names, "models/feature_names.pkl")
    
    print("\n✅ Model saved successfully!")
    print("   - models/fl_ids_model.pkl")
    print("   - models/scaler.pkl")
    print("   - models/feature_names.pkl")
    
    return global_model, scaler

if __name__ == "__main__":
    create_directories()
    model, scaler = federated_training()
    print("\n🎉 Training Complete! You can now run the dashboard with: python app.py")