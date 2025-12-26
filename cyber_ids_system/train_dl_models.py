import numpy as np
import pandas as pd
from sklearn.datasets import fetch_kddcup99
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, LSTM, Conv1D, MaxPooling1D, Flatten, Dropout
import joblib
import os

# Set random seeds for reproducibility
np.random.seed(42)
tf.random.set_seed(42)

def create_directories():
    dirs = ['models', 'logs', 'reports']
    for d in dirs:
        os.makedirs(d, exist_ok=True)

def load_and_preprocess_data():
    print("Loading KDDCup99 dataset...")
    data = fetch_kddcup99(subset="SA", percent10=True, as_frame=True)
    
    X = data.data
    y = data.target
    
    # Clean column names
    X.columns = [col.replace(":", "_") for col in X.columns]
    
    # Encode categorical features
    print("Encoding features...")
    for col in X.select_dtypes(include=["object"]).columns:
        X.loc[:, col] = LabelEncoder().fit_transform(X[col])
    
    # Encode labels
    # Map attack types to integers (Normal=0, Attack=1 for binary, or multi-class)
    # For this advanced model, let's try to keep multi-class but simplified
    y = LabelEncoder().fit_transform(y)
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    # Scale features
    print("Scaling features...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    # Save scaler for app usage
    joblib.dump(scaler, "models/scaler_dl.pkl")
    
    # Reshape for DL models (samples, timesteps, features)
    # We treat the features as a sequence of 1 timestep
    X_train_reshaped = X_train_scaled.reshape((X_train_scaled.shape[0], 1, X_train_scaled.shape[1]))
    X_test_reshaped = X_test_scaled.reshape((X_test_scaled.shape[0], 1, X_test_scaled.shape[1]))
    
    return X_train_reshaped, X_test_reshaped, y_train, y_test, X_train.shape[1]

def build_cnn_model(input_shape, num_classes):
    print("Building CNN Model...")
    model = Sequential([
        Conv1D(filters=64, kernel_size=1, activation='relu', input_shape=input_shape),
        MaxPooling1D(pool_size=1),
        Flatten(),
        Dense(128, activation='relu'),
        Dropout(0.5),
        Dense(num_classes, activation='softmax')
    ])
    model.compile(optimizer='adam', loss='sparse_categorical_crossentropy', metrics=['accuracy'])
    return model

def build_lstm_model(input_shape, num_classes):
    print("Building LSTM Model...")
    model = Sequential([
        LSTM(64, input_shape=input_shape, return_sequences=True),
        LSTM(32),
        Dense(64, activation='relu'),
        Dropout(0.5),
        Dense(num_classes, activation='softmax')
    ])
    model.compile(optimizer='adam', loss='sparse_categorical_crossentropy', metrics=['accuracy'])
    return model

def train_models():
    create_directories()
    
    X_train, X_test, y_train, y_test, num_features = load_and_preprocess_data()
    num_classes = len(np.unique(y_train))
    input_shape = (1, num_features)
    
    # Train CNN
    cnn_model = build_cnn_model(input_shape, num_classes)
    print("\nTraining CNN...")
    cnn_model.fit(X_train, y_train, epochs=5, batch_size=64, validation_data=(X_test, y_test))
    cnn_model.save('models/cnn_ids_model.h5')
    print("✅ CNN Model saved to models/cnn_ids_model.h5")
    
    # Train LSTM
    lstm_model = build_lstm_model(input_shape, num_classes)
    print("\nTraining LSTM...")
    lstm_model.fit(X_train, y_train, epochs=5, batch_size=64, validation_data=(X_test, y_test))
    lstm_model.save('models/lstm_ids_model.h5')
    print("✅ LSTM Model saved to models/lstm_ids_model.h5")

if __name__ == "__main__":
    train_models()
