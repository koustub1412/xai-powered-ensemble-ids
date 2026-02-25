import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler
import joblib


RANDOM_STATE = 42


def load_data(train_path, test_path):
    train = pd.read_csv(train_path)
    test = pd.read_csv(test_path)

    print(f"Train shape: {train.shape}")
    print(f"Test shape: {test.shape}")

    return train, test


def drop_columns(train, test):
    # Safe drop in case column missing
    train = train.drop(columns=["difficulty"], errors="ignore")
    test = test.drop(columns=["difficulty"], errors="ignore")
    return train, test


def encode_categorical(train, test):
    categorical_cols = ["protocol_type", "service", "flag"]

    # Combine for consistent one-hot encoding
    combined = pd.concat([train, test], axis=0).reset_index(drop=True)

    combined = pd.get_dummies(combined, columns=categorical_cols)

    # Split back safely
    train_encoded = combined.iloc[:len(train)].reset_index(drop=True)
    test_encoded = combined.iloc[len(train):].reset_index(drop=True)

    print(f"After encoding: {train_encoded.shape}")

    return train_encoded, test_encoded


def split_features_labels(train, test):
    X_train = train.drop(columns=["label"])
    y_train = train["label"]

    X_test = test.drop(columns=["label"])
    y_test = test["label"]

    print(f"Feature count: {X_train.shape[1]}")

    return X_train, X_test, y_train, y_test


def scale_data(X_train, X_test, save_path=None):
    scaler = StandardScaler()

    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # Optional but IMPORTANT for deployment
    if save_path is not None:
        joblib.dump(scaler, save_path)
        print(f"Scaler saved to {save_path}")

    return X_train_scaled, X_test_scaled, scaler
