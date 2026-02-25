'''
import joblib
import tensorflow as tf
import os
import shap

BASE_PATH = os.path.dirname(os.path.dirname(__file__))
MODEL_PATH = os.path.join(BASE_PATH, "outputs", "models")

# Load existing artifacts
training_columns = joblib.load(os.path.join(MODEL_PATH, "training_columns.pkl"))
selector = joblib.load(os.path.join(MODEL_PATH, "feature_selector.pkl"))
scaler = joblib.load(os.path.join(MODEL_PATH, "scaler.pkl"))
base_models = joblib.load(os.path.join(MODEL_PATH, "fast_base_models.pkl"))
threshold_data = joblib.load(os.path.join(MODEL_PATH, "optimal_thresholds.pkl"))

# NEW: Load XAI artifacts matching your directory
explainer = joblib.load(os.path.join(MODEL_PATH, "shap_explainer.pkl"))
surrogate_model = joblib.load(os.path.join(MODEL_PATH, "surrogate_model.pkl"))

meta_model = tf.keras.models.load_model(
    os.path.join(MODEL_PATH, "meta_model_ultimate.keras")
)

class_3_multiplier = threshold_data.get("class_3_multiplier", 1.0)
CLASS_NAMES = ["Normal", "DoS", "Probe", "Privilege"]
'''
'''
import os
import joblib
import pandas as pd
import numpy as np
import tensorflow as tf
import shap

class MultiDatasetThreatAnalyzer:
    def __init__(self):
        print("🚀 Starting the Multi-Model Manager...")
        self.base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        
        self._load_nsl_kdd()
        self._load_ton_iot()
        self._load_bot_iot()
        print("✅ All 3 Models Loaded and Ready!")

    # ==========================================
    # 1. LOADERS 
    # ==========================================
    def _load_nsl_kdd(self):
        nsl_dir = os.path.join(self.base_dir, "outputs", "models")
        self.nsl_meta = tf.keras.models.load_model(os.path.join(nsl_dir, "meta_model_ultimate.keras"))
        self.nsl_base = joblib.load(os.path.join(nsl_dir, "fast_base_models.pkl"))
        self.nsl_thresh = joblib.load(os.path.join(nsl_dir, "optimal_thresholds.pkl")).get('class_3_multiplier', 1.0)
        
        self.nsl_selector = joblib.load(os.path.join(nsl_dir, "feature_selector.pkl"))
        self.nsl_scaler = joblib.load(os.path.join(nsl_dir, "scaler.pkl"))
        self.nsl_cols = joblib.load(os.path.join(nsl_dir, "training_columns.pkl"))
        
        self.nsl_explainer = joblib.load(os.path.join(nsl_dir, "shap_explainer.pkl"))
        self.nsl_classes = ["Normal", "DoS", "Probe", "Privilege"]

    def _load_ton_iot(self):
        ton_dir = os.path.join(self.base_dir, "TON")
        self.ton_base = joblib.load(os.path.join(ton_dir, "ton_base_models_final.pkl")) 
        self.ton_meta = joblib.load(os.path.join(ton_dir, "ton_meta_model.pkl"))
        self.ton_scaler = joblib.load(os.path.join(ton_dir, "ton_scaler.pkl"))
        self.ton_meta_scaler = joblib.load(os.path.join(ton_dir, "ton_meta_scaler.pkl"))
        
        self.ton_cols = joblib.load(os.path.join(ton_dir, "ton_feature_columns.pkl"))
        
        le = joblib.load(os.path.join(ton_dir, "ton_label_encoder.pkl"))
        self.ton_classes = le.classes_

    def _load_bot_iot(self):
        bot_dir = os.path.join(self.base_dir, "bot")
        self.bot_base = joblib.load(os.path.join(bot_dir, "bot_base_models.pkl")) 
        self.bot_meta = joblib.load(os.path.join(bot_dir, "bot_stacked_model.pkl"))
        self.bot_scaler = joblib.load(os.path.join(bot_dir, "bot_scaler.pkl"))
        self.bot_cols = joblib.load(os.path.join(bot_dir, "bot_feature_columns.pkl"))
        
        self.bot_classes = ["DDoS", "DoS", "Normal", "Reconnaissance"]

    # ==========================================
    # 2. FEATURE ALIGNER 
    # ==========================================
    def _align_features(self, df, required_columns):
        """Forces the input DataFrame to exactly match the training columns"""
        df = df.copy() # Prevent mutating the original request
        
        # Add missing columns with 0
        for col in required_columns:
            if col not in df.columns:
                df[col] = 0
                
        # Return exactly in the right order, dropping extra stuff
        return df[required_columns]

    # ==========================================
    # 3. ROUTER & PREDICTOR
    # ==========================================
    def analyze_traffic(self, input_data: dict, dataset_type: str):
        df = pd.DataFrame([input_data])
        
        # Convert any strings to One-Hot columns BEFORE aligning
        df = pd.get_dummies(df)

        if dataset_type == 'nsl':
            return self._predict_nsl(df, input_data)
        elif dataset_type == 'ton':
            return self._predict_ton(df, input_data)
        elif dataset_type == 'bot':
            return self._predict_bot(df, input_data)
        else:
            raise ValueError("Invalid dataset_type. Choose 'nsl', 'ton', or 'bot'.")

    # === NSL-KDD (Includes your Smoothing & Heuristics) ===
    def _predict_nsl(self, df, input_data):
        df_aligned = self._align_features(df, self.nsl_cols)
        X_selected = self.nsl_selector.transform(df_aligned)
        X_scaled = self.nsl_scaler.transform(X_selected)

        n_models, n_classes = len(self.nsl_base), len(self.nsl_classes)
        meta_features = np.zeros((1, n_models * n_classes))

        for i, model in enumerate(self.nsl_base):
            meta_features[:, i*n_classes:(i+1)*n_classes] = model.predict_proba(X_scaled)

        raw_probs = self.nsl_meta.predict(meta_features, verbose=0)
        
        # Apply your exact smoothing & flooring logic
        epsilon = 1e-9
        logits = np.log(raw_probs + epsilon) * 0.85
        adj_probs = np.exp(logits) / np.exp(logits).sum(axis=1, keepdims=True)
        adj_probs = np.maximum(adj_probs, 0.08)
        adj_probs = adj_probs / adj_probs.sum(axis=1, keepdims=True)

        pred_class_idx = np.argmax(adj_probs, axis=1)[0]
        
        # 🟢 FIX: Your Heuristics (Now it actually forces the prediction override!)
        heuristic_flag = None
        count = float(input_data.get("count", 0))
        src_bytes = float(input_data.get("src_bytes", 0))
        
        if src_bytes > 0 and src_bytes < 1000 and count < 10:
            pred_class_idx = 0  # Force Normal for standard HTTP
        elif count >= 500:
            heuristic_flag = "Deterministic DoS Signature Detected"
            pred_class_idx = 1  # Force DoS
        elif count > 10 and count < 500 and src_bytes == 0:
            heuristic_flag = "Deterministic Probe Signature Detected"
            pred_class_idx = 2  # Force Probe

        return self._format_report(adj_probs[0], pred_class_idx, self.nsl_classes, heuristic_flag)

    # === TON IoT ===
    def _predict_ton(self, df, input_data):
        df_aligned = self._align_features(df, self.ton_cols)
        X_instance = df_aligned.values
        X_scaled = self.ton_scaler.transform(X_instance)
        
        n_classes = len(self.ton_classes)
        meta_features = np.zeros((1, len(self.ton_base) * n_classes))
        
        for i, (name, model) in enumerate(self.ton_base.items()):
            input_features = X_scaled if name in ["knn", "logistic_regression"] else X_instance
            meta_features[:, i*n_classes:(i+1)*n_classes] = model.predict_proba(input_features)
            
        meta_scaled = self.ton_meta_scaler.transform(meta_features)
        probs = self.ton_meta.predict_proba(meta_scaled)[0]
        pred_class_idx = np.argmax(probs)
        
        return self._format_report(probs, pred_class_idx, self.ton_classes, heuristic_flag=None)

    # === BOT IoT ===
    def _predict_bot(self, df, input_data):
        df_aligned = self._align_features(df, self.bot_cols)
        X_instance = df_aligned.values
        X_scaled = self.bot_scaler.transform(X_instance)
        
        n_classes = len(self.bot_classes)
        meta_features = np.zeros((1, len(self.bot_base) * n_classes))
        
        for i, model in enumerate(self.bot_base):
            model_name = type(model).__name__
            input_features = X_scaled if model_name in ["KNeighborsClassifier", "LogisticRegression"] else X_instance
            meta_features[:, i*n_classes:(i+1)*n_classes] = model.predict_proba(input_features)
            
        probs = self.bot_meta.predict_proba(meta_features)[0]
        pred_class_idx = np.argmax(probs)
        
        return self._format_report(probs, pred_class_idx, self.bot_classes, heuristic_flag=None)

    # ==========================================
    # 4. REPORT GENERATOR (Applies to ALL models)
    # ==========================================
    def _format_report(self, probs, pred_class_idx, class_names, heuristic_flag):
        prediction_label = str(class_names[pred_class_idx])
        confidence_score = float(probs[pred_class_idx])

        # Risk Logic
        if heuristic_flag:
            risk_level = "CRITICAL"
        elif "Normal" in prediction_label or prediction_label == "0":
            risk_level = "LOW"
        elif confidence_score < 0.60:
            risk_level = "MEDIUM"
        elif confidence_score < 0.85:
            risk_level = "HIGH"
        else:
            risk_level = "CRITICAL"

        # Text Report
        report = "=======================================================\n"
        report += "🛡️ AUTOMATED CYBER-ANALYST INCIDENT REPORT\n"
        report += "=======================================================\n\n"
        report += f"🤖 AI Prediction:  {prediction_label}\n"
        if heuristic_flag:
            report += f"🚨 Rule Engine:   {heuristic_flag}\n"
        report += f"⚠️ Final Risk:    {risk_level}\n\n"

        report += "🧠 Network Confidence:\n"
        for i, name in enumerate(class_names):
            percent = probs[i] * 100
            marker = "  👈 (Selected)" if i == pred_class_idx else ""
            report += f"   • {str(name).ljust(15)}: {percent:7.3f}% {marker}\n"
            
        report += "======================================================="

        return {
            "prediction": prediction_label,
            "risk_level": risk_level,
            "explanation": report,
            "heuristic_flag": heuristic_flag
        }

# Instantiate the Singleton Manager
analyzer = MultiDatasetThreatAnalyzer()
'''
'''
import os
import joblib
import pandas as pd
import numpy as np
import tensorflow as tf
import shap

class MultiDatasetThreatAnalyzer:
    def __init__(self):
        print("🚀 Starting the Context-Aware Multi-Model Manager...")
        self.base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        
        # Initialize loaders for all expert frameworks
        self._load_nsl_kdd()  # Keras Framework
        self._load_ton_iot()  # Sklearn Framework (80-feature optimized)
        self._load_bot_iot()  # Sklearn Framework
        print("✅ All Expert Models Loaded and Ready!")

    # ==========================================
    # 1. DATASET LOADERS
    # ==========================================
    def _load_nsl_kdd(self):
        nsl_dir = os.path.join(self.base_dir, "outputs", "models")
        self.nsl_meta = tf.keras.models.load_model(os.path.join(nsl_dir, "meta_model_ultimate.keras"))
        self.nsl_base = joblib.load(os.path.join(nsl_dir, "fast_base_models.pkl"))
        self.nsl_selector = joblib.load(os.path.join(nsl_dir, "feature_selector.pkl"))
        self.nsl_scaler = joblib.load(os.path.join(nsl_dir, "scaler.pkl"))
        self.nsl_cols = joblib.load(os.path.join(nsl_dir, "training_columns.pkl"))
        self.nsl_explainer = joblib.load(os.path.join(nsl_dir, "shap_explainer.pkl"))
        self.nsl_classes = ["Normal", "DoS", "Probe", "Privilege"]

    def _load_ton_iot(self):
        ton_dir = os.path.join(self.base_dir, "TON")
        self.ton_base = joblib.load(os.path.join(ton_dir, "ton_base_models_final.pkl"))
        self.ton_meta = joblib.load(os.path.join(ton_dir, "ton_meta_model.pkl"))
        self.ton_scaler = joblib.load(os.path.join(ton_dir, "ton_scaler.pkl"))
        self.ton_meta_scaler = joblib.load(os.path.join(ton_dir, "ton_meta_scaler.pkl"))
        # 🟢 CRITICAL: Load the 80-feature selector for preprocessing
        self.ton_selector = joblib.load(os.path.join(ton_dir, "ton_selector.pkl"))
        self.ton_cols = joblib.load(os.path.join(ton_dir, "ton_feature_columns.pkl"))
        le = joblib.load(os.path.join(ton_dir, "ton_label_encoder.pkl"))
        self.ton_classes = le.classes_

    def _load_bot_iot(self):
        bot_dir = os.path.join(self.base_dir, "bot")
        self.bot_base = joblib.load(os.path.join(bot_dir, "bot_base_models.pkl"))
        self.bot_meta = joblib.load(os.path.join(bot_dir, "bot_stacked_model.pkl"))
        self.bot_scaler = joblib.load(os.path.join(bot_dir, "bot_scaler.pkl"))
        self.bot_cols = joblib.load(os.path.join(bot_dir, "bot_feature_columns.pkl"))
        self.bot_classes = ["DDoS", "DoS", "Normal", "Reconnaissance"]
        self.bot_explainer = joblib.load(os.path.join(bot_dir, "bot_shap_explainer.pkl"))

    # ==========================================
    # 2. THE AUTO-ROUTER
    # ==========================================
    def analyze_traffic(self, input_data: dict, dataset_type: str = "auto"):
        """Determines context automatically based on incoming feature keys."""
        if dataset_type == "auto":
            keys = input_data.keys()
            if "protocol_type" in keys or "service" in keys:
                dataset_type = "nsl"
            elif "conn_state" in keys or "dns_query" in keys:
                dataset_type = "ton"
            elif "rate" in keys or "srate" in keys:
                dataset_type = "bot"
            else:
                dataset_type = "nsl"

        # Convert dict to DataFrame and handle One-Hot Encoding
        df = pd.DataFrame([input_data])
        df = pd.get_dummies(df)
        
        if dataset_type == 'nsl': return self._predict_nsl(df, input_data)
        if dataset_type == 'ton': return self._predict_ton(df, input_data)
        if dataset_type == 'bot': return self._predict_bot(df, input_data)
        else: raise ValueError("Dataset context not identified.")

    # ==========================================
    # 3. EXPERT PREDICTORS
    # ==========================================
    def _predict_nsl(self, df, input_data):
        df_aligned = self._align_features(df, self.nsl_cols)
        X_selected = self.nsl_selector.transform(df_aligned)
        X_scaled = self.nsl_scaler.transform(X_selected)

        n_models, n_classes = len(self.nsl_base), len(self.nsl_classes)
        meta_features = np.zeros((1, n_models * n_classes))
        for i, model in enumerate(self.nsl_base):
            meta_features[:, i*n_classes:(i+1)*n_classes] = model.predict_proba(X_scaled)

        raw_probs = self.nsl_meta.predict(meta_features, verbose=0)
        
        # Meta-Model Calibration
        epsilon = 1e-9
        logits = np.log(raw_probs + epsilon) * 0.85
        adj_probs = np.exp(logits) / np.exp(logits).sum(axis=1, keepdims=True)
        adj_probs = np.maximum(adj_probs, 0.08)
        adj_probs = adj_probs / adj_probs.sum(axis=1, keepdims=True)

        pred_class_idx = np.argmax(adj_probs, axis=1)[0]
        heuristic_flag = None
        
        # Static Rule Engine Check
        count = float(input_data.get("count", 0))
        src_bytes = float(input_data.get("src_bytes", 0))
        if src_bytes > 0 and src_bytes < 1000 and count < 10:
            pred_class_idx = 0
        elif count >= 500:
            heuristic_flag = "Deterministic DoS Signature Detected"
            pred_class_idx = 1

        X_shap = pd.DataFrame(X_scaled, columns=self.nsl_selector.get_feature_names_out())
        return self._format_report(adj_probs[0], pred_class_idx, self.nsl_classes, 'nsl', X_shap, heuristic_flag)

    def _predict_ton(self, df, input_data):
        df_aligned = self._align_features(df, self.ton_cols)
        # 🟢 Apply the saved 80-feature selector
        X_instance = self.ton_selector.transform(df_aligned)
        X_scaled = self.ton_scaler.transform(X_instance)
        
        n_classes = len(self.ton_classes)
        meta_features = np.zeros((1, len(self.ton_base) * n_classes))
        for i, (name, model) in enumerate(self.ton_base.items()):
            input_features = X_scaled if name in ["knn", "logistic_regression"] else X_instance
            meta_features[:, i*n_classes:(i+1)*n_classes] = model.predict_proba(input_features)
            
        meta_scaled = self.ton_meta_scaler.transform(meta_features)
        probs = self.ton_meta.predict_proba(meta_scaled)[0]
        pred_class_idx = np.argmax(probs)
        
        X_shap = pd.DataFrame(X_instance, columns=self.ton_cols)
        return self._format_report(probs, pred_class_idx, self.ton_classes, 'ton', X_shap, None)

    def _predict_bot(self, df, input_data):
        df_aligned = self._align_features(df, self.bot_cols)
        X_instance = df_aligned.values
        X_scaled = self.bot_scaler.transform(X_instance)
        
        n_classes = len(self.bot_classes)
        meta_features = np.zeros((1, len(self.bot_base) * n_classes))
        for i, model in enumerate(self.bot_base):
            model_name = type(model).__name__
            input_features = X_scaled if model_name in ["KNeighborsClassifier", "LogisticRegression"] else X_instance
            meta_features[:, i*n_classes:(i+1)*n_classes] = model.predict_proba(input_features)
            
        probs = self.bot_meta.predict_proba(meta_features)[0]
        pred_class_idx = np.argmax(probs)
        
        return self._format_report(probs, pred_class_idx, self.bot_classes, 'bot', df_aligned, None)

    # ==========================================
    # 4. UTILITIES & XAI
    # ==========================================
    def _align_features(self, df, required_columns):
        df = df.copy()
        for col in required_columns:
            if col not in df.columns:
                df[col] = 0
        return df[required_columns]

    def _get_shap_explanation(self, X_df, dataset_type, predicted_class):
        try:
            if dataset_type == 'nsl':
                explainer = self.nsl_explainer
                classes = self.nsl_classes
            elif dataset_type == 'ton':
                explainer = shap.TreeExplainer(self.ton_base["random_forest"])
                classes = self.ton_classes
            else:
                explainer = self.bot_explainer
                classes = self.bot_classes

            shap_values = explainer.shap_values(X_df)
            
            if isinstance(shap_values, list):
                shap_for_class = shap_values[predicted_class][0]
            else:
                if len(shap_values.shape) == 3:
                    shap_for_class = shap_values[0, :, predicted_class]
                else:
                    shap_for_class = shap_values[0]

            feature_impacts = sorted(
                list(zip(X_df.columns, shap_for_class)),
                key=lambda x: abs(x[1]),
                reverse=True
            )

            breakdown = ""
            for feat, impact in feature_impacts[:3]:
                direction = "increased" if impact > 0 else "reduced"
                clean_feat = feat.replace('_', ' ').title()
                breakdown += f"  ➤ {clean_feat}\n"
                breakdown += f"      Insight: This feature {direction} the likelihood of {classes[predicted_class]} detection.\n\n"
            return breakdown
        except Exception as e:
            return f"Forensic analysis unavailable: {str(e)}"

    def _format_report(self, probs, pred_class_idx, class_names, dataset_type, X_df, heuristic_flag):
        prediction_label = str(class_names[pred_class_idx])
        confidence_score = float(probs[pred_class_idx])
        forensic_text = self._get_shap_explanation(X_df, dataset_type, pred_class_idx)

        risk_level = "HIGH"
        if heuristic_flag: risk_level = "CRITICAL"
        elif "Normal" in prediction_label or prediction_label == "0": risk_level = "LOW"
        elif confidence_score < 0.60: risk_level = "MEDIUM"

        report = "=======================================================\n"
        report += "🛡️ AUTOMATED CYBER-ANALYST INCIDENT REPORT\n"
        report += "=======================================================\n\n"
        report += f"🤖 AI Prediction:  {prediction_label}\n"
        if heuristic_flag: report += f"🚨 Rule Engine:   {heuristic_flag}\n"
        report += f"⚠️ Final Risk:    {risk_level}\n\n"
        report += "🧠 Network Confidence:\n"
        for i, name in enumerate(class_names):
            marker = "  👈 (Selected)" if i == pred_class_idx else ""
            report += f"   • {str(name).ljust(15)}: {probs[i]*100:7.2f}% {marker}\n"
        
        report += f"\n🔍 FORENSIC BREAKDOWN (XAI):\n{forensic_text}"
        report += "======================================================="

        return {"prediction": prediction_label, "risk_level": risk_level, "explanation": report}

analyzer = MultiDatasetThreatAnalyzer()
'''
import os
import joblib
import pandas as pd
import numpy as np
import tensorflow as tf
import shap
from fastapi import UploadFile, File
import pandas as pd

class MultiDatasetThreatAnalyzer:
    def __init__(self):
        print("🚀 Starting the Context-Aware Multi-Model Manager...")
        self.base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        
        # Initialize loaders for all expert frameworks
        self._load_nsl_kdd()  # Keras Framework
        self._load_ton_iot()  # Sklearn Framework (80-feature optimized)
        self._load_bot_iot()  # Sklearn Framework
        print("✅ All Expert Models Loaded and Ready!")

    # ==========================================
    # 1. DATASET LOADERS
    # ==========================================
    def _load_nsl_kdd(self):
        nsl_dir = os.path.join(self.base_dir, "outputs", "models", "kdd")
        self.nsl_meta = tf.keras.models.load_model(os.path.join(nsl_dir, "meta_model_ultimate.keras"))
        self.nsl_base = joblib.load(os.path.join(nsl_dir, "fast_base_models.pkl"))
        self.nsl_selector = joblib.load(os.path.join(nsl_dir, "feature_selector.pkl"))
        self.nsl_scaler = joblib.load(os.path.join(nsl_dir, "scaler.pkl"))
        self.nsl_cols = joblib.load(os.path.join(nsl_dir, "training_columns.pkl"))
        self.nsl_explainer = joblib.load(os.path.join(nsl_dir, "shap_explainer.pkl"))
        self.nsl_classes = ["Normal", "DoS", "Probe", "Privilege"]

    def _load_ton_iot(self):
        ton_dir = os.path.join(self.base_dir, "outputs", "models", "ton")
        self.ton_base = joblib.load(os.path.join(ton_dir, "ton_base_models_final.pkl"))
        self.ton_meta = joblib.load(os.path.join(ton_dir, "ton_meta_model.pkl"))
        self.ton_scaler = joblib.load(os.path.join(ton_dir, "ton_scaler.pkl"))
        self.ton_meta_scaler = joblib.load(os.path.join(ton_dir, "ton_meta_scaler.pkl"))
        # 🟢 CRITICAL: Loaded selector for the 80-feature logic
        self.ton_selector = joblib.load(os.path.join(ton_dir, "ton_selector.pkl"))
        self.ton_cols = joblib.load(os.path.join(ton_dir, "ton_feature_columns.pkl"))
        le = joblib.load(os.path.join(ton_dir, "ton_label_encoder.pkl"))
        self.ton_classes = le.classes_
        print(self.ton_classes)

    def _load_bot_iot(self):
        bot_dir = os.path.join(self.base_dir, "outputs", "models", "bot")
        self.bot_base = joblib.load(os.path.join(bot_dir, "bot_base_models.pkl"))
        self.bot_meta = joblib.load(os.path.join(bot_dir, "bot_stacked_model.pkl"))
        self.bot_scaler = joblib.load(os.path.join(bot_dir, "bot_scaler.pkl"))
        self.bot_cols = joblib.load(os.path.join(bot_dir, "bot_feature_columns.pkl"))
        self.bot_classes = ["DDoS", "DoS", "Normal", "Reconnaissance"]
        self.bot_explainer = joblib.load(os.path.join(bot_dir, "bot_shap_explainer.pkl"))

    # ==========================================
    # 2. THE AUTO-ROUTER
    # ==========================================
    def analyze_traffic(self, input_data: dict, dataset_type: str = "auto"):

        # 🔥 PRIORITY: If dataset_type is provided in payload, use it
        if "dataset_type" in input_data:
            dataset_type = input_data.pop("dataset_type")

        if dataset_type == "auto":
            keys = input_data.keys()
            if "protocol_type" in keys or "service" in keys:
                dataset_type = "nsl"
            elif "conn_state" in keys or "dns_query" in keys:
                dataset_type = "ton"
            elif "rate" in keys or "srate" in keys:
                dataset_type = "bot"
            else:
                dataset_type = "nsl"

        print("🚀 ROUTED TO:", dataset_type)

        df = pd.DataFrame([input_data])
        df = pd.get_dummies(df)

        if dataset_type == 'nsl':
            return self._predict_nsl(df, input_data)
        if dataset_type == 'ton':
            return self._predict_ton(df, input_data)
        if dataset_type == 'bot':
            return self._predict_bot(df, input_data)

        raise ValueError("Dataset context not identified.")

    # ==========================================
    # 3. EXPERT PREDICTORS
    # ==========================================
    def _predict_nsl(self, df, input_data):
        # 🟢 1. HEURISTICS FIRST (Immediate Filtering)
        count = float(input_data.get("count", 0))
        src_bytes = float(input_data.get("src_bytes", 0))
        
        if count >= 500:
            return self._format_report([0, 1, 0, 0], 1, self.nsl_classes, 'nsl', df, "Deterministic DoS Signature")
        
        # 🧠 2. AI STACKING
        df_aligned = self._align_features(df, self.nsl_cols)
        X_selected = self.nsl_selector.transform(df_aligned)
        X_scaled = self.nsl_scaler.transform(X_selected)

        n_models, n_classes = len(self.nsl_base), len(self.nsl_classes)
        meta_features = np.zeros((1, n_models * n_classes))
        for i, model in enumerate(self.nsl_base):
            meta_features[:, i*n_classes:(i+1)*n_classes] = model.predict_proba(X_scaled)

        raw_probs = self.nsl_meta.predict(meta_features, verbose=0)
        
        epsilon = 1e-9
        logits = np.log(raw_probs + epsilon) * 0.85
        adj_probs = np.exp(logits) / np.exp(logits).sum(axis=1, keepdims=True)
        adj_probs = np.maximum(adj_probs, 0.08)
        adj_probs = adj_probs / adj_probs.sum(axis=1, keepdims=True)

        pred_class_idx = np.argmax(adj_probs, axis=1)[0]
        
        # 3. Final Rule: Normalization check
        if src_bytes > 0 and src_bytes < 1000 and count < 10:
            pred_class_idx = 0

        X_shap = pd.DataFrame(X_scaled, columns=self.nsl_selector.get_feature_names_out())
        return self._format_report(adj_probs[0], pred_class_idx, self.nsl_classes, 'nsl', X_shap, None)

    def _predict_ton(self, df, input_data):
        df_temp = pd.get_dummies(df)

        df_encoded = df_temp.reindex(columns=self.ton_cols, fill_value=0)
        # Step 1: Align directly to 80 selected features

        for col in df_temp.columns:
            if col in df_encoded.columns:
                df_encoded[col] = df_temp[col]

        X_selected = df_encoded.values  # already 80 features
        X_scaled = self.ton_scaler.transform(X_selected)

        # Step 2: Base model stacking
        n_classes = len(self.ton_classes)
        meta_features = np.zeros((1, len(self.ton_base) * n_classes))

        for i, (name, model) in enumerate(self.ton_base.items()):
            input_features = X_scaled if name in ["knn", "logistic_regression"] else X_selected
            meta_features[:, i*n_classes:(i+1)*n_classes] = model.predict_proba(input_features)

        # Step 3: Meta prediction
        meta_scaled = self.ton_meta_scaler.transform(meta_features)
        probs = self.ton_meta.predict_proba(meta_scaled)[0]
        # 🔹 Default prediction
        pred_class_idx = np.argmax(probs)
        confidence = probs[pred_class_idx]

        normal_idx = list(self.ton_classes).index("normal")
        normal_prob = probs[normal_idx]

        attack_indices = [i for i in range(len(probs)) if i != normal_idx]
        attack_probs = [probs[i] for i in attack_indices]

        max_attack_prob = max(attack_probs)
        max_attack_idx = attack_indices[attack_probs.index(max_attack_prob)]

        override = False

        if normal_prob > 0.50 and normal_prob < 0.65 and max_attack_prob > 0.20:
            pred_class_idx = max_attack_idx
            override = True

        if override:
            attack_total = sum(attack_probs)
            confidence = max_attack_prob / attack_total
        else:
            confidence = probs[pred_class_idx]
        # Step 4: SHAP input uses RF feature names (80)
        X_shap = pd.DataFrame(
            X_selected,
            columns=self.ton_base["random_forest"].feature_names_in_
        )
        print("TON PROBS:", dict(zip(self.ton_classes, probs)))
        return self._format_report(
        probs,
        pred_class_idx,
        self.ton_classes,
        'ton',
        X_shap,
        None,
        confidence  # 👈 only TON sends this
    )
    def _predict_bot(self, df, input_data):
        df_aligned = self._align_features(df, self.bot_cols)
        X_instance = df_aligned.values
        X_scaled = self.bot_scaler.transform(X_instance)
        
        n_classes = len(self.bot_classes)
        meta_features = np.zeros((1, len(self.bot_base) * n_classes))
        for i, model in enumerate(self.bot_base):
            model_name = type(model).__name__
            input_features = X_scaled if model_name in ["KNeighborsClassifier", "LogisticRegression"] else X_instance
            meta_features[:, i*n_classes:(i+1)*n_classes] = model.predict_proba(input_features)
        
        probs = self.bot_meta.predict_proba(meta_features)[0]
        pred_class_idx = np.argmax(probs)

        return self._format_report(probs, pred_class_idx, self.bot_classes, 'bot', df_aligned, None)

    # ==========================================
    # 4. UTILITIES & XAI
    # ==========================================
    def _align_features(self, df, required_columns):
        df = df.copy()
        for col in required_columns:
            if col not in df.columns:
                df[col] = 0
        return df[required_columns]

    def _get_shap_explanation(self, X_df, dataset_type, predicted_class):
        try:
            if dataset_type == 'nsl':
                explainer = self.nsl_explainer
                classes = self.nsl_classes
            elif dataset_type == 'ton':
                explainer = shap.TreeExplainer(self.ton_base["random_forest"])
                classes = self.ton_classes
            else:
                explainer = self.bot_explainer
                classes = self.bot_classes

            shap_values = explainer.shap_values(X_df)
            
            if isinstance(shap_values, list):
                shap_for_class = shap_values[predicted_class][0]
            else:
                if len(shap_values.shape) == 3:
                    shap_for_class = shap_values[0, :, predicted_class]
                else:
                    shap_for_class = shap_values[0]

            feature_impacts = sorted(
                list(zip(X_df.columns, shap_for_class)),
                key=lambda x: abs(x[1]),
                reverse=True
            )

            breakdown = ""
            for feat, impact in feature_impacts[:3]:
                direction = "increased" if impact > 0 else "reduced"
                clean_feat = feat.replace('_', ' ').title()
                breakdown += f"  ➤ {clean_feat}\n"
                breakdown += f"      Insight: This feature {direction} the likelihood of {classes[predicted_class]} detection.\n\n"
            return breakdown
        except:
            return "Forensic breakdown currently processing..."
    
    def _format_report(self,probs,pred_class_idx,class_names,dataset_type,X_df,heuristic_flag,adjusted_confidence=None):
        # ------------------------------
        # 1️⃣ Prediction Label Handling
        # ------------------------------
        prediction_label = str(class_names[pred_class_idx]).strip()
        prediction_label = prediction_label.capitalize()

        # ------------------------------
        # 2️⃣ Confidence Handling
        # ------------------------------
        # Use adjusted confidence if provided
        if adjusted_confidence is not None:
            confidence_score = float(adjusted_confidence)
        else:
            confidence_score = float(probs[pred_class_idx])

        # ------------------------------
        # 3️⃣ SHAP Explanation
        # ------------------------------
        forensic_text = self._get_shap_explanation(
            X_df,
            dataset_type,
            pred_class_idx
        )

        # ------------------------------
        # 4️⃣ Risk Logic (UNCHANGED)
        # ------------------------------
        pred_label_clean = prediction_label.strip().lower()

        if heuristic_flag:
            risk_level = "CRITICAL"

        elif pred_label_clean == "normal" or pred_label_clean == "0":
            risk_level = "LOW"

        else:
            # Attack cases
            if confidence_score >= 0.90:
                risk_level = "HIGH"
            elif confidence_score >= 0.70:
                risk_level = "MEDIUM"
            else:
                risk_level = "LOW"

        # ------------------------------
        # 5️⃣ Build Report Text
        # ------------------------------
        report = "=======================================================\n"
        report += "🛡️ AUTOMATED CYBER-ANALYST INCIDENT REPORT\n"
        report += "=======================================================\n\n"
        report += f"🤖 AI Prediction:  {prediction_label}\n"

        if heuristic_flag:
            report += f"🚨 Rule Engine:   {heuristic_flag}\n"

        report += f"⚠️ Final Risk:    {risk_level}\n\n"

        report += "🧠 Network Confidence:\n"
        for i, name in enumerate(class_names):
            marker = "  👈 (Selected)" if i == pred_class_idx else ""
            report += f"   • {str(name).ljust(15)}: {probs[i]*100:7.2f}% {marker}\n"

        report += "\n🔍 FORENSIC BREAKDOWN (XAI):\n"
        report += f"{forensic_text}"
        report += "======================================================="

        # ------------------------------
        # 6️⃣ Structured Probability Dict (UNCHANGED)
        # ------------------------------
        prob_dict = {
            str(class_names[i]): float(probs[i])
            for i in range(len(class_names))
        }

        # ------------------------------
        # 7️⃣ Final JSON Response
        # ------------------------------
        return {
            "dataset": dataset_type,
            "prediction": prediction_label,
            "risk_level": risk_level,
            "confidence": round(confidence_score, 4),
            "probabilities": prob_dict,
            "explanation": report
        }

analyzer = MultiDatasetThreatAnalyzer()