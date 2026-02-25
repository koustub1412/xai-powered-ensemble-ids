# 🛡️ Hybrid AI-Driven Intrusion Detection System (IDS)

A sophisticated Intrusion Detection System designed for IoT and IT environments using a **Heterogeneous Stacked Ensemble** architecture.

## 🚀 Project Highlights
- **Hybrid Stacking:** Combines Scikit-Learn (KNN, RF, DT, LR) base models with a **Keras Deep Neural Network** meta-learner.
- **Context-Aware:** Auto-routes traffic between **NSL-KDD** (IT), **ToN-IoT** (Sensors), and **BoT-IoT** (Smart Home) expert models.
- **Explainable AI (XAI):** Integrated SHAP forensic analysis to provide human-readable justifications for every alert.
- **Real-Time Dashboard:** React-based SOC dashboard with MongoDB logging.

## 📁 Project Structure
- `/backend`: FastAPI server logic.
- `/frontend`: React dashboard source code.
- `/notebooks`: Data preprocessing and model training pipeline.
- `/outputs`: Saved `.keras` and `.pkl` artifacts.
- `/src`: Core prediction and analyzer modules.

## 🛠️ Setup
1. `pip install -r requirements.txt`
2. Run Backend: `uvicorn backend.main:app --reload`
3. Run Frontend: `npm install && npm start`