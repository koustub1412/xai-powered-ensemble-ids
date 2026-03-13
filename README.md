---
title: XAI Powered Ensemble IDS
emoji: 🛡️
colorFrom: blue
colorTo: green
sdk: docker
app_file: backend/app.py
pinned: false
---
# 🔐 XAI-Powered Ensemble Intrusion Detection System for IoT

## 📌 Overview

The rapid growth of the **Internet of Things (IoT)** has connected billions of smart devices across healthcare, industries, transportation, and smart cities. While this connectivity enhances automation and efficiency, it also significantly increases vulnerability to cyberattacks.

This project presents an **Explainable Ensemble Machine Learning Framework for Intrusion Detection in IoT**, combining:

- 🧠 Stacked Ensemble Learning  
- 🔎 Explainable AI (XAI) using SHAP  
- 🌐 Multi-dataset evaluation  
- 💻 Full-stack deployment (FastAPI + React)  

The system not only detects intrusions but also explains *why* a network instance is classified as malicious.

---

## 🚨 Problem Statement

Traditional Intrusion Detection Systems (IDS):

- ❌ Cannot detect zero-day attacks (signature-based IDS)
- ❌ Produce high false positives (anomaly-based IDS)
- ❌ Lack interpretability (black-box ML models)
- ❌ Suffer from bias–variance issues (single classifiers)

There is a need for a:

✔ Robust  
✔ Accurate  
✔ Explainable  
✔ IoT-compatible  

Intrusion Detection Framework.

---

## 🧠 Proposed Architecture

### 🔹 Level-1 (Base Learners)
- K-Nearest Neighbors (KNN)
- Decision Tree (DT)
- Logistic Regression (LR)
- Random Forest (RF)

### 🔹 Level-2 (Meta Learner)
- Multilayer Perceptron (MLP)

This **stacking ensemble architecture** improves:

- Detection accuracy  
- Model stability  
- Generalization across datasets  

---

## 🔍 Explainable AI (XAI)

To eliminate black-box behavior, SHAP-based explainability is integrated:

- Feature contribution analysis  
- Human-readable forensic reports  
- Class probability breakdown  
- Risk-level categorization  

The system explains:

- What attack was detected  
- Why it was detected  
- Which features influenced the decision  

---

## 📊 Datasets Used

The system is evaluated on benchmark intrusion datasets:

- **NSL-KDD**
- **ToN-IoT**
- **BoT-IoT**

It also supports CSV upload for custom dataset testing.

---

## 📈 Performance Highlights

The ensemble model achieves:

- ~98%+ Accuracy (NSL-KDD benchmark reference)
- High MCC score
- High F1-score stability
- Low Log Loss
- Reduced false positives

The stacking ensemble outperforms individual ML classifiers.

---

## 🖥️ System Features

### 🔹 Functional Features

- Upload IoT datasets (CSV)
- Real-time traffic injection simulation
- Multi-class attack detection
- Risk categorization (LOW / MEDIUM / HIGH / CRITICAL)
- SHAP-based explainability
- SOC-style dashboard visualization
- Historical traffic log storage

### 🔹 Non-Functional Features

- Scalable backend architecture
- Modular ML design
- Lightweight inference
- IoT-compatible processing
- Research extensibility

---

## 🏗️ Tech Stack

### Backend
- Python
- FastAPI
- Scikit-learn
- SHAP
- NumPy / Pandas

### Frontend
- React (Vite)
- Chart.js / Recharts
- Modern SOC-style UI

### Database
- MongoDB (traffic logs & history storage)

---

## 📂 Project Structure
```
xai-powered-ensemble-ids/
│
├── backend/
│ ├── app.py
│ ├── model_loader.py
│ ├── requirements.txt
│
├── frontend/
│ ├── src/
│ ├── package.json
│
├── README.md
└── .gitignore
```

---

## 🚀 How to Run

### 1️⃣ Backend

```bash
cd backend
pip install -r requirements.txt
uvicorn app:app --reload
```
Backend runs on: http://127.0.0.1:8000

### 2️⃣ Frontend

```bash
cd frontend
npm install
npm run dev
```
Frontend runs on:http://localhost:5173

## 🎯 Applications

- Smart Home Security

- Industrial IoT Protection

- Healthcare IoT (IoMT)

- Smart City Infrastructure

- IoT Edge Deployment

- Cybersecurity Research

## 🧪 Research Contribution

This project contributes by:

- Integrating stacking ensemble + Explainable AI

- Supporting multiple IoT datasets

- Providing deployment-ready architecture

- Delivering transparent forensic insights

- Reducing false positives while maintaining high accuracy

## 👨‍💻 Authors

- Koustub Maktal

- Rigved Katukam

- Ladella Sirivalli