from fastapi import FastAPI, UploadFile, File, BackgroundTasks, Form
from fastapi.middleware.cors import CORSMiddleware
from schemas import NetworkTraffic
from predictor import predict_single
from database import collection
from model_loader import analyzer
import pandas as pd
from datetime import datetime, timezone
from bson import ObjectId

app = FastAPI(title="Hybrid IDS API")

print("🔥 THIS IS THE CORRECT APP.PY LOADED 🔥")

# --- CORS SETUP ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def save_log_to_db(input_data: dict, result: dict):
    """Saves prediction result to MongoDB."""

    log_document = {
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "dataset": result.get("dataset"),  # 🔥 NEW
        "prediction": result.get("prediction", "UNKNOWN"),
        "confidence": result.get("confidence", 0.0),  # 🔥 NEW
        "risk_level": result.get("risk_level", "UNKNOWN"),
        "explanation": result.get("explanation", ""),
        "input_features": input_data,
    }

    collection.insert_one(log_document)


@app.post("/predict")
def predict_traffic(data: NetworkTraffic, background_tasks: BackgroundTasks):
    """Main endpoint to route traffic to specific ML models."""
    input_data = data.model_dump()

    # Extract the dataset type, default to 'nsl' if not provided
    dataset_type = input_data.pop("dataset_type", "nsl")
    enable_xai = input_data.pop("enable_xai", True)

    # Route to the Multi-Model Manager via predictor.py
    result = predict_single(input_data, dataset_type, enable_xai)

    # Save log asynchronously to keep the API fast
    background_tasks.add_task(save_log_to_db, input_data, result)
    return result


@app.get("/history")
def get_history():
    """Returns the last 50 traffic logs."""
    logs = list(collection.find({}, {"_id": 0}).sort("timestamp", -1).limit(50))
    return logs


# --- 🚀 UPDATED: CATEGORY-AGNOSTIC STATS & CHART ROUTE ---
@app.get("/stats")
def get_stats():
    """
    Dynamically calculates stats for all models (NSL, ToN, BoT).
    Uses Risk Levels for cards and Aggregation for the Pie Chart.
    """
    total = collection.count_documents({})

    # 1. Counts based on Risk Level (Universal across all models)
    critical = collection.count_documents({"risk_level": "CRITICAL"})
    high = collection.count_documents({"risk_level": "HIGH"})
    medium = collection.count_documents({"risk_level": "MEDIUM"})
    low = collection.count_documents({"risk_level": "LOW"})

    # 2. Dynamic Attack Distribution Chart Data
    # This groups by 'prediction' and finds the top 5 most frequent attacks
    pipeline = [
        {"$group": {"_id": "$prediction", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
        {"$limit": 5},
    ]
    distribution = list(collection.aggregate(pipeline))

    return {
        "total_packets": total,
        "critical_alerts": critical,
        "high_risk": high,
        "medium_risk": medium,
        "low_risk": low,
        # 'chart_data' provides the dynamic names for your React Pie Chart
        "chart_data": [{"name": d["_id"], "value": d["count"]} for d in distribution],
    }


@app.delete("/delete/{timestamp}")
def delete_log(timestamp: str):
    """Delete a specific log by its timestamp string."""
    result = collection.delete_one({"timestamp": timestamp})
    if result.deleted_count:
        return {"status": "success", "message": "Log deleted"}
    return {"status": "error", "message": "Log not found"}


@app.delete("/clear-all")
def clear_all_logs():
    """Clear the entire traffic_logs collection."""
    collection.delete_many({})
    return {"status": "success", "message": "All logs cleared"}


@app.post("/predict-file/{dataset}")
async def predict_file(dataset: str, file: UploadFile = File(...)):
    df = pd.read_csv(file.file)

    # 1️⃣ Fast batch prediction
    if dataset == "nsl":
        results = analyzer.batch_predict_nsl(df)
    elif dataset == "ton":
        results = analyzer.batch_predict_ton(df)
    elif dataset == "bot":
        results = analyzer.batch_predict_bot(df)
    else:
        return {"error": "Invalid dataset"}
    bulk_docs = []

    # 2️⃣ Select suspicious rows for SHAP
    attack_rows = [
        (i, r["confidence"])
        for i, r in enumerate(results)
        if r["prediction"].lower() != "normal"
    ]

    attack_rows = sorted(attack_rows, key=lambda x: x[1], reverse=True)

    suspicious_indices = [i for i, _ in attack_rows[:5]]

    # Limit to top 5 only
    suspicious_indices = suspicious_indices[:5]

    for i, row in df.iterrows():
        explanation_text = (
            "✅ This traffic instance aligns with normal network behaviour patterns. "
            "No significant threat indicators were identified."
        )

        # 3️⃣ Run SHAP only for selected rows
        if i in suspicious_indices:

            # 🔹 Prepare input correctly based on dataset
            if dataset == "nsl":
                X_shap = analyzer._prepare_nsl_for_shap(row)
                pred_idx = analyzer.nsl_classes.index(results[i]["prediction"])

            elif dataset == "ton":
                X_shap = analyzer._prepare_ton_for_shap(row)
                pred_idx = list(analyzer.ton_classes).index(
                    results[i]["prediction"].lower()
                )

            elif dataset == "bot":
                X_shap = analyzer._prepare_bot_for_shap(row)
                pred_idx = analyzer.bot_classes.index(results[i]["prediction"])

            # 🔹 Now safe SHAP call
            explanation_text = analyzer._get_shap_explanation(
                X_shap, dataset, predicted_class=pred_idx, top_k=5
            )

        bulk_docs.append(
            {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "dataset": dataset,
                "prediction": results[i]["prediction"],
                "confidence": results[i]["confidence"],
                "risk_level": results[i]["risk_level"],
                "explanation": explanation_text,
                "input_features": row.to_dict(),
            }
        )

    collection.insert_many(bulk_docs)

    return {
        "total_rows": len(results),
        "xai_rows": len(suspicious_indices),
        "message": "Batch processed with selective XAI.",
    }


# @app.post("/predict-file/{dataset}")
# async def predict_file(
#     dataset: str,
#     file: UploadFile = File(...)
# ):
#     try:
#         df = pd.read_csv(file.file)

#         bulk_documents = []

#         for _, row in df.iterrows():
#             row_dict = row.to_dict()

#             # 🚀 Disable XAI for batch (huge speed gain)
#             result = analyzer.analyze_traffic(
#                 row_dict,
#                 dataset,
#                 enable_xai=False
#             )

#             log_document = {
#                 "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
#                 "prediction": result.get("prediction", "UNKNOWN"),
#                 "risk_level": result.get("risk_level", "UNKNOWN"),
#                 "confidence": result.get("confidence", 0),
#                 "dataset": result.get("dataset"),
#                 "explanation": result.get("explanation", ""),
#                 "input_features": row_dict
#             }

#             bulk_documents.append(log_document)

#         # 🔥 SINGLE DB INSERT (VERY FAST)
#         if bulk_documents:
#             collection.insert_many(bulk_documents)

#         return {
#             "dataset": dataset,
#             "total_rows": len(bulk_documents),
#             "message": "Batch processed and stored successfully."
#         }

#     except Exception as e:
#         return {"error": str(e)}
