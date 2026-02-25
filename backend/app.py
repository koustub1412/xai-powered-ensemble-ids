
from fastapi import FastAPI, UploadFile, File, BackgroundTasks
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
        "dataset": result.get("dataset"),   # 🔥 NEW
        "prediction": result.get("prediction", "UNKNOWN"),
        "confidence": result.get("confidence", 0.0),   # 🔥 NEW
        "risk_level": result.get("risk_level", "UNKNOWN"),
        "explanation": result.get("explanation", ""),
        "input_features": input_data
    }

    collection.insert_one(log_document)

@app.post("/predict")
def predict_traffic(data: NetworkTraffic, background_tasks: BackgroundTasks):
    """Main endpoint to route traffic to specific ML models."""
    input_data = data.model_dump()
    
    # Extract the dataset type, default to 'nsl' if not provided
    dataset_type = input_data.pop("dataset_type", "nsl")
    
    # Route to the Multi-Model Manager via predictor.py
    result = predict_single(input_data, dataset_type)
    
    # Save log asynchronously to keep the API fast
    background_tasks.add_task(save_log_to_db, input_data, result)
    return result

@app.get("/history")
def get_history():
    """Returns the last 50 traffic logs."""
    logs = list(
        collection.find({}, {"_id": 0})
        .sort("timestamp", -1)
        .limit(50)
    )
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
        {"$limit": 5}
    ]
    distribution = list(collection.aggregate(pipeline))

    return {
        "total_packets": total,
        "critical_alerts": critical,
        "high_risk": high,
        "medium_risk": medium,
        "low_risk": low,
        # 'chart_data' provides the dynamic names for your React Pie Chart
        "chart_data": [{"name": d["_id"], "value": d["count"]} for d in distribution]
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
    try:
        df = pd.read_csv(file.file)

        results = []

        for _, row in df.iterrows():
            row_dict = row.to_dict()
            result = analyzer.analyze_traffic(row_dict, dataset)

            # 🔥 Save each row to Mongo
            save_log_to_db(row_dict, result)

            results.append(result)

        return {
            "dataset": dataset,
            "total_rows": len(results),
            "message": "Batch processed and stored successfully."
        }

    except Exception as e:
        return {"error": str(e)}