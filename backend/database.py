import os
from pymongo import MongoClient
from dotenv import load_dotenv

load_dotenv()  # Load variables from .env

MONGO_URL = os.getenv("MONGO_URL")

if not MONGO_URL:
    raise ValueError("MONGO_URL environment variable not set!")

client = MongoClient(MONGO_URL)

db = client["ids_db"]
collection = db["traffic_logs"]