# mongo_logger.py
from pymongo import MongoClient
from datetime import datetime
import numpy as np

class MongoLogger:
    def __init__(self, uri="mongodb://localhost:27017", db_name="waf_logs", collection_name="requests"):
        self.client = MongoClient(uri)
        self.collection = self.client[db_name][collection_name]

    def _to_python_type(self, obj):
        if isinstance(obj, np.generic):
            return obj.item()
        elif isinstance(obj, dict):
            return {k: self._to_python_type(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._to_python_type(v) for v in obj]
        else:
            return obj

    def log(self, request, blocked, reason=None, ml_prediction=None, is_plugin_blocked=False, features=None, tags=None):
        log_entry = {
            "timestamp": datetime.utcnow(),
            "path": request.path,
            "method": request.method,
            "user_agent": request.headers.get("User-Agent", ""),
            "query": request.query_string.decode(),
            "body": request.get_data(as_text=True),
            "remote_addr": request.remote_addr,
            "blocked": blocked,
            "reason": reason,
            "ml_prediction": ml_prediction,
            "is_plugin_blocked": is_plugin_blocked,
            "features_used": features,
            "tags": tags or []
        }
        log_entry = self._to_python_type(log_entry)
        self.collection.insert_one(log_entry)
