from flask import Flask, request, abort, Response
import requests
import os
import importlib.util
from pymongo import MongoClient
from datetime import datetime
import joblib
import numpy as np
from database.mongodb_logger import MongoLogger
from ml_model.enhanced_ml_manager import EnhancedMLModelManager

# Initialize enhanced ML manager
ml_manager = EnhancedMLModelManager(models_dir="ml_model")
ml_manager.set_current_model("v1.0.0")  # Set your actual model version here

# Load mongodb logger
mongo_logger = MongoLogger()

def forward_to_backend(path):
    backend_url = f"http://localhost:8000/{path}"
    try:
        resp = requests.request(
            method=request.method,
            url=backend_url,
            headers={k: v for k, v in request.headers if k != 'Host'},
            data=request.get_data(),
            cookies=request.cookies,
            allow_redirects=False
        )
        return resp.content, resp.status_code, resp.headers.items()
    except requests.RequestException as e:
        error_message = f"Backend unreachable or error: {str(e)}"
        return Response(error_message, status=502)

# Example endpoint for WAF analysis (add to your Flask app)
app = Flask(__name__)

@app.route('/<path:path>', methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
def waf_proxy(path):
    # Prepare request data for ML
    request_data = {
        "url": request.path,
        "method": request.method,
        "remote_addr": request.remote_addr,
        "headers": dict(request.headers),
        "body": request.get_data(as_text=True)
    }
    prediction = ml_manager.predict(request_data)
    if prediction.is_malicious:
        mongo_logger.log(request, blocked=True, reason="ML malicious", ml_prediction=prediction.to_dict(), features=prediction.features_used)
        return Response("Blocked by WAF (ML detected attack)", status=403)
    # Log allowed requests as well
    mongo_logger.log(request, blocked=False, ml_prediction=prediction.to_dict(), features=prediction.features_used)
    # Forward to backend
    content, status, headers = forward_to_backend(path)
    return Response(content, status=status, headers=dict(headers))