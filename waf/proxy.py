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

# List available models and set the first one as current
available_models = ml_manager.list_models()
if available_models:
    ml_manager.set_current_model(available_models[0])
    print(f"Using model version: {available_models[0]}")
else:
    print("No models available. Creating a dummy model for testing...")
    # Create a simple dummy model for testing
    from sklearn.ensemble import RandomForestClassifier
    import numpy as np
    
    # Create a dummy model
    dummy_model = RandomForestClassifier(n_estimators=10, random_state=42)
    # Train on dummy data
    X_dummy = np.random.rand(100, 9)  # 9 features as expected
    y_dummy = np.random.randint(0, 2, 100)
    dummy_model.fit(X_dummy, y_dummy)
    
    # Register the dummy model
    ml_manager.register_model(
        version="v1.0.0",
        model=dummy_model,
        metadata={
            'description': 'Dummy WAF attack detector for testing',
            'training_data': 'Dummy data',
            'features': 'Network flow statistics',
            'accuracy': 0.5
        }
    )
    ml_manager.set_current_model("v1.0.0")
    print("Dummy model created and set as current")

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