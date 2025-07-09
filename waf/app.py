from flask import Flask, request, abort
import requests
import os
import pandas as pd
import importlib.util
from rules.rule_engine import RuleEngine
from database.mongodb_logger import MongoLogger
from proxy import forward_to_backend
mongo_logger = MongoLogger()
from feature_extractor import extract_live_features_from_request
from ml_model.enhanced_ml_manager import EnhancedMLModelManager
import time

flow_stats = {}

rule_engine = RuleEngine("rules.yaml")
app = Flask(__name__)
MAX_REQUESTS = 2      # requests
WINDOW = 60           # seconds
BLOCK_TIME = 60       # seconds

PLUGIN_FOLDER = os.path.join(os.path.dirname(__file__), "plugins")
plugins = []

# Load plugins
for fname in os.listdir(PLUGIN_FOLDER):
    if fname.endswith(".py"):
        path = os.path.join(PLUGIN_FOLDER, fname)
        spec = importlib.util.spec_from_file_location(fname[:-3], path)
        if spec and spec.loader:
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            plugins.append(mod)

# Initialize Enhanced ML Manager
ml_manager = EnhancedMLModelManager(models_dir="ml_model")
ml_manager.set_current_model("v1.0.0")

@app.before_request
def waf_filter():
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    # 1. Check if IP is blocked
    if mongo_logger.is_ip_blocked(ip):
        print(f"This Ip is Blocked!!!")
        abort(429, "Too many requests. Try again later.")
        

    # 2. Increment request count and check limit
    req_count = mongo_logger.increment_request_count(ip, WINDOW)
    if req_count > MAX_REQUESTS:
        mongo_logger.block_ip(ip, BLOCK_TIME)
        print(f"Too many requests!!!")
        abort(429, "Too many requests. Try again later.")
        
    print(f"[WAF] Checking path: {request.path}")
    print(f"[WAF] User-Agent: {request.headers.get('User-Agent')}")
    features = extract_live_features_from_request(request)

    blocked = False
    reason = "Allowed"
    ml_prediction = None
    is_plugin_blocked = False
    rule_id = None

    # Prepare request_data for ML manager
    request_data = {
        "url": request.path,
        "method": request.method,
        "remote_addr": request.remote_addr,
        "headers": dict(request.headers),
        "body": request.get_data(as_text=True)
    }
    prediction_result = ml_manager.predict(request_data)
    print(f"[ML] Extracted Features: {features}")
    print(f"[ML] Prediction: {prediction_result.is_malicious}, Confidence: {prediction_result.confidence}")

    if prediction_result.is_malicious:
        blocked = True
        reason = "Blocked by ML model"
    else:
        # Only check plugins if ML allows
        for plugin in plugins:
            if plugin.run(request):
                print(f"[WAF] Blocked by {plugin.__name__}")
                blocked = True
                reason = f"Plugin: {plugin.__name__}"
                is_plugin_blocked = True
                break
        # Only check rules if not already blocked
        if not blocked:
            rule_id = rule_engine.evaluate()
            if rule_id:
                print(f"[WAF] Blocked by rule: {rule_id}")
                blocked = True
                reason = f"Rule: {rule_id}"

    mongo_logger.log(
        request,
        blocked=blocked,
        reason=reason,
        ml_prediction=prediction_result.to_dict(),
        is_plugin_blocked=is_plugin_blocked,
        features=features
    )
    if blocked:
        abort(403)

@app.route('/', defaults={'path': ''}, methods=["GET", "POST", "PUT", "DELETE"])
@app.route('/<path:path>', methods=["GET", "POST", "PUT", "DELETE"])
def proxy(path):
    return forward_to_backend(path)
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)