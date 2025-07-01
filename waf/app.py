from flask import Flask, request, abort
import requests
import os
import pandas as pd
import joblib
import importlib.util
from rules.rule_engine import RuleEngine
from database.mongodb_logger import MongoLogger
from proxy import forward_to_backend
mongo_logger = MongoLogger()

model = joblib.load("ml_model/waf_attack_model.pkl")
def extract_live_features(req):
    """
    Extracts 9 features from a live Flask request for ML model input.
    These features must match the features used during training.
    """

    payload_length = len(req.get_data())
    
    features = {
        "Flow Duration": 1,  # Placeholder, since live tracking of full flow duration requires connection state
        "Total Fwd Packets": 1,  # A single HTTP request = 1 forward packet
        "Total Backward Packets": 0,  # No response yet
        "Fwd Packet Length Max": payload_length,
        "Fwd Packet Length Min": payload_length,
        "Bwd Packet Length Max": 0,  # We don't know this yet
        "Bwd Packet Length Min": 0,
        "Flow Bytes/s": payload_length,  # Approximate – request bytes per second
        "Flow Packets/s": 1  # 1 packet/sec (approximate)
    }

    return features

rule_engine = RuleEngine("rules.yaml")
app = Flask(__name__)

PLUGIN_FOLDER = os.path.join(os.path.dirname(__file__), "plugins")
plugins = []

# Load plugins
for fname in os.listdir(PLUGIN_FOLDER):
    if fname.endswith(".py"):
        path = os.path.join(PLUGIN_FOLDER, fname)
        spec = importlib.util.spec_from_file_location(fname[:-3], path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        plugins.append(mod)

@app.before_request
def waf_filter():
    print(f"[WAF] Checking path: {request.path}")
    print(f"[WAF] User-Agent: {request.headers.get('User-Agent')}")
    features = extract_live_features(request)
    df = pd.DataFrame([features])  # ML model expects a DataFrame

    prediction = model.predict(df)[0]  # 1 = attack, 0 = safe
    print(f"[ML] Extracted Features: {features}")
    print(f"[ML] Prediction: {prediction}")

    if prediction == 1:
        mongo_logger.log(request, blocked=True, reason="Blocked by ML model", ml_prediction=prediction, features=features)
        abort(403)
    else:
        mongo_logger.log(request, blocked=False, reason="Allowed by ML model", ml_prediction=prediction, features=features)
    for plugin in plugins:
        if plugin.run(request):
            print(f"[WAF] Blocked by {plugin.__name__}")
            mongo_logger.log(request, blocked=True, reason=f"Plugin: {plugin.__name__}", is_plugin_blocked=True)
            abort(403)
    rule_id = rule_engine.evaluate()
    if rule_id:
        print(f"[WAF] Blocked by rule: {rule_id}")
        mongo_logger.log(request, blocked=True, reason=f"Rule: {rule_id}")
        abort(403)



@app.route('/', defaults={'path': ''}, methods=["GET", "POST", "PUT", "DELETE"])
@app.route('/<path:path>', methods=["GET", "POST", "PUT", "DELETE"])
def proxy(path):
    return forward_to_backend(path)
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
