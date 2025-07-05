from flask import Flask, request, abort, Response
import requests
import os
import importlib.util
from pymongo import MongoClient
from datetime import datetime
import joblib
import numpy as np
from database.mongodb_logger import MongoLogger
#load ml model
model = joblib.load("ml_model/waf_attack_model.pkl")
#load mongodb logger
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