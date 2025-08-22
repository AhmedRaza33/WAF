import json
import pickle
import hashlib
import logging
import numpy as np
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, asdict
from pathlib import Path
import sqlite3
from threading import Lock
import random
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
import joblib
from collections import defaultdict
import time

# Import your network flow extraction
try:
    from scapy.all import sniff, IP, TCP
    SCAPY_AVAILABLE = True
except Exception as e:
    print(f"[WAF] WARNING: Scapy not available: {e}")
    SCAPY_AVAILABLE = False

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class PredictionResult:
    """Structure for ML prediction results"""
    is_malicious: bool
    confidence: float
    model_version: str
    features_used: Dict[str, float]  # Changed to Dict for numerical features
    prediction_time: datetime
    request_hash: str
    
    def to_dict(self) -> Dict:
        result = asdict(self)
        result['prediction_time'] = self.prediction_time.isoformat()
        return result

class NetworkFlowExtractor:
    """Enhanced network flow feature extraction"""
    
    def __init__(self):
        self.flows = defaultdict(lambda: {
            "start_time": None,
            "fwd_packets": 0,
            "fwd_bytes": 0,
            "bwd_packets": 0,
            "bwd_bytes": 0,
            "packets": []  # Store packet timestamps for advanced features
        })
        self.lock = Lock()
    
    def process_packet(self, pkt):
        """Process captured packet and update flow statistics"""
        if not SCAPY_AVAILABLE or not (IP in pkt and TCP in pkt):
            return
            
        with self.lock:
            ip_layer = pkt[IP]
            tcp_layer = pkt[TCP]
            
            fwd_key = (ip_layer.src, ip_layer.dst, tcp_layer.sport, tcp_layer.dport)
            bwd_key = (ip_layer.dst, ip_layer.src, tcp_layer.dport, tcp_layer.sport)
            
            current_time = time.time()
            
            if fwd_key in self.flows:
                flow = self.flows[fwd_key]
                direction = "fwd"
            elif bwd_key in self.flows:
                flow = self.flows[bwd_key]
                direction = "bwd"
            else:
                flow = self.flows[fwd_key]
                flow["start_time"] = current_time
                direction = "fwd"
            
            # Update flow statistics
            if direction == "fwd":
                flow["fwd_packets"] += 1
                flow["fwd_bytes"] += len(pkt)
            else:
                flow["bwd_packets"] += 1
                flow["bwd_bytes"] += len(pkt)
            
            # Store packet info for advanced features
            flow["packets"].append({
                "timestamp": current_time,
                "size": len(pkt),
                "direction": direction
            })
    
    def extract_flow_features(self, flow_key) -> Dict[str, float]:
        """Extract comprehensive flow features"""
        flow = self.flows.get(flow_key)
        if not flow or not flow["start_time"]:
            return self._get_default_features()
        
        current_time = time.time()
        duration = max(current_time - flow["start_time"], 0.001)  # Avoid division by zero
        
        total_packets = flow["fwd_packets"] + flow["bwd_packets"]
        total_bytes = flow["fwd_bytes"] + flow["bwd_bytes"]
        
        # Calculate packet size statistics
        fwd_sizes = [p["size"] for p in flow["packets"] if p["direction"] == "fwd"]
        bwd_sizes = [p["size"] for p in flow["packets"] if p["direction"] == "bwd"]
        
        features = {
            "Flow Duration": duration,
            "Tot Fwd Pkts": flow["fwd_packets"],
            "Tot Bwd Pkts": flow["bwd_packets"],
            "TotLen Fwd Pkts": flow["fwd_bytes"],
            "TotLen Bwd Pkts": flow["bwd_bytes"],
            "Fwd Pkt Len Min": min(fwd_sizes) if fwd_sizes else 0,
            "Bwd Pkt Len Min": min(bwd_sizes) if bwd_sizes else 0,
            "Flow Byts/s": total_bytes / duration,
            "Flow Pkts/s": total_packets / duration,
        }
        
        return features
    
    def _get_default_features(self) -> Dict[str, float]:
        """Return default features when flow data is unavailable"""
        return {
            "Flow Duration": 1.0,
            "Tot Fwd Pkts": 1,
            "Tot Bwd Pkts": 1,
            "TotLen Fwd Pkts": 100,
            "TotLen Bwd Pkts": 100,
            "Fwd Pkt Len Min": 100,
            "Bwd Pkt Len Min": 100,
            "Flow Byts/s": 200,
            "Flow Pkts/s": 2,
        }
    
    def extract_features_from_request(self, request_data: Dict[str, Any], 
                                 interface=None, sniff_duration=2) -> Dict[str, float]:
        """Extract features from HTTP request with network flow analysis"""
        # Set default interface if not provided
        if interface is None:
            interface = "\\Device\\NPF_Loopback"  # or your actual interface name
        # If scapy is not available, return default features
        if not SCAPY_AVAILABLE:
            return self._get_default_features()
        try:
            # Sniff packets for short duration to capture flow
            sniff(iface=interface, prn=self.process_packet, timeout=sniff_duration, count=20)
            # Try to find matching flow based on request source
            src_ip = request_data.get('remote_addr')
            if src_ip:
                for flow_key in self.flows:
                    if flow_key[0] == src_ip or flow_key[1] == src_ip:
                        return self.extract_flow_features(flow_key)
            # If no matching flow found, return default
            return self._get_default_features()
        except Exception as e:
            logger.warning(f"Could not extract network features: {e}")
            return self._get_default_features()

class EnhancedMLModelManager:
    """Enhanced ML Model Manager with network flow feature extraction"""
    
    def __init__(self, models_dir: str = "waf/ml_model", db_path: str = "waf_feedback.db"):
        self.models_dir = Path(models_dir)
        self.models_dir.mkdir(exist_ok=True)
        self.models: Dict[str, Any] = {}
        self.current_model_version = None
        self.lock = Lock()
        
        # Initialize network flow extractor
        self.flow_extractor = NetworkFlowExtractor()
        
        # Feature names expected by the model
        self.feature_names = [
            "Flow Duration", "Tot Fwd Pkts", "Tot Bwd Pkts",
            "TotLen Fwd Pkts", "Fwd Pkt Len Min",
            "TotLen Bwd Pkts", "Bwd Pkt Len Min",
            "Flow Byts/s", "Flow Pkts/s"
        ]
        
        # Load existing models
        self._load_existing_models()
    
    def _load_existing_models(self):
        """Load all existing model versions"""
        for version_dir in self.models_dir.iterdir():
            if version_dir.is_dir():
                try:
                    metadata_path = version_dir / "metadata.json"
                    model_path = version_dir / "model.pkl"
                    
                    if metadata_path.exists() and model_path.exists():
                        with open(metadata_path) as f:
                            metadata = json.load(f)
                        
                        # Load the model
                        model = joblib.load(model_path)
                        
                        self.models[version_dir.name] = {
                            'model': model,
                            'metadata': metadata,
                            'loaded_at': datetime.now(timezone.utc)
                        }
                        
                        logger.info(f"Loaded model version {version_dir.name}")
                except Exception as e:
                    logger.error(f"Failed to load model {version_dir.name}: {e}")
    
    def register_model(self, version: str, model, metadata: Dict[str, Any]):
        """Register a new model version"""
        version_dir = self.models_dir / version
        version_dir.mkdir(exist_ok=True)
        
        # Save model
        model_path = version_dir / "model.pkl"
        joblib.dump(model, model_path)
        
        # Save metadata
        metadata['created_at'] = datetime.now(timezone.utc).isoformat()
        metadata['version'] = version
        metadata['feature_names'] = self.feature_names
        
        with open(version_dir / "metadata.json", 'w') as f:
            json.dump(metadata, f, indent=2)
        
        # Store in memory
        self.models[version] = {
            'model': model,
            'metadata': metadata,
            'loaded_at': datetime.now(timezone.utc)
        }
        
        logger.info(f"Registered new model version {version}")
        return True
    
    def set_current_model(self, version: str):
        """Set the current active model version"""
        if version not in self.models:
            raise ValueError(f"Model version {version} not found")
        
        with self.lock:
            self.current_model_version = version
            logger.info(f"Set current model to version {version}")
    
    def predict(self, request_data: Dict[str, Any]) -> PredictionResult:
        """Make prediction using network flow features"""
        if not self.current_model_version:
            raise ValueError("No active model available")
        
        # Extract network flow features
        features = self.flow_extractor.extract_features_from_request(request_data)
        
        # Ensure features are in correct order
        feature_vector = np.array([features[name] for name in self.feature_names]).reshape(1, -1)
        
        # Get model
        model_info = self.models[self.current_model_version]
        model = model_info['model']
        
        # Make prediction
        prediction = model.predict(feature_vector)[0]
        probabilities = model.predict_proba(feature_vector)[0]
        confidence = max(probabilities)
        
        # Generate request hash
        request_hash = self._generate_request_hash(request_data)
        
        # Create prediction result
        result = PredictionResult(
            is_malicious=bool(prediction),
            confidence=confidence,
            model_version=self.current_model_version,
            features_used=features,
            prediction_time=datetime.now(timezone.utc),
            request_hash=request_hash
        )
        
        return result
    
    def _generate_request_hash(self, request_data: Dict[str, Any]) -> str:
        """Generate unique hash for request"""
        # Create a simplified hash based on key request components
        hash_data = {
            'url': request_data.get('url', ''),
            'method': request_data.get('method', ''),
            'remote_addr': request_data.get('remote_addr', ''),
            'timestamp': int(time.time())
        }
        request_str = json.dumps(hash_data, sort_keys=True)
        return hashlib.sha256(request_str.encode()).hexdigest()
    
    def get_model_info(self, version: str = None) -> Dict[str, Any]:
        """Get information about a specific model version"""
        target_version = version or self.current_model_version
        
        if target_version not in self.models:
            return {}
        
        model_info = self.models[target_version]
        return {
            'version': target_version,
            'metadata': model_info['metadata'],
            'loaded_at': model_info['loaded_at'].isoformat(),
            'feature_names': self.feature_names
        }
    
    def list_models(self) -> List[str]:
        """List all available model versions"""
        return list(self.models.keys()) 