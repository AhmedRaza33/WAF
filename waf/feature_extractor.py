from ml_model.enhanced_ml_manager import NetworkFlowExtractor

# Create a singleton extractor instance
flow_extractor = NetworkFlowExtractor()


def extract_live_features_from_request(req, interface=None, sniff_duration=2):
    request_data = {
        "url": getattr(req, "path", None),
        "method": getattr(req, "method", None),
        "remote_addr": getattr(req, "remote_addr", None),
        "headers": dict(getattr(req, "headers", {})),
        "body": req.get_data(as_text=True) if hasattr(req, "get_data") else None
    }
    return flow_extractor.extract_features_from_request(request_data, interface=interface, sniff_duration=sniff_duration)