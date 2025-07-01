import yaml
from flask import request
import os
import re

class RuleEngine:
    def __init__(self, rules_file="rules.yaml"):
        rules_path = os.path.join(os.path.dirname(__file__), rules_file)
        with open(rules_path, "r") as f:
            loaded = yaml.safe_load(f)
            if isinstance(loaded, dict) and "rules" in loaded:
                self.rules = loaded["rules"]
            else:
                self.rules = loaded

    def evaluate(self):
        path = request.path
        user_agent = request.headers.get("User-Agent", "").lower()
        query_string = request.query_string.decode("utf-8").lower()
        body = request.get_data(as_text=True).lower() if request.data else ""

        for rule in self.rules:
            pattern = rule.get("pattern")
            if pattern:
                # Only match pattern against query_string and body
                if re.search(pattern, query_string) or re.search(pattern, body):
                    return rule["id"]
        return None