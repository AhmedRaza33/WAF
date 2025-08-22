#!/usr/bin/env python3
"""
Sample Data Generator for WAF Dashboard
This script generates sample request data and blocked IPs for testing the dashboard.
"""

import requests
import random
import time
from datetime import datetime, timedelta, timezone
import json

# WAF Dashboard URL
DASHBOARD_URL = "http://localhost:5001"

# Sample attack patterns
ATTACK_PATTERNS = [
    "SQL Injection - basic SQL keywords",
    "XSS - script tag",
    "Command Injection - shell metacharacters",
    "Path Traversal attempt",
    "Local File Inclusion",
    "Remote File Inclusion",
    "XML External Entity (XXE) attack",
    "SSRF - accessing internal services",
    "Insecure Deserialization",
    "Broken Authentication",
    "Potential IDOR"
]

# Sample paths
SAMPLE_PATHS = [
    "/admin/login",
    "/api/users",
    "/search",
    "/upload",
    "/download",
    "/profile",
    "/settings",
    "/api/data",
    "/login",
    "/register"
]

# Sample user agents
SAMPLE_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_7_1 like Mac OS X) AppleWebKit/605.1.15",
    "Mozilla/5.0 (Android 11; Mobile; rv:68.0) Gecko/68.0 Firefox/88.0",
    "python-requests/2.25.1",
    "curl/7.68.0",
    "Wget/1.20.3"
]

# Sample IP addresses (some malicious, some normal)
SAMPLE_IPS = [
    "192.168.1.100",  # Normal
    "10.0.0.50",      # Normal
    "172.16.0.25",    # Normal
    "203.0.113.45",   # Potentially malicious
    "198.51.100.123", # Potentially malicious
    "45.67.89.234",   # Potentially malicious
    "185.220.101.67", # Potentially malicious
    "91.234.56.78",   # Potentially malicious
    "192.168.1.101",  # Normal
    "10.0.0.51"       # Normal
]

def generate_sample_request():
    """Generate a sample request entry"""
    now = datetime.now(timezone.utc)
    
    # Randomly decide if this request should be blocked
    is_blocked = random.random() < 0.3  # 30% chance of being blocked
    
    request_data = {
        "timestamp": now.isoformat(),
        "path": random.choice(SAMPLE_PATHS),
        "method": random.choice(["GET", "POST", "PUT", "DELETE", "HEAD"]),
        "user_agent": random.choice(SAMPLE_USER_AGENTS),
        "query": f"param1={random.randint(1, 1000)}&param2={random.choice(['value1', 'value2', 'value3'])}" if random.random() < 0.5 else "",
        "body": f"data={random.randint(1000, 9999)}" if random.random() < 0.3 else "",
        "remote_addr": random.choice(SAMPLE_IPS),
        "blocked": is_blocked,
        "reason": random.choice(ATTACK_PATTERNS) if is_blocked else None,
        "ml_prediction": round(random.uniform(0.1, 0.9), 3) if is_blocked else round(random.uniform(0.1, 0.3), 3),
        "is_plugin_blocked": random.random() < 0.2 if is_blocked else False,
        "features_used": ["url_length", "method", "user_agent"] if is_blocked else ["url_length"],
        "tags": ["suspicious"] if is_blocked else ["normal"]
    }
    
    return request_data

def send_sample_request(request_data):
    """Send a sample request to the dashboard API"""
    try:
        # Simulate sending to the WAF (this would normally go through the actual WAF)
        # For now, we'll just print the data
        print(f"Generated request: {request_data['method']} {request_data['path']} from {request_data['remote_addr']} - {'BLOCKED' if request_data['blocked'] else 'ALLOWED'}")
        
        # In a real scenario, you would send this to the WAF's logging endpoint
        # For testing, we can manually insert into MongoDB or use the dashboard API
        
    except Exception as e:
        print(f"Error sending request: {e}")

def generate_blocked_ip():
    """Generate a sample blocked IP entry"""
    now = datetime.now(timezone.utc)
    duration = random.choice([300, 900, 1800, 3600, 7200, 14400])  # 5min to 4 hours
    unblock_time = now + timedelta(seconds=duration)
    
    ip_data = {
        "ip": random.choice(SAMPLE_IPS),
        "unblock_time": unblock_time.isoformat(),
        "reason": random.choice(ATTACK_PATTERNS),
        "blocked_at": now.isoformat()
    }
    
    return ip_data

def main():
    """Main function to generate sample data"""
    print("WAF Dashboard Sample Data Generator")
    print("=" * 40)
    
    # Generate sample requests
    print("\nGenerating sample requests...")
    for i in range(50):  # Generate 50 sample requests
        request_data = generate_sample_request()
        send_sample_request(request_data)
        time.sleep(0.1)  # Small delay between requests
    
    # Generate sample blocked IPs
    print("\nGenerating sample blocked IPs...")
    for i in range(5):  # Generate 5 blocked IPs
        ip_data = generate_blocked_ip()
        print(f"Blocked IP: {ip_data['ip']} until {ip_data['unblock_time']}")
    
    print("\nSample data generation complete!")
    print(f"\nDashboard URL: {DASHBOARD_URL}")
    print("You can now view the data in the WAF Dashboard.")
    print("\nNote: This script only generates sample data structures.")
    print("To actually populate the database, you would need to:")
    print("1. Ensure MongoDB is running")
    print("2. Use the WAF's actual logging functionality")
    print("3. Or manually insert the data into the MongoDB collections")

if __name__ == "__main__":
    main()
