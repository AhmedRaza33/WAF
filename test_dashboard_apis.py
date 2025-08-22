#!/usr/bin/env python3
"""
Test Dashboard APIs
This script tests the dashboard APIs to ensure they're working correctly.
"""

import requests
import json

# Dashboard URL
DASHBOARD_URL = "http://localhost:5001"

def test_api_endpoint(endpoint, description):
    """Test an API endpoint and display results"""
    try:
        print(f"\n🔍 Testing {description}...")
        print(f"   URL: {DASHBOARD_URL}{endpoint}")
        
        response = requests.get(f"{DASHBOARD_URL}{endpoint}")
        
        if response.status_code == 200:
            data = response.json()
            print(f"   ✅ Status: {response.status_code}")
            print(f"   📊 Data: {json.dumps(data, indent=2)}")
        else:
            print(f"   ❌ Status: {response.status_code}")
            print(f"   📄 Response: {response.text}")
            
    except requests.exceptions.ConnectionError:
        print(f"   ❌ Connection Error: Could not connect to {DASHBOARD_URL}")
    except Exception as e:
        print(f"   ❌ Error: {e}")

def main():
    """Test all dashboard APIs"""
    print("🧪 Testing WAF Dashboard APIs")
    print("=" * 50)
    
    # Test stats API
    test_api_endpoint("/api/stats", "Statistics API")
    
    # Test blocked IPs API
    test_api_endpoint("/api/blocked-ips", "Blocked IPs API")
    
    # Test requests API
    test_api_endpoint("/api/requests", "Requests API")
    
    # Test rules API
    test_api_endpoint("/api/rules", "Rules API")
    
    # Test analytics API
    test_api_endpoint("/api/analytics", "Analytics API")
    
    print("\n" + "=" * 50)
    print("✅ API testing complete!")
    print(f"\n🌐 Dashboard URL: {DASHBOARD_URL}")
    print("📖 Check the dashboard in your browser to see the data!")

if __name__ == "__main__":
    main()
