#!/usr/bin/env python3
"""
Debug MongoDB Connection and Data
This script helps debug the MongoDB connection and shows what data is available.
"""

from pymongo import MongoClient
from datetime import datetime, timezone
import json

def debug_mongodb():
    """Debug MongoDB connection and data"""
    try:
        # Connect to MongoDB
        print("Connecting to MongoDB...")
        client = MongoClient("mongodb://localhost:27017")
        
        # Test connection
        client.admin.command('ping')
        print("✅ MongoDB connection successful!")
        
        # List databases
        print("\n📚 Available databases:")
        for db_name in client.list_database_names():
            print(f"  - {db_name}")
        
        # Check waf_logs database
        if 'waf_logs' in client.list_database_names():
            print("\n🔍 WAF Logs Database:")
            db = client['waf_logs']
            
            # List collections
            print("  Collections:")
            for collection_name in db.list_collection_names():
                print(f"    - {collection_name}")
            
            # Check blocked_ips collection
            if 'blocked_ips' in db.list_collection_names():
                blocked_ips = db['blocked_ips']
                blocked_count = blocked_ips.count_documents({})
                print(f"\n🚫 Blocked IPs Collection: {blocked_count} documents")
                
                if blocked_count > 0:
                    print("  Sample blocked IPs:")
                    for ip in blocked_ips.find().limit(5):
                        unblock_time = ip.get('unblock_time')
                        current_time = datetime.now(timezone.utc)
                        
                        # Handle timezone-naive timestamps
                        if unblock_time and unblock_time.tzinfo is None:
                            # Assume UTC if no timezone info
                            unblock_time = unblock_time.replace(tzinfo=timezone.utc)
                        
                        print(f"    - IP: {ip.get('ip')}")
                        print(f"      Unblock Time: {ip.get('unblock_time')}")
                        print(f"      Current Time: {current_time}")
                        if unblock_time:
                            is_blocked = unblock_time > current_time
                            print(f"      Is Still Blocked: {is_blocked}")
                        print()
            
            # Check requests collection
            if 'requests' in db.list_collection_names():
                requests = db['requests']
                requests_count = requests.count_documents({})
                print(f"\n📊 Requests Collection: {requests_count} documents")
                
                if requests_count > 0:
                    print("  Sample requests:")
                    for req in requests.find().limit(3):
                        print(f"    - IP: {req.get('remote_addr')}")
                        print(f"      Method: {req.get('method')}")
                        print(f"      Path: {req.get('path')}")
                        print(f"      Timestamp: {req.get('timestamp')}")
                        print(f"      Blocked: {req.get('blocked')}")
                        print(f"      Reason: {req.get('reason')}")
                        print()
                    
                    # Check recent requests (last 24 hours)
                    from datetime import timedelta
                    yesterday = datetime.now(timezone.utc) - timedelta(hours=24)
                    recent_count = requests.count_documents({"timestamp": {"$gte": yesterday}})
                    print(f"  Recent requests (last 24h): {recent_count}")
                    
                    # Check all time requests
                    all_time_count = requests.count_documents({})
                    print(f"  All time requests: {all_time_count}")
                    
                    # Check blocked requests
                    blocked_requests_count = requests.count_documents({"blocked": True})
                    print(f"  Blocked requests: {blocked_requests_count}")
                    
                    # Check allowed requests
                    allowed_requests_count = requests.count_documents({"blocked": False})
                    print(f"  Allowed requests: {allowed_requests_count}")
            
            # Check ip_requests collection
            if 'ip_requests' in db.list_collection_names():
                ip_requests = db['ip_requests']
                ip_requests_count = ip_requests.count_documents({})
                print(f"\n🌐 IP Requests Collection: {ip_requests_count} documents")
        
        else:
            print("\n❌ WAF Logs database not found!")
            print("Available databases:", client.list_database_names())
        
        # Test the specific queries used in the dashboard
        print("\n🧪 Testing Dashboard Queries:")
        
        if 'waf_logs' in client.list_database_names():
            db = client['waf_logs']
            
            # Test blocked IPs query
            if 'blocked_ips' in db.list_collection_names():
                print("\n  Testing Blocked IPs Query:")
                current_time = datetime.now(timezone.utc)
                print(f"    Current time: {current_time}")
                
                # Query 1: All blocked IPs
                all_blocked = list(db['blocked_ips'].find({}))
                print(f"    All blocked IPs: {len(all_blocked)}")
                for ip in all_blocked:
                    print(f"      - {ip.get('ip')}: {ip.get('unblock_time')}")
                
                # Query 2: Currently blocked IPs (unblock_time > now)
                # Fix: Handle timezone-naive timestamps
                currently_blocked = []
                for ip in all_blocked:
                    unblock_time = ip.get('unblock_time')
                    if unblock_time:
                        if unblock_time.tzinfo is None:
                            unblock_time = unblock_time.replace(tzinfo=timezone.utc)
                        if unblock_time > current_time:
                            currently_blocked.append(ip)
                
                print(f"    Currently blocked IPs: {len(currently_blocked)}")
                for ip in currently_blocked:
                    print(f"      - {ip.get('ip')}: {ip.get('unblock_time')}")
                
                # Query 3: Expired blocked IPs (unblock_time <= now)
                expired_blocked = []
                for ip in all_blocked:
                    unblock_time = ip.get('unblock_time')
                    if unblock_time:
                        if unblock_time.tzinfo is None:
                            unblock_time = unblock_time.replace(tzinfo=timezone.utc)
                        if unblock_time <= current_time:
                            expired_blocked.append(ip)
                
                print(f"    Expired blocked IPs: {len(expired_blocked)}")
                for ip in expired_blocked:
                    print(f"      - {ip.get('ip')}: {ip.get('unblock_time')}")
            
            # Test requests query
            if 'requests' in db.list_collection_names():
                print("\n  Testing Requests Query:")
                from datetime import timedelta
                yesterday = datetime.now(timezone.utc) - timedelta(hours=24)
                print(f"    Looking for requests since: {yesterday}")
                
                # Fix: Handle timezone-naive timestamps in requests
                recent_requests = []
                all_requests = list(db['requests'].find().sort("timestamp", -1).limit(10))
                
                for req in all_requests:
                    req_time = req.get('timestamp')
                    if req_time:
                        if req_time.tzinfo is None:
                            req_time = req_time.replace(tzinfo=timezone.utc)
                        if req_time >= yesterday:
                            recent_requests.append(req)
                
                print(f"    Recent requests found: {len(recent_requests)}")
                for req in recent_requests[:3]:
                    print(f"      - {req.get('remote_addr')}: {req.get('timestamp')}")
                
                # Check if there are any requests at all
                print(f"    Total requests sample: {len(all_requests)}")
                for req in all_requests:
                    print(f"      - {req.get('remote_addr')}: {req.get('timestamp')} - {req.get('method')} {req.get('path')}")
        
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    debug_mongodb()
