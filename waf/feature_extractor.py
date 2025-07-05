from collections import defaultdict
import time

try:
    from scapy.all import sniff, IP, TCP
    SCAPY_AVAILABLE = True
except Exception as e:
    print(f"[WAF] WARNING: Scapy not available or WinPcap/Npcap missing: {e}")
    SCAPY_AVAILABLE = False

flows = defaultdict(lambda: {
    "start_time": None,
    "fwd_packets": 0,
    "fwd_bytes": 0,
    "bwd_packets": 0,
    "bwd_bytes": 0
})

def process_packet(pkt):
    print(f"Captured packet: {pkt.summary()}")
    if SCAPY_AVAILABLE and IP in pkt and TCP in pkt:
        ip_layer = pkt[IP]
        tcp_layer = pkt[TCP]
        fwd_key = (ip_layer.src, ip_layer.dst, tcp_layer.sport, tcp_layer.dport)
        bwd_key = (ip_layer.dst, ip_layer.src, tcp_layer.dport, tcp_layer.sport)
        if fwd_key in flows:
            flow = flows[fwd_key]
            direction = "fwd"
        elif bwd_key in flows:
            flow = flows[bwd_key]
            direction = "bwd"
        else:
            flow = flows[fwd_key]
            flow["start_time"] = time.time()
            direction = "fwd"
        if direction == "fwd":
            flow["fwd_packets"] += 1
            flow["fwd_bytes"] += len(pkt)
        else:
            flow["bwd_packets"] += 1
            flow["bwd_bytes"] += len(pkt)

def extract_features(flow_key):
    flow = flows.get(flow_key)
    if not flow:
        return None
    duration = time.time() - flow["start_time"] if flow["start_time"] else 1
    return {
        "Flow Duration": duration,
        "Tot Fwd Pkts": flow["fwd_packets"],
        "Tot Bwd Pkts": flow["bwd_packets"],
        "TotLen Fwd Pkts": flow["fwd_bytes"],
        "Fwd Pkt Len Min": flow["fwd_bytes"],
        "TotLen Bwd Pkts": flow["bwd_bytes"],
        "Bwd Pkt Len Min": flow["bwd_bytes"],
        "Flow Byts/s": (flow["fwd_bytes"] + flow["bwd_bytes"]) / duration,
        "Flow Pkts/s": (flow["fwd_packets"] + flow["bwd_packets"]) / duration,
    }

def extract_live_features_from_request(req, interface="\\Device\\NPF_Loopback", sniff_duration=2):
    """
    Extract features for the flow related to the incoming request.
    If sniffing is not available, returns default features.
    """
    if not SCAPY_AVAILABLE:
        return {
            "Flow Duration": 0,
            "Total Fwd Packets": 0,
            "Total Backward Packets": 0,
            "Fwd Packet Length Max": 0,
            "Fwd Packet Length Min": 0,
            "Bwd Packet Length Max": 0,
            "Bwd Packet Length Min": 0,
            "Flow Bytes/s": 0,
            "Flow Packets/s": 0
        }
    try:
        #Sniff packets for a short duration
        sniff(iface=interface, prn=process_packet, timeout=sniff_duration, count=10)
         #Try to find a flow matching the request's remote_addr
        src_ip = req.remote_addr
         # This is a best-effort guess; you may want to refine this logic
        for key in flows:
             if key[0] == src_ip or key[1] == src_ip:
                return extract_features(key)
        #  If no matching flow, return default
        return {
            "Flow Duration":5001052,
            "Tot Fwd Pkts": 4,
            "Tot Bwd Pkts": 4,
            "TotLen Fwd Pkts": 646,
            "Fwd Pkt Len Min": 364,
            "TotLen Bwd Pkts": 646,
            "Bwd Pkt Len Min": 346,
            "Flow Byts/s": 201,
            "Flow Pkts/s": 1
        }
    except Exception as e:
        print(f"[WAF] WARNING: Could not sniff packets: {e}")
        return {
            "Flow Duration":5001052,
            "Tot Fwd Pkts": 4,
            "Tot Bwd Pkts": 4,
            "TotLen Fwd Pkts": 646,
            "Fwd Pkt Len Min": 364,
            "TotLen Bwd Pkts": 646,
            "Bwd Pckt Len Min": 346,
            "Flow Byts/s": 201,
            "Flow Pkts/s": 1
        }

print(f"Flows after sniffing: {dict(flows)}")