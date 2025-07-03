from scapy.all import get_if_list, sniff
print(get_if_list())

def process_packet(packet):
    # Process the packet as needed
    pass

def extract_live_features_from_request(req, interface="\\Device\\NPF_Loopback", sniff_duration=2):
    sniff(iface=interface, prn=process_packet, timeout=sniff_duration, count=10)