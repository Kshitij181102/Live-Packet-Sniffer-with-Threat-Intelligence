from flask import Flask, render_template, request, jsonify
from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS
import requests

app = Flask(__name__)

VT_API_KEY = "82939168c802f23bcbfdee9278e0dfa9098e1b9dae2ac224c851290b52da0722"
GEOLOCATION_API = "http://ip-api.com/json/"

captured_packets = []

def get_geolocation(ip):
    try:
        response = requests.get(GEOLOCATION_API + ip)
        data = response.json()
        if data["status"] == "success":
            return f"{data['city']}, {data['country']}"
        return "Unknown"
    except:
        return "Unknown"
    



















    

def check_virustotal(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VT_API_KEY}
    
    try:
        response = requests.get(url, headers=headers)
        data = response.json()
        if "data" in data and "attributes" in data["data"]:
            malicious_count = data["data"]["attributes"].get("last_analysis_stats", {}).get("malicious", 0)
            return "Malicious" if malicious_count > 0 else "Clean"
    except:
        return "Unknown"
    return "Unknown"

def packet_callback(packet):
    if IP in packet:
        proto = "TCP" if TCP in packet else "UDP" if UDP in packet else "ICMP" if ICMP in packet else "DNS" if DNS in packet else "Other"
        geo_location = get_geolocation(packet[IP].src)
        vt_status = check_virustotal(packet[IP].dst)

        packet_info = {
            "summary": packet.summary(),
            "src": packet[IP].src,
            "dst": packet[IP].dst,
            "proto": proto,
            "geolocation": geo_location,
            "vt_status": vt_status,
            "payload": str(packet.payload)
        }
        captured_packets.append(packet_info)

@app.route('/')
def index():
    return render_template("index.html")

@app.route('/capture', methods=['POST'])
def capture_packets():
    global captured_packets
    captured_packets = []  

    ip_address = request.json.get("ip_address")
    packet_type = request.json.get("packet_type", "").upper()
    count = int(request.json.get("count", 10))

  
    filter_str = ""
    if ip_address:
        filter_str += f"host {ip_address} "
    if packet_type in ["TCP", "UDP", "ICMP", "DNS"]:
        filter_str += f"and {packet_type.lower()}"

    sniff(filter=filter_str.strip(), prn=packet_callback, count=count, store=False)

    return jsonify({"status": "success", "packets": captured_packets})

if __name__ == "__main__":
    app.run(debug=True)
