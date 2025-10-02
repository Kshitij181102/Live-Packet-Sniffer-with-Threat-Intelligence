from flask import Flask, render_template, request, jsonify
from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS
import requests
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import lru_cache
import time

app = Flask(__name__)

VT_API_KEY = "82939168c802f23bcbfdee9278e0dfa9098e1b9dae2ac224c851290b52da0722"
GEOLOCATION_API = "http://ip-api.com/json/"

captured_packets = []
# Thread pool for parallel API calls
executor = ThreadPoolExecutor(max_workers=20)

def create_human_readable_summary(packet):
    """Create a more human-readable summary of the packet"""
    try:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            flags = packet[TCP].flags
            
            # Enhanced port descriptions with more services
            port_descriptions = {
                20: "FTP Data", 21: "FTP Control", 22: "SSH", 23: "Telnet",
                25: "SMTP", 53: "DNS", 67: "DHCP Server", 68: "DHCP Client",
                80: "HTTP (Web)", 110: "POP3 Email", 143: "IMAP Email",
                443: "HTTPS (Secure Web)", 993: "IMAPS (Secure IMAP)", 
                995: "POP3S (Secure POP3)", 587: "SMTP (Email Submission)",
                3389: "Remote Desktop", 5432: "PostgreSQL", 3306: "MySQL",
                6379: "Redis", 27017: "MongoDB", 8080: "HTTP Alt", 9200: "Elasticsearch"
            }
            
            dst_service = port_descriptions.get(dst_port, f"Port {dst_port}")
            
            # Enhanced TCP flag descriptions
            flag_desc = []
            if flags & 0x02: flag_desc.append("SYN")
            if flags & 0x10: flag_desc.append("ACK") 
            if flags & 0x01: flag_desc.append("FIN")
            if flags & 0x04: flag_desc.append("RST")
            if flags & 0x08: flag_desc.append("PSH")
            if flags & 0x20: flag_desc.append("URG")
            
            flag_str = f" [{', '.join(flag_desc)}]" if flag_desc else ""
            
            # Determine connection type
            if flags & 0x02 and not (flags & 0x10):  # SYN only
                connection_type = "🔄 Connection Request"
            elif flags & 0x02 and flags & 0x10:  # SYN+ACK
                connection_type = "✅ Connection Accepted"
            elif flags & 0x01:  # FIN
                connection_type = "👋 Connection Closing"
            elif flags & 0x04:  # RST
                connection_type = "❌ Connection Reset"
            elif flags & 0x08:  # PSH
                connection_type = "📤 Data Transfer"
            else:
                connection_type = "🔗 Data Exchange"
            
            return f"{connection_type}: {src_ip}:{src_port} → {dst_ip}:{dst_port} ({dst_service}){flag_str}"
            
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            
            port_descriptions = {
                53: "🌐 DNS Query", 67: "📡 DHCP Server", 68: "📱 DHCP Client",
                123: "🕐 Time Sync (NTP)", 161: "📊 Network Monitor (SNMP)", 
                514: "📝 System Log", 1194: "🔒 VPN (OpenVPN)",
                5353: "🔍 Local Discovery (mDNS)", 137: "💻 NetBIOS Name",
                138: "📂 NetBIOS Datagram", 139: "🗂️ NetBIOS Session"
            }
            
            dst_service = port_descriptions.get(dst_port, f"📡 UDP Port {dst_port}")
            
            return f"📦 UDP Message: {src_ip}:{src_port} → {dst_ip}:{dst_port} ({dst_service})"
            
        elif ICMP in packet:
            icmp_type = packet[ICMP].type
            icmp_code = packet[ICMP].code
            
            icmp_types = {
                0: "🏓 Ping Reply (Success)",
                3: "🚫 Destination Unreachable", 
                8: "🏓 Ping Request",
                11: "⏰ Request Timed Out",
                5: "🔄 Redirect Message",
                12: "⚠️ Parameter Problem"
            }
            
            icmp_desc = icmp_types.get(icmp_type, f"📡 ICMP Type {icmp_type}")
            
            return f"{icmp_desc}: {src_ip} → {dst_ip}"
            
        elif DNS in packet:
            try:
                query_name = packet[DNS].qd.qname.decode().rstrip('.') if packet[DNS].qd else "Unknown"
                query_type = "❓ DNS Query" if packet[DNS].qr == 0 else "✅ DNS Response"
                
                # Identify common domain types
                if any(social in query_name.lower() for social in ['facebook', 'twitter', 'instagram', 'linkedin']):
                    domain_type = "📱 Social Media"
                elif any(search in query_name.lower() for search in ['google', 'bing', 'yahoo']):
                    domain_type = "🔍 Search Engine"
                elif any(video in query_name.lower() for video in ['youtube', 'netflix', 'twitch']):
                    domain_type = "🎥 Video Streaming"
                elif any(cloud in query_name.lower() for cloud in ['amazonaws', 'cloudflare', 'azure']):
                    domain_type = "☁️ Cloud Service"
                else:
                    domain_type = "🌐 Website"
                
                return f"{query_type}: {src_ip} → {dst_ip} | Looking up '{query_name}' ({domain_type})"
            except:
                return f"🌐 DNS: {src_ip} → {dst_ip}"
        else:
            protocol_names = {
                1: "🏓 ICMP", 6: "🔗 TCP", 17: "📦 UDP", 
                47: "🔒 GRE Tunnel", 50: "🛡️ IPSec ESP", 51: "🔐 IPSec AH"
            }
            proto_name = protocol_names.get(packet[IP].proto, f"📡 Protocol {packet[IP].proto}")
            return f"{proto_name}: {src_ip} → {dst_ip}"
            
    except Exception as e:
        return f"📡 Network Packet: {packet[IP].src} → {packet[IP].dst}"

# Cache API results for 5 minutes to avoid repeated calls
@lru_cache(maxsize=500)
def get_geolocation_cached(ip):
    try:
        response = requests.get(GEOLOCATION_API + ip, timeout=1.5)  # Reduced timeout
        data = response.json()
        if data["status"] == "success":
            country_flag = {
                'United States': '🇺🇸', 'Canada': '🇨🇦', 'United Kingdom': '🇬🇧',
                'Germany': '🇩🇪', 'France': '🇫🇷', 'Japan': '🇯🇵', 'China': '🇨🇳',
                'India': '🇮🇳', 'Australia': '🇦🇺', 'Brazil': '🇧🇷', 'Russia': '🇷🇺'
            }.get(data['country'], '🌍')
            return f"{country_flag} {data['city']}, {data['country']}"
        return "🌐 Unknown Location"
    except:
        return "🌐 Unknown Location"

@lru_cache(maxsize=500)
def check_virustotal_cached(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VT_API_KEY}
    
    try:
        response = requests.get(url, headers=headers, timeout=2)  # Reduced timeout
        data = response.json()
        if "data" in data and "attributes" in data["data"]:
            malicious_count = data["data"]["attributes"].get("last_analysis_stats", {}).get("malicious", 0)
            return "Malicious" if malicious_count > 0 else "Clean"
    except:
        return "Unknown"
    return "Unknown"

# Fast local IP detection to skip API calls for local IPs
def is_local_ip(ip):
    """Check if IP is local/private to skip API calls"""
    return (ip.startswith('192.168.') or 
            ip.startswith('10.') or 
            ip.startswith('172.') or 
            ip.startswith('127.') or
            ip == 'localhost')

def get_geolocation_fast(ip):
    """Fast geolocation with local IP detection"""
    if is_local_ip(ip):
        return "🏠 Local Network"
    return get_geolocation_cached(ip)

def check_virustotal_fast(ip):
    """Fast VirusTotal check with local IP detection"""
    if is_local_ip(ip):
        return "Clean"  # Local IPs are safe
    return check_virustotal_cached(ip)

def packet_callback(packet):
    if IP in packet:
        proto = "TCP" if TCP in packet else "UDP" if UDP in packet else "ICMP" if ICMP in packet else "DNS" if DNS in packet else "Other"
        
        # Create enhanced human-readable summary (fast, no API calls)
        human_summary = create_human_readable_summary(packet)
        
        # Enhanced protocol display with emojis
        proto_display = {
            "TCP": "🔗 TCP",
            "UDP": "📦 UDP", 
            "ICMP": "🏓 ICMP",
            "DNS": "🌐 DNS",
            "Other": "📡 Other"
        }.get(proto, proto)

        # Create packet info with placeholders for API data
        packet_info = {
            "summary": human_summary,
            "src": packet[IP].src,
            "dst": packet[IP].dst,
            "proto": proto_display,
            "geolocation": "🔄 Loading...",  # Placeholder
            "vt_status": "🔄 Checking...",   # Placeholder
            "payload": str(packet.payload)[:100] + "..." if len(str(packet.payload)) > 100 else str(packet.payload),
            "index": len(captured_packets)  # Track position for updates
        }
        captured_packets.append(packet_info)

def enrich_packets_parallel():
    """Enrich all packets with API data in parallel after capture"""
    if not captured_packets:
        return
    
    # Create futures for parallel API calls
    geo_futures = {}
    vt_futures = {}
    
    # Get unique IPs to avoid duplicate API calls
    src_ips = set(p["src"] for p in captured_packets)
    dst_ips = set(p["dst"] for p in captured_packets)
    
    # Submit geolocation requests
    for ip in src_ips:
        geo_futures[ip] = executor.submit(get_geolocation_fast, ip)
    
    # Submit VirusTotal requests  
    for ip in dst_ips:
        vt_futures[ip] = executor.submit(check_virustotal_fast, ip)
    
    # Wait for all API calls to complete (with timeout)
    start_time = time.time()
    
    # Update packets as results come in
    for i, packet in enumerate(captured_packets):
        src_ip = packet["src"]
        dst_ip = packet["dst"]
        
        # Get geolocation result
        if src_ip in geo_futures:
            try:
                geo_result = geo_futures[src_ip].result(timeout=3)
                captured_packets[i]["geolocation"] = geo_result
            except:
                captured_packets[i]["geolocation"] = "🌐 Unknown Location"
        
        # Get VirusTotal result
        if dst_ip in vt_futures:
            try:
                vt_result = vt_futures[dst_ip].result(timeout=3)
                security_display = {
                    "Clean": "✅ Safe",
                    "Malicious": "⚠️ Threat",
                    "Unknown": "❓ Unknown"
                }.get(vt_result, vt_result)
                captured_packets[i]["vt_status"] = security_display
            except:
                captured_packets[i]["vt_status"] = "❓ Unknown"
        
        # Don't spend more than 5 seconds total on API calls
        if time.time() - start_time > 5:
            break

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

    # Step 1: Fast packet capture (no API calls during capture)
    print(f"Starting fast packet capture for {count} packets...")
    start_time = time.time()
    
    sniff(filter=filter_str.strip(), prn=packet_callback, count=count, store=False, timeout=10)
    
    capture_time = time.time() - start_time
    print(f"Packet capture completed in {capture_time:.2f} seconds")
    
    # Step 2: Parallel API enrichment (geolocation + VirusTotal)
    print("Enriching packets with API data...")
    enrich_start = time.time()
    
    enrich_packets_parallel()
    
    enrich_time = time.time() - enrich_start
    print(f"API enrichment completed in {enrich_time:.2f} seconds")
    
    total_time = time.time() - start_time
    print(f"Total processing time: {total_time:.2f} seconds for {len(captured_packets)} packets")

    return jsonify({
        "status": "success", 
        "packets": captured_packets,
        "stats": {
            "capture_time": round(capture_time, 2),
            "enrich_time": round(enrich_time, 2),
            "total_time": round(total_time, 2),
            "packet_count": len(captured_packets)
        }
    })

if __name__ == "__main__":
    app.run(debug=True)
