import sys
import threading
import json
import nmap
import shodan
import subprocess
import pandas as pd
import webbrowser
from flask import *
from scapy.all import IP, TCP, sniff, conf 
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split 
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix


TARGET_IP = "118.107.204.58"
IFACE = "en0"
SHODAN_KEY = "4f1D3q6TVioHjC8uupTfDDqpUeZ0q01O" 

app = Flask(__name__)
conf.verb = 0 
api = shodan.Shodan(SHODAN_KEY)

# Global variables for the dashboard
benign_count = 0
malicious_count = 0
alerts_list = []
recon_data = []
report_str = "Wait for training..."
matrix_str = "Wait for training..."
model = None

# Recon Function
def do_recon(ip):
    print("\n[1] Starting Nmap Scan...")
    nm = nmap.PortScanner()
    
    # Nmap scan
    nm.scan(ip, arguments='-sV -T4 -Pn')

    # check target status
    if ip not in nm.all_hosts():
        print("Target is down.")
        return

    # loop through protocols to get version information
    for proto in nm[ip].all_protocols():
        for port in nm[ip][proto]:
            service_name = nm[ip][proto][port]['name']
            product = nm[ip][proto][port].get('product', '')
            version = nm[ip][proto][port].get('version', '')
            full_name = f"{service_name} {product} {version}"
            
            # Default risk rating
            risk_level = "Unverified/Potential Risk"
            
            try:
                host_info = api.host(ip)
                
                # If we find the IP, the service is at least "Verified"
                risk_level = "Low" 
                
                for item in host_info.get('data', []):
                    # Find the specific port entry in Shodan data
                    if item['port'] == port:
                        
                        # Try to get the CVSS Score
                        cvss = item.get('cvss') 
                        
                        if cvss and isinstance(cvss, (float, int)):
                            if cvss >= 9.0:
                                risk_level = f"CRITICAL (CVSS {cvss})"
                            elif cvss >= 7.0:
                                risk_level = f"HIGH (CVSS {cvss})"
                            elif cvss >= 4.0:
                                risk_level = f"MEDIUM (CVSS {cvss})"
                            else:
                                risk_level = f"LOW (CVSS {cvss})"
                                
                        # Fallback: If no score, but 'vulns' list exists
                        elif 'vulns' in item: 
                            risk_level = "HIGH (Known Vulns - No Score)"
                            
            except Exception as e:
                # Keep as Unverified if API fails
                pass
            
            print(f"   Found Port: {port} ({full_name}) - Risk: {risk_level}")
            recon_data.append({"port": port, "service": full_name, "risk": risk_level})
            
    # save to json
    with open("recon_results.json", "w") as f:
        json.dump(recon_data, f)

# Extract Features
def get_features(pkt):
    # Only captures the TCP packets
    if IP in pkt and TCP in pkt:
        length = len(pkt)
        ttl = pkt[IP].ttl
        proto = pkt[IP].proto
        flags = int(pkt[TCP].flags)
        return [length, ttl, proto, flags]
    return None

# Training the AI
def train_model(ip):
    print("\n[2] Training Model...")
    
    benign_traffic = []
    attack_traffic = []

    # Start sniffing benign packets using scapy sniff
    print("   Capturing Benign traffic...")
    t1 = threading.Thread(target=lambda: sniff(iface=IFACE, prn=lambda x: benign_traffic.append(x) if IP in x else None, timeout=75))
    t1.start()
    subprocess.run([sys.executable, "gen_benign.py", ip])
    t1.join() 

    # Start sniffing attack packets using scapy sniff
    print("   Capturing Attack traffic...")
    t2 = threading.Thread(target=lambda: sniff(iface=IFACE, prn=lambda x: attack_traffic.append(x) if IP in x else None, timeout=15))
    t2.start()
    subprocess.run([sys.executable, "gen_attack.py", ip])
    t2.join() 

    # Prepare data for sklearn
    dataset = []
    labels = []
    
    for p in benign_traffic:
        feat = get_features(p)
        if feat: 
            dataset.append(feat)
            labels.append(0) # 0 is benign

    for p in attack_traffic:
        feat = get_features(p)
        if feat: 
            dataset.append(feat)
            labels.append(1) # 1 is malicious

    if len(dataset) == 0:
        print("Error: No packets captured.")
        return None
    
    # Create Dataframe
    df = pd.DataFrame(dataset, columns=["Size","TTL","Proto","Flags"])
    
    # Split 75/25
    X_train, X_test, y_train, y_test = train_test_split(df, labels, test_size=0.25, random_state=35)
    
    # Train
    clf = RandomForestClassifier()
    clf.fit(X_train, y_train)
    
    # Test
    y_pred = clf.predict(X_test)
    
    # Update globals for dashboard
    global report_str, matrix_str
    report_str = classification_report(y_test, y_pred, target_names=["Benign", "Malicious"])
    matrix_str = str(confusion_matrix(y_test, y_pred))
    
    print("\nModel Accuracy: " + str(accuracy_score(y_test, y_pred)))
    print(report_str)
    print(matrix_str)
    
    return clf

# Web Page
@app.route("/")
def home():
    html = """
        <html>
        <body>
            <h1>Threat Hunter Dashboard - 118.107.204.58</h1>
            <a href="/">Refresh</a>
            <hr>
            <h3>Packets</h3>
            <p>Benign: {{ b }}</p>
            <p>Malicious: {{ m }}</p>
            <hr>
            <h3>Recent Alerts (Last 10)</h3>
            <ul>
                {% for a in alerts %} 
                    <li>{{ a }}</li> 
                {% endfor %}
            </ul>
            <hr>
            <h3>Recon Results</h3>
            <ul>
                {% for r in recon %} 
                    <li>Port {{ r.port }} - {{ r.service }} [{{ r.risk }}]</li> 
                {% endfor %}
            </ul>
            <hr>
            <h3>Model Training Evaluation</h3>
            <pre>{{ rep }}</pre>
            <pre>{{ mat }}</pre>
        </body>
        </html>
    """
    recent_alerts = alerts_list[-10:][::-1]
    return render_template_string(html, b=benign_count, m=malicious_count, alerts=recent_alerts, recon=recon_data, rep=report_str, mat=matrix_str)

# Main Loop
def start_monitoring(ip):
    print(f"\n[3] Monitoring {ip} on {IFACE}...")
    webbrowser.open("http://127.0.0.1:6969")

    def process_packet(pkt):
        global benign_count, malicious_count
        
        if IP in pkt:
            # check destination
            if pkt[IP].dst == ip:
                print(".", end="", flush=True)
                
                f = get_features(pkt)
                if f:
                    # predict
                    df = pd.DataFrame([f], columns=["Size","TTL","Proto","Flags"])
                    prediction = model.predict(df)[0]
                    
                    if prediction == 1:
                        malicious_count += 1
                        alerts_list.append(f"ATTACK DETECTED TO {ip}")
                    else:
                        benign_count += 1
                
    sniff(iface=IFACE, prn=process_packet, store=0)

if __name__ == "__main__":
    do_recon(TARGET_IP)
    model = train_model(TARGET_IP)
    
    if model:
        # Run flask in a thread
        t = threading.Thread(target=lambda: app.run(port=6969, use_reloader=False))
        t.start()
        
        try: 
            start_monitoring(TARGET_IP)
        except KeyboardInterrupt: 
            sys.exit()