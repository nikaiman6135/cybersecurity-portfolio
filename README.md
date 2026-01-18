# Autonomous Threat Hunter: AI-Driven Network Defense

## Project Overview
This project is an automated network security tool that combines **Active Reconnaissance** with **Machine Learning** to identify, classify, and monitor network threats in real-time. By utilizing **Random Forest Classification**, the system distinguishes between benign traffic and malicious activity with high accuracy.

## Key Features
* **Intelligent Reconnaissance:** Integrated **Nmap** scanning and **Shodan API** lookups to identify open ports and correlate them with known CVSS vulnerability scores.
* **AI Traffic Classification:** A **Random Forest** model trained on live-captured packet features (Size, TTL, Protocol, and TCP Flags).
* **Real-time Dashboard:** A **Flask-based web interface** providing live telemetry on packet counts, security alerts, and model evaluation metrics (Accuracy, Precision, Recall).
* **Automated Simulation:** Includes dedicated scripts (`gen_benign.py` and `gen_attack.py`) to simulate traffic for model training and verification.

## Technical Stack
* **Language:** Python
* **Traffic Analysis:** Scapy (Packet sniffing and feature extraction)
* **Machine Learning:** Scikit-Learn (Random Forest, Train-Test Split)
* **Reconnaissance:** Nmap & Shodan API
* **Web Framework:** Flask
* **Data Handling:** Pandas & JSON

## Methodology
1.  **Recon Phase:** The system scans the target IP, retrieves service versions, and assigns a risk level (Low to Critical) based on Shodan intelligence.
2.  **Training Phase:**
    * Captures **Benign** traffic via a 75-second simulation.
    * Captures **Attack** traffic via a 15-second simulation (FTP-style brute force).
    * Extracts TCP/IP features into a **Pandas DataFrame**.
3.  **Monitoring Phase:** The trained model performs real-time inference on every inbound packet. If a packet is classified as malicious, an alert is instantly generated on the dashboard.

## How to Run
1. Ensure `nmap` is installed on your system.
2. Install dependencies: `pip install scapy nmap shodan flask pandas sklearn`
3. Run the main script:
   ```bash
   python autonomous_threat_hunter.py
4. Access the live dashboard at http://127.0.0.1:6969.
