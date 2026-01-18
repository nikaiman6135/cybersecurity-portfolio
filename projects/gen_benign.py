import requests
import time
import random
import sys

# Simple dot-style progress
if len(sys.argv) < 2:
    sys.exit()

target = sys.argv[1]
print(f"Generating 50 benign requests to {target} (approx 60-75s)...")

try:
    for i in range(50):
        try:
            requests.get(f"http://{target}/", timeout=2)
            print(".", end="", flush=True)
        except:
            print("x", end="", flush=True) # Print 'x' if connection fails
            
        # Human behavior delay
        time.sleep(random.uniform(0.5, 1.5))
        
    print("\n[V] Benign Simulation Complete.")
    
except KeyboardInterrupt:
    print("\n[!] Stopped.")