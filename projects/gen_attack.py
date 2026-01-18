import socket
import time
import sys

if len(sys.argv) < 2:
    sys.exit()

target = sys.argv[1]
print(f"Generating 50 attacks to {target} (approx 10-15s)...")

try:
    for i in range(50):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            s.connect((target, 21))
            s.send(b"USER admin\r\n")
            s.recv(1024)
            s.send(b"PASS 1234\r\n")
            s.close()
            print(".", end="", flush=True)
        except:
            print("x", end="", flush=True)
            
        time.sleep(0.1)

    print("\n[!] Attack Simulation Complete.")

except KeyboardInterrupt:
    print("\n[!] Stopped.")