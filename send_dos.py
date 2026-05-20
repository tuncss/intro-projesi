from scapy.all import IP, TCP, send
import time

src = "192.168.56.50"
dst = "192.168.56.10"
for i in range(70):
    pkt = IP(src=src, dst=dst) / TCP(dport=8080, flags="S", sport=1024+i)
    send(pkt, iface="wlo1", verbose=False)
    time.sleep(0.01)
