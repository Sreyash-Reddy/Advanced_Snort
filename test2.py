
from scapy.all import *
# A dictionary mapping port numbers to service names
services = {
    21: 'ftp',
    22: 'ssh',
    23: 'telnet',
    25: 'smtp',
    53: 'domain',
    80: 'http',
    110: 'pop_3',
    443: 'http_443',
    # Add more port numbers and service names here
}





def packet_callback(packet):
    if TCP in packet:
        service = services.get(packet[TCP].dport, 'unknown')
        print(f"Service: {service}")

sniff(prn=packet_callback, filter="tcp", store=0)