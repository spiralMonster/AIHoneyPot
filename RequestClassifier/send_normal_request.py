import sys
import os
from scapy.all import *
import netifaces

def SendRequest(payload_data,destination_ip="127.0.0.1",target_port=8002):
    print("Initializing sniffer")
    sniffer=AsyncSniffer(
        iface="lo",
        filter=f"tcp and host {destination_ip} and port {target_port}"
    )
    sniffer.start()
    time.sleep(1)

    print(f"Sending request to : priyanshu23.pythonanywhere.com")
    http_payload=f"GET {payload_data} HTTP/1.1\r\nHost: {destination_ip}\r\n\r\n"

    source_port = RandShort()
    src_ip = netifaces.ifaddresses("wlp1s0")[netifaces.AF_INET][0]['addr']

    #Sending SYN Packet:
    syn_pkt=IP(dst=destination_ip,src=src_ip)/TCP(sport=source_port,dport=target_port,flags="S",seq=1000)
    syn_ack_response=sr1(syn_pkt,timeout=3)
    if not syn_ack_response:
        print("No SYN-ACK response received")

    #Sending ACK packet:
    ack_pkt=IP(dst=destination_ip,src=src_ip)/TCP(
        sport=source_port,
        dport=target_port,
        flags="A",
        seq=syn_pkt[TCP].seq+1,
        ack=syn_ack_response[TCP].seq+1
    )
    send(ack_pkt)

    #Sending Actual HTTP packet:
    actual_ip_pkt=IP(dst=destination_ip,src=src_ip)
    actual_tcp_pkt=TCP(sport=source_port,dport=target_port,flags="PA",seq=ack_pkt[TCP].seq+1,ack=syn_ack_response[TCP].seq+1)
    payload=Raw(load=http_payload)
    http_pkt=actual_ip_pkt/actual_tcp_pkt/payload
    send(http_pkt,verbose=0)

    print(f"Packet send to {destination_ip}...")
    print("Stopping sniffer...")
    sniffer.stop()

    response=sniffer.results


    if response:
        print(f"Received: {len(response)} packets")
        response[0].summary()
        response[0].show()

        all_pkts=list(response)+[http_pkt]


    else:
        print("No respone received....")
        all_pkts=http_pkt

    print("Creating PCAP File")
    print("Deleting previous PCAP file")
    if os.path.exists("analysis.pcap"):
        os.remove("analysis.pcap")

    wrpcap("analysis.pcap", all_pkts)
    print("New PCAP file created successfully...")

if __name__=="__main__":
    argv=sys.argv
    if len(argv)!=2:
        raise ValueError("Usage: sudo python3 send_normal_request.py destination_ip")

    destination_ip=argv[-1]
    SendRequest(destination_ip)

# import requests
# response = requests.get("http://priyanshu23.pythonanywhere.com/api/file")
# print(response.status_code, response.text)