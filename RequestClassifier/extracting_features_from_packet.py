from scapy.all import *
from collections import defaultdict
import socket
import json
import pandas as pd

with open("valid_services.json","r") as file:
    valid_services=json.load(file)

with open("valid_protocols.json","r") as file:
    valid_protocols=json.load(file)

# def get_tcp_flag(pkt):
#     if pkt[TCP].flags==0x02:
#         return 'S0'
#
#     elif pkt[TCP].flags==0x12:
#         return 'SF'
#
#     elif pkt[TCP].flags==0x14:
#         return 'REJ'
#
#     return 'OTH'

def get_tcp_flag(pkt):
    # Check for SYN flag (0x02)
    if pkt[TCP].flags & 0x02:
        return 'SYN'

    # Check for SYN + ACK flags (0x12)
    elif pkt[TCP].flags == 0x12:
        return 'SYN-ACK'

    # Check for RST flag (0x04) or combination of flags (0x14 = SYN + RST)
    elif pkt[TCP].flags & 0x04:
        return 'RST'

    # Check for FIN flag (0x01)
    elif pkt[TCP].flags & 0x01:
        return 'FIN'

    # Default case
    return 'OTHER'


def resolve_service(port,proto):
    try:
        service=socket.getservbyport(port,proto.lower())
        return service if service in valid_services else 'other'

    except:
        return 'other'

def extract_features(pcap_file):
    packets=rdpcap(pcap_file)
    packet_list=defaultdict(list)
    src_port = "None"
    for pkt in packets:
        if IP in pkt:
            proto_num=pkt[IP].proto
            protocol_type={6:'tcp',17:'udp',1:'icmp'}.get(proto_num,'other')

            if protocol_type not in valid_protocols:
                continue

            src_ip=pkt[IP].src
            dest_ip=pkt[IP].dst
            timestamp=pkt.time
            wrong_fragment=pkt[IP].frag>0
            urgent=0
            dst_port=0
            flag='OTH'

            if protocol_type=='tcp' and TCP in pkt:
                src_port=pkt[TCP].sport
                dst_port=pkt[TCP].dport
                urgent=pkt[TCP].urgptr
                flag=get_tcp_flag(pkt)

            elif protocol_type=='udp' and UDP in pkt:
                dst_port=pkt[UDP].dport
                src_port=pkt[UDP].sport

            service=resolve_service(dst_port,protocol_type)

            packet_list_key=(src_ip,dest_ip,dst_port,protocol_type)
            packet_list[packet_list_key].append((timestamp,len(pkt[IP].payload),pkt,wrong_fragment,urgent,flag,service))

        elif IPv6 in pkt:
            proto_num=pkt[IPv6].proto
            protocol_type={6:'tcp',17:'udp',1:'icmp'}.get(proto_num,'other')

            if protocol_type not in valid_protocols:
                continue

            src_ip=pkt[IPv6].src
            dest_ip=pkt[IPv6].dst
            timestamp=pkt.time
            wrong_fragment=pkt[IPv6].frag>0
            urgent=0
            dst_port=0
            flag='OTH'

            if protocol_type=='tcp' and TCP in pkt:
                src_port=pkt[TCP].sport
                dst_port=pkt[TCP].dport
                urgent=pkt[TCP].urgptr
                flag=get_tcp_flag(pkt)

            elif protocol_type=='udp' and UDP in pkt:
                dst_port=pkt[UDP].dport
                src_port=pkt[UDP].sport

            service=resolve_service(dst_port,protocol_type)

            packet_list_key=(src_ip,dest_ip,dst_port,protocol_type)
            packet_list[packet_list_key].append((timestamp,len(pkt[IPv6].payload),pkt,wrong_fragment,urgent,flag,service))


    for key,pkts in packet_list.items():
        timestamps=[t for t,*_ in pkts]
        first_time=min(timestamps)
        last_time=max(timestamps)
        duration=last_time-first_time

        src_ip,dest_ip,dest_port,proto_type=key

        src_bytes=sum(length for t,length,pkt,*_ in pkts if pkt[IP].src==src_ip)
        dst_bytes=sum(length for t,length,pkt,*_ in pkts if pkt[IP].dst==dest_ip)


        first_pkt=pkts[0]
        wrong_fragment=int(first_pkt[3])
        urgent=first_pkt[4]
        flag=first_pkt[5]
        service=first_pkt[6]
        count=len(pkts)

        results={
                'duration':int(duration),
                'src_bytes':src_bytes,
                'dst_bytes':dst_bytes,
                'wrong_fragment':wrong_fragment,
                'urgent':urgent,
                'count':count,
                'protocol_type':protocol_type,
                'service':service,
                'flag':flag
        }

    return (results,src_ip,src_port)


def FeaturePreprocessing(features):
    with open("label.json","r") as file:
        labels=json.load(file)

    features["protocol_type"]=labels[features["protocol_type"]]
    features["service"]=labels[features["service"]]
    features["flag"]=labels[features["flag"]]

    return features

if __name__=="__main__":
    features=extract_features(pcap_file="analysis.pcap")
    print("Features Extracted...")
    print(f"Features: {features}")
    # processed_features=FeaturePreprocessing(features)
    # print("Feature Preprocessing Completed...")
    # print(f"Processed Features: {processed_features}")
    # dataframe=pd.DataFrame([features])
    # dataframe.to_csv("features.csv",index=False)
    # print("Extracted features stored in csv file....")