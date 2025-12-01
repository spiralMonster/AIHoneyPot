import requests
import os
import sys
import pandas as pd
from RequestClassifier.send_normal_request import SendRequest
from RequestClassifier.response_from_url import ResponseFromURL
from RequestClassifier.udp_flooding import UDP_Flooding
from RequestClassifier.syn_flooding import SynFlooding
from RequestClassifier.icmp_flood import ICMP_Flooding
from RequestClassifier.extracting_features_from_packet import extract_features
from RequestClassifier.request_predictor import RequestPredictor
from RequestClassifier.get_hostname_and_payload_from_url import GetHostnameAndPayloadInfo
from RequestClassifier.context_from_internet import ContextFromInternet
from RequestClassifier.honeypot import HoneyPot

if __name__=="__main__":
    print("Welcome to our AIPOT....")

    argv=sys.argv
    if len(argv)!=2:
        raise ValueError("Usage sudo response_from_url.py your_url")

    url=sys.argv[-1]
    print(f"You want to access the url: {url}")

    host,payload_info=GetHostnameAndPayloadInfo(url)

    print("Who are you??:")
    print("1.Attacker")
    print("2.Normal User")
    choice=int(input("Enter your choice: "))

    if choice==1:
        print("Choose the type of attack to be send...")
        print("1.SYN-Flooding")
        print("2.UDP-Flooding")
        print("3.ICMP-Flooding")
        choice=int(input("Enter your choice: "))

        if choice==1:
            print("##Started SYN-FLooding##")
            SynFlooding()

        elif choice==2:
            print("##Started UDP-FLooding##")
            UDP_Flooding(payload_info)

        elif choice==3:
            print("##Started ICMP-FLooding##")
            ICMP_Flooding(payload_info)

        print("[Extracting Features from send packets..]")
        features,attacker_ip,attacker_port=extract_features(pcap_file="analysis.pcap")
        print(f"Features: {features}")

        print("[Request Predictor Started...]")
        request_prediction=RequestPredictor(features)
        print(f"Predictions made: {request_prediction}")

        print("[Generating Response from Honeybot]")
        context_from_home=ResponseFromURL(url=url,request_type="harmful")
        print("[Context from Home Server Acheived...]")
        context_from_internet=ContextFromInternet(payload_data=payload_info)
        print("[Context from Internet Achieved....]")

        honeypot_response=HoneyPot(context_from_home_network=context_from_home,context_from_internet=context_from_internet)
        print(f"[HoneyPot Response]: {honeypot_response}")

        print("[SAVING The information of attacker]")
        attacker_info={
            "IP_address":attacker_ip,
            "Port":attacker_port,
            "Attack":request_prediction["attack"],
            "Explanation":request_prediction["explanation"]
        }
        attacker_df=pd.DataFrame([attacker_info])
        attacker_df.to_csv("attacker_info.csv",index=False)
        print("[Attacker info saved at attacker_info.csv]")


    elif choice==2:
        print(f"[Sending normal request to url: {url}]")
        SendRequest(payload_data=payload_info)

        print("[Extracting Features from send packets..]")
        features,ip,port = extract_features(pcap_file="analysis.pcap")
        print(f"Features: {features}")

        print("[Request Predictor Started...]")
        request_prediction = RequestPredictor(features)
        print(f"Predictions made: {request_prediction}")

        print(f"[Actual Server Response]:")
        ResponseFromURL(url,request_type="normal")










