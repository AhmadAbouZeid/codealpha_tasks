from scapy.all import sniff, IP, TCP, Raw

def process_packet(packet):
    if packet.haslayer(Raw):
        payload = packet[Raw].load.decode(errors='ignore')
        # Look for the 'Host:' line in the HTTP header
        if "Host:" in payload:
            # Extract the website name
            host = payload.split("Host: ")[1].split("\r\n")[0]
            print(f"[!] Intercepted Request to: {host}")

print("[*] Monitoring Windows traffic... Go to a website now!")
sniff(iface="eth0", store=False, prn=process_packet, filter="tcp port 80")
