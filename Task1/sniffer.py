from scapy.all import sniff, wrpcap

packets = [] # This list will store the packets in memory

def packet_callback(packet):
    if packet.haslayer('DNSQR'):
        print(f"[!] Logged DNS Query: {packet['DNSQR'].qname.decode()}")
        packets.append(packet) # Add the packet to the list

print("Sniffing 20 DNS queries and saving to 'capture.pcap'...")
sniff(iface="eth0", filter="udp port 53", prn=packet_callback, count=20)

# This saves everything in the 'packets' list to a file
wrpcap('capture.pcap', packets)
print("\n[+] Done! File saved as capture.pcap")

