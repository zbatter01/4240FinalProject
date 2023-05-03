from scapy.all import sniff
import sys
def main():
   pcap_file_path = sys.argv[1]
   packets  = sniff(filter="udp port 5353", prn=lambda x: x.show(), offline=pcap_file_path, store=0)
      
def is_from_mini(packet):
    ip_address = "192.168.0.23"
    ip_layer = packet.getLayer(IP)
    if ip_layer and (ip_layer.src == ip_address or ip_layer.src == ip_address):
        return True
    else:
        return False

main()
