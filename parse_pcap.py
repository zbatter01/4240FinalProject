from scapy.all import sniff

def main():
   pcap_file_path = "sample1_home_mini.pcapng"
   packets  = sniff(filter="(ip src host 192.168.0.23) or (ip dst host 192.168.0.23)", prn=summarize, offline=pcap_file_path, store=0)
      
 
def summarize(packet):
    print(packet.summary())

def is_from_mini(packet):
    ip_address = "192.168.0.23"
    ip_layer = packet.getLayer(IP)
    if ip_layer and (ip_layer.src == ip_address or ip_layer.src == ip_address):
        return True
    else:
        return False

main()
