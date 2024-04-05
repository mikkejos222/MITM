#! /usr/bin/python
from scapy.layers.inet import ICMP, fragment
from scapy.layers.l2 import Ether, ARP
import scapy.all as scapy
import time
from scapy.sendrecv import sr


def ICMPAttacks():
    def thePingOfDeath():
        ans, unans = sr(IP(dst="192.168.1.0/24")/ICMP(), timeout=3)
        scapy.layers.inet.ICMP(type = 8, code = 0, chksum = None, id = 0, seq = 0, ts_ori = 22485762, ts_rx = 22485762, ts_tx = 22485762, gw = '0.0.0.0', ptr = 0, reserved = 0, length = 0, addr_mask = '0.0.0.0', nexthopmtu = 0, unused = None);
    if __name__ == '__main__':
        thePingOfDeath()
