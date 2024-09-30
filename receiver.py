import argparse
from scapy.all import *
from scapy.config import conf
conf.debug_dissector = 2

def test_rtt_receiver(pkt, dst_port: int, dst_mac: str, iface: str):
    response = Ether(dst=dst_mac) / IP(dst=pkt[IP].src) / UDP(dport=pkt[UDP].sport, sport=dst_port) / pkt[Raw]
    sendp(response, iface=iface, verbose=False)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("dst_mac", type=str)
    parser.add_argument("iface", type=str)
    parser.add_argument("dst_port", type=int)
    parser.add_argument("src_ip", type=str)
    args = parser.parse_args()

    sniff(count=0,
          iface=args.iface,
          filter=f"udp and dst port {args.dst_port} and src net {args.src_ip}",
          prn = lambda pkt: test_rtt_receiver(pkt, args.dst_port, args.dst_mac, args.iface),
          store=False)
