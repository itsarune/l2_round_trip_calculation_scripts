import argparse
import os
from typing import List, Optional
from scapy.all import *
import statistics
import time

def test_rtt_sender(dst_mac: str, dst_ip: str, dport: int, iface: str, count: int, pkt_size: int = 1426):
    random_bytes = os.urandom(pkt_size)
    pkt = Ether(dst=dst_mac) / IP(dst=dst_ip) / UDP(dport=dport, sport=dport) / random_bytes

    latencies: List[Optional[float]] = [None] * count

    for i in range(count):
        start_time = time.time()

        response = srp1(pkt, iface=iface, timeout=1, verbose=False)

        end_time = time.time()

        if response:
            latencies[i] = end_time - start_time

    dropped = latencies.count(None)
    actual_latencies = [lat for lat in latencies if lat is not None]
    avg_latency = sum(actual_latencies) / len(actual_latencies) * 1000
    std_dev = statistics.stdev(actual_latencies) * 1000

    print(f"Sent {count} packets, dropped {dropped}, avg latency {avg_latency:.6f}ms, std dev {std_dev:.6f}ms")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("dst_mac", type=str)
    parser.add_argument("dst_ip", type=str)
    parser.add_argument("dport", type=int)
    parser.add_argument("iface", type=str)
    parser.add_argument("count", type=int)
    parser.add_argument("--pkt-size", type=int, default=1426)
    args = parser.parse_args()

    test_rtt_sender(args.dst_mac, args.dst_ip, args.dport, args.iface, args.count, args.pkt_size)
