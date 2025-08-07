#!/usr/bin/env python3

from argparse import ArgumentParser
import struct
from time import sleep
from uuid import uuid4

from scapy.all import Ether, Dot1Q, sendp

from l2.protocol import Payload
from l2.constants import VLAN_ETHERTYPE, L2HI_ETHERTYPE


def parse_args():
    parser = ArgumentParser(
        description="Send raw ethernet frame with custom type")
    parser.add_argument("-s", "--src-mac")
    parser.add_argument("-d", "--dst-mac")
    parser.add_argument("-v", "--vlan_id", default=None)
    parser.add_argument("-i", "--interface")
    parser.add_argument("-x", action="count", default=0)
    return parser.parse_args()


def main():
    message = "Hello :-)"

    args = parse_args()
    pkt = Ether(
        src=args.src_mac,
        dst=args.dst_mac,
        type=VLAN_ETHERTYPE if args.vlan_id else L2HI_ETHERTYPE,
    )
    if args.vlan_id:
        pkt /= Dot1Q(vlan=int(args.vlan_id), type=L2HI_ETHERTYPE)

    tcpdump = f"tcpdump -vv -n -i any ether proto {L2HI_ETHERTYPE} -XX"

    while True:
        payload = Payload(msg=message)
        request = pkt / payload.bytes
        if args.x:
            print(f"--> {bytes(request).hex()}, ({len(bytes(request))})")
        sendp(request, iface=args.interface, verbose=True)
        sleep(3)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass

