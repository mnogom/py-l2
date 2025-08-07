#!/usr/bin/env python3

from argparse import ArgumentParser
from collections import deque
from time import sleep

from scapy.all import Ether, Dot1Q, sendp, sniff, get_if_hwaddr

from l2.protocol import Payload
from l2.constants import VLAN_ETHERTYPE, L2HI_ETHERTYPE


def parse_args():
    parser = ArgumentParser(
        description="Server for raw ethernet frame with custom type")
    parser.add_argument("-i", "--interface")
    parser.add_argument("-x", action="count", default=0)
    return parser.parse_args()


def get_handle(iface: str, verbose: int):
    message = "I gotchu bro (-:"
    handled = deque(maxlen=50)

    def handle(pkt):
        if Dot1Q in pkt:
            request = pkt[Dot1Q].payload
        else:
            request = pkt.payload

        payload = Payload.from_bytes(bytes(request))

        if payload.uuid in handled:
            return
        handled.append(payload.uuid)
        payload.msg = message

        has_vlan = Dot1Q in pkt
        reply = Ether(dst=pkt[Ether].src, src=pkt[Ether].dst, type=VLAN_ETHERTYPE if has_vlan else L2HI_ETHERTYPE)
        if has_vlan:
            reply /= Dot1Q(vlan=pkt[Dot1Q].vlan, type=L2HI_ETHERTYPE)
        response = reply / payload.bytes

        if verbose:
            request_bytes = bytes(pkt)
            response_bytes = bytes(response)
            print(f"--> Recieve package:  {request_bytes.hex()} ({len(request_bytes)})")
            print(f"--> Response package: {response_bytes.hex()} ({len(response_bytes)})")
        sendp(response, iface=iface)
    return handle


def get_lfilter(server_mac):
    def lfilter(pkt):
        if Ether not in pkt:
            return False
        if pkt[Ether].dst.lower() != server_mac:
            return False

        type_ = pkt[Dot1Q].type if Dot1Q in pkt else pkt.type
        if type_ != L2HI_ETHERTYPE:
            return False

        return True
    return lfilter


def main():
    args = parse_args()
    server_mac = get_if_hwaddr(args.interface)

    handle = get_handle(iface=args.interface, verbose=args.x)
    lfilter = get_lfilter(server_mac=server_mac)

    print(f"Listen on '{args.interface}' with mac '{server_mac}'")
    sniff(iface=args.interface, prn=handle, store=False, lfilter=lfilter)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
