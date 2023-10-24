# SPDX-License-Identifier: AGPL-3.0-or-later

from scapy.all import sniff, bind_layers, Ether, IP, UDP, sendp, hexdump
from scapy.contrib.bfd import BFD
from scion_scapy.scion import SCION, SCIONOneHopPath, InfoField, HopField
from scion_crypto import get_key, compute_mac
from multiprocessing import Process, Lock, Pool, Value
from tofino import *

import argparse
import dpkt
import time
import random
import binascii
import ipaddress
import json
import socket
import logging

logger = logging.getLogger('scion_onehope_processor')
logger.addHandler(logging.StreamHandler())
logger.setLevel(logging.INFO)

class TestValidator:
    def __init__(self, interface, pcap):
        self.interface = interface
        pcap_file = open(pcap, 'rb')
        self.pcap_reader = dpkt.pcap.Reader(pcap_file)
        self.length = sum(1 for _,_ in self.pcap_reader)
        pcap_file.close()
        logger.info("Test will include %d frames." % self.length)
        pcap_file = open(pcap, 'rb')
        self.pcap_reader = dpkt.pcap.Reader(pcap_file)
        self.cnt = 1
        self.errcnt = 0

    def receivedPacket(self, pkt):
        if SCION in pkt:
            _, reference_bytes = next(self.pcap_reader)
            reference = Ether(reference_bytes)
            hasError = 0
            if pkt[Ether].dst != reference[Ether].dst:
                logger.info("Packet %d not matched." % self.cnt)
                logger.info("Expected Ethernet dst MAC: %s" % reference[Ether].dst)
                logger.info("Received Ethernet dst MAC: %s" % pkt[Ether].dst)
                hasError = 1
            if pkt[Ether].src != reference[Ether].src:
                logger.info("Packet %d not matched." % self.cnt)
                logger.info("Expected Ethernet src MAC: %s" % reference[Ether].src)
                logger.info("Received Ethernet src MAC: %s" % pkt[Ether].src)
                hasError = 1
            if pkt[Ether].type != reference[Ether].type:
                logger.info("Packet %d not matched." % self.cnt)
                logger.info("Expected Ethernet type: %d" % reference[Ether].type)
                logger.info("Received Ethernet type: %d" % pkt[Ether].type)
                hasError = 1
            if pkt[IP].version != reference[IP].version:
                logger.info("Packet %d not matched." % self.cnt)
                logger.info("Expected IP version: %d" % reference[IP].version)
                logger.info("Received IP version: %d" % pkt[IP].version)
                hasError = 1
            if pkt[IP].ihl != reference[IP].ihl:
                logger.info("Packet %d not matched." % self.cnt)
                logger.info("Expected IP header length: %d" % reference[IP].ihl)
                logger.info("Received IP header length: %d" % pkt[IP].ihl)
                hasError = 1
            if pkt[IP].len != reference[IP].len:
                logger.info("Packet %d not matched." % self.cnt)
                logger.info("Expected IP total length: %s" % reference[IP].len)
                logger.info("Received IP total length: %s" % pkt[IP].len)
                hasError = 1
            if pkt[IP].proto != reference[IP].proto:
                logger.info("Packet %d not matched." % self.cnt)
                logger.info("Expected IP protocol: %s" % reference[IP].proto)
                logger.info("Received IP protocol: %s" % pkt[IP].proto)
                hasError = 1
            if pkt[IP].src != reference[IP].src:
                logger.info("Packet %d not matched." % self.cnt)
                logger.info("Expected Src IP: %s" % reference[IP].src)
                logger.info("Received src IP: %s" % pkt[IP].src)
                hasError = 1
            if pkt[IP].dst != reference[IP].dst:
                logger.info("Packet %d not matched." % self.cnt)
                logger.info("Expected Dst IP: %s" % reference[IP].dst)
                logger.info("Received Dst IP: %s" % pkt[IP].dst)
                hasError = 1
            if pkt[UDP].sport != reference[UDP].sport:
                logger.info("Packet %d not matched." % self.cnt)
                logger.info("Expected src UDP port: %s" % reference[UDP].sport)
                logger.info("Received src UDP port: %s" % pkt[UDP].sport)
                hasError = 1
            if pkt[UDP].dport != reference[UDP].dport:
                logger.info("Packet %d not matched." % self.cnt)
                logger.info("Expected dst UDP port: %s" % reference[UDP].dport)
                logger.info("Received dst UDP port: %s" % pkt[UDP].dport)
                hasError = 1
            if pkt[UDP].len != reference[UDP].len:
                logger.info("Packet %d not matched." % self.cnt)
                logger.info("Expected UDP length: %s" % reference[UDP].len)
                logger.info("Received UDP length: %s" % pkt[UDP].len)
                hasError = 1
            if pkt[UDP].chksum != reference[UDP].chksum and pkt[UDP].chksum != 0:
                logger.info("Packet %d not matched." % self.cnt)
                logger.info("Expected UDP length: %s" % reference[UDP].chksum)
                logger.info("Received UDP length: %s" % pkt[UDP].chksum)
                hasError = 1
            if pkt[UDP].payload != reference[UDP].payload:
                logger.info("Packet %d not matched." % self.cnt)
                logger.info("Expected packet: %s" % hexdump(reference[UDP].payload))
                logger.info("Received packet: %s" % hexdump(pkt[UDP].payload))
                hasError = 1
            if hasError == 0:
                logger.debug("Packet %d was correct." % self.cnt)
            else:
                self.errcnt += 1
            if self.length == self.cnt:
                if self.errcnt == 0:
                    logger.info("Finished test successfully!")
                else:
                    logger.info("Test failed with %d errors" % self.errcnt)
                exit()
            self.cnt += 1

    # Run BFD session handler
    def run(self):
        logger.info("Start sniffing on interface %s" % self.interface)
        sniff(prn=self.receivedPacket, iface=self.interface, filter="inbound", store=0)

def main():
    parser = argparse.ArgumentParser(description="Service to process one-hop paths: compute and register missing hop field")
    parser.add_argument(
        "-i",
        "--interface",
        default="veth251",
        nargs="?",
        help="interface to listen on for SCION packets and send processed packets on (default: veth251)")
    parser.add_argument(
        "-f",
        "--file",
        help="Path to .pcap file with the expected frames")
    parser.add_argument(
        "-d",
        "--debug",
        action="store_true",
        help="Enable output of debug info")
    args = parser.parse_args()
    
    if args.debug:
        logger.setLevel(logging.DEBUG)
    
    # Start test packet validation
    test_validator = TestValidator(args.interface, args.file)
    test_validator.run()

bind_layers(Ether, Ether, type = 0x5C10)

if __name__ == "__main__":
    main()
