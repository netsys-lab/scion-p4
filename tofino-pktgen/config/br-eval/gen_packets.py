# SPDX-License-Identifier: AGPL-3.0-or-later
import base64
import os
from datetime import datetime

from controller.ts_header import TimestampHdr
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from scapy.layers.inet import IP, UDP, Ether
from scapy.packet import Raw
from scapy_scion.layers.scion import SCION, HopField, InfoField, SCIONPath

# Run as 'python3 config/br-eval/gen_packets.py' from repo root

def derive_hf_mac_key(key: str) -> str:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=16,
        salt=b"Derive OF Key",
        iterations=1000
    )
    return base64.b64encode(kdf.derive(base64.b64decode(key)))


PKT_SIZES = [192, 800, 1500]
KEY = derive_hf_mac_key("VqoTW140sYOCgR+09I4EuA==")


def create_1seg_packet(size: int):
    """SCION packet 1 info field, 3 hop fields, down-segment
    """
    pkt = Ether(dst="10:70:fd:1c:c1:fc", src="d6:a9:96:c4:0f:9e")
    pkt = pkt / IP(dst="10.1.4.1", src="10.1.4.2")
    pkt = pkt / UDP(sport=50000, dport=50000) / SCION(
        DstAS="ff00:0:7",
        SrcAS="ff00:0:1",
        Path=SCIONPath(
            CurrHF=0,
            Seg0Len=3, Seg1Len=0, Seg2Len=0,
            InfoFields=[
                InfoField(Flags="C", SegID=0x300a)],
            HopFields=[
                HopField(ExpTime=63, ConsIngress=0, ConsEgress=2115, MAC=0x6b80829f8a2a),
                HopField(ExpTime=63, ConsIngress=1403, ConsEgress=1633, MAC=0xf6d72dbfca8b),
                HopField(ExpTime=63, ConsIngress=3720, ConsEgress=0, MAC=0x7b62af778bd1)]
        )
    )
    pkt = pkt / UDP() / TimestampHdr()
    assert size >= 138
    pkt = pkt / Raw(os.urandom(size - 138))
    pkt[SCION].Path.init_path(3 * [KEY], [b"ab"])
    pkt[SCION].Path.egress(KEY)
    return pkt


def create_2seg_packet(size: int):
    """SCION packet 2 info field, 4 hop fields, up- and down-segment
    """
    pkt = Ether(dst="10:70:fd:1c:c1:fc", src="d6:a9:96:c4:0f:9e")
    pkt = pkt / IP(dst="10.1.4.1", src="10.1.4.2")
    pkt = pkt / UDP(sport=50000, dport=50000) / SCION(
        DstAS="ff00:0:7",
        SrcAS="ff00:0:6",
        Path=SCIONPath(
            CurrHF=0,
            Seg0Len=2,
            Seg1Len=2,
            Seg2Len=0,
            InfoFields=[
                InfoField(SegID=0xbfb0),
                InfoField(SegID=0x0a31, Flags=0x01)],
            HopFields=[
                HopField(ExpTime=63, ConsIngress=1985, ConsEgress=0, MAC=0x2548cc93e92f),
                HopField(ExpTime=63, ConsIngress=0, ConsEgress=5, MAC=0x4826abe3726e),
                HopField(ExpTime=63, ConsIngress=0, ConsEgress=6, MAC=0x9ac5899b09dc),
                HopField(ExpTime=63, ConsIngress=494, ConsEgress=0, MAC=0x8a85795d1646)]
        )
    )
    pkt = pkt / UDP() / TimestampHdr()
    assert size >= 158
    pkt = pkt / Raw(os.urandom(size - 158))
    pkt[SCION].Path.init_path(4 * [KEY], [b"ab", b"ab"])
    pkt[SCION].Path.egress(KEY)
    return pkt


if __name__ == "__main__":
    for size in PKT_SIZES:
        with open(f"config/br-eval/scion_1seg_{size}byte.bin", "bw") as file:
            file.write(bytes(create_1seg_packet(size)))
    for size in PKT_SIZES:
        with open(f"config/br-eval/scion_2seg_{size}byte.bin", "bw") as file:
            file.write(bytes(create_2seg_packet(size)))
