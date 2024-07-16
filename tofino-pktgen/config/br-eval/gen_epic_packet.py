# SPDX-License-Identifier: AGPL-3.0-or-later
import os
from datetime import datetime

from controller.ts_header import TimestampHdr
from scapy.layers.inet import IP, UDP, Ether
from scapy.packet import Raw
from scapy_scion.layers.scion import SCION, HopField, InfoField, SCIONPath, EPICPath


def create_epic_packet(size):
    """SCION EPIC-HP packet
    """
    pkt = Ether(dst="10:70:fd:1c:c1:fc", src="d6:a9:96:c4:0f:9e")
    pkt = pkt / IP(dst="10.1.4.1", src="10.1.4.2")
    pkt = pkt / UDP(sport=50000, dport=50000) / SCION(
        DstAS="ff00:0:7",
        SrcAS="ff00:0:1",
        PathType=0x03,
        Path=EPICPath(
            epicTs=0x00ae9bf4,
            epicCounter=0x00000004,
            phvf=0x521e70a0,
            lhvf=0xf2eba288,
            scionpath=SCIONPath(
                CurrHF=1,
                Seg0Len=3,
                InfoFields=[InfoField(Flags="C", SegID=0x300a, Timestamp=datetime(2023, 9, 9, 0, 13, 15))],
                HopFields=[
                    HopField(ExpTime=63, ConsIngress=0, ConsEgress=2115, MAC=0x6b80829f8a2a),
                    HopField(ExpTime=63, ConsIngress=1403, ConsEgress=1633, MAC=0xf6d72dbfca8b),
                    HopField(ExpTime=63, ConsIngress=3720, ConsEgress=0, MAC=0x7b62af778bd1)
                ]
            )
        )
    )
    pkt = pkt / UDP() / TimestampHdr()
    assert size >= 138
    pkt = pkt / Raw(os.urandom(size - 138))
    return pkt


if __name__ == "__main__":
    with open(f"evaluation/scion_epic.bin", "bw") as file:
        file.write(bytes(create_epic_packet(192)))
