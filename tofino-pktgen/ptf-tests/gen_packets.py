# SPDX-License-Identifier: AGPL-3.0-or-later
from scapy.layers.inet import IP, UDP, Ether
from scapy.packet import Raw
from scapy_scion.layers.scion import SCION, HopField, InfoField, SCIONPath
from scapy_scion.layers.idint import IDINT, StackEntry

from controller.ts_header import TimestampHdr


def create_scion_packet():
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff", src="00:00:00:00:00:00")
    pkt = pkt / IP(dst="127.0.0.1", src="127.0.0.1")
    pkt = pkt / UDP() / SCION(
        Path=SCIONPath(
            Seg0Len=2,
            Seg1Len=2,
            InfoFields=[InfoField(), InfoField()],
            HopFields=[HopField(), HopField(), HopField(), HopField()]
        )
    )
    pkt = pkt / UDP() / TimestampHdr()
    pkt = pkt / Raw(34 * b"\x00")

    with open("ptf-tests/scion_packet.bin", "bw") as file:
        file.write(bytes(pkt))


def create_idint_packet():
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff", src="00:00:00:00:00:00")
    pkt = pkt / IP(dst="127.0.0.1", src="127.0.0.1")
    pkt = pkt / UDP() / SCION(
        Path=SCIONPath(
            Seg0Len=2,
            Seg1Len=2,
            InfoFields=[InfoField(), InfoField()],
            HopFields=[HopField(), HopField(), HopField(), HopField()]
        )
    )
    pkt = pkt / IDINT(
        Flags="Discard",
        AggrMode="Off",
        Verifier="Destination",
        InstFlags="NodeID",
        Inst1="INGRESS_TSTAMP",
        Inst2="EGRESS_TSTAMP",
        TelemetryStack = [
            StackEntry(Flags="Ingress", Hop=2, Mask="NodeID",
                NodeID=3, MD1=(5).to_bytes(4, 'big'), MD2=(6).to_bytes(4, 'big')),
            StackEntry(Flags="Ingress+Egress", Hop=1, Mask="NodeID",
                NodeID=2, MD1=(3).to_bytes(4, 'big'), MD2=(4).to_bytes(2, 'big')),
            StackEntry(Flags="Source+Egress", Hop=0, Mask="NodeID",
                NodeID=1, MD1=(1).to_bytes(4, 'big'), MD2=(2).to_bytes(4, 'big'))
        ]
    )
    pkt = pkt / UDP() / TimestampHdr()
    pkt = pkt / Raw(34 * b"\x00")

    with open("ptf-tests/idint_packet.bin", "bw") as file:
        file.write(bytes(pkt))


if __name__ == "__main__":
    create_scion_packet()
    create_idint_packet()
