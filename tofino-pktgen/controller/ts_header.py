# SPDX-License-Identifier: AGPL-3.0-or-later
import scapy
from scapy.fields import IntField
from scapy.layers.inet import UDP


UDP_PORT_TIMESTAMP = 0x9999


class TimestampHdr(scapy.packet.Packet):
    name = "Timestamp"

    fields_desc = [
        IntField("Timestamp", default=0)
    ]


scapy.packet.bind_layers(UDP, TimestampHdr,
    dport=UDP_PORT_TIMESTAMP, sport=UDP_PORT_TIMESTAMP)
