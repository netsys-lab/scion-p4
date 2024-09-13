# SPDX-License-Identifier: AGPL-3.0-or-later
import base64
import os
from typing import List

from controller.ts_header import TimestampHdr
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from scapy.layers.inet import IP, UDP, Ether
from scapy.packet import Raw
from scapy.utils import wrpcap
from scapy_scion.layers.scion import SCION, HopField, InfoField, SCIONPath
from scapy_scion.layers.idint import IDINT, StackEntry

# Run as 'python3 config/idint-osr-eval/gen_packets.py'

def derive_hf_mac_key(key: str) -> str:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=16,
        salt=b"Derive OF Key",
        iterations=1000
    )
    return base64.b64encode(kdf.derive(base64.b64decode(key)))


# We only need the secret of the AS under test
AS_KEY = derive_hf_mac_key("fM0MjEYgyHUJgx7/q5ZA+w==")
# DRKey keys don't matter as we never validate the packets
IDINT_KEY = 16 * b"\x00"
# UDP payload size of the generated packets
PAYLOAD = 1000


def create_pkt():
    pkt = Ether(dst="10:70:fd:1c:c1:fc", src="d6:a9:96:c4:0f:9e")
    pkt = pkt / IP(dst="10.1.4.1", src="10.1.4.2")
    pkt = pkt / UDP(sport=50000, dport=50000) / SCION(
        DstISD=1,
        DstAS="ff00:0:112",
        SrcISD=1,
        SrcAS="ff00:0:111",
        DstHostAddr="127.0.0.2",
        SrcHostAddr="127.0.0.1",
        Path=SCIONPath(
            Seg0Len=2, Seg1Len=2, Seg2Len=0,
            InfoFields=[
                InfoField(Flags="", SegID=0x5435),
                InfoField(Flags="C", SegID=0x2ab5),
            ],
            HopFields=[
                HopField(ExpTime=63, ConsIngress=2, ConsEgress=0),
                HopField(ExpTime=63, ConsIngress=0, ConsEgress=2),
                HopField(ExpTime=63, ConsIngress=0, ConsEgress=4),
                HopField(ExpTime=63, ConsIngress=2, ConsEgress=0),
            ],
        )
    )
    pkt = pkt / UDP() / TimestampHdr()
    pkt = pkt / Raw(os.urandom(PAYLOAD - 4))
    pkt[SCION].Path.init_path(4 * [AS_KEY], [b"ab"])
    pkt[SCION].Path.egress(AS_KEY)
    return pkt


def create_idint_pkt(instr: List[int], req_default_md: bool, encrypt: bool):
    pkt = Ether(dst="10:70:fd:1c:c1:fc", src="d6:a9:96:c4:0f:9e")
    pkt = pkt / IP(dst="10.1.4.1", src="10.1.4.2")
    pkt = pkt / UDP(sport=50000, dport=50000) / SCION(
        DstISD=1,
        DstAS="ff00:0:112",
        SrcISD=1,
        SrcAS="ff00:0:111",
        DstHostAddr="127.0.0.2",
        SrcHostAddr="127.0.0.1",
        Path=SCIONPath(
            Seg0Len=2, Seg1Len=2, Seg2Len=0,
            InfoFields=[
                InfoField(Flags="", SegID=0x5435),
                InfoField(Flags="C", SegID=0x2ab5),
            ],
            HopFields=[
                HopField(ExpTime=63, ConsIngress=2, ConsEgress=0),
                HopField(ExpTime=63, ConsIngress=0, ConsEgress=2),
                HopField(ExpTime=63, ConsIngress=0, ConsEgress=4),
                HopField(ExpTime=63, ConsIngress=2, ConsEgress=0),
            ],
        )
    )
    pkt = pkt / IDINT(
        Flags="Encrypted" if encrypt else "",
        AggrMode="Off",
        Verifier="Destination",
        InstFlags=0xf if req_default_md else 0,
        Inst1=instr[0],
        Inst2=instr[1],
        Inst3=instr[2],
        Inst4=instr[3],
        TelemetryStack = [
            # Two empty entries withput encryption
            StackEntry(Flags="Egress", Hop=0, Mask=0),
            StackEntry(Flags="Source", Hop=0, Mask=0),
        ]
    )
    pkt = pkt / UDP() / TimestampHdr()
    pkt = pkt / Raw(os.urandom(PAYLOAD - 4))
    pkt[SCION].Path.init_path(4 * [AS_KEY], [b"ab"])
    pkt[SCION].Path.egress(AS_KEY)
    pkt[IDINT].verify(keys=2*[IDINT_KEY], update=True)
    return pkt


if __name__ == "__main__":
    PATH = "config/idint-osr-eval/packets"

    pkt = create_pkt()
    with open(f"{PATH}/baseline.bin", "bw") as file:
        file.write(bytes(pkt))

    pkt = create_idint_pkt(["ZERO_8", "NOP", "NOP", "NOP"], False, False)
    with open(f"{PATH}/idint_8.bin", "bw") as file:
        file.write(bytes(pkt))
    pkt = create_idint_pkt(["ZERO_8", "NOP", "NOP", "NOP"], False, True)
    with open(f"{PATH}/idint_8_enc.bin", "bw") as file:
        file.write(bytes(pkt))

    pkt = create_idint_pkt(["ZERO_8", "ZERO_8", "NOP", "NOP"], False, False)
    with open(f"{PATH}/idint_16.bin", "bw") as file:
        file.write(bytes(pkt))
    pkt = create_idint_pkt(["ZERO_8", "ZERO_8", "NOP", "NOP"], False, True)
    with open(f"{PATH}/idint_16_enc.bin", "bw") as file:
        file.write(bytes(pkt))

    pkt = create_idint_pkt(["ZERO_8", "ZERO_8", "ZERO_8", "NOP"], False, False)
    with open(f"{PATH}/idint_24.bin", "bw") as file:
        file.write(bytes(pkt))
    pkt = create_idint_pkt(["ZERO_8", "ZERO_8", "ZERO_8", "NOP"], False, True)
    with open(f"{PATH}/idint_24_enc.bin", "bw") as file:
        file.write(bytes(pkt))

    pkt = create_idint_pkt(["ZERO_8", "ZERO_8", "ZERO_8", "ZERO_8"], False, False)
    with open(f"{PATH}/idint_32.bin", "bw") as file:
        file.write(bytes(pkt))
    pkt = create_idint_pkt(["ZERO_8", "ZERO_8", "ZERO_8", "ZERO_8"], False, True)
    with open(f"{PATH}/idint_32_enc.bin", "bw") as file:
        file.write(bytes(pkt))

    pkt = create_idint_pkt(["ZERO_8", "ZERO_8", "ZERO_8", "ZERO_8"], True, False)
    with open(f"{PATH}/idint_42.bin", "bw") as file:
        file.write(bytes(pkt))
    pkt = create_idint_pkt(["ZERO_8", "ZERO_8", "ZERO_8", "ZERO_8"], True, True)
    with open(f"{PATH}/idint_42_enc.bin", "bw") as file:
        file.write(bytes(pkt))
