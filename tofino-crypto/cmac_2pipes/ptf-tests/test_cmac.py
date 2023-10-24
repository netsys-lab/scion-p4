# SPDX-License-Identifier: AGPL-3.0-or-later
import enum

import bfrt_grpc.client as gc
import ptf
import scapy
from bfruntime_client_base_tests import BaseTest, BfRuntimeTest
from controller.cmac import CmacFirstPipe, CmacSecondPipe, CmacTestPipe
from p4testutils.misc_utils import *
from scapy.fields import BitField, ByteField, ConditionalField, FlagsField, PacketField, XNBytesField
from scapy.layers.inet import Ether, IP, UDP
from scapy.packet import Packet, Raw, bind_layers

logger = get_logger()


class BrFlags(enum.IntFlag):
    CHECK_MAC0 = (1 << 7)
    CHECK_MAC1 = (1 << 6)


class CmacBlock(Packet):
    """Input data and MAC to check against."""

    name = "CMAC Validation Block"

    fields_desc= [
        XNBytesField("Data", default=0, sz=16),
        XNBytesField("MAC", default=0, sz=6),
    ]


class BridgeHeader(Packet):
    """Bridge header for submitting work to the AES pipeline."""

    name = "AES Bridge Header"
    assert(tuple(int(x) for x in scapy.VERSION.split('.')) >= (2, 5, 0))

    fields_desc = [
        FlagsField("Flags", default=0, size=8, names={
            # Change to 'f.value.bit_length()-1' for Scapy < 2.5.0
            f.value: f.name for f in BrFlags}
        ),
        ByteField("Length", default=0),
        BitField("UserData0", default=0, size=5),
        BitField("EgressPort", default=0, size=9),
        BitField("UserData1", default=0, size=2),
        ConditionalField(
            PacketField(name="Block0", default=None, pkt_cls=CmacBlock),
            lambda pkt: BrFlags.CHECK_MAC0.name in pkt.Flags),
        ConditionalField(
            PacketField(name="Block1", default=None, pkt_cls=CmacBlock),
            lambda pkt: BrFlags.CHECK_MAC1.name in pkt.Flags),
    ]

    def post_build(self, hdr: bytes, payload: bytes):
        if self.Length == 0:
            hdr_len = len(hdr)
            hdr = hdr[:1] + hdr_len.to_bytes(1, byteorder='big') + hdr[2:]
        return hdr + payload


bind_layers(Ether, BridgeHeader, type=0x9999)


def _make_port(pipe: int, port: int) -> int:
    """Make port number from pipe ID and port within the pipe."""
    return (pipe << 7) | port


class Cmac2PipesTest(BaseTest):

    class Pipe0(BfRuntimeTest):
        def setUp(self, client_id, p4_name="cmac_pipe0"):
            BfRuntimeTest.setUp(self, client_id, p4_name)
            self.bfrt_info = self.interface.bfrt_info_get(p4_name)
            self.controller = CmacFirstPipe(self.interface)

        def tearDown(self):
            super().tearDown()

        def programTables(self):
            self.controller.program_tables()

        def clearTables(self):
            self.controller.clear_tables()

        def setKey(self, key: bytes):
            self.controller.set_key(key)

    class Pipe1(BfRuntimeTest):
        def setUp(self, client_id, p4_name="cmac_pipe1"):
            BfRuntimeTest.setUp(self, client_id, p4_name)
            self.bfrt_info = self.interface.bfrt_info_get(p4_name)
            self.controller = CmacSecondPipe(self.interface)

        def tearDown(self):
            super().tearDown()

        def programTables(self):
            self.controller.program_tables()

        def clearTables(self):
            self.controller.clear_tables()

        def setKey(self, key: bytes):
            self.controller.set_key(key)

    class Pipe2(BfRuntimeTest):
        def setUp(self, client_id, p4_name="cmac_test"):
            BfRuntimeTest.setUp(self, client_id, p4_name)
            self.bfrt_info = self.interface.bfrt_info_get(p4_name)
            self.controller = CmacTestPipe(self.interface)

        def tearDown(self):
            super().tearDown()

        def programTables(self):
            self.controller.program_tables()

        def clearTables(self):
            self.controller.clear_tables()

    def setUp(self):
        self.pipe0 = self.Pipe0()
        self.pipe1 = self.Pipe1()
        self.pipe2 = self.Pipe2()

        self.pipe0.setUp(1)
        self.pipe1.setUp(2)
        self.pipe2.setUp(3)

        # PTF dataplane
        self.dataplane = ptf.dataplane_instance
        self.dataplane.flush()
        self.target = gc.Target(device_id=0)

    def tearDown(self):
        self.pipe0.tearDown()
        self.pipe1.tearDown()
        self.pipe2.tearDown()
        super().tearDown()

    def runTest(self):
        self.pipe0.clearTables()
        self.pipe1.clearTables()
        self.pipe2.clearTables()

        logger.info("Program tables")
        self.pipe0.programTables()
        self.pipe1.programTables()
        self.pipe2.programTables()

        ether = Ether(dst="ff:ff:ff:ff:ff:ff", src="00:00:00:00:00:00")
        payload = Ether(dst="00:00:00:00:00:00", src="00:00:00:00:00:00")
        payload = payload / IP(dst="127.0.0.1", src="127.0.0.1") / UDP(dport=50000, sport=50000)
        payload = payload / Raw(32*b"\x00")

        key = (0x2b7e151628aed2a6abf7158809cf4f3c).to_bytes(16, 'big')
        self.pipe0.setKey(key)
        self.pipe1.setKey(key)

        logger.info("Test valid packet (1 MAC)")
        pkt = ether / BridgeHeader(Flags=BrFlags.CHECK_MAC0,
            EgressPort=_make_port(2, 9),
            Block0=CmacBlock(
                Data=0x6bc1bee22e409f96e93d7e117393172a,
                MAC=0x070a16b46b4d
            )
        ) / payload
        send_packet(self, _make_port(2, 8), pkt)
        verify_packet(self, payload, _make_port(2, 9))

        logger.info("Test invalid packet (1 MAC)")
        pkt = ether / BridgeHeader(Flags=BrFlags.CHECK_MAC0,
            EgressPort=_make_port(2, 9),
            Block0=CmacBlock(
                Data=0x6bc1bee22e409f96e93d7e117393172a,
                MAC=0xffffffffffff
            )
        ) / payload
        send_packet(self, _make_port(2, 8), pkt)
        verify_no_packet(self, payload, _make_port(2, 9))

        logger.info("Test valid packet (2 MACs)")
        pkt = ether / BridgeHeader(Flags=BrFlags.CHECK_MAC0 | BrFlags.CHECK_MAC1,
            EgressPort=_make_port(2, 9),
            Block0=CmacBlock(
                Data=0x6bc1bee22e409f96e93d7e117393172a,
                MAC=0x070a16b46b4d
            ),
            Block1=CmacBlock(
                Data=0x462b917e785e36fb04a790cfa45ad25f,
                MAC=0x59835a364eb6
            )
        ) / payload
        send_packet(self, _make_port(2, 8), pkt)
        verify_packet(self, payload, _make_port(2, 9))

        logger.info("Test invalid packet (2 MACs)")
        pkt = ether / BridgeHeader(Flags=BrFlags.CHECK_MAC0 | BrFlags.CHECK_MAC1,
            EgressPort=_make_port(2, 9),
            Block0=CmacBlock(
                Data=0x6bc1bee22e409f96e93d7e117393172a,
                MAC=0xffffffffffff
            ),
            Block1=CmacBlock(
                Data=0x462b917e785e36fb04a790cfa45ad25f,
                MAC=0x59835a364eb6
            )
        ) / payload
        send_packet(self, _make_port(2, 8), pkt)
        verify_no_packet(self, payload, _make_port(2, 9))

        pkt = ether / BridgeHeader(Flags=BrFlags.CHECK_MAC0 | BrFlags.CHECK_MAC1,
            EgressPort=_make_port(2, 9),
            Block0=CmacBlock(
                Data=0x6bc1bee22e409f96e93d7e117393172a,
                MAC=0x070a16b46b4d
            ),
            Block1=CmacBlock(
                Data=0x462b917e785e36fb04a790cfa45ad25f,
                MAC=0xffffffffffff
            )
        ) / payload
        send_packet(self, _make_port(2, 8), pkt)
        verify_no_packet(self, payload, _make_port(2, 9))

        pkt = ether / BridgeHeader(Flags=BrFlags.CHECK_MAC0 | BrFlags.CHECK_MAC1,
            EgressPort=_make_port(2, 9),
            Block0=CmacBlock(
                Data=0x6bc1bee22e409f96e93d7e117393172a,
                MAC=0xffffffffffff
            ),
            Block1=CmacBlock(
                Data=0x462b917e785e36fb04a790cfa45ad25f,
                MAC=0xffffffffffff
            )
        ) / payload
        send_packet(self, _make_port(2, 8), pkt)
        verify_no_packet(self, payload, _make_port(2, 9))

        logger.info("Test different keys")
        keys = [
            0x3eb9b5b4b9849ade4d76cbc38384cb12,
            0x359817e94fe2b30971b6f7f93b0e7613,
            0xd46247835b46311ae9c1c46809e47970,
            0x75f8544f15a8b414448ef199552775ee,
            0xd8a1f00e33acd6390fc85ab344280250,
            0xa2ad5832b5f5b67fe85a40d5ee9b8fa9,
            0xe13e1c7688a066aa5e5be125083861ff,
            0x493328695d153ee7cf54ce9e0ee8b347,
            0x8b4c8688fc7a02e97493932de4492c7e,
            0x2e922992756fe2c581e17edcc1c20e3c
        ]
        macs = [
            (0x857613ea3c5cd42f23b4e0f291202ff9, 0xdc57ab95b5416e66b98bb5bbfde9fec1),
            (0x5935d25821e1db39b2d2f2bbabfbb861, 0xfb51e1bb0721b78f5fa39d0123015e5c),
            (0x950db088b27676052ac421ac742b256d, 0xdc18d44d0d03042180ee88213b527f03),
            (0x45954cfd3deaf521b236e8d542e41408, 0x0dc44b87ef38e4abba8264dbe167a9b2),
            (0xf6eb0aafa8698457903af143c06a1674, 0xc77f1883d00e749125108a36c5e90d5e),
            (0x9c13862b413e80e24084523023e993a3, 0x3b0e0b1daa61c33e0a3bfe0a70f927cc),
            (0x67c08e6e6fa3f0d21fd8b4bbe78a4927, 0xed2639ab38c145f912f58f04db7103bb),
            (0x5a42071b82d11b9ce08000f3962d6065, 0x8a5ebae209aa3c0c61b3c4cf9a4d77a7),
            (0x8ef4ade666bbd9e13673274220d0d93d, 0xf715bc3c16c3585ade90ec19a46bf6d7),
            (0x2329349cc0c2aa4987a4d36f8b0c50e4, 0x9ecd470571588fe236fa61edb3f0dc91)
        ]
        for key, (mac0, mac1) in zip(keys, macs):
            self.pipe0.setKey(key.to_bytes(16, "big"))
            self.pipe1.setKey(key.to_bytes(16, "big"))
            pkt = ether / BridgeHeader(Flags=BrFlags.CHECK_MAC0 | BrFlags.CHECK_MAC1,
                EgressPort=_make_port(2, 9),
                Block0=CmacBlock(
                    Data=0xf15e013adb1ee186e0451a4e3df80d91,
                    MAC=mac0 >> 80
                ),
                Block1=CmacBlock(
                    Data=0x62de9c92e5f02bb7485a443aa2d0e89c,
                    MAC=mac1 >> 80
                )
            ) / payload
            send_packet(self, _make_port(2, 8), pkt)
            verify_packet(self, payload, _make_port(2, 9))
