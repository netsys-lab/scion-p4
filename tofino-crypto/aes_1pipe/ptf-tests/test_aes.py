# SPDX-License-Identifier: AGPL-3.0-or-later
import enum

import bfrt_grpc.client as gc
import ptf
import scapy
from ptf.mask import Mask
from bfruntime_client_base_tests import BaseTest, BfRuntimeTest
from controller.aes import AesPipe, AesTestPipe
from p4testutils.misc_utils import *
from scapy.fields import ByteField, ConditionalField, FlagsField, ShortField, XNBytesField
from scapy.layers.inet import Ether, IP
from scapy.packet import Packet, bind_layers

logger = get_logger()


class BrFlags(enum.IntFlag):
    ENB_BLOCK0 = (1 << 7)
    ENB_BLOCK1 = (1 << 6)
    SCND_ITER  = (1 << 5)


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
        ShortField("Reserved", default=0),
        ConditionalField(
            XNBytesField("Block0", default=0, sz=16),
            lambda pkt: BrFlags.ENB_BLOCK0.name in pkt.Flags),
        ConditionalField(
            XNBytesField("Block1", default=0, sz=16),
            lambda pkt: BrFlags.ENB_BLOCK1.name in pkt.Flags),
        XNBytesField("Key", default=0, sz=16)
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


class Aes2PipesTest(BaseTest):

    class Pipe0(BfRuntimeTest):
        def setUp(self, client_id, p4_name="aes_1pipe"):
            BfRuntimeTest.setUp(self, client_id, p4_name)
            self.bfrt_info = self.interface.bfrt_info_get(p4_name)
            self.controller = AesPipe(self.interface)

        def tearDown(self):
            super().tearDown()

        def programTables(self):
            self.controller.program_tables()

        def clearTables(self):
            self.controller.clear_tables()

    class Pipe1(BfRuntimeTest):
        def setUp(self, client_id, p4_name="aes_1pipe_test"):
            BfRuntimeTest.setUp(self, client_id, p4_name)
            self.bfrt_info = self.interface.bfrt_info_get(p4_name)
            self.controller = AesTestPipe(self.interface)

        def tearDown(self):
            super().tearDown()

        def programTables(self):
            self.controller.program_tables()

        def clearTables(self):
            self.controller.clear_tables()

    def setUp(self):
        self.pipe0 = self.Pipe0()
        self.pipe1 = self.Pipe1()

        self.pipe0.setUp(1)
        self.pipe1.setUp(2)

        # PTF dataplane
        self.dataplane = ptf.dataplane_instance
        self.dataplane.flush()
        self.target = gc.Target(device_id=0)

    def tearDown(self):
        self.pipe0.tearDown()
        self.pipe1.tearDown()
        super().tearDown()

    def runTest(self):
        self.pipe0.clearTables()
        self.pipe1.clearTables()

        logger.info("Program tables")
        self.pipe0.programTables()
        self.pipe1.programTables()

        ether = Ether(dst="ff:ff:ff:ff:ff:ff", src="00:00:00:00:00:00")

        # Send a normal packet without the bridge header through the AES pipeline.
        # The packet should be echoed back unmodified.
        logger.info("Test forwarding")
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff", src="00:00:00:00:00:00")/IP()
        send_packet(self, _make_port(1, 8), pkt)
        verify_packet(self, pkt, _make_port(1, 8))
        send_packet(self, _make_port(1, 9), pkt)
        verify_packet(self, pkt, _make_port(1, 9))

        logger.info("Test encryption (1 block)")
        pkt = ether / BridgeHeader(Flags=BrFlags.ENB_BLOCK0,
            Block0=0x3243f6a8885a308d313198a2e0370734,
            Key=0x2b7e151628aed2a6abf7158809cf4f3c
        )
        exp = ether / BridgeHeader(Flags=BrFlags.ENB_BLOCK0 | BrFlags.SCND_ITER,
            Block0=0x3925841d02dc09fbdc118597196a0b32,
            Key=0xd014f9a8c9ee2589e13f0cc8b6630ca6
        )
        send_packet(self, _make_port(1, 8), pkt)
        verify_packet(self, exp, _make_port(1, 8))

        logger.info("Test encryption (2 blocks)")
        pkt = ether / BridgeHeader(Flags=BrFlags.ENB_BLOCK0 | BrFlags.ENB_BLOCK1,
            Block0=0x3243f6a8885a308d313198a2e0370734,
            Block1=0xd92e283a1f692b18448b285a9caf9831,
            Key=0x2b7e151628aed2a6abf7158809cf4f3c
        )
        exp = ether / BridgeHeader(
            Flags=BrFlags.ENB_BLOCK0 | BrFlags.ENB_BLOCK1 | BrFlags.SCND_ITER,
            Block0=0x3925841d02dc09fbdc118597196a0b32,
            Block1=0x374fc69ac189a13854485c80c66ff6d3,
            Key=0xd014f9a8c9ee2589e13f0cc8b6630ca6
        )
        send_packet(self, _make_port(1, 8), pkt)
        verify_packet(self, exp, _make_port(1, 8))

        logger.info("Test changing keys")
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
        block0 = [
            0xf15e013adb1ee186e0451a4e3df80d91,
            0xfbd0ae56e3b69020e267cf06f22a80a1,
            0x92727a2352fd5f21e97b3f6f84658bb6,
            0x81d89cd5a2f9b5e662ba0b0f28fa7d7d,
            0x6106a753aa4fd17aac0614acedd7f6e7,
            0xac249c930264aa0a4bb2c3d33386fcd5,
            0xdf239b8156d9c81c103dfb24655e6da2,
            0xfe1f78e29a01ec541dca37da7837b6a3,
            0xe429a0a75900fa4dd76a20dd8954032f,
            0x958cdc0a095dc891564581ed9ebdf94d,
            0xc10a7d0a618c8d9bbe444280da976a93
        ]
        block1 = [
            0x62de9c92e5f02bb7485a443aa2d0e89c,
            0x165fec866dd64887a263e0b60e7da457,
            0xf1316ed4085a1f757ba7a6de46d8c0de,
            0x336bf76b43214e2187432d82ff27bad6,
            0xfd7c19b9aa7521ce97c575cc210fc60f,
            0x18cefe8b76f691488deb1e5e0debf6fb,
            0x6c9467ad65644964a88cc529907eb04b,
            0xc762daa8426471597771e2181823e61b,
            0xb807a60a00698e16cb7b9571d67e6c09,
            0xf81190a75fd84ce89cee3d65ca19f510,
            0x5c95119e7ddc51fcf272d14d713c0aef
        ]
        for i, key in enumerate(keys):
            pkt = ether / BridgeHeader(Flags=BrFlags.ENB_BLOCK0 | BrFlags.ENB_BLOCK1,
                Block0=block0[i],
                Block1=block1[i],
                Key=key
            )
            exp = Mask(ether / BridgeHeader(
                Flags=BrFlags.ENB_BLOCK0 | BrFlags.ENB_BLOCK1 |BrFlags.SCND_ITER,
                Block0=block0[i + 1],
                Block1=block1[i + 1],
            ))
            exp.set_do_not_care_scapy(BridgeHeader, "Key")
            send_packet(self, _make_port(1, 8), pkt)
            verify_packet(self, exp, _make_port(1, 8))
