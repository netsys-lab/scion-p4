# SPDX-License-Identifier: AGPL-3.0-or-later
import logging
from typing import Iterable, List, Tuple

import bfrt_grpc.client as gc

from . import tables

AES_RCON = [
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
]

logger = logging.getLogger(__name__)


def _make_port(pipe: int, port: int) -> int:
    """Make port number from pipe ID and port within the pipe."""
    return (pipe << 7) | port


def _add_fwd_entry(t_fwd, target, ig_port: int, eg_port: int):
    """Add an entry to the forwarding table."""
    t_fwd.entry_add(target,
        [t_fwd.make_key(
            [gc.KeyTuple("ig_intr_md.ingress_port", ig_port)])],
        [t_fwd.make_data(
            [gc.DataTuple("egress_port", eg_port)],
            "Ingress.set_egress")])


def _clear_fwd_table(t_fwd, target):
    """Clear all entries from the forwarding table."""
    t_fwd.entry_del(target)


def _program_aes_table(tab, target, key: str, action: str, data: Iterable[int]):
    """Program a hash action table with 256 entries for AES.

    ### Parameters
    key    : Key field
    action : The one and only action used in the table
    data   : 256 integers with which the table will be programmed
    """
    tkeys = 256 * [None]
    tdata = 256 * [None]
    for i, v in enumerate(data):
        tkeys[i] = tab.make_key([gc.KeyTuple(key, i)])
        tdata[i] = tab.make_data([gc.DataTuple("value", v)], action)
    tab.entry_add_or_mod(target, tkeys, tdata)


class AesController:
    """Controller the AES pipeline. The full program consists of two pipelines
    and requires two instances of this controller.
    """

    def __init__(self,
        interface: gc.ClientInterface,
        p4_name: str = "aes_pipe0",
        aes_rounds: Tuple[int, int] = (1, 11),
        key_exp: Tuple[int, int] = (1, 11),
        key_exp_no_meta : List[int] = [],
        pipe: int = 0,
        next_pipe: int = 1):
        """
        ### Parameters
        interface       : gRPC client interface connected to switch driver
        p4_name         : Name of the P4 program
        aes_rounds      : Half-open range of AES rounds covered by the pipeline
        key_exp         : Half-open range of key expansion steps in the pipeline
        key_exp_no_meta : Rounds in which the second copy of the key in the metadata is not expanded
        pipe            : Which pipe the program is loaded on (0-3)
        next_pipe       : Next pipe the packets will be sent to (0-3)
        """
        self.interface = interface
        self.p4_name = p4_name
        self.aes_rounds = aes_rounds
        self.key_exp = key_exp
        self.key_exp_no_meta = key_exp_no_meta
        self.pipe = pipe
        self.next_pipe = next_pipe

        self.bfrt_info = self.interface.bfrt_info_get(self.p4_name)
        logger.info("AES pipe %d program name: %s", self.pipe, self.bfrt_info.p4_name_get())

        self._get_tables()

    def _get_tables(self):
        # Forwarding
        self.t_fwd = self.bfrt_info.table_get("tab_forward")

        # S-boxes for key expansion
        self.t_sbox = {}
        for round in range(*self.key_exp):
            blocks = 1 if round in self.key_exp_no_meta else 2
            for block in range(blocks):
                tab = self.bfrt_info.table_get(f"tab_b{block}_r{round}_sbox_rcon_byte0")
                self.t_sbox[(block, round, 0)] = tab
                for byte in range(1, 4):
                    tab = self.bfrt_info.table_get(f"tab_b{block}_r{round}_sbox_byte{byte}")
                    self.t_sbox[(block, round, byte)] = tab

        # T-tables
        self.t_tbox = {}
        for round in range(self.aes_rounds[0], min(self.aes_rounds[1], 10)):
            for block in range(2):
                for t in range(4):
                    for column in range(4):
                        tab = self.bfrt_info.table_get(f"tab_b{block}_r{round}_t{t}_c{column}")
                        self.t_tbox[(block, round, t, column)] = tab

        # Round 10 S-boxes
        if 10 in range(*self.aes_rounds):
            self.t_last_sbox = {}
            for block in range(2):
                for s in range(4):
                    for column in range(4):
                        tab = self.bfrt_info.table_get(f"tab_b{block}_r10_s{s}_c{column}")
                        self.t_last_sbox[(block, s, column)] = tab

    def program_tables(self):
        target = gc.Target(device_id=0)

        # pipe-to-pipe forwarding
        logger.info("Pipe %s: Program forwarding table", self.pipe)
        for port in range(8, 72):
            _add_fwd_entry(self.t_fwd, target,
                _make_port(self.pipe, port), _make_port(self.next_pipe, port))

        # S-boxes for key expansion
        logger.info("Pipe %s: Program key expansion S-boxes", self.pipe)
        for round in range(*self.key_exp):
            blocks = 1 if round in self.key_exp_no_meta else 2
            for block in range(blocks):
                _program_aes_table(self.t_sbox[(block, round, 0)], target,
                    key=f"{'hdr' if block == 0 else 'meta'}.key.c3[23:16]",
                    action=f"add_byte0_b{block}",
                    data=[x ^ AES_RCON[round] for x in tables.AES_S])
                _program_aes_table(self.t_sbox[(block, round, 1)], target,
                    key=f"{'hdr' if block == 0 else 'meta'}.key.c3[15:8]",
                    action=f"add_byte1_b{block}",
                    data=tables.AES_S)
                _program_aes_table(self.t_sbox[(block, round, 2)], target,
                    key=f"{'hdr' if block == 0 else 'meta'}.key.c3[7:0]",
                    action=f"add_byte2_b{block}",
                    data=tables.AES_S)
                _program_aes_table(self.t_sbox[(block, round, 3)], target,
                    key=f"{'hdr' if block == 0 else 'meta'}.key.c3[31:24]",
                    action=f"add_byte3_b{block}",
                    data=tables.AES_S)

        # T-tables
        logger.info("Pipe %s: Program T-tables", self.pipe)
        T = [tables.AES_T0, tables.AES_T1, tables.AES_T2, tables.AES_T3]
        for round in range(self.aes_rounds[0], min(self.aes_rounds[1], 10)):
            for block in range(2):
                for t, shift in enumerate([0, 1, 2, 3]):
                    a, b = 8*((3-t)+1)-1, 8*(3-t)
                    _program_aes_table(self.t_tbox[(block, round, t, 0)], target,
                        key=f"hdr.block{block}.c{(0+shift)%4}[{a}:{b}]",
                        action=f"{'set' if t == 0 else 'add'}_col0_b{block}",
                        data=T[t])
                    _program_aes_table(self.t_tbox[(block, round, t, 1)], target,
                        key=f"hdr.block{block}.c{(1+shift)%4}[{a}:{b}]",
                        action=f"{'set' if t == 0 else 'add'}_col1_b{block}",
                        data=T[t])
                    _program_aes_table(self.t_tbox[(block, round, t, 2)], target,
                        key=f"hdr.block{block}.c{(2+shift)%4}[{a}:{b}]",
                        action=f"{'set' if t == 0 else 'add'}_col2_b{block}",
                        data=T[t])
                    _program_aes_table(self.t_tbox[(block, round, t, 3)], target,
                        key=f"hdr.block{block}.c{(3+shift)%4}[{a}:{b}]",
                        action=f"{'set' if t == 0 else 'add'}_col3_b{block}",
                        data=T[t])

        # Round 10 S-boxes
        logger.info("Pipe %s: Program S-boxes", self.pipe)
        if 10 in range(*self.aes_rounds):
            for block in range(2):
                for s, shift in enumerate([0, 1, 2, 3]):
                    a, b = 8*((3-s)+1)-1, 8*(3-s)
                    _program_aes_table(self.t_last_sbox[(block, s, 0)], target,
                        key=f"hdr.block{block}.c{(0+shift)%4}[{a}:{b}]",
                        action=f"{'set' if s == 0 else 'add'}_col0_b{block}",
                        data=[x << (8*(3-s)) for x in tables.AES_S])
                    _program_aes_table(self.t_last_sbox[(block, s, 1)], target,
                        key=f"hdr.block{block}.c{(1+shift)%4}[{a}:{b}]",
                        action=f"{'set' if s == 0 else 'add'}_col1_b{block}",
                        data=[x << (8*(3-s)) for x in tables.AES_S])
                    _program_aes_table(self.t_last_sbox[(block, s, 2)], target,
                        key=f"hdr.block{block}.c{(2+shift)%4}[{a}:{b}]",
                        action=f"{'set' if s == 0 else 'add'}_col2_b{block}",
                        data=[x << (8*(3-s)) for x in tables.AES_S])
                    _program_aes_table(self.t_last_sbox[(block, s, 3)], target,
                        key=f"hdr.block{block}.c{(3+shift)%4}[{a}:{b}]",
                        action=f"{'set' if s == 0 else 'add'}_col3_b{block}",
                        data=[x << (8*(3-s)) for x in tables.AES_S])


    def clear_tables(self):
        target = gc.Target(device_id=0)
        _clear_fwd_table(self.t_fwd, target)


class AesFirstPipe(AesController):
    def __init__(self,
        interface: gc.ClientInterface,
        p4_name: str = "aes_pipe0",
        pipe: int = 0,
        next_pipe: int = 1):
        super().__init__(interface, p4_name, pipe=pipe, next_pipe=next_pipe,
            aes_rounds=(1, 6), key_exp=(1, 7), key_exp_no_meta=[4, 6])


class AesSecondPipe(AesController):
    def __init__(self,
        interface: gc.ClientInterface,
        p4_name: str = "aes_pipe1",
        pipe: int = 1,
        next_pipe: int = 2):
        super().__init__(interface, p4_name, pipe=pipe, next_pipe=next_pipe,
            aes_rounds=(6, 11), key_exp=(7, 11), key_exp_no_meta=[9])


class AesTestPipe(AesController):
    """Empty pipe for testing"""
    def __init__(self,
        interface: gc.ClientInterface,
        p4_name: str = "aes_test",
        pipe: int = 2,
        next_pipe: int = 0):
        super().__init__(interface, p4_name, pipe=pipe, next_pipe=next_pipe,
            aes_rounds=(0, 0), key_exp=(0, 0))
