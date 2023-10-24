# SPDX-License-Identifier: AGPL-3.0-or-later
import logging
from typing import Iterable, List, Tuple

import bfrt_grpc.client as gc

from . import tables

AES_RCON = [
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
]

logger = logging.getLogger(__name__)


def _aes_key_expansion(key: bytes) -> bytes:
    """Calculate the AES-128 key schedule from a 16-byte key."""
    def rot_sub_word(w):
        res = 0
        res |= tables.AES_S[(w >> 24) & 0xff]
        res |= tables.AES_S[w & 0xff] << 8
        res |= tables.AES_S[(w >> 8) & 0xff] << 16
        res |= tables.AES_S[(w >> 16) & 0xff] << 24
        return res

    sched = [int.from_bytes(key[i:i+4], 'big') for i in range(0, 16, 4)]
    for i in range(4, 11*4):
        temp = sched[-1]
        if i % 4 == 0:
            temp = rot_sub_word(temp) ^ (AES_RCON[i // 4] << 24)
        sched.append(sched[-4] ^ temp)
    return b"".join(w.to_bytes(4, 'big') for w in sched)


def _aes_encrypt(input: bytes, key_schedule: bytes):
    """Encrypt a 16-byte block using the given key schedule."""
    state = [int.from_bytes(input[i:i+4], 'big') for i in range(0, 16, 4)]

    S = tables.AES_S
    T0, T1, T2, T3 = tables.AES_T0, tables.AES_T1, tables.AES_T2, tables.AES_T3

    # XOR key
    for i in range(4):
        state[i] ^= int.from_bytes(key_schedule[i*4:(i+1)*4], 'big')

    # First 9 rounds
    for round in range(1, 10):
        c = [0, 0, 0, 0]
        c[0] = T0[state[0]>>24&0xff] ^ T1[state[1]>>16&0xff] ^ T2[state[2]>>8&0xff] ^ T3[state[3]&0xff]
        c[1] = T0[state[1]>>24&0xff] ^ T1[state[2]>>16&0xff] ^ T2[state[3]>>8&0xff] ^ T3[state[0]&0xff]
        c[2] = T0[state[2]>>24&0xff] ^ T1[state[3]>>16&0xff] ^ T2[state[0]>>8&0xff] ^ T3[state[1]&0xff]
        c[3] = T0[state[3]>>24&0xff] ^ T1[state[0]>>16&0xff] ^ T2[state[1]>>8&0xff] ^ T3[state[2]&0xff]
        for i in range(4):
            state[i] = c[i] ^ int.from_bytes(key_schedule[(round*4+i)*4:(round*4+i+1)*4], 'big')

    # Last round
    round = 10
    c = [0, 0, 0, 0]
    c[0] = S[state[0]>>24&0xff]<<24 ^ S[state[1]>>16&0xff]<<16 ^ S[state[2]>>8&0xff]<<8 ^ S[state[3]&0xff]
    c[1] = S[state[1]>>24&0xff]<<24 ^ S[state[2]>>16&0xff]<<16 ^ S[state[3]>>8&0xff]<<8 ^ S[state[0]&0xff]
    c[2] = S[state[2]>>24&0xff]<<24 ^ S[state[3]>>16&0xff]<<16 ^ S[state[0]>>8&0xff]<<8 ^ S[state[1]&0xff]
    c[3] = S[state[3]>>24&0xff]<<24 ^ S[state[0]>>16&0xff]<<16 ^ S[state[1]>>8&0xff]<<8 ^ S[state[2]&0xff]
    for i in range(4):
        state[i] = c[i] ^ int.from_bytes(key_schedule[(round*4+i)*4:(round*4+i+1)*4], 'big')

    return b"".join(w.to_bytes(4, 'big') for w in state)


def _cmac_key_schedule(key: bytes) -> bytearray:
    """Generate the key schedule for AES-CMAC. The first subkey is already XORed
    with the "round 0" key (the original key).
    """
    key_sched = bytearray(_aes_key_expansion(key))

    # Generate AES-CMAC subkey
    zero = 16*b"\x00"
    subkey = _aes_encrypt(zero, key_sched)
    msb = subkey[0] >> 7
    subkey = bytearray((int.from_bytes(subkey, 'big') << 1).to_bytes(17, 'big')[1:])
    if msb:
        subkey[15] ^= 0x87

    # XOR subkey
    for i in range(16):
        key_sched[i] ^= subkey[i]

    return key_sched


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


def _program_aes_table_512(tab, target, key: str, action: str, data: Iterable[int]):
    """Program a hash action table with 512 entries where the fist 256 entries
    apply to pass0 and the second 256 entries apply to pass 1.

    ### Parameters
    key    : Key field
    action : The one and only action used in the table
    data   : 512 integers with which the table will be programmed
    """
    tkeys = 512 * [None]
    tdata = 512 * [None]
    for i, v in enumerate(data):
        tkeys[i] = tab.make_key([
            gc.KeyTuple("hdr.meta.iter", i // 256),
            gc.KeyTuple(key, i % 256)
        ])
        tdata[i] = tab.make_data([gc.DataTuple("value", v)], action)
    tab.entry_add_or_mod(target, tkeys, tdata)


def _program_key_table(tab, target, key: str, index: int, iteration: int, action: str, data: bytes):
    """Write a round key to a key table.

    ### Parameters
    key       : Key field
    index     : Key value
    iteration : Pipeline iteration the key is for
    action    : The one and only action used in the table
    data      : 16 bytes round key
    """
    tab.entry_add_or_mod(target,
        [tab.make_key([
            gc.KeyTuple("hdr.meta.iter", iteration),
            gc.KeyTuple(key, index)
        ])],
        [tab.make_data([
            gc.DataTuple("c0", data[0:4]),
            gc.DataTuple("c1", data[4:8]),
            gc.DataTuple("c2", data[8:12]),
            gc.DataTuple("c3", data[12:16])
        ], action)]
    )


class _CmacController:
    """Controller for AES pipeline using two passes.
    """
    _key_tables = range(0, 7)
    _t_tables = [1, 2, 3, 5, 6]
    _st_table = 4

    def __init__(self, bfrt_info: gc._BfRtInfo, pipe: int = 0):
        self.bfrt_info = bfrt_info
        self.pipe = pipe
        self._get_tables()

    def _get_tables(self):
        # Key tables
        self.t_key = {}
        for round in self._key_tables:
            for block in range(2):
                tab = self.bfrt_info.table_get(f"tab_b{block}_r{round}_key")
                self.t_key[(block, round)] = tab

        # T-tables
        self.t_tbox = {}
        for round in self._t_tables:
            for block in range(2):
                for t in range(4):
                    for column in range(4):
                        tab = self.bfrt_info.table_get(f"tab_b{block}_r{round}_t{t}_c{column}")
                        self.t_tbox[(block, round, t, column)] = tab

        # Round 4/10 T-tables/S-boxes
        self.t_stbox = {}
        for block in range(2):
            for s in range(4):
                for column in range(4):
                    tab = self.bfrt_info.table_get(f"tab_b{block}_r{self._st_table}_st{s}_c{column}")
                    self.t_stbox[(block, s, column)] = tab

    def program_tables(self, target):
        """Program constant tables."""
        # T-tables
        logger.info("Pipe %s: Program T-tables", self.pipe)
        T = [tables.AES_T0, tables.AES_T1, tables.AES_T2, tables.AES_T3]
        for round in self._t_tables:
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

        # Round 4/10 T-/S-boxes
        logger.info("Pipe %s: Program S/T-boxes", self.pipe)
        for block in range(2):
            for t, shift in enumerate([0, 1, 2, 3]):
                a, b = 8*((3-t)+1)-1, 8*(3-t)
                _program_aes_table_512(self.t_stbox[(block, t, 0)], target,
                    key=f"hdr.block{block}.c{(0+shift)%4}[{a}:{b}]",
                    action=f"{'set' if t == 0 else 'add'}_col0_b{block}",
                    data=T[t] + [x << (8*(3-t)) for x in tables.AES_S])
                _program_aes_table_512(self.t_stbox[(block, t, 1)], target,
                    key=f"hdr.block{block}.c{(1+shift)%4}[{a}:{b}]",
                    action=f"{'set' if t == 0 else 'add'}_col1_b{block}",
                    data=T[t] + [x << (8*(3-t)) for x in tables.AES_S])
                _program_aes_table_512(self.t_stbox[(block, t, 2)], target,
                    key=f"hdr.block{block}.c{(2+shift)%4}[{a}:{b}]",
                    action=f"{'set' if t == 0 else 'add'}_col2_b{block}",
                    data=T[t] + [x << (8*(3-t)) for x in tables.AES_S])
                _program_aes_table_512(self.t_stbox[(block, t, 3)], target,
                    key=f"hdr.block{block}.c{(3+shift)%4}[{a}:{b}]",
                    action=f"{'set' if t == 0 else 'add'}_col3_b{block}",
                    data=T[t] + [x << (8*(3-t)) for x in tables.AES_S])

    def set_key(self, target, key, index=0, blocks=0x03):
        key_schedule = _cmac_key_schedule(key)
        for block in range(2):
            if (1 << block) & blocks:
                for round in range(11):
                    tab = self.t_key[(block, round if round < 7 else round - 6)]
                    _program_key_table(tab, target,
                        key=f"key_b{block}",
                        index=index,
                        iteration=0 if round < 7 else 1,
                        action=f"add_key_b{block}",
                        data=key_schedule[round*16:(round+1)*16])


class _PipeForwardingController:
    def __init__(self,
        bfrt_info: gc._BfRtInfo,
        pipe: int = 0,
        next_pipe: int = 1):

        self.bfrt_info = bfrt_info
        self.pipe = pipe
        self.next_pipe = next_pipe

        self._get_tables()

    def _get_tables(self):
        self.t_fwd = self.bfrt_info.table_get("tab_forward")

    def program_tables(self, target):
        logger.info("Pipe %s: Program forwarding table", self.pipe)
        # First half of the ports recirculate into second half
        for port in range(8, 40):
            _add_fwd_entry(self.t_fwd, target,
                _make_port(self.pipe, port), _make_port(self.pipe, port + 32))
        # Second half of the ports forward to next pipe
        for port in range(40, 72):
            _add_fwd_entry(self.t_fwd, target,
                _make_port(self.pipe, port), _make_port(self.next_pipe, port - 32))

    def clear_tables(self, target):
        _clear_fwd_table(self.t_fwd, target)


class CmacPipe:
    def __init__(self,
        interface: gc.ClientInterface,
        p4_name: str = "cmac_1pipe",
        pipe: int = 0):
        """
        ### Parameters
        interface       : gRPC client interface connected to switch driver
        p4_name         : Name of the P4 program
        pipe            : Which pipe the program is loaded on (0-3)
        """
        self.interface = interface
        self.p4_name = p4_name
        self.bfrt_info = self.interface.bfrt_info_get(self.p4_name)
        logger.info("AES pipe %d program name: %s", pipe, self.bfrt_info.p4_name_get())

        self.cmac = _CmacController(self.bfrt_info, pipe)
        self.fwd = _PipeForwardingController(self.bfrt_info, pipe)

    def program_tables(self):
        target = gc.Target(device_id=0)
        self.cmac.program_tables(target)
        self.fwd.program_tables(target)

    def clear_tables(self):
        target = gc.Target(device_id=0)
        self.fwd.clear_tables(target)

    def set_key(self, key, index=0, blocks=0x03):
        """Set MAC validation key.
        ### Parameters
        key    : 128-bit AES key
        index  : Key index (0-15)
        blocks : Which input block the key applies as bitmask
        """
        target = gc.Target(device_id=0)
        self.cmac.set_key(target, key, index, blocks)


class CmacTestPipe:
    def __init__(self,
        interface: gc.ClientInterface,
        p4_name: str = "cmac_1pipe_test",
        pipe: int = 1,
        next_pipe: int = 0):
        """Empty pipe for testing.
        ### Parameters
        interface       : gRPC client interface connected to switch driver
        p4_name         : Name of the P4 program
        pipe            : Which pipe the program is loaded on (0-3)
        next_pipe       : Next pipe the packets will be sent to (0-3)
        """
        self.interface = interface
        self.p4_name = p4_name
        self.pipe = pipe
        self.next_pipe = next_pipe
        self.bfrt_info = self.interface.bfrt_info_get(self.p4_name)
        logger.info("Pipe %d program name: %s", pipe, self.bfrt_info.p4_name_get())

        self.t_fwd = self.bfrt_info.table_get("tab_forward")

    def program_tables(self):
        target = gc.Target(device_id=0)
        for port in range(8, 72):
            _add_fwd_entry(self.t_fwd, target,
                _make_port(self.pipe, port), _make_port(self.next_pipe, port))

    def clear_tables(self):
        target = gc.Target(device_id=0)
        _clear_fwd_table(self.t_fwd, target)
