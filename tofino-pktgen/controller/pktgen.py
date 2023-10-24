# SPDX-License-Identifier: AGPL-3.0-or-later
import logging
import sys
from typing import List, Tuple

import bfrt_grpc.client as gc
import numpy as np


logger = logging.getLogger(__name__)
logger.setLevel(logging.WARNING)
logger.addHandler(logging.StreamHandler(stream=sys.stdout))


def _make_port(pipe: int, port: int) -> int:
    """Make port number from pipe ID and port within the pipe."""
    return (pipe << 7) | port


def _find_in_dict(dict, key_suffix):
    for k, d in dict.items():
        if k.endswith(key_suffix):
            return d
    else:
        raise KeyError(f"Key with suffix {key_suffix} not found")


class StatelessTrafficGenerator:
    """Controller for a stateless traffic generator.
    """
    TS_DELTA_BITS = 32
    HIST_MAX_BITS = 10

    def __init__(self,
        interface: gc.ClientInterface,
        p4_name: str = "pktgen",
        hist_bits: int = 10,
        hist_shift: int = 6,
        pipe: int = 0,
        device_id: int = 0):
        """
        Initialize and retrieve P4 tables.

        ### Parameters ###
        interface  : gRPC client interface connected to switch driver
        p4_name    : Name of the P4 program
        hist_bits  : 2**hist_bits is the number of histogram bins.
        hist_shift : By how much to right-shift the latency before it is counted in the histogram.
                     Defines the size of the bins in powers of two.
        pipe       : Which pipe the program is loaded on (0-3)
        device_id  : Usually 0
        """
        self.interface = interface
        self.p4_name = p4_name
        self.bfrt_info = self.interface.bfrt_info_get(self.p4_name)
        logger.info("Pipe %d program name: %s", pipe, self.bfrt_info.p4_name_get())
        self.pipe = pipe
        self.device_id = device_id
        self.target = gc.Target(device_id=self.device_id)

        assert 0 < hist_bits <= self.HIST_MAX_BITS
        assert 0 <= hist_shift <= (self.TS_DELTA_BITS - self.HIST_MAX_BITS)
        self.hist_bits = hist_bits
        self.hist_shift = hist_shift

        self._get_tables()

    def _get_tables(self):
        self.t_pktgen_app_cfg    = self.bfrt_info.table_get("pktgen.app_cfg")
        self.t_pktgen_port_cfg   = self.bfrt_info.table_get("pktgen.port_cfg")
        self.t_pktgen_pkt_buffer = self.bfrt_info.table_get("pktgen.pkt_buffer")
        self.t_pre_mgid          = self.bfrt_info.table_get("$pre.mgid")
        self.t_pre_node          = self.bfrt_info.table_get("$pre.node")
        self.t_src_ports         = self.bfrt_info.table_get("IgParser.src_ports")
        self.t_timer_app_ids     = self.bfrt_info.table_get("IgParser.timer_app_ids")
        self.t_forward           = self.bfrt_info.table_get("tab_forward")
        self.t_mod_ports         = self.bfrt_info.table_get("tab_mod_underlay_ports")
        self.t_mod_flow_id       = self.bfrt_info.table_get("tab_mod_flow_id")
        self.t_ig_tx_first       = self.bfrt_info.table_get("reg_ig_tx_first")
        self.t_ig_tx_last        = self.bfrt_info.table_get("reg_ig_tx_last")
        self.t_rx_first          = self.bfrt_info.table_get("reg_rx_first")
        self.t_rx_last           = self.bfrt_info.table_get("reg_rx_last")
        self.t_rx_first_pkt      = self.bfrt_info.table_get("reg_rx_first_pkt")
        self.t_ts_delta_ovfl     = self.bfrt_info.table_get("tab_ts_delta_ovfl")
        self.t_ovfl_cntr         = self.bfrt_info.table_get("ts_delta_ovfl_counter")
        self.t_latency_histogram = self.bfrt_info.table_get("tab_lat_hist")
        self.t_array_index       = self.bfrt_info.table_get("reg_array_index")
        self.t_index             = self.bfrt_info.table_get("reg_index")
        self.t_lat_array = 16 * [None]
        for i in range(16):
            self.t_lat_array[i] = self.bfrt_info.table_get(f"reg_lat_array{i}")

    def program_tables(self, config, cleanup=False):
        """Prepare the dataplane by programming the P4 and device tables.

        Must be called before the packet generator can be triggered.
        To change the configuration after `program_tables` has been called, call
        `program_tables(old_config, cleanup=True)` and then `program_tables(new_config)`.

        ### Parameters ###
        config  : Dictionary with configuration. The object keeps a reference to the configuration
                  and it should not be changed externally after `program_tables` has been called.
        cleanup : Remove table entries again.
        """
        self.config = config

        # Determine which ports and app IDs to accept in the parser
        pktgen_ports = list({int(app["pktgen_port"]) for app in config["apps"].values() if app["enabled"]})
        enabled_apps = sorted([int(id) for id, app in config["apps"].items() if app["enabled"]])

        # Determine PRE configuration and forwarding table
        unicast = {}
        mcast = {}
        mgid = 1
        for gid, group in config["eg_port_groups"].items():
            apps = [id for id, app in config["apps"].items() if app["enabled"] and app["eg_port_group"] == gid]
            if len(group) == 1:
                for app in apps:
                    unicast[app] = int(group[0])
            else:
                ports = list(sorted(map(int, group)))
                mcast[mgid] = (apps, ports)
                mgid += 1

        # Load packets
        packets = {}
        offset = 0
        for app_id, app in config["apps"].items():
            if not app["enabled"]:
                continue
            with open(app["packet"], "rb") as file:
                pkt = bytearray(file.read(1500))
                packets[app_id] = (offset, pkt)
                offset += (len(pkt) + 8) & ~0x0f # offsets must be aligned

        self._program_parser_value_sets(self.target, pktgen_ports, enabled_apps, cleanup)
        self._program_pre(self.target, mcast, cleanup)
        self._program_forwarding_table(self.target, unicast, mcast, cleanup)
        self._program_port_mod(self.target, config.get("port_map", []), cleanup)
        self._program_flow_id_mod(self.target, config.get("flow_map", []), cleanup)
        if not cleanup:
            self._load_packet_buffer(self.target, packets)
            self._program_port_cfg(self.target, pktgen_ports)
        self._program_pktgen(self.target, config, packets, cleanup)
        self._program_ovfl_tab(self.target, cleanup)
        self._clear_ovfl_cntr(self.target)
        self._program_hist(self.target, op="add" if not cleanup else "del")
        if not cleanup:
            self._program_registers(self.target)
            self.reset_timestamps()

    def _program_parser_value_sets(self, target, ports, apps, cleanup):
        logger.info("Program parser value sets")
        # Source ports
        keys = [self.t_src_ports.make_key([
            gc.KeyTuple("f1", port, mask=0x1ff)
        ]) for port in ports]
        if not cleanup:
            self.t_src_ports.entry_add(target, keys)
        else:
            self.t_src_ports.entry_del(target, keys)

        # Pktgen app IDs
        keys = [self.t_timer_app_ids.make_key([
            gc.KeyTuple("f1", app, mask=0xf)
        ]) for app in apps]
        if not cleanup:
            self.t_timer_app_ids.entry_add(target, keys)
        else:
            self.t_timer_app_ids.entry_del(target, keys)

    def _program_pre(self, target, mcast, cleanup):
        logger.info("Program PRE")
        l1_keys, l1_data = [], []
        l2_keys, l2_data = [], []
        mcast_node_id = 0
        mcast_rid = 0

        for mgid, (_, ports) in mcast.items():
            # PRE.MGID table
            l1_keys.append(self.t_pre_mgid.make_key([
                gc.KeyTuple("$MGID", mgid)
            ]))
            l1_data.append(self.t_pre_mgid.make_data([
                gc.DataTuple("$MULTICAST_NODE_ID", int_arr_val=[mcast_node_id]),
                gc.DataTuple("$MULTICAST_NODE_L1_XID_VALID", bool_arr_val=[False]),
                gc.DataTuple("$MULTICAST_NODE_L1_XID", int_arr_val=[0])
            ]))

            # PRE.NODE table
            l2_keys.append(self.t_pre_node.make_key([
                gc.KeyTuple("$MULTICAST_NODE_ID", mcast_node_id)
            ]))
            l2_data.append(self.t_pre_node.make_data([
                gc.DataTuple("$MULTICAST_RID", mcast_rid),
                gc.DataTuple("$MULTICAST_LAG_ID", int_arr_val=[]),
                gc.DataTuple("$DEV_PORT", int_arr_val=ports)
            ]))

            mcast_node_id += 1
            mcast_rid += 1

        if not cleanup:
            if len(l2_keys) > 0:
                self.t_pre_node.entry_add(target, l2_keys, l2_data)
            if len(l1_keys) > 0:
                self.t_pre_mgid.entry_add(target, l1_keys, l1_data)
        else:
            if len(l1_keys) > 0:
                self.t_pre_mgid.entry_del(target, l1_keys)
            if len(l2_keys) > 0:
                self.t_pre_node.entry_del(target, l2_keys)

    def _program_forwarding_table(self, target, unicast, mcast, cleanup):
        logger.info("Program forwarding table")
        keys, data = [], []

        for app, port in unicast.items():
            keys.append(self.t_forward.make_key([
                gc.KeyTuple("hdr.pktgen_timer.pipe_id", self.pipe),
                gc.KeyTuple("hdr.pktgen_timer.app_id", app)
            ]))
            data.append(self.t_forward.make_data([
                gc.DataTuple("egress_port", port)
            ], "set_egress"))

        for mgid, (app_ids, _) in mcast.items():
            for app_id in app_ids:
                keys.append(self.t_forward.make_key([
                    gc.KeyTuple("hdr.pktgen_timer.pipe_id", self.pipe),
                    gc.KeyTuple("hdr.pktgen_timer.app_id", app_id)
                ]))
                data.append(self.t_forward.make_data([
                    gc.DataTuple("mcast_grp", mgid)
                ], "multicast"))

        if not cleanup:
            self.t_forward.entry_add(target, keys, data)
        else:
            self.t_forward.entry_del(target, keys)

    def _program_port_mod(self, target, port_map, cleanup):
        logger.info("Program underlay port table")
        keys, data = [], []

        for entry in port_map:
            keys.append(self.t_mod_ports.make_key([
                gc.KeyTuple("hdr.pktgen_timer.app_id",
                    value=entry["app"]["value"], mask=entry["app"]["mask"]),
                gc.KeyTuple("hdr.pktgen_timer.batch_id",
                    value=entry["batch"]["value"], mask=entry["batch"]["mask"]),
                gc.KeyTuple("hdr.pktgen_timer.packet_id",
                    value=entry["packet"]["value"], mask=entry["packet"]["mask"])
            ]))
            if entry["action"] == "set":
                data.append(self.t_mod_ports.make_data([
                    gc.DataTuple("src", entry["src"]),
                    gc.DataTuple("dst", entry["dst"])
                ], "set_underlay_ports"))
            elif entry["action"] == "random":
                data.append(self.t_mod_ports.make_data([], "randomize_underlay_ports"))
            else:
                raise KeyError(f"Unknown action \"{entry['action']}\"")

        if not cleanup:
            self.t_mod_ports.entry_add(target, keys, data)
        else:
            self.t_mod_ports.entry_del(target, keys)

    def _program_flow_id_mod(self, target, flow_map, cleanup):
        logger.info("Program flow ID table")
        keys, data = [], []

        for entry in flow_map:
            keys.append(self.t_mod_flow_id.make_key([
                gc.KeyTuple("hdr.pktgen_timer.app_id",
                    value=entry["app"]["value"], mask=entry["app"]["mask"]),
                gc.KeyTuple("hdr.pktgen_timer.batch_id",
                    value=entry["batch"]["value"], mask=entry["batch"]["mask"]),
                gc.KeyTuple("hdr.pktgen_timer.packet_id",
                    value=entry["packet"]["value"], mask=entry["packet"]["mask"])
            ]))
            if entry["action"] == "set":
                data.append(self.t_mod_flow_id.make_data([
                    gc.DataTuple("flow_id", entry["flow_id"])
                ], "set_flow_id"))
            elif entry["action"] == "random":
                data.append(self.t_mod_flow_id.make_data([], "randomize_flow_id"))
            else:
                raise KeyError(f"Unknown action \"{entry['action']}\"")

        if not cleanup:
            self.t_mod_flow_id.entry_add(target, keys, data)
        else:
            self.t_mod_flow_id.entry_del(target, keys)

    def _load_packet_buffer(self, target, packets):
        for _, (offset, pkt) in packets.items():
            logger.info("Load packet of length %d at offset %d", len(pkt), offset)
            key = self.t_pktgen_pkt_buffer.make_key([
                gc.KeyTuple("pkt_buffer_offset", offset),
                gc.KeyTuple("pkt_buffer_size", len(pkt))
            ])
            data = self.t_pktgen_pkt_buffer.make_data([
                gc.DataTuple("buffer", pkt)
            ])
            self.t_pktgen_pkt_buffer.entry_mod(target, [key], [data])

    def _program_port_cfg(self, target, devports):
        keys, data = [], []
        for port in devports:
            logger.info("Enabling pktgen on port %d", port)
            keys.append(self.t_pktgen_port_cfg.make_key([
                gc.KeyTuple("dev_port", port)
            ]))
            data.append(self.t_pktgen_port_cfg.make_data([
                gc.DataTuple("recirculation_enable", bool_val=False),
                gc.DataTuple("pktgen_enable", bool_val=True),
                gc.DataTuple("pattern_matching_enable", bool_val=False)
            ]))
        self.t_pktgen_port_cfg.entry_mod(target, keys, data)

    def _program_pktgen(self, target, config, packets, cleanup):
        keys, data = [], []
        for app_id, app in config["apps"].items():
            if not app["enabled"]:
                continue
            logger.info("Program application %d", app_id)
            keys.append(self.t_pktgen_app_cfg.make_key([
                gc.KeyTuple("app_id", app_id)
            ]))
            if not cleanup:
                data.append(self.t_pktgen_app_cfg.make_data([
                    gc.DataTuple("timer_nanosec",          int(app["timer_nanosec"])),
                    gc.DataTuple("app_enable",             bool_val=False),
                    gc.DataTuple("pkt_len",                len(packets[app_id][1])),
                    gc.DataTuple("pkt_buffer_offset",      packets[app_id][0]),
                    gc.DataTuple("pipe_local_source_port", int(app["pktgen_port"]) & 0x7f),
                    gc.DataTuple("increment_source_port",  bool_val=False),
                    gc.DataTuple("batch_count_cfg",        int(app["batch_count"]) - 1),
                    gc.DataTuple("packets_per_batch_cfg",  int(app["packets_per_batch"]) - 1),
                    gc.DataTuple("ibg",                    int(app["ibg"])),
                    gc.DataTuple("ibg_jitter",             int(app["ibg_jitter"])),
                    gc.DataTuple("ipg",                    int(app["ipg"])),
                    gc.DataTuple("ipg_jitter",             int(app["ipg_jitter"])),
                    gc.DataTuple("batch_counter",          0),
                    gc.DataTuple("pkt_counter",            0),
                    gc.DataTuple("trigger_counter",        0),
                    gc.DataTuple("assigned_chnl_id",       int(app["pktgen_port"]) & 0x7f),
                ], "trigger_timer_one_shot"))
            else:
                data.append(self.t_pktgen_app_cfg.make_data([
                    gc.DataTuple("app_enable", bool_val=False)
                ], "trigger_timer_one_shot"))

        self.t_pktgen_app_cfg.entry_mod(target, keys, data)

    def _program_ovfl_tab(self, target, cleanup):
        logger.info("Program overflow table")
        ovfl_mask = ((1 << (self.hist_bits + self.hist_shift)) - 1)
        ovfl_mask = (1 << self.TS_DELTA_BITS) - 1 - ovfl_mask # unsigned bitwise not
        key = self.t_ts_delta_ovfl.make_key([
            gc.KeyTuple("ts_delta", value=0, mask=ovfl_mask)
        ])
        if not cleanup:
            self.t_ts_delta_ovfl.entry_add(target, [key])
        else:
            self.t_ts_delta_ovfl.entry_del(target, [key])

    def _clear_ovfl_cntr(self, target):
        logger.info("Clear overflow counter")
        key = self.t_ovfl_cntr.make_key([
            gc.KeyTuple("$COUNTER_INDEX", value=0)
        ])
        data = self.t_ovfl_cntr.make_data([
                gc.DataTuple("$COUNTER_SPEC_BYTES", 0),
                gc.DataTuple("$COUNTER_SPEC_PKTS", 0)
        ])
        self.t_ovfl_cntr.entry_mod(target, [key], [data])

    def _program_hist(self, target, op):
        logger.info("Program histogram")
        mask = ((1 << self.hist_bits) - 1) << self.hist_shift
        keys = [self.t_latency_histogram.make_key([
                gc.KeyTuple("ts_delta", value=val << self.hist_shift, mask=mask)
            ]) for val in range(2**self.hist_bits)]
        data = [self.t_latency_histogram.make_data([
                gc.DataTuple("$COUNTER_SPEC_BYTES", 0),
                gc.DataTuple("$COUNTER_SPEC_PKTS", 0)
            ], "count_pkt")] * (len(keys))
        if op == "add":
            self.t_latency_histogram.entry_add(target, keys, data)
        elif op == "reset":
            self.t_latency_histogram.entry_mod(target, keys, data)
        elif op == "del":
            self.t_latency_histogram.entry_del(target, keys)
        else:
            assert False

    def _program_registers(self, target):
        logger.info("Initialize registers")
        # Array index
        key = self.t_array_index.make_key([
            gc.KeyTuple("$REGISTER_INDEX", 0)
        ])
        data = self.t_array_index.make_data([
            gc.DataTuple("reg_array_index.f1", 0)
        ])
        self.t_array_index.entry_mod(target, [key], [data])

        # Index
        key = self.t_index.make_key([
            gc.KeyTuple("$REGISTER_INDEX", 0)
        ])
        data = self.t_index.make_data([
            gc.DataTuple("reg_index.f1", 0)
        ])
        self.t_index.entry_mod(target, [key], [data])

    def trigger(self, enable: bool = True):
        """Start or stop the packet generator.

        If enable is True, the packet generator is started/enabled. If enable is set to False,
        the packet generator is disabled. After the generator has been triggered, it has to be
        reset by a call to `trigger(False)` before it can be triggered again.
        """
        logger.info("Trigger packet generator" if enable else "Reset packet generator")
        keys, data = [], []
        for app_id, app in self.config["apps"].items():
            if not app["enabled"]:
                continue
            keys.append(self.t_pktgen_app_cfg.make_key([
                gc.KeyTuple("app_id", app_id)
            ]))
            data.append(self.t_pktgen_app_cfg.make_data([
                gc.DataTuple("app_enable", bool_val=enable)
            ], "trigger_timer_one_shot"))

        self.t_pktgen_app_cfg.entry_mod(self.target, keys, data)

    def get_tx_counters(self) -> Tuple[int, int]:
        """Get the number of bytes and packets actually generated.

        The byte count includes 6 bytes of pktgen header for every packet.
        Returns a tuple of `(tx_bytes, tx_packets)`.
        """
        tx_bytes = 0
        tx_pkts = 0
        entries = self.t_forward.entry_get(self.target, flags={"from_hw": True})
        for data, _ in entries:
            data_dict = data.to_dict()
            tx_bytes += data_dict["$COUNTER_SPEC_BYTES"]
            tx_pkts += data_dict["$COUNTER_SPEC_PKTS"]
        return (tx_bytes, tx_pkts)

    def get_timestamps(self, pipe=None) -> Tuple[Tuple[int, int], Tuple[int, int]]:
        """Get first/last transmitted/received timestamps from ingress pipeline.

        Returns a nested pair `((tx_first, tx_last), (rx_first, rx_last))` Values are set to -1
        to indicated missing timestamps.
        """
        if pipe is None:
            pipe = self.pipe

        entries = self.t_ig_tx_first.entry_get(self.target, flags={"from_hw": True})
        data, _ = next(entries)
        ig_tx_first = _find_in_dict(data.to_dict(), "reg_ig_tx_first.f1")[pipe]
        if ig_tx_first >> 48 != 0:
            ig_tx_first = -1

        entries = self.t_ig_tx_last.entry_get(self.target, flags={"from_hw": True})
        data, _ = next(entries)
        ig_tx_last = _find_in_dict(data.to_dict(), "reg_ig_tx_last.f1")[pipe]
        if ig_tx_last >> 48 != 0:
            ig_tx_last = -1

        entries = self.t_rx_first.entry_get(self.target, flags={"from_hw": True})
        data, _ = next(entries)
        rx_first = _find_in_dict(data.to_dict(), "reg_rx_first.f1")[pipe]
        if rx_first >> 48 != 0:
            rx_first = -1

        entries = self.t_rx_last.entry_get(self.target, flags={"from_hw": True})
        data, _ = next(entries)
        rx_last = _find_in_dict(data.to_dict(), "reg_rx_last.f1")[pipe]
        if rx_last >> 48 != 0:
            rx_last = -1

        return ((ig_tx_first, ig_tx_last), (rx_first, rx_last))

    def reset_timestamps(self) -> None:
        """Reset recorded timestamps and prime for the next pass.

        All ones is used as sentinel value to indicate no timestamp has been recorded yet.
        """
        sentinel = (1<<64) - 1
        self.t_ig_tx_first.entry_mod(self.target,
            [self.t_ig_tx_first.make_key([gc.KeyTuple("$REGISTER_INDEX", 0)])],
            [self.t_ig_tx_first.make_data([gc.DataTuple("reg_ig_tx_first.f1", sentinel)])])
        self.t_ig_tx_last.entry_mod(self.target,
            [self.t_ig_tx_last.make_key([gc.KeyTuple("$REGISTER_INDEX", 0)])],
            [self.t_ig_tx_last.make_data([gc.DataTuple("reg_ig_tx_last.f1", sentinel)])])
        self.t_rx_first.entry_mod(self.target,
            [self.t_rx_first.make_key([gc.KeyTuple("$REGISTER_INDEX", 0)])],
            [self.t_rx_first.make_data([gc.DataTuple("reg_rx_first.f1", sentinel)])])
        self.t_rx_last.entry_mod(self.target,
            [self.t_rx_last.make_key([gc.KeyTuple("$REGISTER_INDEX", 0)])],
            [self.t_rx_last.make_data([gc.DataTuple("reg_rx_last.f1", sentinel)])])
        self.t_rx_first_pkt.entry_mod(self.target,
            [self.t_rx_first_pkt.make_key([gc.KeyTuple("$REGISTER_INDEX", 0)])],
            [self.t_rx_first_pkt.make_data([gc.DataTuple("reg_rx_first_pkt.f1", 1)])])

    def get_histogram(self) -> Tuple[List[float], List[int], List[int]]:
        """Retrieve data from packet delay histogram.

        Returns three lists:
            - Lower thresholds of the bins in seconds
            - Byte count for each bin
            - Packet count for each bin
        """
        hist = []
        entries = self.t_latency_histogram.entry_get(self.target, flags={"from_hw": True})
        for data, key in entries:
            key_dict = key.to_dict()
            bin = key_dict["ts_delta"]["value"]
            data_dict = data.to_dict()
            bytes = data_dict["$COUNTER_SPEC_BYTES"]
            pkts = data_dict["$COUNTER_SPEC_PKTS"]
            hist.append((1e-9 * float(bin), bytes, pkts))
        hist.sort(key=lambda x: x[0])
        return tuple(list(x) for x in zip(*hist))

    def get_hist_overflow(self) -> Tuple[int, int]:
        """Get the number of packets with latency too high to fit in the histogram.
        Returns a tuple of (byte count, packet count)
        """
        entries = self.t_ovfl_cntr.entry_get(self.target, flags={"from_hw": True})
        data, _ = next(entries)
        data_dict = data.to_dict()
        bytes = data_dict["$COUNTER_SPEC_BYTES"]
        pkts = data_dict["$COUNTER_SPEC_PKTS"]
        return (bytes, pkts)

    def reset_histogram(self):
        """Reset the packet delay histogram and overflow counters to zero.
        """
        self._clear_ovfl_cntr(self.target)
        self._program_hist(self.target, op="reset")

    def get_latency(self, pipe=None) -> List[float]:
        """Get recorded packet delays in seconds.

        The dataplane stores the last 1,507,328 recorded packet delays which get continuously
        overwritten as more packets arrive.
        """
        result = []
        if pipe is None:
            pipe = self.pipe
        for i in range(16):
            entries = self.t_lat_array[i].entry_get(self.target, flags={"from_hw": True})
            for data, _ in entries:
                data_dict = data.to_dict()
                lat = _find_in_dict(data_dict, f"reg_lat_array{i}.f1")[pipe]
                result.append(1e-9 * float(lat))
        return result
