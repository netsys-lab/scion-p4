# SPDX-License-Identifier: AGPL-3.0-or-later

import os, sys
import importlib.util

import argparse
import base64
import logging
import json
import yaml
import numpy as np
import datetime

from tofino import *
from multiprocessing import Process

pktgen_spec = importlib.util.spec_from_file_location("controller.pktgen", os.path.abspath(__file__ + '/../../../' + 'tofino-pktgen/controller/pktgen.py'))
pktgen_lib = importlib.util.module_from_spec(pktgen_spec)
sys.modules["controller.pktgen"] = pktgen_lib
pktgen_spec.loader.exec_module(pktgen_lib)

sys.path.append(os.path.abspath(__file__ + '/../../../' + 'tofino-crypto'))

from bfd_handling import BfdHandler
from scion_crypto import get_key, get_subkey_1
from load_config import load_configuration
from aes_2pipes.controller.aes import AesFirstPipe, AesSecondPipe
from aes_1pipe.controller.aes import  AesPipe

logger = logging.getLogger('scion_onehope_processor')
logger.addHandler(logging.StreamHandler())
logger.setLevel(logging.INFO)

# Pktgen error
class PktGenError(Exception):
    pass

# Create Interface to Tofino
class Interface:
    def __init__(self, grpc_addr = 'localhost:50052', dev=0, client_id=0):
        self.dev_tgt = gc.Target(dev, pipe_id=0xFFFF)
        self.interface = gc.ClientInterface(grpc_addr,
                                            client_id=client_id,
                                            device_id=dev)

    def get_if(self):
        return self.interface

    def get_dev_tgt(self):
        return self.dev_tgt

def run_pktgen(interface, pipe, config, hist_bits, hist_shift, read_lat_reg = False, repeat=1):
    """Configure and run traffic generator.
    """

    PKTGEN_HDR_LEN = 6 # length of the pktgen header for timer events
    FCS_LEN = 4        # frame check sequence (part of the 64 byte minimal frame size)
    L1_OVERHEAD = 20   # Ethernet preamble + start-of-frame + average inter-frame gap
    PORT_SPEED = 100e9 # bit/s pktgen port speed

    calc_duration = 0
    calc_tx_pkts = 0
    calc_tx_bytes = 0

    for app_id, app in config["apps"].items():
        if not app["enabled"]:
            continue

        tx_packets = int(float(app["batch_count"]) * float(app["packets_per_batch"]))

        frame_size = os.stat(app["packet"]).st_size + FCS_LEN
        tx_bytes = tx_packets * frame_size

        # Time per frame
        frame_time = 8 * (frame_size + L1_OVERHEAD) / PORT_SPEED # in seconds
        frame_time = frame_time + 1e-9 * float(app["ipg"]) # inter-packet gap

        # Calculate (approximate) overall traffic duration from the longest running pktgen application
        app_dur = app["batch_count"] * (app["packets_per_batch"] * frame_time + float(app["ibg"]))
        app_dur += 1e-9 * float(app["timer_nanosec"]) # delay before starting
        calc_duration = max(calc_duration, app_dur) # in seconds

        print("App {}: {:>4} bytes/frame, {:6.4} ns/frame, {:8.6} Mpkt/s, {:8.6} Mbit/s".format(
            app_id,
            frame_size,
            1e9 * frame_time,
            1e-6 * tx_packets / app_dur,
            8e-6 * tx_bytes / app_dur))

        calc_tx_pkts += tx_packets
        calc_tx_bytes += tx_bytes

    if calc_tx_pkts == 0:
        return None

    controller = pktgen_lib.StatelessTrafficGenerator(interface, pipe=pipe, hist_bits=hist_bits, hist_shift=hist_shift)

    print("Program tables")
    controller.program_tables(config)

    try:
        result = []
        for i in range(repeat):
            if i > 0:
                print("Reset experiment")
                controller.trigger(False)
                controller.reset_timestamps()
                controller.reset_histogram()

            print("Pass {}".format(i))
            print("Send packets ({:.4} s)".format(calc_duration))
            tx_bytes0, tx_pkts0 = controller.get_tx_counters()
            controller.trigger()
            time.sleep(calc_duration + 10) # wait some extra time for control plane overhead

            print("Read results")
            # TX counters
            tx_bytes1, tx_pkts1 = controller.get_tx_counters()
            # counters are 64 bit each, no risk of wraparound
            total_tx_pkts = tx_pkts1 - tx_pkts0
            total_gen_bytes = tx_bytes1 - tx_bytes0
            total_tx_bytes = total_gen_bytes - (total_tx_pkts * PKTGEN_HDR_LEN)

            # TX, RX timestamps
            (tx_first, tx_last), (rx_first, rx_last) = controller.get_timestamps(pipe=0)
            if tx_first < 0 or tx_last < 0 or rx_first < 0 or rx_last < 0:
                raise PktGenError("ERROR: Got invalid timestamps from dataplane")
            tx_timedelta    = 1e-9 * float((tx_last - tx_first) % 2**48)
            rx_timedelta    = 1e-9 * float((rx_last - rx_first) % 2**48)
            first_timedelta = 1e-9 * float((rx_first - tx_first) % 2**48)
            last_timedelta  = 1e-9 * float((rx_last - tx_last) % 2**48)
            total_time      = 1e-9 * float((rx_last - tx_first) % 2**48)

            # Histogram
            hist_bins, hist_bytes, hist_packets = controller.get_histogram()
            ovfl_bytes, ovfl_pkts = controller.get_hist_overflow()
            total_rx_bytes = sum(hist_bytes) + ovfl_bytes
            total_rx_pkts = sum(hist_packets) + ovfl_pkts
            hist_bins_array = np.array(hist_bins)
            bin_mids = 0.5 * (hist_bins_array[:-1] + hist_bins_array[1:])
            try:
                hist_avg = np.average(bin_mids, weights=hist_packets[:-1])
            except ZeroDivisionError:
                hist_avg = np.nan # all packets are in the overflow bin

            # Latency trace
            latency = None
            lat_mean = None
            lat_stddev = None
            if read_lat_reg:
                latency = np.array(controller.get_latency(pipe=0))
                lat_mean = np.mean(latency[latency > 0])
                lat_stddev = np.std(latency[latency > 0])

            print("=== Result ===")
            print("Generated: {} of {} packets ({} bytes)".format(total_tx_pkts, calc_tx_pkts, total_gen_bytes))
            print("Received : {} of {} packets".format(int(total_rx_pkts), total_tx_pkts))
            print("Loss rate: {:.4} %".format(100.0 - 100.0 * min(1.0, total_rx_pkts / total_tx_pkts)))
            print("TX duration: {:.6} ms".format(1e3 * tx_timedelta))
            print("RX duration: {:.6} ms".format(1e3 * rx_timedelta))
            print("Total time : {:.6} ms".format(1e3 * total_time))
            print("First packet delay: {:.6} µs".format(1e6 * first_timedelta))
            print("Last packet delay : {:.6} µs".format(1e6 * last_timedelta))
            print("Latency (approx.) : {:.6} µs".format(1e6 * hist_avg))
            print("High latency pkts.: {}".format(ovfl_pkts))
            if read_lat_reg:
                print("Average recorded latency: {:.6} µs".format(1e6 * lat_mean))
                print("Latency std. deviation  : {:.6} µs".format(1e6 * lat_stddev))
            print("TX packet rate: {:.6} pkt/s". format(total_tx_pkts / tx_timedelta))
            print("RX packet rate: {:.6} pkt/s". format(total_rx_pkts / rx_timedelta))
            print("Attempted bandwidth: {:.6} Gbit/s".format(8e-9 * total_tx_bytes / tx_timedelta))
            print("Achieved bandwidth : {:.6} Gbit/s".format(8e-9 * total_rx_bytes / rx_timedelta))
            print("==============")

            result.append({
                "version"        : 2,
                "timestamp"      : datetime.datetime.now().astimezone().isoformat(),
                "calc_tx_pkts"   : calc_tx_pkts,
                "calc_tx_bytes"  : calc_tx_bytes,
                "calc_duration"  : calc_duration,
                "total_time"     : total_time,
                "total_gen_bytes": total_gen_bytes,
                "total_tx_pkts"  : int(total_tx_pkts),
                "total_tx_bytes" : int(total_tx_bytes),
                "total_rx_pkts"  : int(total_rx_pkts),
                "total_rx_bytes" : int(total_rx_bytes),
                "tx_first"       : tx_first,
                "tx_last"        : tx_last,
                "rx_first"       : rx_first,
                "rx_last"        : rx_last,
                "hist_ovfl_bytes": ovfl_bytes,
                "hist_ovfl_pkts" : ovfl_pkts,
                "hist_bins"      : hist_bins,
                "hist_bytes"     : hist_bytes,
                "hist_packets"   : hist_packets,
                "hist_avg"       : hist_avg,
                "latency_trace"  : {
                    "mean"  : lat_mean,
                    "stddev": lat_stddev,
                    "values": latency,
                }
            })

        return result

    finally:
        print("Clear tables")
        controller.program_tables(config, cleanup=True)

# Main
def main():
    parser = argparse.ArgumentParser(description="Service to process one-hop paths: compute and register missing hop field")
    parser.add_argument(
        "-k",
        "--key_file",
        default="master0.key",
        required=True,
        help="key file containing the master key for the generation of hop field MACs (default: master0.key).")
    parser.add_argument(
        "-i",
        "--interface",
        default="veth251",
        nargs="?",
        help="interface to listen on for SCION packets and send processed packets on (default: veth251).")
    parser.add_argument(
        "--grpc_address",
        default="localhost:50052",
        nargs=1,
        help="address of the Tofino's GRPC server (default: localhost:50052).")
    parser.add_argument(
        "-d",
        "--debug",
        action="store_true",
        help="Enable output of debug info.")
    parser.add_argument(
        "-c",
        "--config",
        nargs=1,
        required=True,
        help="Provide switch_config with the data to initialize the switch.")
    parser.add_argument(
        "-t",
        "--test_prepare",
        action="store_true",
        help="Set all BFD connections up and disable BFD messages as preparation for a test run.")
    parser.add_argument(
        "-e",
        "--with_eval",
        nargs=2,
        metavar=("pktgen_config", "pktgen_pipe"),
        help="Use with Tofino packet generator for evaluation setup. Give the config File for pktgen and its pipe.")
    parser.add_argument(
        "-p",
        "--aes_pipes",
        nargs=3,
        metavar=("scion_br_pipe","cmac_pipe1","cmac_pipe2"),
        help="Enables CMAC P4 implementation. List the numbers of the pipes to which SCION BR, cmac_pipe1 and cmac_pipe2 are assigned.")
    parser.add_argument(
        "-o",
        "--histo_out",
        nargs=1,
        help="If evaluation is run, the resulting history file can be saved in the file [HISTO_OUT].")
    parser.add_argument(
        "-l",
        "--latency_out",
        nargs=1,
        help="If evaluation is run, the resulting latency file can be saved in the file [LATENCY_OUT].")
    parser.add_argument(
        "-r",
        "--repeat",
        default=1,
        type=int,
        help="Number of repetitions for the evaluation.")
    args = parser.parse_args()

    if args.debug:
        logger.setLevel(logging.DEBUG)
    test = False
    if args.test_prepare:
        test = True
    
    master0_file = open(args.key_file, 'r')
    master0 = master0_file.read()
    key = get_key(master0)
    key_int = int.from_bytes(key, byteorder='big')
    subkey = get_subkey_1(key)
    
    # Get Tofino interface
    interface = Interface()
    tofino_if = interface.get_if()
    dev_tgt = interface.get_dev_tgt()

    # Check, whether AES_CMAC pipes have to be initialized
    if args.aes_pipes:
        if args.aes_pipes[1] == args.aes_pipes[2]:
            tofino_if.bind_pipeline_config("aes_1pipe")
            cmac = AesPipe(interface=tofino_if, pipe=int(args.aes_pipes[1]))
            cmac.clear_tables()
            cmac.program_tables()
        else:
            tofino_if.bind_pipeline_config("aes_pipe0")
            cmac1 = AesFirstPipe(interface=tofino_if, pipe=int(args.aes_pipes[1]), next_pipe=int(args.aes_pipes[2]))
            cmac1.clear_tables()
            cmac1.program_tables()

            tofino_if.bind_pipeline_config("aes_pipe1")
            cmac2 = AesSecondPipe(tofino_if, pipe=int(args.aes_pipes[2]), next_pipe=int(args.aes_pipes[0]))
            cmac2.clear_tables()
            cmac2.program_tables()

    # Init tables
    #tofino_if.clear_all_tables()
    tofino_if.bind_pipeline_config("scion")
    if args.aes_pipes:
        load_configuration(args.config[0], tofino_if, dev_tgt, "scion", key_int, subkey, [int(args.aes_pipes[0])], [int(args.aes_pipes[1])])
    else:
        load_configuration(args.config[0], tofino_if, dev_tgt, "scion", key_int, subkey)

    # Start BFD handler
    bfdHandler = BfdHandler(args.config[0], key, args.interface, test, tofino_if, dev_tgt)
    if not test:
        bfdProcess = Process(target=bfdHandler.run)
        bfdProcess.demon = True
        bfdProcess.start()

    # Check packet generator has to be initialized, too
    if args.with_eval:
        tofino_if.bind_pipeline_config("pktgen")
        with open(args.with_eval[0], "rt") as file:
            config = dict(yaml.safe_load(file))
        results = run_pktgen(tofino_if, int(args.with_eval[1]), config, 8, 6, read_lat_reg=args.latency_out is not None, repeat = args.repeat)

        if args.latency_out:
            lat = np.concatenate([rep["latency_trace"]["values"] for rep in results])
            np.save(args.latency_out[0], lat)

        if args.histo_out is not None:
            with open(args.histo_out[0], "wt") as file:
                for res in results:
                    del res["latency_trace"]["values"]
                json.dump(results, file, indent=2)



if __name__ == "__main__":
    main()
