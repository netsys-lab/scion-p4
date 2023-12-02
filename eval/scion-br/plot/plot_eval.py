#!/usr/bin/python3

import argparse
import io
import json
import tarfile
from pathlib import Path
from typing import Any, Dict, Tuple

import numpy as np
from matplotlib.figure import Figure


EXPERIMENTS = [
    # "loop-cable",
    # "pipe-recirc",
    # "osr_old",
    "osr",
    # "hsr",
    "sidn-p4",
    "p4-no-cmac",
    "p4-cmac-1pipe",
    "p4-cmac-2pipes"
]

EXP_LABELS = {
    "loop-cable"    : "Loop Cable",
    "pipe-recirc"   : "Direct Recirculation",
    "osr_old"       : "Open-Source Router (SCIONLab)",
    "osr"           : "Open-Source Router",
    "hsr"           : "High-speed Router",
    "sidn-p4"       : "Original BR w/o AES (Tofino 1)",
    "p4-no-cmac"    : "Our BR w/o AES (Tofino 2)",
    "p4-cmac-1pipe" : "1BR+1AES (Tofino 2)",
    "p4-cmac-2pipes": "1BR+2AES (Tofino 2)"
}

EXP_STYLE= {
    "loop-cable"    : {"color": "tab:purple", "hatch": ""},
    "pipe-recirc"   : {"color": "tab:pink", "hatch": ""},
    "osr_old"       : {"color": "tab:green", "hatch": ""},
    "osr"           : {"color": "darkgreen", "hatch": ""},
    "hsr"           : {"color": "black", "hatch": ""},
    "sidn-p4"       : {"color": "tab:blue", "hatch": "//"},
    "p4-no-cmac"    : {"color": "#ffb500", "hatch": "\\\\"},
    "p4-cmac-1pipe" : {"color": "tab:orange", "hatch": "+"},
    "p4-cmac-2pipes": {"color": "tab:red", "hatch": "x"}
}

PATH_TYPES = [
    "1seg",
    "2seg"
]

PATH_TYPE_LABELS = {
    "1seg": "1 path segment",
    "2seg": "2 path segments"
}

PKT_SIZES = [
    192,
    800,
    1500
]


class DataError(Exception):
    pass


def load_results(dir: Path) -> Tuple[Dict[str, Dict], np.array]:
    """Load files with experiment results from a directory.
    Returns pair of JSON result data and numpy arrays containing the precise
    latency measurements.
    """
    data = {}
    lat = {}
    for path in PATH_TYPES:
        for size in PKT_SIZES:
            try:
                with open(dir / f"{path}_{size}byte.json", "rt") as file:
                    data[(path, size)] = json.load(file)
            except OSError:
                pass
            try:
                lat[(path, size)] = np.load(dir / f"{path}_{size}byte_lat.npy", allow_pickle=False)
            except OSError:
                pass
    return data, lat


def load_results_tar(tar: Path) -> Tuple[Dict[str, Dict], np.array]:
    """Load files with experiment results from a tar file.
    Returns pair of JSON result data and numpy arrays containing the precise
    latency measurements.
    """
    data = {}
    lat = {}
    with tarfile.open(tar, "r") as archive:
        for path in PATH_TYPES:
            for size in PKT_SIZES:
                try:
                    file = archive.extractfile(f"{path}_{size}byte.json")
                    data[(path, size)] = json.load(file)
                except KeyError:
                    pass
                try:
                    file = archive.extractfile(f"{path}_{size}byte_lat.npy")
                    buffer = io.BytesIO()
                    buffer.write(file.read())
                    buffer.seek(0)
                    lat[(path, size)] = np.load(buffer, allow_pickle=False)
                except KeyError:
                    pass
    return data, lat


def load_all_experiments(dir: Path) -> Dict[str, Any]:
    """Load results of all experiments from a directory.
    Data can be provided in subdirectories or as tar files. If both are provided,
    tar files take precedence.
    """
    results = {}
    for exp in EXPERIMENTS:
        path = dir / exp
        for suffix in [".tar", ".tar.gz"]:
            file = path.with_suffix(suffix)
            if file.is_file():
                results[exp] = load_results_tar(file)
                break
        else:
            if path.is_dir():
                results[exp] = load_results(path)
            else:
                print(f"No data for {exp}")
    return results


def plot_bars(data, path_type: str, bar_width: float=0.2):
    """Plot bar charts of achieved packet- and bit-rate.
    """
    measurements = {}
    for exp in EXPERIMENTS:
        for pkt_size in PKT_SIZES:
            try:
                exp_res = data[exp][0][(path_type, pkt_size)]
            except KeyError:
                continue

            mpps = [] # million packets per second
            gbps = [] # gigabit per second
            for res in exp_res:
                rx_timedelta = 1e-9 * float((res["rx_last"] - res["rx_first"]) % 2**48)
                mpps.append(1e-6 * res["total_rx_pkts"] / rx_timedelta)
                gbps.append(8e-9 * res["total_rx_bytes"] / rx_timedelta)
            mpps = np.array(mpps)
            gbps = np.array(gbps)
            measurements[(exp, pkt_size)] = (mpps, gbps)
            print(f"Throughput for {exp}_{path_type}_{pkt_size}bytes:")
            print("  {:8.6} Mpkt/s".format(np.mean(mpps)))
            print("  {:8.6} GBit/s".format(np.mean(gbps)))

    # Plot packet rate
    pkt_fig = Figure(figsize=(8, 5), dpi=96)
    ax = pkt_fig.add_subplot()
    x = np.arange(len(PKT_SIZES))
    offset = 0
    for exp in EXPERIMENTS:
        try:
            y = np.array([np.mean(measurements[exp, size][0]) for size in PKT_SIZES])
            y_min = np.array([np.min(measurements[exp, size][0]) for size in PKT_SIZES])
            y_max = np.array([np.max(measurements[exp, size][0]) for size in PKT_SIZES])
            ax.bar(x + offset, y, yerr=[y-y_min, y_max-y], width=bar_width,
                label=EXP_LABELS[exp], **EXP_STYLE[exp])
            for pos, value in zip(x + offset, y):
                if value < 10:
                    label = np.round(value, decimals=2)
                else:
                    label = int(np.round(value, decimals=1))
                ax.text(pos, value, str(label), ha="center", va="bottom")
            offset += bar_width
        except KeyError:
            pass
    ax.set_xticks(x + 0.5 * (offset - bar_width), PKT_SIZES)
    ax.set_xlabel("Packet size [bytes]")
    ax.set_ylabel("Packet rate [$10^6$ packets per second]")
    ax.legend()

    # Plot bandwidth
    bw_fig = Figure(figsize=(8, 5), dpi=96)
    ax = bw_fig.add_subplot()
    x = np.arange(len(PKT_SIZES))
    offset = 0
    for exp in EXPERIMENTS:
        try:
            y = np.array([np.mean(measurements[exp, size][1]) for size in PKT_SIZES])
            y_min = np.array([np.min(measurements[exp, size][1]) for size in PKT_SIZES])
            y_max = np.array([np.max(measurements[exp, size][1]) for size in PKT_SIZES])
            ax.bar(x + offset, y, yerr=[y-y_min, y_max-y], width=bar_width,
                label=EXP_LABELS[exp], **EXP_STYLE[exp])
            for pos, value in zip(x + offset, y):
                if value < 10:
                    label = np.round(value, decimals=1)
                else:
                    label = int(np.round(value, decimals=0))
                ax.text(pos, value, str(label), ha="center", va="bottom")
            offset += bar_width
        except KeyError:
            pass
    ax.set_xticks(x + 0.5 * (offset- bar_width), PKT_SIZES)
    ax.set_xlabel("Packet size [bytes]")
    ax.set_ylabel("Bandwidth [Gbit/s]")
    ax.legend(loc="center right")

    return pkt_fig, bw_fig


def plot_lat_hist(data, bar_width: float = 0.05):
    """Plot the latency histogram generated by the data plane.
    """
    # This assumes all repetitions use the same histogram thresholds
    hist_bins = 1e3 * np.array(data[0]["hist_bins"])
    hist_pkts = np.array([rep["hist_packets"] for rep in data])

    fig = Figure(figsize=(8, 5), dpi=96)
    ax = fig.add_subplot()

    for rep in data:
        ver = rep.get("version", 1)
        if ver == 1 and rep["hist_packets"][-1] > 0:
            raise DataError("Overflow bin is not empty, the resulting histogram would not be accurate")
        elif ver == 2 and rep["hist_ovfl_pkts"] > 0:
            raise DataError("Histogram did not capture all packets")

    bar_width = hist_bins[1] - hist_bins[0]
    # y = np.mean(hist_pkts, axis=0)
    y = np.sum(hist_pkts, axis=0)
    # y_min = np.min(hist_pkts, axis=0)
    # y_max = np.max(hist_pkts, axis=0)
    ax.bar(hist_bins[:-1], y[:-1], width=bar_width, align="edge")#, yerr=[y_min[:-1], y_max[:-1]])
    # ax.hist(hist_bins[:-1], bins=64, weights=y[:-1])
    ax.set_xlim(0, hist_bins[-2])
    ax.set_xlabel("Latency [ms]")
    ax.set_ylabel("Packets")

    return fig


def plot_exact_lat_hist(latencies, num_bins:int = 150):
    """Plot recorded packet latencies as histogram.
    """
    fig = Figure(figsize=(8, 5), dpi=96)
    ax = fig.add_subplot()

    lat = 1e6 * latencies
    if np.any(lat <= 0):
        raise DataError("Insufficient data for latency histogram")

    ax.hist(lat, bins=num_bins)
    ax.set_xlabel("Latency [µs]")
    ax.set_ylabel("Packets")
    # ax.set_xlim(0, np.max(lat))

    return fig


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path, help="Input directory")
    parser.add_argument("output", type=Path, help="Output directory")
    parser.add_argument("-f", dest="format", type=str, default="pdf",
        help="File name extension / format of the generated figures")
    args = parser.parse_args()

    data = load_all_experiments(args.input)

    fmt = args.format
    dir = args.output
    dir.mkdir(parents=True, exist_ok=True)

    pkts, bw = plot_bars(data, "1seg")
    pkts.axes[0].set_title("Packet Throughput (1 Segment)")
    bw.axes[0].set_title("Bandwidth (1 Segment)")
    pkts.savefig(dir / f"pkts_1seg.{fmt}", bbox_inches="tight")
    bw.savefig(dir / f"bw_1seg.{fmt}", bbox_inches="tight")

    pkts, bw = plot_bars(data, "2seg")
    pkts.axes[0].set_title("Packet Throughput (2 Segments)")
    bw.axes[0].set_title("Bandwidth (2 Segments)")
    pkts.savefig(dir / f"pkts_2seg.{fmt}", bbox_inches="tight")
    bw.savefig(dir / f"bw_2seg.{fmt}", bbox_inches="tight")

    for exp in EXPERIMENTS:
        for path in PATH_TYPES:
            for size in PKT_SIZES:
                pass
                # Data plane histogram
                try:
                    res = data[exp][0][(path, size)]
                except KeyError:
                    continue
                try:
                    fig = plot_lat_hist(res)
                    fig.axes[0].set_title("{} ({}, {} byte packets)".format(
                        EXP_LABELS[exp],
                        PATH_TYPE_LABELS[path],
                        size
                    ))
                    fig.savefig(dir / f"{exp}_{path}_{size}bytes.{fmt}", bbox_inches="tight")
                except DataError as e:
                    print(f"ERROR {exp}_{path}_{size}bytes:", e)

                # Exact histogram
                try:
                    lat = data[exp][1][(path, size)]
                except KeyError:
                    continue
                try:
                    print(f"Latency for {exp}_{path}_{size}bytes:")
                    print("  mean = {:8.6} µs".format(1e6 * np.mean(lat)))
                    print("   std = {:8.6} µs".format(1e6 * np.std(lat)))
                    fig = plot_exact_lat_hist(lat, num_bins=250)
                    fig.axes[0].set_title("{} ({}, {} byte packets)".format(
                        EXP_LABELS[exp],
                        PATH_TYPE_LABELS[path],
                        size
                    ))
                    fig.savefig(dir / f"latency_{exp}_{path}_{size}bytes.{fmt}", bbox_inches="tight")
                except DataError as e:
                    print(f"ERROR {exp}_{path}_{size}bytes:", e)


if __name__ == "__main__":
    main()
