#!/usr/bin/python3

import argparse
import io
import json
import tarfile
from pathlib import Path
from typing import Any, Dict, Tuple, List

import numpy as np
from matplotlib.figure import Figure


def load_results(dir: Path):
    res = {}
    with open(dir / "baseline.json", "rt") as file:
        res["baseline"] = json.load(file)

    res["idint"] = {}
    res["idint_enc"]= {}
    for s in [8, 16, 24, 32, 42]:
        with open(dir / f"idint_{s}.json", "rt") as file:
            res["idint"][s] = json.load(file)
        with open(dir / f"idint_{s}_enc.json", "rt") as file:
            res["idint_enc"][s] = json.load(file)

    return res


def calc_pps(data):
    res = []
    for rep in data:
        rx_timedelta = 1e-9 * float((rep["rx_last"] - rep["rx_first"]) % 2**48)
        res.append(1e-5 * rep["total_rx_pkts"] / rx_timedelta)
    return np.array(res)


def plot_pps(data):
    fig = Figure(figsize=(7, 4), dpi=96)
    ax = fig.add_subplot()
    width = 0.4

    base = calc_pps(data["baseline"])
    base_min = np.min(base)
    base_avg = np.mean(base)
    base_max = np.max(base)

    idint_min = np.zeros(5)
    idint_avg = np.zeros(5)
    idint_max = np.zeros(5)
    idint_enc_min = np.zeros(5)
    idint_enc_avg = np.zeros(5)
    idint_enc_max = np.zeros(5)
    for i, s in enumerate([8, 16, 24, 32, 42]):
        idint = calc_pps(data["idint"][s])
        idint_min[i] = np.min(idint)
        idint_avg[i] = np.mean(idint)
        idint_max[i] = np.max(idint)
        idint_enc = calc_pps(data["idint_enc"][s])
        idint_enc_min[i] = np.min(idint_enc)
        idint_enc_avg[i] = np.mean(idint_enc)
        idint_enc_max[i] = np.max(idint_enc)

    print("Base:", base_avg)
    print("IDINT:", idint_avg)
    print("Encrypted:", idint_enc_avg)

    ax.bar([0], [base_avg], width, align="center", capsize=5, color="tab:blue", hatch="x",
        yerr=[[base_avg-base_min], [base_max-base_avg]], label="No INT")

    x = np.array([1, 2, 3, 4, 5])
    ax.bar(x - width, idint_avg, width, align="edge", capsize=5, color="tab:orange", hatch="/",
        yerr=[idint_avg-idint_min, idint_max-idint_avg], label="INT")
    ax.bar(x, idint_enc_avg, width, align="edge", capsize=5, color="tab:red", hatch="\\",
        yerr=[idint_enc_avg-idint_enc_min, idint_enc_max-idint_enc_avg], label="Encrypted INT")

    ax.set_xticks(range(6), [
        "Disabled",
        "8 byte",
        "16 byte",
        "24 byte",
        "32 byte",
        "42 byte"
    ])
    ax.set_ylabel("1e5 packets/s")
    ax.legend(loc="upper right", ncol=3)

    return fig


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path, help="Input directory")
    parser.add_argument("output", type=Path, help="Output directory")
    parser.add_argument("-f", dest="format", type=str, default="pdf",
        help="File name extension / format of the generated figures")
    args = parser.parse_args()

    data = load_results(args.input)
    fig = plot_pps(data)
    fig.savefig(args.output / f"idint-osr-pps.{args.format}", bbox_inches="tight")


if __name__ == "__main__":
    main()
