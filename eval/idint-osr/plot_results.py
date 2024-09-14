#!/usr/bin/python3

import argparse
import json
from pathlib import Path

import numpy as np
import matplotlib
from matplotlib.figure import Figure

matplotlib.rcParams["pdf.fonttype"] = 42

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
    return 1e-5 * np.array([rep["rx_pkt_rate"] for rep in data])


def plot_pps(data_cgo, data_go):
    fig = Figure(figsize=(7, 4), dpi=96)
    ax = fig.add_subplot()
    width = 0.2
    lowerQuantiale = 0.2
    upperQuantiale = 0.8

    base = calc_pps(data_cgo["baseline"])
    base_min = np.quantile(base, lowerQuantiale)
    base_avg = np.mean(base)
    base_max = np.quantile(base, upperQuantiale)

    cgo_min = np.zeros(5)
    cgo_avg = np.zeros(5)
    cgo_max = np.zeros(5)
    cgo_enc_min = np.zeros(5)
    cgo_enc_avg = np.zeros(5)
    cgo_enc_max = np.zeros(5)
    go_min = np.zeros(5)
    go_avg = np.zeros(5)
    go_max = np.zeros(5)
    go_enc_min = np.zeros(5)
    go_enc_avg = np.zeros(5)
    go_enc_max = np.zeros(5)
    for i, s in enumerate([8, 16, 24, 32, 42]):
        cgo = calc_pps(data_cgo["idint"][s])
        cgo_min[i] = np.quantile(cgo, lowerQuantiale)
        cgo_avg[i] = np.mean(cgo)
        cgo_max[i] = np.quantile(cgo, upperQuantiale)
        cgo_enc = calc_pps(data_cgo["idint_enc"][s])
        cgo_enc_min[i] = np.quantile(cgo_enc, lowerQuantiale)
        cgo_enc_avg[i] = np.mean(cgo_enc)
        cgo_enc_max[i] = np.quantile(cgo_enc, upperQuantiale)
        go = calc_pps(data_go["idint"][s])
        go_min[i] = np.quantile(go, lowerQuantiale)
        go_avg[i] = np.mean(go)
        go_max[i] = np.quantile(go, upperQuantiale)
        go_enc = calc_pps(data_go["idint_enc"][s])
        go_enc_min[i] = np.quantile(go_enc, lowerQuantiale)
        go_enc_avg[i] = np.mean(go_enc)
        go_enc_max[i] = np.quantile(go_enc, upperQuantiale)

    print("Base:", base_avg)
    print("IDINT (CGo)    :", -100 * (1 - (cgo_avg / base_avg)))
    print("Encrypted (CGo):", -100 * (1 - (cgo_enc_avg / base_avg)))
    print("IDINT (Go)     :", -100 * (1 - (go_avg / base_avg)))
    print("Encrypted (Go) :", -100 * (1 - (go_enc_avg / base_avg)))

    ax.bar([0.3], [base_avg], width, align="center", capsize=5, color="tab:blue", hatch="xx",
        yerr=[[base_avg-base_min], [base_max-base_avg]])

    x = np.array([1, 2, 3, 4, 5])

    ax.bar(x - 2*width, cgo_avg, width, align="edge", capsize=5, color="red", hatch=".",
        yerr=[cgo_avg-cgo_min, cgo_max-cgo_avg], label="Auth. ID-INT (cgo)")
    ax.bar(x - width, cgo_enc_avg, width, align="edge", capsize=5, color="tab:orange", hatch="o",
        yerr=[cgo_enc_avg-cgo_enc_min, cgo_enc_max-cgo_enc_avg], label="Encrypted ID-INT (cgo)")

    ax.bar(x, go_avg, width, align="edge", capsize=5, color="seagreen", hatch="/",
        yerr=[go_avg-go_min, go_max-go_avg], label="Auth. ID-INT")
    ax.bar(x + width, go_enc_avg, width, align="edge", capsize=5, color="mediumseagreen", hatch="\\",
        yerr=[go_enc_avg-go_enc_min, go_enc_max-go_enc_avg], label="Encrypted ID-INT")

    ax.set_xlim(0, 5.6)
    ax.hlines([base_avg], 0, 6, color="black", linestyle="dotted")

    ax.set_xticks([0.3, 1, 2, 3, 4, 5], [
        "No ID-INT",
        "8 byte",
        "16 byte",
        "24 byte",
        "32 byte",
        "42 byte"
    ])
    ax.set_yticks(
        [0, 0.5, 1, 1.5, 2, 2.5, base_avg, 3],
        ["0", "0.5", "1", "1.5", "2", "2.5", f"{base_avg:.2}", "3"]
    )
    ax.set_ylabel("1e5 packets/s")
    ax.legend(loc="lower right", ncol=2)

    return fig


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path, help="Input directory")
    parser.add_argument("output", type=Path, help="Output directory")
    parser.add_argument("-f", dest="format", type=str, default="pdf",
        help="File name extension / format of the generated figures")
    args = parser.parse_args()

    cgo = load_results(args.input / "cgo")
    go = load_results(args.input / "go")
    fig = plot_pps(cgo, go)
    fig.savefig(args.output / f"idint-osr-pps.{args.format}", bbox_inches="tight")


if __name__ == "__main__":
    main()
