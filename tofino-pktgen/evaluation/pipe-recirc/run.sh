#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later

# This is script is intended to be run from the root of the repository as
# evaluation/pipe-recirc/run.sh [1seg|2seg]

# Port Setup
# port-add 16/- 400G RS
# port-add 15/- 400G RS
# port-add 14/- 400G RS
# port-add 13/- 400G RS
# port-add 12/- 400G RS
# port-add 11/- 400G RS
# port-add 10/- 400G RS
# port-add 9/- 400G RS
# port-loopback 16/- pipe-loopback
# port-loopback 15/- pipe-loopback
# port-loopback 14/- pipe-loopback
# port-loopback 13/- pipe-loopback
# port-loopback 12/- pipe-loopback
# port-loopback 11/- pipe-loopback
# port-loopback 10/- pipe-loopback
# port-loopback 9/- pipe-loopback
# port-enb 16/-
# port-enb 15/-
# port-enb 14/-
# port-enb 13/-
# port-enb 12/-
# port-enb 11/-
# port-enb 10/-
# port-enb 9/-

set -e
topology=$1

eval_dir=evaluation/pipe-recirc

if [[ "$topology" == "1seg" ]]; then
    controller/pktgen-cli $eval_dir/1seg_192byte.yaml --pipe 2 --repeat 10 --out "$eval_dir/1seg_192byte.json"
    controller/pktgen-cli $eval_dir/1seg_800byte.yaml --pipe 2 --repeat 10 --out "$eval_dir/1seg_800byte.json"
    controller/pktgen-cli $eval_dir/1seg_1500byte.yaml --pipe 2 --repeat 10 --out "$eval_dir/1seg_1500byte.json"
    controller/pktgen-cli $eval_dir/1seg_192byte.yaml --pipe 2 --lat-out "$eval_dir/1seg_192byte_lat"
    controller/pktgen-cli $eval_dir/1seg_800byte.yaml --pipe 2 --lat-out "$eval_dir/1seg_800byte_lat"
    controller/pktgen-cli $eval_dir/1seg_1500byte.yaml --pipe 2 --lat-out "$eval_dir/1seg_1500byte_lat"
elif [[ "$topology" == "2seg" ]]; then
    controller/pktgen-cli $eval_dir/2seg_192byte.yaml --pipe 2 --repeat 10 --out "$eval_dir/2seg_192byte.json"
    controller/pktgen-cli $eval_dir/2seg_800byte.yaml --pipe 2 --repeat 10 --out "$eval_dir/2seg_800byte.json"
    controller/pktgen-cli $eval_dir/2seg_1500byte.yaml --pipe 2 --repeat 10 --out "$eval_dir/2seg_1500byte.json"
    controller/pktgen-cli $eval_dir/2seg_192byte.yaml --pipe 2 --lat-out "$eval_dir/2seg_192byte_lat"
    controller/pktgen-cli $eval_dir/2seg_800byte.yaml --pipe 2 --lat-out "$eval_dir/2seg_800byte_lat"
    controller/pktgen-cli $eval_dir/2seg_1500byte.yaml --pipe 2 --lat-out "$eval_dir/2seg_1500byte_lat"
else
    echo "Run as evaluation/pipe-recirc/run.sh [1seg|2seg]"
    exit 1
fi
