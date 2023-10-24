#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later

# This is script is intended to be run from the root of the repository as
# evaluation/loop-cable/run.sh [1seg|2seg]

# Port Setup
# port-add 8/- 400G RS
# port-add 9/- 400G RS
# port-enb 8/-
# port-enb 9/-

set -e
topology=$1

eval_dir=evaluation/loop-cable

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
    echo "Run as evaluation/loop-cable/run.sh [1seg|2seg]"
    exit 1
fi
