#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later

# This is script is intended to be run from the root of the repository as
# evaluation/osr/run.sh [1seg|2seg]

# Port Setup
# port-add 18/0 100G RS
# port-add 19/0 100G RS
# an-set 18/0 enable
# an-set 19/0 enable
# port-enb 18/0
# port-enb 19/0

set -e
topology=$1

eval_dir=evaluation/osr
ARGS="--pipe 3 --hist-shift 16"

if [[ "$topology" == "1seg" ]]; then
    controller/pktgen-cli $eval_dir/1seg_192byte.yaml $ARGS --repeat 10 --out "$eval_dir/1seg_192byte.json"
    controller/pktgen-cli $eval_dir/1seg_800byte.yaml $ARGS --repeat 10 --out "$eval_dir/1seg_800byte.json"
    controller/pktgen-cli $eval_dir/1seg_1500byte.yaml $ARGS --repeat 10 --out "$eval_dir/1seg_1500byte.json"
    controller/pktgen-cli $eval_dir/1seg_192byte.yaml $ARGS --lat-out "$eval_dir/1seg_192byte_lat"
    controller/pktgen-cli $eval_dir/1seg_800byte.yaml $ARGS --lat-out "$eval_dir/1seg_800byte_lat"
    controller/pktgen-cli $eval_dir/1seg_1500byte.yaml $ARGS --lat-out "$eval_dir/1seg_1500byte_lat"
elif [[ "$topology" == "2seg" ]]; then
    controller/pktgen-cli $eval_dir/2seg_192byte.yaml $ARGS --repeat 10 --out "$eval_dir/2seg_192byte.json"
    controller/pktgen-cli $eval_dir/2seg_800byte.yaml $ARGS --repeat 10 --out "$eval_dir/2seg_800byte.json"
    controller/pktgen-cli $eval_dir/2seg_1500byte.yaml $ARGS --repeat 10 --out "$eval_dir/2seg_1500byte.json"
    controller/pktgen-cli $eval_dir/2seg_192byte.yaml $ARGS --lat-out "$eval_dir/2seg_192byte_lat"
    controller/pktgen-cli $eval_dir/2seg_800byte.yaml $ARGS --lat-out "$eval_dir/2seg_800byte_lat"
    controller/pktgen-cli $eval_dir/2seg_1500byte.yaml $ARGS --lat-out "$eval_dir/2seg_1500byte_lat"
else
    echo "Run as evaluation/osr/run.sh [1seg|2seg]"
    exit 1
fi
