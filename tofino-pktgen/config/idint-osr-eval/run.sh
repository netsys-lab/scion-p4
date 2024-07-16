#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later

# Run as config/idint-osr-eval/run.sh

set -e

input=config/idint-osr-eval/packets
output=config/idint-osr-eval/results
ARGS="--pipe 3 --hist-shift 16"

mkdir -p $output

controller/pktgen-cli "$input/pktgen.yaml" $ARGS --repeat 5 --packet "$input/baseline.bin" --out "$output/baseline.json"
controller/pktgen-cli "$input/pktgen.yaml" $ARGS --repeat 5 --packet "$input/idint_8.bin" --out "$output/idint_8.json"
controller/pktgen-cli "$input/pktgen.yaml" $ARGS --repeat 5 --packet "$input/idint_16.bin" --out "$output/idint_16.json"
controller/pktgen-cli "$input/pktgen.yaml" $ARGS --repeat 5 --packet "$input/idint_24.bin" --out "$output/idint_24.json"
controller/pktgen-cli "$input/pktgen.yaml" $ARGS --repeat 5 --packet "$input/idint_32.bin" --out "$output/idint_32.json"
controller/pktgen-cli "$input/pktgen.yaml" $ARGS --repeat 5 --packet "$input/idint_42.bin" --out "$output/idint_42.json"
controller/pktgen-cli "$input/pktgen.yaml" $ARGS --repeat 5 --packet "$input/idint_8_enc.bin" --out "$output/idint_8_enc.json"
controller/pktgen-cli "$input/pktgen.yaml" $ARGS --repeat 5 --packet "$input/idint_16_enc.bin" --out "$output/idint_16_enc.json"
controller/pktgen-cli "$input/pktgen.yaml" $ARGS --repeat 5 --packet "$input/idint_24_enc.bin" --out "$output/idint_24_enc.json"
controller/pktgen-cli "$input/pktgen.yaml" $ARGS --repeat 5 --packet "$input/idint_32_enc.bin" --out "$output/idint_32_enc.json"
controller/pktgen-cli "$input/pktgen.yaml" $ARGS --repeat 5 --packet "$input/idint_42_enc.bin" --out "$output/idint_42_enc.json"
