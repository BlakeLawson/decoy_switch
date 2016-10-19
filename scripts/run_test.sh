#!/bin/bash

# Blake Lawson
# Adviser: Jennifer Rexford
#
# This script runs the P4 test defined in topo.py. The code for this script is
# based on the code in 
# https://github.com/p4lang/tutorials/blob/master/SIGCOMM_2016/heavy_hitter/run_demo.sh

TOP_DIR=$( cd "$(dirname "${BASH_SOURCE[0]}" )/.." && pwd )

source $TOP_DIR/scripts/env.sh

P4C_BM_SCRIPT=$P4C_BM_PATH/p4c_bm/__main__.py

SWITCH_PATH=$BMV2_PATH/targets/simple_switch/simple_switch

CLI_PATH=$BMV2_PATH/tools/runtime_CLI.py

$P4C_BM_SCRIPT $TOP_DIR/p4src/tag_detection.p4 --json tag_detection.json

sudo $SWITCH_PATH > /dev/null 2>&1
sudo PYTHONPATH=$PYTHONPATH:$BMV2_PATH/mininet/ python $TOP_DIR/scripts/topo.py \
    --behavioral-exe $SWITCH_PATH \
    --json tag_detection.json \
    --p4-cli $CLI_PATH \
    --mininet-cli \
    --verbose \
    --p4-commands $TOP_DIR/p4src/commands.txt
