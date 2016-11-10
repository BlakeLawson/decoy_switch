#!/bin/bash
#
# Blake Lawson (blawson@princeton.edu)
# Adviser: Jennifer Rexford
#
# This script runs the P4 test defined in topo.py. The code for this script is
# based on the code in 
# https://github.com/p4lang/tutorials/blob/master/SIGCOMM_2016/heavy_hitter/run_demo.sh

TOP_DIR=$( cd "$(dirname "${BASH_SOURCE[0]}" )/.." && pwd )

source $TOP_DIR/scripts/env.sh

P4C_BM_SCRIPT=$P4C_BM_PATH/p4c_bm/__main__.py

SWITCH_PATH=$BMV2_PATH/targets/simple_switch/simple_switch

CLI_PATH=$BMV2_PATH/targets/simple_switch/sswitch_CLI

$P4C_BM_SCRIPT $TOP_DIR/p4src/tag_detection.p4 --json tag_detection.json
$P4C_BM_SCRIPT $TOP_DIR/p4src/client_switch.p4 --json client_switch.json

# Create CPU Port
inf0="cpu-veth-0"
inf1="cpu-veth-1"
if ! ip link show $inf0 &> /dev/null; then
  ip link add name $inf0 type veth peer name $inf1
  ip link set dev $inf0 up
  ip link set dev $inf1 up
  TOE_OPTIONS="rx tx sg tso ufo gso gro lro rxvlan txvlan rxhash"
  for TOE_OPTION in $TOE_OPTIONS; do
    /sbin/ethtool --offload $inf0 "$TOE_OPTION" off
    /sbin/ethtool --offload $inf1 "$TOE_OPTION" off
  done
fi
sysctl net.ipv6.conf.$inf0.disable_ipv6=1
sysctl net.ipv6.conf.$inf1.disable_ipv6=1

sudo $SWITCH_PATH > /dev/null 2>&1
sudo python $TOP_DIR/p4src/decoy_controller.py \
    --cli $CLI_PATH \
    --json $TOP_DIR/tag_detection.json \
    --thrift-port 22222 \
    --proxy-addr "10.0.0.2" \
    --proxy-port 8888 \
    --verbose \
    &> $TOP_DIR/log/controller.log &

sudo PYTHONPATH=$PYTHONPATH:$BMV2_PATH/mininet/ python $TOP_DIR/scripts/topo.py \
    --behavioral-exe $SWITCH_PATH \
    --p4-cli $CLI_PATH \
    --mininet-cli \
    --verbose \
    --switch-json $TOP_DIR/tag_detection.json \
    --switch-commands $TOP_DIR/p4src/commands/tag_commands.txt \
    --client-json $TOP_DIR/client_switch.json \
    --client-commands $TOP_DIR/p4src/commands/client_commands.txt

# Get mininet log files
mv /tmp/p4s.* $TOP_DIR/log/
mv $TOP_DIR/*.pcap $TOP_DIR/log/

# Kill mininet
sudo mn -c

# Kill decoy controller
sudo kill $(ps aux | grep "[d]ecoy_controller.py" | awk '{print $2}') -9

# Disable CPU Port
if ip link show $inf0 &> /dev/null; then
  ip link delete $inf0 type veth
fi
