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

$P4C_BM_SCRIPT $TOP_DIR/p4src/decoy_switch/decoy_switch.p4 \
  --json $TOP_DIR/p4src/decoy_switch/decoy_switch.json
$P4C_BM_SCRIPT $TOP_DIR/p4src/client_switch/client_switch.p4 \
  --json $TOP_DIR/p4src/client_switch/client_switch.json

# Parse command line arguments (really just for software switch)
use_cli=0
sswitch=""

# Reset in case previously used
OPTIND=1
while getopts "h?cs:" opt; do
  case "$opt" in
    h|\?)
      show_help
      exit 0
      ;;
    c) use_cli=1
      ;;
    s) sswitch=$OPTARG
      ;;
  esac
done

# Let the switch library "warm up"
sudo $SWITCH_PATH > /dev/null 2>&1

# Create CPU port for decoy switch
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
sudo python $TOP_DIR/p4src/decoy_switch/controller.py \
    --cli $CLI_PATH \
    --json $TOP_DIR/p4src/decoy_switch/decoy_switch.json \
    --thrift-port 22222 \
    --proxy-addr "10.0.0.2" \
    --proxy-port 8888 \
    --interface $inf0 \
    --verbose \
    &> $TOP_DIR/log/decoy_controller.log &

# Create CPU port for client switch
inf2="cpu-veth-2"
inf3="cpu-veth-3"
if ! ip link show $inf2 &> /dev/null; then
  ip link add name $inf2 type veth peer name $inf3
  ip link set dev $inf2 up
  ip link set dev $inf3 up
  TOE_OPTIONS="rx tx sg tso ufo gso gro lro rxvlan txvlan rxhash"
  for TOE_OPTION in $TOE_OPTIONS; do
    /sbin/ethtool --offload $inf2 "$TOE_OPTION" off
    /sbin/ethtool --offload $inf3 "$TOE_OPTION" off
  done
fi
sysctl net.ipv6.conf.$inf2.disable_ipv6=1
sysctl net.ipv6.conf.$inf3.disable_ipv6=1
sudo python $TOP_DIR/p4src/client_switch/controller.py \
    --cli $CLI_PATH \
    --json $TOP_DIR/p4src/client_switch/client_switch.json \
    --thrift-port 22223 \
    --interface $inf2 \
    --verbose \
    &> $TOP_DIR/log/client_controller.log &

sudo PYTHONPATH=$PYTHONPATH:$BMV2_PATH/mininet/ python $TOP_DIR/scripts/topo.py \
    --behavioral-exe $SWITCH_PATH \
    --p4-cli $CLI_PATH \
    --switch-json $TOP_DIR/p4src/decoy_switch/decoy_switch.json \
    --switch-commands $TOP_DIR/p4src/decoy_switch/commands.txt \
    --client-json $TOP_DIR/p4src/client_switch/client_switch.json \
    --client-commands $TOP_DIR/p4src/client_switch/commands.txt \
    --verbose \
    $([[ $use_cli = 1 ]] && echo "--mininet-cli") \
    $([[ $sswitch != "" ]] && echo "--sw-switch $sswitch")

# Get mininet log files
mv /tmp/p4s.* $TOP_DIR/log/
mv $TOP_DIR/*.pcap $TOP_DIR/log/

# Kill mininet
sudo mn -c

# Kill controllers
sudo kill $(ps aux | grep "[c]ontroller.py" | awk '{print $2}') -9

# Disable CPU Port
if ip link show $inf0 &> /dev/null; then
  ip link delete $inf0 type veth
fi
if ip link show $inf2 &> /dev/null; then
  ip link delete $inf2 type veth
fi
