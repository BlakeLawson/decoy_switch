#!/bin/bash
TOP_DIR=$( cd "$(dirname "${BASH_SOURCE[0]}" )/.." && pwd)
sudo mn -c
sudo killall lt-simple-switch
sudo killall behavioral-model
sudo rm -f $TOP_DIR/*.pcap
sudo rm -f $TOP_DIR/*.json
sudo rm -f $TOP_DIR/log/*
