#!/bin/bash
TOP_DIR=$( cd "$(dirname "${BASH_SOURCE[0]}" )/.." && pwd)
sudo rm -f $TOP_DIR/p4src/client_switch/*.json
sudo rm -f $TOP_DIR/p4src/decoy_switch/*.json
sudo rm -f $TOP_DIR/log/*
