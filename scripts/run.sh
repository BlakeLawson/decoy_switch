#!/bin/bash
#
# Blake Lawson (blawson@princeton.edu)
# Adviser: Jennifer Rexford

TOP_DIR=$( cd "$(dirname "${BASH_SOURCE[0]}" )/.." && pwd )

sudo $TOP_DIR/scripts/cleanup.sh
sudo $TOP_DIR/scripts/start_test.sh
