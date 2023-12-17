#!/bin/env bash
set -e

function get_zerotier_address {
	if [[ $# -ne 1 ]]; then
		echo "only 1 argument allowed, the network name"
		exit 1
	fi
	network=$1
	sudo zerotier-cli listnetworks | grep "$network" | awk '{print $9}' | sed 's/\/[0-9]*//g'
}

get_zerotier_address "$1"
