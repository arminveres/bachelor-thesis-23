#!/bin/env bash
set -e

export DOCKERHOST="172.30.54.15" # $(./scripts/getDockerHost.sh)
export LEDGER_URL="http://172.30.101.208:9000"
export PUBLIC_TAILS_URL="http://172.30.101.208:6543"
export GENESIS_URL="$LEDGER_URL/genesis"
export POSTGRES=1
export RUNMODE=pwd

pushd src
python3 -m agents.node --wallet-type askar --did-exchange --reuse-connections --revocation --ident=node_raspi --port 8000
popd
