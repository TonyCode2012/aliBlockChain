#!/bin/bash
#
# Copyright IBM Corp All Rights Reserved
#
# SPDX-License-Identifier: Apache-2.0
#
# Exit on first error
set -e

# clear docker container and network
#../first-network/byfn.sh down
docker rm -f $(docker ps -aq)
docker network prune

# don't rewrite paths for Windows Git Bash users
basedir=`dirname $0`
basedir=`cd $basedir;pwd`
versionfile=$basedir/VERSION
version=`cat $versionfile`
export MSYS_NO_PATHCONV=1
starttime=$(date +%s)
LANGUAGE=${1:-"golang"}
CC_SRC_PATH=github.com/ali/go
if [ "$LANGUAGE" = "node" -o "$LANGUAGE" = "NODE" ]; then
	CC_SRC_PATH=/opt/gopath/src/github.com/fabcar/node
fi

# clean the keystore
rm -rf ./hfc-key-store

# launch network; create channel and join peer to channel
cd ../basic-network
./start.sh

# Now launch the CLI container in order to install, instantiate chaincode
# and prime the ledger with our 10 cars
docker-compose -f ./docker-compose.yml up -d cli

docker exec -e "CORE_PEER_LOCALMSPID=Org1MSP" -e "CORE_PEER_MSPCONFIGPATH=/opt/gopath/src/github.com/hyperledger/fabric/peer/crypto/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp" cli peer chaincode install -n ali -v $version -p "$CC_SRC_PATH" -l "$LANGUAGE"
docker exec -e "CORE_PEER_LOCALMSPID=Org1MSP" -e "CORE_PEER_MSPCONFIGPATH=/opt/gopath/src/github.com/hyperledger/fabric/peer/crypto/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp" cli peer chaincode instantiate -o orderer.example.com:7050 -C mychannel -n ali -l "$LANGUAGE" -v $version -c '{"Args":[""]}' -P "OR ('Org1MSP.member','Org2MSP.member')"
sleep 5
#docker exec -e "CORE_PEER_LOCALMSPID=Org1MSP" -e "CORE_PEER_MSPCONFIGPATH=/opt/gopath/src/github.com/hyperledger/fabric/peer/crypto/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp" cli peer chaincode invoke -o orderer.example.com:7050 -C mychannel -n ali -c '{"function":"initLedger","Args":[""]}'

printf "\nTotal setup execution time : $(($(date +%s) - starttime)) secs ...\n\n\n"
printf "Start by installing required packages run 'npm install'\n"
#printf "Then run 'node enrollAdmin.js', then 'node registerUser'\n\n"
#printf "The 'node invoke.js' will fail until it has been updated with valid arguments\n"
#printf "The 'node query.js' may be run at anytime once the user has been registered\n\n"
echo "scale=2;$version+0.1" | bc > $versionfile
node $basedir/enrollAdmin.js
node $basedir/registerUser.js
#docker exec cli peer chaincode invoke -o orderer.example.com:7050 -C mychannel -n ali -c ' {"Args":["encRecord","1009","2008","collegel","bachelor"]}'  --transient "{\"ENCKEY\":\"1234567887654321\",\"IV\":\"2345678998765432\"}"
#node $basedir/invoke.js
#node $basedir/query.js
$basedir/testEncDec.sh
#$basedir/testAddGet.sh
#$basedir/test.sh
