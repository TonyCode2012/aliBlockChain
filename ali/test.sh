function dealAndCompare() {
    expectedRet="$1"
    orgGotRet=`cat $TMPFILE`

    if [[ ! "$orgGotRet" =~ payload ]]; then
        gotRet=""
    else
        gotRet=${orgGotRet#*\"}
        gotRet=${gotRet%\"*}
    fi

    compareResult "$gotRet" "$expectedRet"
}
function compareResult() {
    gotRet="$1"
    expectedRet="$2"
    
    if [ "$gotRet" != "$expectedRet" ]; then
        echo "[INFO] >>>>>>>>>> test failed! get: $gotRet, expected: $expectedRet"
    else
        echo "[INFO] >>>>>>>>>> test successfully!"
    fi
}
TMPFILE="tmp.$$"

echo "[INFO] testing adding record"
echo "[INFO] case 1: add duplicated record"
docker exec cli peer chaincode invoke -o orderer.example.com:7050 -C mychannel -n ali -c '{"Args":["addRecord","1002","2008","collegel1","bachelor"]}'
docker exec cli peer chaincode invoke -o orderer.example.com:7050 -C mychannel -n ali -c '{"Args":["addRecord","1002","2008","collegel2","bachelor"]}'
docker exec cli peer chaincode invoke -o orderer.example.com:7050 -C mychannel -n ali -c '{"Args":["addRecord","1002","2008","collegel3","bachelor"]}'
sleep 2
`docker exec cli peer chaincode invoke -o orderer.example.com:7050 -C mychannel -n ali -c '{"Args":["getRecord","1002","2008"]}'` > $TMPFILE
`docker exec cli peer chaincode invoke -o orderer.example.com:7050 -C mychannel -n ali -c '{"Args":["getRecord","1002","2009"]}'` > $TMPFILE
`docker exec cli peer chaincode invoke -o orderer.example.com:7050 -C mychannel -n ali -c '{"Args":["getRecord","1001","2008"]}'` > $TMPFILE
dealAndCompare "collegel1"
dealAndCompare ""
dealAndCompare ""

echo "[INFO] case 2: add smae ID, different years record"
docker exec cli peer chaincode invoke -o orderer.example.com:7050 -C mychannel -n ali -c '{"Args":["addRecord","1002","2013","collegel","Unknown"]}'
docker exec cli peer chaincode invoke -o orderer.example.com:7050 -C mychannel -n ali -c '{"Args":["addRecord","1002","2014","sjtu","master"]}'
docker exec cli peer chaincode invoke -o orderer.example.com:7050 -C mychannel -n ali -c '{"Args":["addRecord","1002","2014","university","master"]}'
sleep 2
`docker exec cli peer chaincode invoke -o orderer.example.com:7050 -C mychannel -n ali -c '{"Args":["getRecord","1002","2013"]}'` > $TMPFILE
`docker exec cli peer chaincode invoke -o orderer.example.com:7050 -C mychannel -n ali -c '{"Args":["getRecord","1002","2014"]}'` > $TMPFILE
dealAndCompare "collegel"
dealAndCompare "university"

echo "[INFO] case 3: encrypt record"
docker exec cli peer chaincode invoke -o orderer.example.com:7050 -C mychannel -n ali -c '{"Args":["encRecord","1009","2008","collegel","bachelor"]}' --transient "{\"ENCKEY\":\"1234567887654321\",\"IV\":\"2345678998765432\"}"
docker exec cli peer chaincode invoke -o orderer.example.com:7050 -C mychannel -n ali -c '{"Args":["encRecord","1009","2008","xjtu","bachelor"]}' --transient "{\"ENCKEY\":\"1234567887654321\",\"IV\":\"2345678998765432\"}"
sleep 2
`docker exec cli peer chaincode invoke -o orderer.example.com:7050 -C mychannel -n ali -c '{"Args":["decRecord","1009","2008"]}' --transient "{\"DECKEY\":\"1234567887654321\"}"` > $TMPFILE
`docker exec cli peer chaincode invoke -o orderer.example.com:7050 -C mychannel -n ali -c '{"Args":["decRecord","1009","2018"]}' --transient "{\"DECKEY\":\"1234567887654321\"}"` > $TMPFILE
`docker exec cli peer chaincode invoke -o orderer.example.com:7050 -C mychannel -n ali -c '{"Args":["decRecord","1010","2018"]}' --transient "{\"DECKEY\":\"1234567887654321\"}"` > $TMPFILE
dealAndCompare "collegel"
dealAndCompare ""
dealAndCompare ""

#echo "[INFO] case 4: encrypt record by using none block size key"
#docker exec cli peer chaincode invoke -o orderer.example.com:7050 -C mychannel -n ali -c '{"Args":["encRecord","1019","2018","cisco","master"]}' --transient "{\"ENCKEY\":\"12345678876\",\"IV\":\"2345678998765432\"}"
#sleep 2
#docker exec cli peer chaincode invoke -o orderer.example.com:7050 -C mychannel -n ali -c '{"Args":["decRecord","1019","2018"]}' --transient "{\"DECKEY\":\"12345678876\"}"
