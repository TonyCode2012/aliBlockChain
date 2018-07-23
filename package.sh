#!/bin/bash
basedir=`dirname $0`
basedir=`cd $basedir;pwd`

gosourceFile=$basedir/chaincode/ali/go/ali.go
vendorDir=$basedir/chaincode/bitly
gofileName=`basename $gosourceFile`

packageDir=$basedir/pkgs

mkdir -p $packageDir

cp -r $gosourceFile $vendorDir $packageDir
cd $packageDir
mv $gofileName cvChain.go
mkdir vendor
mv bitly vendor
zip -r $basedir/cvChain.zip cvChain.go vendor
cd ..
rm -rf $packageDir
#mv cvChain.zip tmp
#cd tmp
#unzip cvChain.zip
