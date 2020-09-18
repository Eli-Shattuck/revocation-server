#!/bin/bash

## Check you are at root of repo, will need to modify this if you changed directory names
url="http://localhost:8080"
curdir=${PWD##*/}
if [ $curdir != "revocation-server" ]; then
  echo "Must run from the root of the repository, cd to base of revocation-server"
  exit 1
fi

## Check if server is up
curl "{$url}/" && echo "Server is up"
if [ ! "$?" -eq 0 ]; then
  echo "Revocation server is not up (or not running on expected port 8080)"
  exit 1
fi

url="http://localhost:8080/new-ct"

jsonType='Content-Type:application/json'

## Test post revocation
handle="$url/post-revocation"

# We dont expect responses for these
echo "First, lets get the sth (should be of an empty root)"
curl "$url/get-sth"

echo "Revoking serials using post-revocation"
curl -d '{"Serial":5}' -H $jsonType $handle
curl -d '{"Serial":15}' -H $jsonType $handle
curl -d '{"Serial":27}' -H $jsonType $handle

echo "After 30s mmd they will be integrated into the tree"
echo -e "\n"
sleep 20

## Test post-multiple-revocations
handle="$url/post-multiple-revocations"
echo "Revoking serials 25, 150, 80123 in a single request"
curl -d '{"Serials": [25,150,80123]}' -H "Content-Type: application/json" $handle
sleep 20

echo "Lets check the sth now, it should have a different LogRoot and signature"
curl "$url/get-sth"
echo -e "\n"

echo "What happens if we try and revoke a serial number larger than maxSerial for the tree?"
echo "Assumes tree height of 20"
curl -X POST -H $jsonType -d '{"Serial": 1048576}' "$url/post-revocation"
sleep 5
echo -e "\n"

## Test get-inclusion-proof
handle="$url/get-inclusion-proof"
echo "Get inclusion proof for serial 25"
curl -X GET -H $jsonType -d '{"Serial": 25}' $handle
echo -e "\n"

sleep 5
echo "Get inclusion proof for a node we haven't revoked"
curl -X GET -H $jsonType -d '{"Serial": 10}' $handle
echo -e "\n"
