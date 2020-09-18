#!/bin/bash

## This script assumes you are running this from repo root
## filetopost path will be incorrect if this is not the case and will throw error

url="http://localhost:8080"
handle="$url/new-ct/get-ocsp"

## Check you are at root of repo, will need to modify this if you changed directory names
curdir=${PWD##*/}
if [ $curdir != "revocation-server" ]; then
  echo "Must run from the root of the repository, cd to base of revocation-server"
  exit 1
fi

## Generate ocsp request
reqoutfile="testdata/generated.req"
echo "Generating ocsp request"
echo -e "Output is stored in $reqoutfile\n"
cmd/revocation-server/./generateRequest --serial "15" --outFile $reqoutfile
sleep 3

## output is generated.req
filetopost="testdata/generated.req"

## Check if server is up
curl "{$url}/" && echo "Server is up"
if [ ! "$?" -eq 0 ]; then
  echo "Revocation server is not up (or not running on expected port 8080)"
  exit 1
fi

## Check that you can find the file
if [ ! -f "$filetopost" ]; then
  echo "Cannot find file $filetopost. Make sure you run script from repo root and that the file exists"
  exit 1
fi

## Post as binary
echo "Post request to server and receive ocsp response, stored in $outfile\n"
outfile="testdata/ocsp.response"
curl -X GET --data-binary "@$filetopost" --output $outfile $handle && echo "Output saved to file $outfile"
sleep 3

## Parse response
echo "Parse response"
echo -e "Get ready for a large-ish proof response\n"
sleep 3

## I parse ls to get file size because we just want the response size, not how much space it actually takes up on disk
fsize=$(ls -lah $outfile | cut -d" " -f 5)
cmd/revocation-server/./parseResponse --serial "15" --resp $outfile --logtostderr
echo -e "\n Size of response (what was transmitted over network) = $fsize"


echo -e "\n\nNow, lets revoke a cert and get the response for it\n"
echo -e "The cert is not immediately revoked once posted to the server, we have to wait for a full mmd for it to be incorporated and the status to be updated"
echo -e "This test assumes you have started the server with a 20s mmd"

jsonHeader='Content-Type:application/json'
echo "Posting revocation to server"
curl -d '{"Serial": 5 }' -H $jsonHeader $url/new-ct/post-revocation
echo "Waiting 20s for it to be incorporated"

## Takes a bit longer than the true mmd
sleep 20

echo -e "\n\n Now, check status"
cmd/revocation-server/./generateRequest --serial "5" --outFile $reqoutfile
sleep 3
curl -X GET --data-binary "@$filetopost" --output $outfile $handle && echo "Output saved to file $outfile"
cmd/revocation-server/./parseResponse --serial "5" --resp $outfile --logtostderr

