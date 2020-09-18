package main

import (
  "flag"
  "github.com/golang/glog"
  "encoding/pem"
  "crypto/x509"
  "revocation-server/crypto/ocsp"
  "io/ioutil"
  "strconv"
)

var (
  certSerial = flag.String("serial","","Serial number corresponding to cert to check for revocation status. Must be hex string")
  issuerCertFile = flag.String("cert","testdata/root.cert","Location of issuer CA cert file")
  outFile = flag.String("outFile","./generated.req","location of generated request")
)

func main() {
  flag.Parse()
  defer glog.Flush()

  var serial uint64
  // Check inputs
  if(*certSerial=="") {
    glog.Exitf("Serial number is a required argument, check --help for details")
  }

  serial, err := strconv.ParseUint(*certSerial,10,64)
  if(err!=nil) {glog.Exitf("Could not parse input as uint64")}

  glog.Infof("serial = %v\n",serial)

  ct, err := ioutil.ReadFile(*issuerCertFile)
  if err != nil {
    glog.Exit(err)
  }
  block, _ := pem.Decode(ct)
  cert, err := x509.ParseCertificate(block.Bytes)
  if err != nil {
    glog.Exit(err)
  }

  req, err := ocsp.CreateRequest(cert,serial)
  if err != nil {
    glog.Exitf("failed to create request: %v\n",err)
  }
  glog.Infof("Request = %v\n",req)

  glog.Info("Writing request to file")
  err = ioutil.WriteFile(*outFile,req,0644)
  if err != nil {
    glog.Exitf("Error writing to file: %v",err.Error())
  }
}

