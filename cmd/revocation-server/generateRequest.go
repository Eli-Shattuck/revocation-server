package main

import (
  "flag"
  "github.com/golang/glog"
  "encoding/hex"
  "encoding/pem"
  "crypto/x509"
  "encoding/binary"
  "revocation-server/crypto/ocsp"
  "revocation-server/padding"
  "io/ioutil"
)

var (
  certSerial = flag.String("serial","","Serial number corresponding to cert to check for revocation status. Must be hex string")
  issuerCertFile = flag.String("cert","testdata/root.cert","Location of issuer CA cert file")
  outFile = flag.String("outFile","./generated.req","location of generated request")
)

func main() {
  flag.Parse()
  defer glog.Flush()

  var serial []byte = make([]byte,8)
  var err error

  // Check inputs
  if(*certSerial=="") {
    glog.Exitf("Serial number is a required argument, check --help for details")
  } else {
    // Check if hex input
    serial, err = hex.DecodeString(*certSerial)
    if(err!=nil) {
      glog.Exitf("Could not parse input as hex string: %v",err.Error())
    }
  }

  ct, err := ioutil.ReadFile(*issuerCertFile)
  if err != nil {
    glog.Exit(err)
  }
  block, _ := pem.Decode(ct)
  cert, err := x509.ParseCertificate(block.Bytes)
  if err != nil {
    glog.Exit(err)
  }

  padded,err := padding.LeftPad(serial,8)
  if err != nil {
    glog.Exit(err)
  }
  numRepresented := binary.BigEndian.Uint64(padded)


  req, err := ocsp.CreateRequest(cert,numRepresented)
  glog.Infof("Request = %v\n",req)

  glog.Info("Writing request to file")
  err = ioutil.WriteFile(*outFile,req,0644)
  if err != nil {
    glog.Exitf("Error writing to file: %v",err.Error())
  }
}

