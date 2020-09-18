package main

import (
  "flag"
  "github.com/golang/glog"
  "revocation-server/crypto/ocsp"
  "revocation-server/handler"
  "crypto/x509"
  "encoding/pem"
  "io/ioutil"
  "strconv"
  "encoding/json"
  "encoding/asn1"
)

var (
  responseFile = flag.String("resp","","Path to file containing ocsp response from server")
  issuerCertFile = flag.String("cert","testdata/root.cert","Location of issuer(CA) cert")
  serialStr = flag.String("serial","","Serial that we are checking response for status")
)

func main() {
  flag.Parse()
  defer glog.Flush()

  if(*responseFile=="") {
    glog.Exitf("Path to file containing response is required, check --help for details")
  }

  // Parse issuer cert
  ct, err := ioutil.ReadFile(*issuerCertFile)
  if(err!=nil) {glog.Exitf("failed to read file: %v\n",err)}
  block, rest := pem.Decode(ct)
  if(len(rest)>0) {glog.Exitf("trailing bytes in certificate when decoding pem\n")}
  cert, err := x509.ParseCertificate(block.Bytes)
  if(err!=nil) {glog.Exitf("Failed to parse cert: %v\n",err)}

  // Parse response
  serial, err := strconv.ParseUint(*serialStr,10,64)
  if(err!=nil) {glog.Exitf("Failed to parse serial to uint64 format: %v\n",err)}

  bytes, err := ioutil.ReadFile(*responseFile)
  if(err!=nil) {glog.Exitf("Could not read response file: %v\n",err)}

  var resp *ocsp.Response
  resp, err = ocsp.ParseResponse(bytes,cert,serial)
  if(err!=nil) {glog.Exitf("Could not parse ocsp response: %v\n",err)}

  // If we have reached this point without errors, the response is valid and the cert status is Good
  // Status of 0 == good
  glog.Infof("Cert status according to response: %v\n",resp.Status)
  if(resp.Status==0) {
    glog.Infof("Status is Good (nonRevoked)\n\n")
  }
  if(resp.Status==1) {
    glog.Infof("Status is Revoked\n\n")
  }

  // Parse extension for proof
  // Proof was json encoded with asn1 id for ietf certificate transparency object "TransItem"
  // However the actual structure is just [][]byte
  idTransInfo := asn1.ObjectIdentifier([]int{1,3,101,75})
  for _,v := range(resp.Extensions) {
    if(v.Id.Equal(idTransInfo)) {
      // We found the proof ext
      // Unmarshal json
      var proofjson handler.ProofResponse
      err = json.Unmarshal(v.Value,&proofjson)
      if(err!=nil) {glog.Exitf("error unmarshalling proof struct: %v\n",err)}
      var proof [][]byte
      proof = proofjson.Proof
      glog.Infof("Proof = %v\n",proof)
    }
  }
}


