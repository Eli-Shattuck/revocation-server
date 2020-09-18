package handler

import (
  "encoding/json"
  "encoding/asn1"
  "encoding/binary"
  "net/http"
  "revocation-server/types"
  "revocation-server/tree"
  "revocation-server/crypto/ocsp"
  "fmt"
  "github.com/golang/glog"
  "crypto/x509"
  "crypto/x509/pkix"
  "crypto/ecdsa"
  "io/ioutil"
  "time"
)

type Handler struct {
  t *tree.MerkleTree
  cert *x509.Certificate
  key *ecdsa.PrivateKey
}

func NewHandler(t *tree.MerkleTree, cert *x509.Certificate, key *ecdsa.PrivateKey) Handler {
  return Handler{t,cert,key}
}

// get-sth, post-revocation, get-inclusion-proof are json-encoded
// for ease of use right now, can be changed later
// get-ocsp uses ocsp request/response ietf specification

// Something to know is that for json decoding to work correctly, all struct var's must be capitalized
type GetInclusionProofRequest struct {
  Serial uint64
}

type GetInclusionProofResponse struct {
  Proof [][]byte
}

// Ocsp Request/Response types defined in revocation-server/ocsp
// asn.1/der encoded

type PostRevocationRequest struct {
  Serial uint64
}

// for mass-revocation event, or for testing
type PostMultipleRevocationsRequest struct {
  Serials []uint64
}

type ProofResponse struct {
  Proof [][]byte
}

func writeWrongMethodResponse(rw *http.ResponseWriter, allowed string) {
	(*rw).Header().Add("Allow", allowed)
	(*rw).WriteHeader(http.StatusMethodNotAllowed)
}

func writeErrorResponse(rw *http.ResponseWriter, status int, body string) {
	(*rw).WriteHeader(status)
	(*rw).Write([]byte(body))
}

func (h *Handler) GetSth(rw http.ResponseWriter, req *http.Request) {
  glog.V(1).Infoln("Received GetSth Request")
  if req.Method != "GET" {
    writeWrongMethodResponse(&rw, "GET")
    return
  }

  var sthData *types.SignedLogRoot
  sthData = h.t.GetSth()
  if(sthData==nil) {
    writeErrorResponse(&rw, http.StatusInternalServerError, fmt.Sprintf("Sth is nil pointer"))
  }

  // convert to json
  encoder := json.NewEncoder(rw)
  if err := encoder.Encode(*sthData); err != nil {
    writeErrorResponse(&rw, http.StatusInternalServerError, fmt.Sprintf("Couldn't encode STH to return: %v", err))
    return
  }
}

func (h *Handler) GetInclusionProof(rw http.ResponseWriter, req *http.Request) {
  glog.V(1).Infoln("Received GetInclusionProof Request")
  if req.Method != "GET" {
    writeWrongMethodResponse(&rw, "GET")
    return
  }

  decoder := json.NewDecoder(req.Body)
  var p GetInclusionProofRequest
  if err := decoder.Decode(&p); err != nil {
    writeErrorResponse(&rw, http.StatusInternalServerError, fmt.Sprintf("Invalid InclusionProofRequest: %v", err))
    return
  }
    
  serial := p.Serial
  proof, err := h.t.GetInclusionProof(serial)
  if err != nil {
    writeErrorResponse(&rw, http.StatusInternalServerError, fmt.Sprintf("Unable to get inclusion proof from storage: %v", err))
  }
  proofResponse := &GetInclusionProofResponse{proof}

  // convert to json
  encoder := json.NewEncoder(rw)
  if err := encoder.Encode(*proofResponse); err != nil {
    writeErrorResponse(&rw, http.StatusInternalServerError, fmt.Sprintf("Couldn't encode InclusionProof to return: %v", err))
    return
  }
}

func (h *Handler) PostRevocation(rw http.ResponseWriter, req *http.Request) {
  glog.V(1).Infoln("Received PostRevocation Request")
  if req.Method != "POST" {
		writeWrongMethodResponse(&rw, "POST")
		return
	}

	decoder := json.NewDecoder(req.Body)
	var a PostRevocationRequest
	if err := decoder.Decode(&a); err != nil {
		writeErrorResponse(&rw, http.StatusBadRequest, fmt.Sprintf("Invalid AddRevocation Request: %v", err))
		return
	}

	if err := h.t.AddNode(a.Serial); err != nil {
		writeErrorResponse(&rw, http.StatusInternalServerError, fmt.Sprintf("Unable to store revocation: %v", err))
		return
	}
	rw.WriteHeader(http.StatusOK)
}

func (h *Handler) PostMultipleRevocations(rw http.ResponseWriter, req *http.Request) {
  glog.V(1).Infoln("Received PostMultipleRevocations Request")
  if req.Method != "POST" {
		writeWrongMethodResponse(&rw, "POST")
		return
	}

	decoder := json.NewDecoder(req.Body)
	var a PostMultipleRevocationsRequest
	if err := decoder.Decode(&a); err != nil {
		writeErrorResponse(&rw, http.StatusBadRequest, fmt.Sprintf("Invalid AddRevocations Request: %v", err))
		return
	}

  for _,s := range(a.Serials) {
	  if err := h.t.AddNode(s); err != nil {
		  writeErrorResponse(&rw, http.StatusInternalServerError, fmt.Sprintf("Unable to store revocation: %v", err))
		  return
	  }
  }
	rw.WriteHeader(http.StatusOK)
}

func (h *Handler) GetOcsp(rw http.ResponseWriter, req *http.Request) {
  glog.V(1).Infoln("Received GetOcsp Request")
  if req.Method != "GET" {
		writeWrongMethodResponse(&rw, "GET")
		return
	}

  glog.V(3).Infoln("Reading request body")
  var parsed *ocsp.Request
  body, err := ioutil.ReadAll(req.Body)
  if err != nil {
		writeErrorResponse(&rw, http.StatusBadRequest, fmt.Sprintf("error reading body: %v", err))
		return
	}
  glog.V(3).Infoln("Parsing request")
  parsed, exts, err := ocsp.ParseRequest(body)
  if err != nil {
		writeErrorResponse(&rw, http.StatusBadRequest, fmt.Sprintf("Parse error during Ocsp Request: %v", err))
		return
	}

  // Extract serial number from request
  var serialb []byte
  serialb = parsed.SerialNumber
  serial := uint64(binary.BigEndian.Uint64(serialb))
  glog.V(3).Infof("Got serial from request %v\n",serialb)

  // Check if revoked
  revoked,err := h.t.GetRevocationValue(serial)
  if err != nil {
		writeErrorResponse(&rw, http.StatusBadRequest, fmt.Sprintf("Error while checking revocation value corresponding to serial: %v", err))
		return
	}

  glog.V(3).Infof("Revocation value is %v\n",revoked)

  // Get proof
  proof, err := h.t.GetInclusionProof(serial)
  if err != nil {
    writeErrorResponse(&rw, http.StatusInternalServerError, fmt.Sprintf("Unable to get inclusion proof from storage: %v", err))
  }

  glog.V(3).Infof("Length of proof = %v bytes\n",len(proof))

  // chose oid for "Transparency Information X.509v3 extension"
  // detailed in https://tools.ietf.org/html/draft-ietf-trans-rfc6962-bis-34
  // Not correctly implemented according to specification
  // Should convert proof []byte into a serialized TransItem as talked about in rfc6962
  idTransInfo := asn1.ObjectIdentifier([]int{1,3,101,75})

  // serialize proof to json []byte
  proofjson := ProofResponse{proof}
  proofb, err := json.Marshal(proofjson)
  if err != nil {
    writeErrorResponse(&rw, http.StatusInternalServerError, fmt.Sprintf("Couldn't encode proof as json: %v", err))
    return
  }
  proofext := pkix.Extension{Id: idTransInfo, Critical: false, Value: proofb}
  proofextarray := []pkix.Extension{proofext}

  // Marshal response
  var status int
  if(revoked == true) {
    status = ocsp.Revoked
  } else {
    status = ocsp.Good
  }

  rtemplate := ocsp.Response{
    Status:           status,
		SerialNumber:     serialb,
		Certificate:      h.cert,
		RevocationReason: ocsp.Unspecified,
		IssuerHash:       parsed.HashAlgorithm,
		RevokedAt:        time.Time{}, //nil time, our implementation does not support time of revocation
		ThisUpdate:       h.t.LastUpdated,
		NextUpdate: h.t.NextUpdate,
		Extensions: exts,
    ExtraExtensions: proofextarray,
  }

  resp, err := ocsp.CreateResponse(h.cert,rtemplate,h.key)
  if err != nil {
    writeErrorResponse(&rw, http.StatusInternalServerError, fmt.Sprintf("Error marshalling response to asn1: %v", err))
  }

  rw.Write(resp)
}
