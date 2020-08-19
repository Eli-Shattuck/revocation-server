package handler

import (
  "encoding/json"
  "net/http"
  "revocation-server/tree"
  "fmt"
  "log"
)

type Handler struct {}


type MthResponse struct {
  Data []byte
}

type InclusionProofResponse struct {
  Proof [][]byte
}

type InclusionProofRequest struct {
  Serial string
}

func (r *InclusionProofRequest) GetSerial() string {
  return r.Serial
}

type AddRevocationRequest struct {
  Serial string
}

func (r *AddRevocationRequest) GetSerial() string {
  return r.Serial
}

type AddRevocationsRequest struct {
  Serials []string
}


func writeWrongMethodResponse(rw *http.ResponseWriter, allowed string) {
	(*rw).Header().Add("Allow", allowed)
	(*rw).WriteHeader(http.StatusMethodNotAllowed)
}

func writeErrorResponse(rw *http.ResponseWriter, status int, body string) {
	(*rw).WriteHeader(status)
	(*rw).Write([]byte(body))
}

// Really this is an MTH for now, TODO(jeremy)
func (h *Handler) GetSTH(rw http.ResponseWriter, req *http.Request) {
  if req.Method != "GET" {
    writeWrongMethodResponse(&rw, "GET")
    return
  }

  mthData := tree.GetMTH()
  mth := &MthResponse{Data:mthData}

  // convert to json
  encoder := json.NewEncoder(rw)
  if err := encoder.Encode(*mth); err != nil {
    writeErrorResponse(&rw, http.StatusInternalServerError, fmt.Sprintf("Couldn't encode MTH to return: %v", err))
    return
  }
}

func (h *Handler) GetInclusionProof(rw http.ResponseWriter, req *http.Request) {
  if req.Method != "GET" {
    writeWrongMethodResponse(&rw, "GET")
    return
  }

  decoder := json.NewDecoder(req.Body)
  var p InclusionProofRequest
  if err := decoder.Decode(&p); err != nil {
    writeErrorResponse(&rw, http.StatusInternalServerError, fmt.Sprintf("Invalid InclusionProofRequest: %v", err))
    return
  }
    

  serial := p.Serial
  proof, err := tree.GetInclusionProof(serial)
  if err != nil {
    writeErrorResponse(&rw, http.StatusInternalServerError, fmt.Sprintf("Unable to get inclusion proof from storage: %v", err))
  }
  proofResponse := &InclusionProofResponse{Proof:proof}

  // convert to json
  encoder := json.NewEncoder(rw)
  if err := encoder.Encode(*proofResponse); err != nil {
    writeErrorResponse(&rw, http.StatusInternalServerError, fmt.Sprintf("Couldn't encode InclusionProof to return: %v", err))
    return
  }
}

func (h *Handler) AddRevocation(rw http.ResponseWriter, req *http.Request) {
  log.Println("Adding revocation")
  if req.Method != "POST" {
		writeWrongMethodResponse(&rw, "POST")
		return
	}

	decoder := json.NewDecoder(req.Body)
	var a AddRevocationRequest
	if err := decoder.Decode(&a); err != nil {
		writeErrorResponse(&rw, http.StatusBadRequest, fmt.Sprintf("Invalid AddRevocation Request: %v", err))
		return
	}

	if err := tree.AddNode(a.Serial); err != nil {
		writeErrorResponse(&rw, http.StatusInternalServerError, fmt.Sprintf("Unable to store revocation: %v", err))
		return
	}
	rw.WriteHeader(http.StatusOK)
}

func (h *Handler) AddRevocations(rw http.ResponseWriter, req *http.Request) {
  log.Println("Adding revocations")
  if req.Method != "POST" {
		writeWrongMethodResponse(&rw, "POST")
		return
	}

	decoder := json.NewDecoder(req.Body)
	var a AddRevocationsRequest
	if err := decoder.Decode(&a); err != nil {
		writeErrorResponse(&rw, http.StatusBadRequest, fmt.Sprintf("Invalid AddRevocations Request: %v", err))
		return
	}

        for _,s := range(a.Serials) {
	  if err := tree.AddNode(s); err != nil {
		  writeErrorResponse(&rw, http.StatusInternalServerError, fmt.Sprintf("Unable to store revocation: %v", err))
		  return
	  }
        }
        tree.PrintCount()
	rw.WriteHeader(http.StatusOK)
}

func NewHandler() Handler {
  return Handler{}
}
