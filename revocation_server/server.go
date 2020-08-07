package main

import (
  "flag"
  "log"
  "net/http"
  "revocation-server/types"
  "revocation-server/tree"
  rev "revocation-server/handler"
)

var listenAddress = flag.String("listen", ":8080", "Listen address:port for HTTP server.")

func main() {
  flag.Parse()
  log.Print("Starting revocation server.")
  exCfg := types.Config{MaxCerts:256,UpdateDelay:10}

  err := tree.Initialize(exCfg)
  if err != nil {
    log.Fatalf("Failed to initialize tree: %v",err)
  }

  handler := rev.NewHandler()
  serveMux := http.NewServeMux()
  serveMux.HandleFunc("/new-ct/get-sth", handler.GetSTH)
  serveMux.HandleFunc("/new-ct/get-inclusion-proof", handler.GetInclusionProof)
  serveMux.HandleFunc("/new-ct/add-revocation", handler.AddRevocation)
  server := &http.Server {
    Addr: *listenAddress,
    Handler: serveMux,
  }
  if err := server.ListenAndServe(); err != nil {
    log.Printf("Error serving: %v", err)
  }
}

