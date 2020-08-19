package main

import (
  "context"
  "os"
  "os/signal"
  "time"
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
  exCfg := types.Config{MaxCerts:1000000,UpdateDelay:10}

  err := tree.Initialize(exCfg)
  if err != nil {
    log.Fatalf("Failed to initialize tree: %v",err)
  }

  stop := make(chan os.Signal, 1)
  signal.Notify(stop, os.Interrupt)

  handler := rev.NewHandler()
  serveMux := http.NewServeMux()
  serveMux.HandleFunc("/new-ct/get-sth", handler.GetSTH)
  serveMux.HandleFunc("/new-ct/get-inclusion-proof", handler.GetInclusionProof)
  serveMux.HandleFunc("/new-ct/add-revocation", handler.AddRevocation)
  serveMux.HandleFunc("/new-ct/add-revocations", handler.AddRevocations)
  server := &http.Server {
    Addr: *listenAddress,
    Handler: serveMux,
  }

  go func() {
    if err := server.ListenAndServe(); err != nil {
      log.Printf("Problem serving: %v\n",err)
    }
  }()
  
  <-stop
  log.Println("Saving to file and exiting")

  tree.SaveToFile()

  ctx, _ := context.WithTimeout(context.Background(), 5*time.Second)

  server.Shutdown(ctx)
  log.Println("Graceful shutdown")
}
