package main

import (
  "context"
  "os"
  "os/signal"
  "time"
  "flag"
  "github.com/golang/glog"
  "net/http"
  "revocation-server/tree"
  "revocation-server/sequencer"
  rev "revocation-server/handler"
)

var (
  listenAddress = flag.String("listen", ":8080", "Listen address:port for HTTP server")
  maxCerts = flag.Uint64("max_certs", 1000000, "Highest serial number the server can store, affects tree height")
// could add support for this later  configFile = flag.String("config", "", "Config file containing flags, file contents can be overridden by command line flags")
  certFile = flag.String("cert_file","testdata/root.cert","File containing pem-encoded SSL certificate")
  mmd = flag.String("mmd","24h","Duration corresponding to mmd for log, valid time units are ns,us,ms,s,m,h")
  key = flag.String("key","testdata/key.pem","Private key for revocation server")
)

func main() {
  flag.Parse()
  defer glog.Flush()

  glog.Infoln("Starting revocation server.")

  cfg := tree.Config{
    MaxCerts: *maxCerts,
    KeyPath: *key,
    CertPath: *certFile,
    Mmd: *mmd,
  }
  t, key, cert, mmdDuration, err := tree.Initialize(cfg)
  if err != nil {
    glog.Exitf("Failed to initialize tree: %v",err)
  }

  stop := make(chan os.Signal, 1)
  signal.Notify(stop, os.Interrupt)

  glog.Infoln("Setting up handlers")
  handler := rev.NewHandler(t,cert,key)
  serveMux := http.NewServeMux()
  serveMux.HandleFunc("/new-ct/get-sth", handler.GetSth)
  serveMux.HandleFunc("/new-ct/get-inclusion-proof", handler.GetInclusionProof)
  serveMux.HandleFunc("/new-ct/get-ocsp", handler.GetOcsp)
  serveMux.HandleFunc("/new-ct/post-revocation", handler.PostRevocation)
  serveMux.HandleFunc("/new-ct/post-multiple-revocations", handler.PostMultipleRevocations)

  // Return a 200 on the root so clients can easily check if server is up
  serveMux.HandleFunc("/", func(resp http.ResponseWriter, req *http.Request) {
    if req.URL.Path == "/" {
      resp.WriteHeader(http.StatusOK)
    } else {
      resp.WriteHeader(http.StatusNotFound)
    }
  })

  server := &http.Server {
    Addr: *listenAddress,
    Handler: serveMux,
  }

  // start up handles
  go func() {
    if err := server.ListenAndServe(); err != nil {
      glog.Exitf("Problem serving: %v\n",err)
    }
  }()

  // start up sequencer
  glog.Infoln("Starting sequencer")
  seqdone := make(chan bool)
  go func() {
    if err := sequencer.Run(seqdone,t,*mmdDuration); err != nil {
      glog.Exitf("Problem integrating queued nodes to merkle tree: %v",err)
    }
  }()
  glog.Infoln("Sequencer started")

  
  <-stop
  glog.Infoln("Received stop signal")

  // Might have to wait for this to shutdown safely
  seqdone <- true

  ctx, _ := context.WithTimeout(context.Background(), 5*time.Second)

  server.Shutdown(ctx)
  glog.Infoln("Graceful shutdown")
}
