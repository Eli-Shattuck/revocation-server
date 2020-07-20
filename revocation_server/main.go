package main

import (
  "fmt"
  "revocation-server/storage"
)

func main() {
  fmt.Println("Starting test run")
  s.Open("test:pass@tcp(127.0.0.1:3306)/revocation")
  if err != nil {
    panic(err.Error())
  }

  defer s.Close()

  s.AddEntry()
