package main

import (
  "fmt"
  rev "revocation-server"
)

func main() {
  fmt.Println("Starting test run")
  s := rev.Storage{} 
  err := s.Open("test:pass@tcp(127.0.0.1:3306)/revocation")
  if err != nil {
    panic(err.Error())
  }

  defer s.Close()

  fmt.Println("Adding dummy node to storage")
  testnode := rev.Node{0,1,[]byte{0,1},2,3}
  err = s.AddNode(testnode)
  if err != nil {
    panic(err.Error())
  }
  
  fmt.Println("Grabbing MTH")
  mth,err := s.GetMTH()
  if err != nil {
    panic(err.Error())
  }
  fmt.Printf("MTH is %v\n",mth)

  fmt.Println("Adding second node")
  testnode = rev.Node{14,1,[]byte{0,3},5,6}
  err = s.AddNode(testnode)

  fmt.Println("Grabbing MTH")
  mth,err = s.GetMTH()
  if err != nil {
    panic(err.Error())
  }
  fmt.Printf("MTH is %v\n",mth)

  fmt.Println("Grabbing all nodes")
  nodes,err := s.GetNodes()
  if err != nil {
    panic(err.Error())
  }
  fmt.Println("Got nodes, looping through each entry")
  for i,v := range nodes {
    fmt.Printf("Row %d: %v\n",i,v)
  }

  fmt.Println("Setting height = 3")
  err = s.SetHeight(3)
  if err != nil {
    panic(err.Error())
  }

  fmt.Println("Done, querying height")
  height,err := s.GetHeight()
  if err != nil {
    panic(err.Error())
  }
  fmt.Printf("Height is %d\n",height)
}
