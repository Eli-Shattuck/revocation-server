package main

import (
	"fmt"
  "revocation-server/tree"
  "revocation-server/types"
)

func main() {
  fmt.Println("Begin Test\n\n")
  fmt.Printf("### Startup and Tree Creation Testing ###\n\n")
  exCfg := types.Config{MaxCerts:256,UpdateDelay:10}
  err := tree.Initialize(exCfg)
  if err != nil {
    panic(err.Error())
  }
  var nodeList []string = []string{"05","07"}
  for _,v := range nodeList {
    tree.PrintTree()
    err = tree.AddNode(v)
    if err != nil {
      panic(err.Error())
    }
  }
  tree.PrintTree()
  fmt.Println("Grab MTH:")
  fmt.Println(tree.GetMTH())
  fmt.Printf("\n\n")

  fmt.Printf("### Inclusion Proof Testing ###\n\n")

  fmt.Println("Grab inclusion for node serial 00000101 (id 8)")
  proof, err := tree.GetInclusionProof("05")
  if err != nil {
    panic(err.Error())
  }
  fmt.Printf("%v\n\n",proof)
  
  fmt.Println("Grab inclusion for node serial 00000111 (id 10)")
  proof, err = tree.GetInclusionProof("07")
  if err != nil {
    panic(err.Error())
  }
  fmt.Printf("%v\n\n",proof)

  // proof of non-revocation
  fmt.Println("Grab inclusion (proof of non-revocation) for node serial 00000000 (not stored)")
  proof, err = tree.GetInclusionProof("00")
  if err != nil {
    panic(err.Error())
  }
  fmt.Printf("%v\n\n",proof)
}
