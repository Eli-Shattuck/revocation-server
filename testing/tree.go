package main

import (
	"fmt"
  "revocation-server/tree"
)

func main() {
  nodes := tree.GetInternalNodes(6,3)
  fmt.Printf("%v",nodes)
}
