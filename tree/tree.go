package tree

import (
  "math"
  "fmt"
  "revocation-server"
  "revocation-server/rfc6962"
)


var (
  inMemoryTree map[int][]Node
  currentHeight int
)

// Given a serial number, returns a list of internal ID's that must be in the tree
// nodes internal id = postorder traversal
func getInternalNodes(serial int, height int) []int {
  ret := make([]int,height-1)
  cur := int(math.Pow(2,float64(height+1)))-1 //number of nodes in full tree of that height
  fmt.Println("num nodes in full tree:",cur)
  for i := range ret {
    decision := serial&(1<<(height-1-i))
    fmt.Printf("decision is %v\n",decision)
    if decision!=0 {
      cur = cur - 1 //took a right
    } else {
      cur = cur - int(math.Pow(2,float64(height-i))) //took a left
    }
    ret[i] = cur
  }
  return ret
}

func getRootInternalId() int {
  height := currentHeight
  cur := int(math.Pow(2,float64(height+1)))-1 //number of nodes in full tree of that height
  return cur
}

// adds internal nodes + leaf node to the in memory tree
func addNodes(serial int, s *Storage) err {
  height := currentHeight
  maxnodes := getRootInternalId()

  // Check and reassign root if needed
  while serial > maxnodes-1 { //resize tree
    maxnodes = incrementHeight(maxnodes, s)
  }

  // Add node to tree
  lastparent := maxnodes
  impactedNodes := make([]int,height+1)
  for i := 0;i<(len(impactedNodes)-2);i++ {
    decision := serial&(1<<(height-1-i))
    if decision!=0 {
      cur = cur - 1 //take a right
      inMemoryTree[lastparent].Right = cur
    } else {
      cur = cur - int(math.Pow(2,float64(height-i))) //take a left
      inMemoryTree[lastparent].Left = cur
    }
    ret[i+1] = cur
  }

  // Hash up impacted nodes
  for i = len(impactedNodes)-1; i>=0; i-- { 
    node := inMemoryTree[impactedNodes[i]]
    if i== len(impactedNodes)-1{ //leaf
      node.Data = rfc6962.HashLeaf(node.Data)
    } else {
      node.Data = rfc6962.HashChildren(inMemoryTree[node.Left].Data,inMemoryTree[node.Right].Data)
    }
  }

// re-assigns root and adds empty right sub-tree and returns new max num_nodes
// before any more nodes assigned the root retains its hash
func incrementHeight(oldrootId int, s *Storage) int {
  currentHeight = currentHeight + 1
  cur := getRootInternalId()
  oldrootdata := inMemoryTree[oldrootId].Data
  newroot := Node{cur,0,oldrootdata,oldrootId,0}
  err := s.SetHeight(currentHeight)
  if err != nil {
    panic(err.Error())
  }
}

func initializeTree() {
  currentHeight = 1
  maxnodes := getRootInternalId()
  root := Node{maxnodes,0

func AddRevocation(serial int) err {

