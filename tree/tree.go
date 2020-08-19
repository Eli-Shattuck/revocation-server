package tree

import (
  "math"
  "fmt"
  "revocation-server/types"
  "revocation-server/rfc6962"
  "revocation-server/padding"
  "os"
  "encoding/hex"
  "errors"
  "encoding/binary"
  "encoding/gob"
)

//global var
var (
  tree = types.NewTree() //maps id to node pointer
  height int //final height of tree
  nodesCount int = 0 //we ignore root in this variable, for use in ID-ing new nodes
  storageFile string = "storage.bin"
  zeroHashes [][]byte //precomputed values for zero-leaf or zero-children hashes
  hasher *rfc6962.Hasher
  maxCerts uint64
)

func setCount(count int) {
  *(&nodesCount) = count
}

func SaveToFile() {
  encodeFile,err := os.Create(storageFile)
  if err != nil {
    panic(err)
  }
  encoder := gob.NewEncoder(encodeFile)

  if err := encoder.Encode(tree); err != nil {
    panic(err)
  }
}

func PrintTree() error {
  fmt.Printf("\nCurrent Tree:\n")
  for k,v := range(tree) {
    fmt.Printf("%d: %v\n",k,v)
  }
  fmt.Println()
  return nil
}

func PrintCount() {
  fmt.Printf("Current nodesCount = %d\n",nodesCount)
}

func nextPow2(v uint64) uint64 { 
  v = v - 1
  v = v | v >> 1;
  v = v | v >> 2;
  v = v | v >> 4;
  v = v | v >> 8;
  v = v | v >> 16;
  v = v | v >> 32;
  v = v + 1
  return v;
}

func nextMult8(v int) int { 
  v = (v+7)&(-8)
  return v;
}

func getMaxHeight(maxCerts uint64) int {
  p := nextPow2(maxCerts)
  h := math.Log2(float64(p))
  v := nextMult8(int(math.Ceil(h)))
  return v
}

func precomputeHashes(h int) error {
  // precompute leaf 
  // maybe confusingly, indices are backwards here when compared to the tree
  // index 0 = leaf node hash of 0
  // index (height) = root hash of all zero children when entire tree is empty
  zeroHashes = make([][]byte,height+1)
  var lastHash []byte
  lastHash = hasher.HashLeaf([]byte{0})
  zeroHashes[0] = lastHash
  for i:=0;i<h;i++ {
    hash := hasher.HashChildren(lastHash,lastHash)
    zeroHashes[i+1] = hash
    lastHash = hash
  }
  return nil
}



func Initialize(cfg types.Config) error {
  //check storage file
  fmt.Println("Initializing")

  // set hasher
  hasher = rfc6962.DefaultHasher

//  _, err := os.Stat(storageFile)
//  if os.IsNotExist(err) { 
//    err := initializeFirstTime(cfg)
//    if err != nil {
//      return err
//    }
//  }
  err := initializeFirstTime(cfg)
  // cfg vars to global
  fmt.Printf("Setting global vars\n")
  h := getMaxHeight(uint64(cfg.MaxCerts))
  *(&height) = h
  maxCerts = uint64(cfg.MaxCerts)

  fmt.Printf("Tree height = %d\n",h)


  // precompute hashes
  err = precomputeHashes(h)
  if err != nil {
    return err
  }

  err = loadTree()
  if err != nil {
    return err
  }
  return nil
}

func initializeFirstTime(cfg types.Config) error {
  fmt.Println("initializing for the first time")
  // add empty root
  rt := hasher.EmptyRoot()

  node := types.NewNode(0,-1)
  node.SetData(rt)
  tree[0] = node

  return nil
}


func loadTree() error {
  return nil
}

func GetMTH() []byte {
  return tree[0].GetData()
}

func GetInclusionProof(serialString string) ([][]byte,error) {
  root := 0
  next := root
  height := height
  proof := make([][]byte,height)
  curNode := tree[root]
  serial, err := hex.DecodeString(serialString)
  if err != nil {
    return proof,err
  }
  var temp int
  for _,v := range(serial) {
    mask := uint8(128)
    for i:=0;i<8;i++ {
        curNode = tree[next]
        height -= 1
        step := mask & v
        if(step==0) {
          temp = curNode.GetRight()
          next = curNode.GetLeft()
          fmt.Println("Left")
        } else {
          temp = curNode.GetLeft()
          next = curNode.GetRight()
          fmt.Println("Right")
        }
        if(temp==-1) { //null
          proof[height] = zeroHashes[height]
        } else {
          proof[height] = tree[temp].GetData()
        }
      mask = mask >> 1
      fmt.Println(next)
      if(height<1 || next==-1) {
        break
      }
    }
    if(height<1 || next==-1) {
      break
    } 
  }
  if(next==-1) { // defaults for the rest
    for (height >= 1) {
      height -= 1
      proof[height] = zeroHashes[height]
      fmt.Println("Either")
    }
  }
  return proof,nil
}



// accepts string hex serial, i.e "078c"
func AddNode(serialString string) error {
//  fmt.Printf("Adding leaf node %v\n",serialString)
  serial, err := hex.DecodeString(serialString)
  if err != nil {
    return err
  }
//  fmt.Printf("Decoded string: %v\n",serial)

  // Check that we didnt recieve a request that exceeds maxcerts
  padded,err := padding.LeftPad(serial,64)
  if err != nil {
    return err
  }
  num := binary.BigEndian.Uint64(padded)
  if(num>maxCerts) {
    return errors.New("Provided serial number exceeds current tree's max number of certs, to store more revocations, increase MaxCerts in the Config file")
  }

  curNodeId := 0
  curNode := tree[curNodeId]
  count := nodesCount
  
  nextNode := types.NewNode(count,curNodeId)
  nextNodeId := -1

  // add internal nodes as needed
  for _,v := range(serial) {
    mask := uint8(128)
    for i:=0; i<8; i++ {
      goright := mask & v
      if(goright > 0) {
//        fmt.Println("Right")
        nextNodeId = curNode.GetRight()
        if(nextNodeId==-1) {
//          fmt.Println("Creating Node")
          count+=1
          nextNodeId=count
          curNode.SetRight(nextNodeId)
          nextNode = types.NewNode(count,curNodeId)
          tree[nextNodeId] = nextNode
        }
      } else { //go left
//        fmt.Println("Left")
        nextNodeId = curNode.GetLeft()
        if(nextNodeId==-1) {
//          fmt.Println("Creating Node")
          count+=1
          nextNodeId=count
          curNode.SetLeft(nextNodeId)
          nextNode = types.NewNode(count,curNodeId)
          tree[nextNodeId] = nextNode
        }
      }
//      print(nextNodeId,"\n")
      curNode = tree[nextNodeId]
      curNodeId = curNode.GetId()
      mask = mask >> 1
    }
  }

  // add to nodesCount
  setCount(count)

  // add serial to leaf node
  curNode.SetSerial(serial)


  // hash up impacted nodes, starting with leaf node added
//  fmt.Println("hashing up")
  h := 0 //height counter as we go up
  curHash := hasher.HashLeaf([]byte{1}) //we could index this, leaving as TODO(jeremy) for now
  curNodeId = curNode.GetId()
  curNode.SetData(curHash)
  for curNodeId != 0 {
    curNodeId = curNode.GetParent()
    curNode = tree[curNodeId]
    // get hashes

    leftId := curNode.GetLeft()
    var leftHash,rightHash []byte
    if (leftId==-1) {
      leftHash = zeroHashes[h]
    } else {
      leftHash = tree[leftId].GetData()
    }

    rightId := curNode.GetRight()
    if (rightId==-1) {
      rightHash = zeroHashes[h]
    } else {
      rightHash = tree[rightId].GetData()
    }

    curHash = hasher.HashChildren(leftHash,rightHash)
    curNode.SetData(curHash)
    h+=1
  }
  return nil
}
