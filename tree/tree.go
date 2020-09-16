package tree

import (
  "time"
  "math"
  "github.com/golang/glog"
  "revocation-server/rfc6962"
  "errors"
  "revocation-server/signer"
  "revocation-server/types"
  "crypto"
  "crypto/ecdsa"
  "crypto/x509"
  "sync"
  "io/ioutil"
  "encoding/pem"
)

//
// Package Tree
// Holds code relating to the in-memory merkle tree implementation for revocation server
// Uses optimization: non-revoked values are not stored
// If a node is present in the tree, it's serial number is revoked
//


// Struct definitions
type MerkleTree struct {
  Root *Node
  merkleRoot []byte //mth, is updated by IntegrateQueue
  hashFunc *rfc6962.Hasher //hash algo for tree

  height int
  maxSerial uint64
  nodesCreated uint64 //current number of nodes in the tree, is updated by IntegrateQueue
  updatedTimes uint64 //how many times we have updated mth, is updated by IntegrateQueue

  s *signer.Signer //contains hash/signer algo's for generating SLR's 
  slr *types.SignedLogRoot //updated by SignRoot
  mmd time.Duration
  LastUpdated *string //updated by SignRoot
  NextUpdate *string //updated by SignRoot

  zeroHashes [][]byte //precomputed values for zero-leaf or zero-children hashes
  queue []uint64 //Added nodes not yet incorporated in the tree
  sync.RWMutex //multiple goroutines have access to this struct, more reads than writes
}

type Node struct {
  Parent *Node
  Left *Node
  Right *Node
  Hash []byte
}

type Config struct { //input parameters for Initialize
  MaxCerts uint64 //uint64 holds up to 18 quintillian certs
  KeyPath string
  CertPath string
  Mmd string
}

// MerkleTree Methods
func (t MerkleTree) SignRoot() error {
  var newLogRoot *types.LogRootV1
  var newSLR *types.SignedLogRoot

  versionNum := t.updatedTimes
  newLogRoot = &types.LogRootV1{
    RootHash: t.merkleRoot,
    TimestampNanos: uint64(time.Now().UnixNano()),
    TreeSize: t.nodesCreated, //number of nodes for treeSize
    Revision: versionNum,
  }

  newSLR, err := t.s.SignLogRoot(newLogRoot)
  if(newSLR==nil) {
    return errors.New("newSLR is nil pointer")
  }
  if(err != nil){return err}

  // mutex
  t.Lock()
  t.slr = newSLR
  t.LastUpdated = &(time.Now().String())
  t.NextUpdate = &(time.Now().Add(t.mmd))
  t.Unlock()
  return nil
}

func Initialize(cfg Config) (*MerkleTree,*ecdsa.PrivateKey,*x509.Certificate,*time.Duration,error) {
  glog.V(2).Infoln("Loading Tree Parameters")
  h := getMaxHeight(cfg.MaxCerts)
  
  glog.V(2).Infoln("Reading in key file")
  key, err := getKeyFromFile(cfg.KeyPath) //private key for slr's
  if(err != nil){return nil,nil,nil,nil,err}

  glog.V(2).Infoln("Reading in cert file")
  cert, err := getCertFromFile(cfg.CertPath)

  glog.V(2).Infoln("Generating empty log root")
  hasher := rfc6962.DefaultHasher //for hashing leaves/nodes
  rootHash := hasher.EmptyRoot()
  root := Node{nil,nil,nil,rootHash}
  maxSerial := uint64(math.Pow(2.0,float64(h)-1))

  glog.V(2).Infoln("Parsing mmd string")
  mmdDuration,err := time.ParseDuration(cfg.Mmd)
  if err != nil {return nil,nil,nil,nil,err}
  glog.V(2).Infof("mmd parsed as %v seconds\n",mmdDuration.Seconds())

  s := signer.NewSigner(0,key,crypto.SHA256)

  t := MerkleTree{
    Root: &root,
    merkleRoot: rootHash,
    hashFunc: hasher,
    height: h,
    maxSerial: maxSerial,
    nodesCreated: uint64(0),
    updatedTimes: uint64(0),
    mmd: mmdDuration,
    s: s,
  }

  glog.V(2).Infoln("Signing empty root")
  t.SignRoot()

  t.Lock()
  glog.V(3).Infoln("lastupdated,slr = %v, %v\n",t.LastUpdated,t.slr)
  t.Unlock()
  
  glog.V(2).Infoln("Precomputing zero hashes")
  zeroHashes := precomputeHashes(t.hashFunc,h)
  t.zeroHashes = zeroHashes
  
  return &t, key, cert, &mmdDuration, nil
}

func (t MerkleTree) GetSth() *types.SignedLogRoot {
  t.Lock()
  slr := t.slr
  t.Unlock()
  glog.Infof("slr = %v",slr)
  return slr
}

// Loop through tree to see if leaf is present
// true = revoked
func (t MerkleTree) GetRevocationValue(serial uint64) (bool,error) {
  mask := uint64(math.Pow(2,float64(t.height-1)))
  curNode := t.Root
  for i:=0;i<(t.height-1);i++ {
    if(mask&serial>0) { 
      curNode = curNode.Right
    } else {
      curNode = curNode.Left
    }

    if(curNode==nil) {
      return false,nil
    }
  }

  // if we make it to a leaf node it is revoked
  return true,nil
}

// Add node to the queue to be incorporated 
func (t MerkleTree) AddNode(serial uint64) error {
  if(serial > t.maxSerial) {
    return errors.New("Request serial exceeds maximum serial storable by tree. Increase MaxCerts in config file")
  }

  // mutex
  t.Lock()
  t.queue = append(t.queue,serial)
  t.Unlock()
  return nil
}

// Starting from root, loop through serial in binary to place node in tree
// 1 == right, 0 == left
// runs in parallel with normal log operation
func (t MerkleTree) IntegrateQueue() error {
  // Reset the queue, work with a copy to allow nodes to be added while integration is happening
  // mutex
  t.Lock()
  queueCopy := t.queue[:]
  t.queue = []uint64{}
  t.Unlock()

  // Add leaf + required internal nodes to tree
  var integratedNodes []*Node = make([]*Node,len(queueCopy)) //save pointers of added nodes for hashing later
  nodesIncreased := uint64(0) //number of nodes we added to the tree this batch
  for j,v := range(queueCopy) {
    mask := uint64(math.Pow(2,float64(t.height-1)))
    curNode := t.Root
    var newNode *Node
    for i:=0;i<(t.height-1);i++ {
      if(mask&v>0) { 
        if(curNode.Right==nil) {
          newNode = &Node{curNode,nil,nil,nil}
          nodesIncreased += 1
          curNode.Right = newNode
        }
        curNode = curNode.Right
      } else {
        if(curNode.Left==nil) {
          newNode = &Node{curNode,nil,nil,nil}
          nodesIncreased += 1
          curNode.Left = newNode
        }
        curNode = curNode.Left
      }
      mask = mask>>1
      if(i==t.height-2) { //leaf node
        integratedNodes[j] = newNode
      }
    }
  }

  // update nodesCreated
  // mutex
  t.Lock()
  t.nodesCreated += nodesIncreased
  t.Unlock()

  // Hash up impacted nodes
  leafHash := t.hashFunc.HashLeaf([]byte{1})
  for _,v := range(integratedNodes) {
    curNode := v
    curNode.Hash = leafHash
    curHeight := t.height
    for (curNode!=t.Root) {
      curNode = curNode.Parent
      var leftHash,rightHash []byte

      if(curNode.Left==nil) {
        leftHash = t.zeroHashes[curHeight]
      } else {
        leftHash = curNode.Left.Hash
      }

      if(curNode.Right==nil) {
        rightHash = t.zeroHashes[curHeight]
      } else {
        rightHash = curNode.Right.Hash
      }

      curNode.Hash = t.hashFunc.HashChildren(leftHash,rightHash)
      curHeight += 1
    }
  }

  // Update MTH
  // mutex
  t.Lock()
  t.merkleRoot = t.Root.Hash
  t.updatedTimes++
  t.Unlock()

  // Sign the root
  err := t.SignRoot()
  if(err != nil){return err}

  return nil
}

func (t MerkleTree) GetInclusionProof(serial uint64) ([][]byte,error) {
  proof := make([][]byte,t.height)

  var curNode *Node
  var temp *Node //for proof, node we will take hash of
  var next *Node

  mask := uint64(math.Pow(2,float64(t.height-1)))
  curNode = t.Root
  curHeight := t.height-1
  for i:=(t.height-1);i<0;i-- {
    if(serial&mask>0) {
      // Grab child for proof
      temp = curNode.Left
      next = curNode.Right
    } else {
      temp = curNode.Right
      next = curNode.Left
    }

    // check if child is present
    if(temp!=nil) {
      proof[i] = temp.Hash
    } else {
      proof[i] = t.zeroHashes[curHeight]
    }

    // check if next node is present
    if(next!=nil) {
      curNode = next
      curHeight--
    } else { //defaults for the rest of the proof
      for(i<0) {
        proof[i] = t.zeroHashes[curHeight]
        curHeight--
        i--
      }
      break;
    }
  }
  return proof, nil
}

// Helper Functions
func getKeyFromFile(path string) (*ecdsa.PrivateKey, error) {
  b, err := ioutil.ReadFile(path)
  if err != nil {return nil,err}
  block,_ := pem.Decode(b)
  if err != nil {return nil,err}
  key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
  if err != nil {return nil,err}
  t, ok := key.(*ecdsa.PrivateKey)
  glog.Infof("Key is of type: %T\n",key)
  if(ok!=true) {return nil,errors.New("Private key is not ecdsa type")}
  return t,nil
}

func getCertFromFile(path string) (*x509.Certificate,error) {
  b, err := ioutil.ReadFile(path)
  if err != nil {return nil,err}
  block,_ := pem.Decode(b)
  if err != nil {return nil,err}
  cert, err := x509.ParseCertificate(block.Bytes)
  if err != nil {return nil,err}
  return cert,nil
}


func precomputeHashes(hashFunc *rfc6962.Hasher, h int) ([][]byte) {
  // precompute leaf 

  // indices are ordered backwards here when compared to the tree
  // index 0 = leaf node hash of 0
  // index (height) = root hash of all zero children when entire tree is empty
  zeroHashes := make([][]byte,h+1)
  var lastHash []byte
  lastHash = hashFunc.HashLeaf([]byte{0})
  zeroHashes[0] = lastHash
  for i:=0;i<h;i++ {
    hash := hashFunc.HashChildren(lastHash,lastHash)
    zeroHashes[i+1] = hash
    lastHash = hash
  }
  return zeroHashes
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

func getMaxHeight(v uint64) int {
  p := nextPow2(v)
  h := int(math.Log2(float64(p)))
  return h
}
