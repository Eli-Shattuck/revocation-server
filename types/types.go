package types

type Node struct {
  Id  int
  Parent int
  Data []byte
  Left int
  Right int
  Serial []byte
}

func NewNode(id int, par int) *Node {
  n := Node{}
  n.Id = id
  n.Parent = par
  n.Left = -1
  n.Right = -1
  n.Serial = []byte{}
  n.Data = []byte{}
  return &n
}

func NewTree() map[int]*Node {
  return make(map[int]*Node)
}

func (n *Node) SetSerial(s []byte) {
  n.Serial = s
}

func (n *Node) SetData(d []byte) {
  n.Data = d
}

func (n *Node) SetRight(r int) {
  n.Right = r
}

func (n *Node) SetLeft(l int) {
  n.Left = l
}

func (n *Node) GetLeft() int{
  return n.Left
}

func (n *Node) GetRight() int {
  return n.Right
}

func (n *Node) GetData() []byte {
  return n.Data
}

func (n *Node) GetParent() int {
  return n.Parent
}

func (n *Node) GetId() int {
  return n.Id
}

type Info struct {
  Height int
  MaxNodes int
}

type Config struct {
  MaxCerts int
  UpdateDelay int //seconds
}
