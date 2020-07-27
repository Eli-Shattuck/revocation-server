package revocation

type Node struct {
  Internal_id  int
  Leaf_id int
  Data []byte
  Left int
  Right int
}
