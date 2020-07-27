// Package rfc6962 provides hashing functionality according to RFC6962.
package rfc6962

import (
	"crypto"
	_ "crypto/sha256" // SHA256 is the default algorithm.

	"github.com/google/trillian"
	"github.com/google/trillian/merkle/hashers"
)

func init() {
	hashers.RegisterLogHasher(trillian.HashStrategy_RFC6962_SHA256, New(crypto.SHA256))
}

// Domain separation prefixes
const (
	RFC6962LeafHashPrefix = 0
	RFC6962NodeHashPrefix = 1
)

// DefaultHasher is a SHA256 based LogHasher.
var DefaultHasher = New(crypto.SHA256)

// Hasher implements the RFC6962 tree hashing algorithm.
type Hasher struct {
	crypto.Hash
}

// New creates a new Hashers.LogHasher on the passed in hash function.
func New(h crypto.Hash) *Hasher {
	return &Hasher{Hash: h}
}

// EmptyRoot returns a special case for an empty tree.
func (t *Hasher) EmptyRoot() []byte {
	return t.New().Sum(nil)
}

// HashLeaf returns the Merkle tree leaf hash of the data passed in through leaf.
// The data in leaf is prefixed by the LeafHashPrefix.
func (t *Hasher) HashLeaf(leaf []byte) []byte {
	h := t.New()
	h.Write([]byte{RFC6962LeafHashPrefix})
	h.Write(leaf)
	return h.Sum(nil)
}

// hashChildrenOld returns the inner Merkle tree node hash of the two child nodes l and r.
// The hashed structure is NodeHashPrefix||l||r.
// TODO(al): Remove me.
func (t *Hasher) hashChildrenOld(l, r []byte) []byte {
	h := t.New()
	h.Write([]byte{RFC6962NodeHashPrefix})
	h.Write(l)
	h.Write(r)
	return h.Sum(nil)
}

// HashChildren returns the inner Merkle tree node hash of the two child nodes l and r.
// The hashed structure is NodeHashPrefix||l||r.
func (t *Hasher) HashChildren(l, r []byte) []byte {
	h := t.New()
	b := append(append(append(
		make([]byte, 0, 1+len(l)+len(r)),
		RFC6962NodeHashPrefix),
		l...),
		r...)

	h.Write(b)
	return h.Sum(nil)
}
