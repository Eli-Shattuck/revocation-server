package signer

import (
	"crypto"
	"crypto/rand"

	"github.com/golang/glog"
	"revocation-server/types"
	"golang.org/x/crypto/ed25519"
)

const noHash = crypto.Hash(0)

// Signer is responsible for signing log-related data and producing the appropriate
// application specific signature objects.
type Signer struct {
	KeyHint []byte
	// If Hash is noHash (zero), the signer expects to be given the full message not a hashed digest.
	Hash   crypto.Hash
	Signer crypto.Signer
}

// NewSigner returns a new signer. The signer will set the KeyHint field, when available, with KeyID.
func NewSigner(keyID int64, signer crypto.Signer, hash crypto.Hash) *Signer {
	if _, ok := signer.(ed25519.PrivateKey); ok {
		// Ed25519 signing requires the full message.
		hash = noHash
	}
	return &Signer{
		KeyHint: types.SerializeKeyHint(keyID),
		Hash:    hash,
		Signer:  signer,
	}
}

// NewSHA256Signer creates a new SHA256 based Signer and a KeyID of 0.
//
// Deprecated: NewSHA256Signer was only meant for use in tests. It can be
// replaced by NewSigner(0, key, crypto.SHA256).
func NewSHA256Signer(signer crypto.Signer) *Signer {
	return &Signer{
		Hash:   crypto.SHA256,
		Signer: signer,
	}
}

// Public returns the public key that can verify signatures produced by s.
func (s *Signer) Public() crypto.PublicKey {
	return s.Signer.Public()
}

// Sign obtains a signature over the input data; this typically (but not always)
// involves first hashing the input data.
func (s *Signer) Sign(data []byte) ([]byte, error) {
	if s.Hash == noHash {
		return s.Signer.Sign(rand.Reader, data, noHash)
	}
	h := s.Hash.New()
	h.Write(data)
	digest := h.Sum(nil)

	return s.Signer.Sign(rand.Reader, digest, s.Hash)
}

// SignLogRoot returns a complete SignedLogRoot (including signature).
func (s *Signer) SignLogRoot(r *types.LogRootV1) (*types.SignedLogRoot, error) {
	logRoot, err := r.MarshalBinary()
  glog.V(3).Infof("logroot = %v\n",logRoot)
	if err != nil {
		return nil, err
	}
	signature, err := s.Sign(logRoot)
  glog.V(3).Infof("signature over logroot = %v\n",signature)
	if err != nil {
		glog.Warningf("%v: signer failed to sign log root: %v", s.KeyHint, err)
		return nil, err
	}

	return &types.SignedLogRoot{
		LogRoot:          logRoot,
		LogRootSignature: signature,
	}, nil
}
