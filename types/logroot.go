// Package types defines serialization and parsing functions for SignedLogRoot
package types

import (
	"encoding/binary"
	"fmt"

	"github.com/google/certificate-transparency-go/tls"
)

// LogRootV1 holds the TLS-deserialization of the following structure
// (described in RFC5246 section 4 notation):
// struct {
//   uint64 tree_size;
//   opaque root_hash<0..128>;
//   uint64 timestamp_nanos;
//   uint64 revision;
//   opaque metadata<0..65535>;
// } LogRootV1;
type LogRootV1 struct {
	TreeSize       uint64
	RootHash       []byte `tls:"minlen:0,maxlen:128"`
	TimestampNanos uint64
	Revision       uint64
	Metadata       []byte `tls:"minlen:0,maxlen:65535"`
}

// LogRoot holds the TLS-deserialization of the following structure
// (described in RFC5246 section 4 notation):
// enum { v1(1), (65535)} Version;
// struct {
//   Version version;
//   select(version) {
//     case v1: LogRootV1;
//   }
// } LogRoot;
type LogRoot struct {
	Version tls.Enum   `tls:"size:2"`
	V1      *LogRootV1 `tls:"selector:Version,val:1"`
}

// This was in a protobuf file in original trillian repo
// Refactored into a simple struct
// Signature is over serialized/hashed log_root
type SignedLogRoot struct {
  LogRoot []byte
  LogRootSignature []byte
}

// (Jeremy) Stuck this in here from the trillian repo
// LogRootFormat specifies the fields that are covered by the
// SignedLogRoot signature, as well as their ordering and formats.
var (
  LogRootFormat_LOG_ROOT_FORMAT_UNKNOWN int = 0
  LogRootFormat_LOG_ROOT_FORMAT_V1 int = 1
)

// UnmarshalBinary verifies that logRootBytes is a TLS serialized LogRoot, has
// the LOG_ROOT_FORMAT_V1 tag, and populates the caller with the deserialized
// *LogRootV1.
func (l *LogRootV1) UnmarshalBinary(logRootBytes []byte) error {
	if len(logRootBytes) < 3 {
		return fmt.Errorf("logRootBytes too short")
	}
	if l == nil {
		return fmt.Errorf("nil log root")
	}
	version := binary.BigEndian.Uint16(logRootBytes)
	if version != uint16(LogRootFormat_LOG_ROOT_FORMAT_V1) {
		return fmt.Errorf("invalid LogRoot.Version: %v, want %v",
			version, LogRootFormat_LOG_ROOT_FORMAT_V1)
	}

	var logRoot LogRoot
	if _, err := tls.Unmarshal(logRootBytes, &logRoot); err != nil {
		return err
	}

	*l = *logRoot.V1
	return nil
}

// MarshalBinary returns a canonical TLS serialization of LogRoot.
func (l *LogRootV1) MarshalBinary() ([]byte, error) {
	return tls.Marshal(LogRoot{
		Version: tls.Enum(LogRootFormat_LOG_ROOT_FORMAT_V1),
		V1:      l,
	})
}

// SerializeKeyHint returns a byte slice with logID serialized as a big endian uint64.
func SerializeKeyHint(logID int64) []byte {
	hint := make([]byte, 8)
	binary.BigEndian.PutUint64(hint, uint64(logID))
	return hint
}

// ParseKeyHint converts a keyhint into a keyID.
func ParseKeyHint(hint []byte) (int64, error) {
	if len(hint) != 8 {
		return 0, fmt.Errorf("hint is %v bytes, want %v", len(hint), 8)
	}
	keyID := int64(binary.BigEndian.Uint64(hint))
	if keyID < 0 {
		return 0, fmt.Errorf("hint %x is negative", keyID)
	}
	return keyID, nil
}
