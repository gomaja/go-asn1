package per

import (
	"fmt"

	"github.com/gomaja/go-asn1/runtime/ber"
)

// X.691 (02/2021) §23.1-23.4 encodes an OBJECT IDENTIFIER as an
// unconstrained-length octet string whose contents are exactly the contents
// octets X.690 §8.19 specifies for BER — the same bytes, without the BER tag
// and length. The value is therefore delegated to the BER OID codec rather
// than reimplemented, so the two encodings cannot drift apart on subidentifier
// packing or on the first-two-arcs rule (X.690 §8.19.4).
//
// Both variants below differ only in how the length determinant and the
// octets that follow it are aligned, which EncodeOctetString and
// EncodeOctetStringAligned already handle.

// EncodeObjectIdentifier writes an OBJECT IDENTIFIER in unaligned PER.
func EncodeObjectIdentifier(bb *BitBuffer, oid []uint64) error {
	contents, err := oidContents(oid)
	if err != nil {
		return err
	}
	return EncodeOctetString(bb, contents, 0, 0, false)
}

// DecodeObjectIdentifier reads an OBJECT IDENTIFIER in unaligned PER.
func DecodeObjectIdentifier(bb *BitBuffer) ([]uint64, error) {
	contents, err := DecodeOctetString(bb, 0, 0, false)
	if err != nil {
		return nil, fmt.Errorf("object identifier: %w", err)
	}
	return decodeOIDContents(contents)
}

// EncodeObjectIdentifierAligned writes an OBJECT IDENTIFIER in aligned PER.
func EncodeObjectIdentifierAligned(bb *BitBuffer, oid []uint64) error {
	contents, err := oidContents(oid)
	if err != nil {
		return err
	}
	return EncodeOctetStringAligned(bb, contents, 0, 0, false)
}

// DecodeObjectIdentifierAligned reads an OBJECT IDENTIFIER in aligned PER.
func DecodeObjectIdentifierAligned(bb *BitBuffer) ([]uint64, error) {
	contents, err := DecodeOctetStringAligned(bb, 0, 0, false)
	if err != nil {
		return nil, fmt.Errorf("object identifier: %w", err)
	}
	return decodeOIDContents(contents)
}

// oidContents produces the X.690 §8.19 contents octets for oid.
//
// ber.EncodeOIDValue returns those contents directly (no tag, no length),
// which is exactly what PER wraps. An OID needs at least two arcs, since the
// first two are combined into a single subidentifier; rejecting a shorter one
// here keeps a malformed value from being encoded as something a decoder
// would silently read back as a different OID.
func oidContents(oid []uint64) ([]byte, error) {
	if len(oid) < 2 {
		return nil, fmt.Errorf("object identifier needs at least 2 arcs, got %d", len(oid))
	}
	return ber.EncodeOIDValue(oid), nil
}

func decodeOIDContents(contents []byte) ([]uint64, error) {
	oid, err := ber.DecodeOIDValue(contents)
	if err != nil {
		return nil, fmt.Errorf("object identifier: %w", err)
	}
	return oid, nil
}
