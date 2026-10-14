package per

import (
	"fmt"

	"github.com/gomaja/go-asn1/runtime"
	"github.com/gomaja/go-asn1/runtime/ber"
)

// X.691 (02/2021) §24 encodes an OBJECT IDENTIFIER from the contents octets
// specified by X.690 (02/2021) §8.19, preceded by a length determinant for a
// semi-constrained whole number octet count (§11.9). The contents exclude the
// BER tag and length. The BER OID codec supplies the same subidentifier packing
// and first-two-arcs rule (X.690 §8.19.4).
//
// Both variants below differ only in how the length determinant and the
// octets that follow it are aligned, which EncodeOctetString and
// EncodeOctetStringAligned already handle.

// EncodeObjectIdentifier writes an OBJECT IDENTIFIER in unaligned PER.
func EncodeObjectIdentifier(bb *BitBuffer, oid runtime.ObjectIdentifier) error {
	contents, err := oidContents(oid)
	if err != nil {
		return err
	}
	return EncodeOctetString(bb, contents, 0, 0, false)
}

// DecodeObjectIdentifier reads an OBJECT IDENTIFIER in unaligned PER.
func DecodeObjectIdentifier(bb *BitBuffer) (runtime.ObjectIdentifier, error) {
	contents, err := DecodeOctetString(bb, 0, 0, false)
	if err != nil {
		return runtime.ObjectIdentifier{}, fmt.Errorf("object identifier: %w", err)
	}
	return decodeOIDContents(contents)
}

// EncodeObjectIdentifierAligned writes an OBJECT IDENTIFIER in aligned PER.
func EncodeObjectIdentifierAligned(bb *BitBuffer, oid runtime.ObjectIdentifier) error {
	contents, err := oidContents(oid)
	if err != nil {
		return err
	}
	return EncodeOctetStringAligned(bb, contents, 0, 0, false)
}

// DecodeObjectIdentifierAligned reads an OBJECT IDENTIFIER in aligned PER.
func DecodeObjectIdentifierAligned(bb *BitBuffer) (runtime.ObjectIdentifier, error) {
	contents, err := DecodeOctetStringAligned(bb, 0, 0, false)
	if err != nil {
		return runtime.ObjectIdentifier{}, fmt.Errorf("object identifier: %w", err)
	}
	return decodeOIDContents(contents)
}

// EncodeRelativeObjectIdentifier writes a RELATIVE-OID in unaligned PER.
// X.691 (02/2021) §25 wraps X.690 (02/2021) §8.20 contents octets with the
// semi-constrained whole number octet count determinant of X.691 §11.9.
func EncodeRelativeObjectIdentifier(bb *BitBuffer, oid runtime.RelativeObjectIdentifier) error {
	contents, err := ber.EncodeRelativeOIDValueChecked(oid)
	if err != nil {
		return fmt.Errorf("relative object identifier: %w", err)
	}
	return EncodeOctetString(bb, contents, 0, 0, false)
}

// DecodeRelativeObjectIdentifier reads a RELATIVE-OID in unaligned PER.
func DecodeRelativeObjectIdentifier(bb *BitBuffer) (runtime.RelativeObjectIdentifier, error) {
	contents, err := DecodeOctetString(bb, 0, 0, false)
	if err != nil {
		return runtime.RelativeObjectIdentifier{}, fmt.Errorf("relative object identifier: %w", err)
	}
	oid, err := ber.DecodeRelativeOIDValue(contents)
	if err != nil {
		return runtime.RelativeObjectIdentifier{}, fmt.Errorf("relative object identifier: %w", err)
	}
	return oid, nil
}

// EncodeRelativeObjectIdentifierAligned writes a RELATIVE-OID in aligned PER.
func EncodeRelativeObjectIdentifierAligned(bb *BitBuffer, oid runtime.RelativeObjectIdentifier) error {
	contents, err := ber.EncodeRelativeOIDValueChecked(oid)
	if err != nil {
		return fmt.Errorf("relative object identifier: %w", err)
	}
	return EncodeOctetStringAligned(bb, contents, 0, 0, false)
}

// DecodeRelativeObjectIdentifierAligned reads a RELATIVE-OID in aligned PER.
func DecodeRelativeObjectIdentifierAligned(bb *BitBuffer) (runtime.RelativeObjectIdentifier, error) {
	contents, err := DecodeOctetStringAligned(bb, 0, 0, false)
	if err != nil {
		return runtime.RelativeObjectIdentifier{}, fmt.Errorf("relative object identifier: %w", err)
	}
	oid, err := ber.DecodeRelativeOIDValue(contents)
	if err != nil {
		return runtime.RelativeObjectIdentifier{}, fmt.Errorf("relative object identifier: %w", err)
	}
	return oid, nil
}

// oidContents produces the X.690 §8.19 contents octets for oid.
//
// ber.EncodeOIDValueChecked returns those contents directly (no tag, no length),
// which is exactly what PER wraps. An OID needs at least two arcs, since the
// first two are combined into a single subidentifier; rejecting a shorter one
// here keeps a malformed value from being encoded as something a decoder
// would silently read back as a different OID.
func oidContents(oid runtime.ObjectIdentifier) ([]byte, error) {
	contents, err := ber.EncodeOIDValueChecked(oid)
	if err != nil {
		return nil, fmt.Errorf("object identifier: %w", err)
	}
	return contents, nil
}

func decodeOIDContents(contents []byte) (runtime.ObjectIdentifier, error) {
	oid, err := ber.DecodeOIDValue(contents)
	if err != nil {
		return runtime.ObjectIdentifier{}, fmt.Errorf("object identifier: %w", err)
	}
	return oid, nil
}
