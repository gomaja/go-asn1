package per

import (
	"bytes"
	"fmt"
	"math"
)

// X.680 (02/2021) 22.7 lets encoding rules add or remove trailing 0 bits of
// a BIT STRING type with a NamedBitList; X.691 (02/2021) fixes them:
//
//   - 16.2: "Where there are no PER-visible constraints and Rec. ITU-T X.680
//     | ISO/IEC 8824-1, 22.7, applies the value shall be encoded with no
//     trailing 0 bits";
//   - 16.3: "Where there is a PER-visible constraint and ... 22.7, applies
//     ..., the value shall be encoded with trailing 0 bits added or removed
//     as necessary to ensure that the size of the transmitted value is the
//     smallest size capable of carrying this value and satisfies the
//     effective size constraint."
//
// A new value is encoded that way. A decoder accepts any length, and a
// decoded value records each such BIT STRING received with another length
// (KeptBitStrings), so that an unchanged received value re-encodes
// byte-exactly: the same exception to 16.2 and 16.3 as the replay of nonzero
// padding (go-asn1#90), of an extension bitmap width (go-asn1#96) and of an
// explicitly received DEFAULT (go-asn1#94). The received length is used only
// while the BIT STRING still holds exactly the received value; an edited one
// is encoded as a new value.

// namedBitLength returns the length 16.2 and 16.3 give a value of a BIT
// STRING type with a NamedBitList: its trailing 0 bits removed, then 0 bits
// added up to the lower bound of the size constraint.
//
// With an extensible constraint, SIZE (lb..ub, ...), a value whose 1 bits fit
// in ub bits is padded to lb and sent in the root; only a value whose 1 bits
// reach beyond ub takes the extension form with its own length (16.6). 16.3
// asks for "the smallest size capable of carrying this value and [that]
// satisfies the effective size constraint", and 10.3.10 defines the effective
// size constraint as the sizes "permitted if and only if there is some value
// of the constrained type that has that (permitted) size". Read with the
// extension, a length below lb in extension form could also qualify. It is
// not used: X.680 (02/2021) 22.7 makes the padded value the same abstract
// value, which the root therefore carries, and a root value in extension form
// is what X.691 (02/2021) 13.1, 16.6 and 17.3 reserve for values outside the
// root (go-asn1#105, go-asn1#101).
func namedBitLength(data []byte, bitLen int, lb, ub int64, constrained, extensible bool) (int, error) {
	if err := validateSizeBounds(lb, ub, constrained); err != nil {
		return 0, err
	}
	if bitLen < 0 || bitLen/8 > len(data) || bitLen%8 != 0 && bitLen/8 >= len(data) {
		return 0, fmt.Errorf("%w: BIT STRING length %d bits exceeds its %d octets", ErrInvalidValue, bitLen, len(data))
	}
	length := bitLen
	for length > 0 {
		last := length - 1
		if data[last/8]&(0x80>>(last%8)) != 0 {
			break
		}
		length = last
	}
	if !constrained {
		return length, nil
	}
	if int64(length) > ub {
		if extensible {
			return length, nil
		}
		return 0, fmt.Errorf("%w: BIT STRING value needs %d bits, above SIZE(%d..%d)", ErrConstraintViolation, length, lb, ub)
	}
	if int64(length) < lb {
		if lb > int64(math.MaxInt)-7 {
			return 0, fmt.Errorf("%w: BIT STRING lower bound %d exceeds host int", ErrInvalidValue, lb)
		}
		return int(lb), nil
	}
	return length, nil
}

// NamedBitStringMinimal reports whether a decoded value of a BIT STRING type
// with a NamedBitList has the length X.691 (02/2021) 16.2 and 16.3 give a new
// value. A decoder records a value that does not (KeepBitString), so that it
// re-encodes as received while unchanged.
func NamedBitStringMinimal(data []byte, bitLen int, lb, ub int64, constrained, extensible bool) bool {
	length, err := namedBitLength(data, bitLen, lb, ub, constrained, extensible)
	return err == nil && length == bitLen
}

// EncodeNamedBitString encodes a value of a BIT STRING type with a
// NamedBitList in UPER. A new value is encoded with the length X.691
// (02/2021) 16.2 and 16.3 require. keep is set when the decoded value
// recorded this BIT STRING as received with another length and it still
// holds the received value (KeptBits.Keeps); it is then encoded with its
// own length, as received.
func EncodeNamedBitString(bb *BitBuffer, data []byte, bitLen int, lb, ub int64, constrained, extensible, keep bool) error {
	return encodeNamedBitString(bb, data, bitLen, lb, ub, constrained, extensible, keep, false)
}

// EncodeNamedBitStringAligned is the APER form of EncodeNamedBitString.
func EncodeNamedBitStringAligned(bb *BitBuffer, data []byte, bitLen int, lb, ub int64, constrained, extensible, keep bool) error {
	return encodeNamedBitString(bb, data, bitLen, lb, ub, constrained, extensible, keep, true)
}

func encodeNamedBitString(bb *BitBuffer, data []byte, bitLen int, lb, ub int64, constrained, extensible, keep, aligned bool) error {
	encode := EncodeBitStringExt
	if aligned {
		encode = EncodeBitStringAlignedExt
	}
	if keep {
		return encode(bb, data, bitLen, lb, ub, constrained, extensible)
	}
	length, err := namedBitLength(data, bitLen, lb, ub, constrained, extensible)
	if err != nil {
		return err
	}
	if length > bitLen {
		// Only the 0 bits up to the lower bound are added; the bits of data
		// beyond bitLen are not part of the value.
		if bitLen < 0 || int64(length) > int64(math.MaxInt)-7 {
			return fmt.Errorf("%w: BIT STRING length %d exceeds host int", ErrInvalidValue, length)
		}
		padded := make([]byte, (length+7)/8)
		copy(padded, data[:(bitLen+7)/8])
		if bitLen%8 != 0 {
			padded[bitLen/8] &= 0xff << (8 - bitLen%8)
		}
		data = padded
	}
	return encode(bb, data, length, lb, ub, constrained, extensible)
}

// KeptBits records a BIT STRING with a NamedBitList that a decoded value
// received with a length other than the minimal one, or a list of them: a
// copy of the received value, or of the list's length and of the records of
// its elements. The zero value records nothing.
type KeptBits struct{ node *keptBits }

type keptBits struct {
	// value holds a copy of the received octets and bitLength their length;
	// list is false. A value of up to eight octets is copied into short, so
	// that recording it allocates once.
	value     []byte
	short     [8]byte
	bitLength int
	// list is set for a list of length elements; elements[i] is the record
	// of element i, which may be empty, and may be shorter than length.
	list     bool
	length   int
	elements []KeptBits
}

// KeepBitString records a BIT STRING received with bitLength bits, a length
// other than the minimal one. It copies the value, so that an edit of the
// decoded octets in place counts as a change.
func KeepBitString(data []byte, bitLength int) KeptBits {
	if bitLength < 0 || bitLength/8 > len(data) {
		return KeptBits{}
	}
	octets := bitLength / 8
	if bitLength%8 != 0 {
		if octets >= len(data) {
			return KeptBits{}
		}
		octets++
	}
	node := &keptBits{bitLength: bitLength}
	if octets <= len(node.short) {
		node.value = node.short[:octets]
		copy(node.value, data)
	} else {
		node.value = append([]byte(nil), data[:octets]...)
	}
	return KeptBits{node: node}
}

// KeptList records a list of length elements with the records of its
// elements, or nothing when no element has one.
func KeptList(length int, elements []KeptBits) KeptBits {
	if len(elements) == 0 || length < len(elements) {
		return KeptBits{}
	}
	return KeptBits{node: &keptBits{list: true, length: length, elements: elements}}
}

// KeepAt returns kept with record at index, growing it as needed. An empty
// record leaves kept unchanged, so a value received with minimal lengths
// allocates nothing.
func KeepAt(kept []KeptBits, index int, record KeptBits) []KeptBits {
	if record.node == nil || index < 0 || index >= math.MaxInt/2 {
		return kept
	}
	if index >= cap(kept) {
		grown := make([]KeptBits, index+1, max(index+1, 2*cap(kept)))
		copy(grown, kept)
		kept = grown
	} else if index >= len(kept) {
		kept = kept[:index+1]
	}
	kept[index] = record
	return kept
}

// Keeps reports whether k records exactly the BIT STRING data holds in its
// first bitLength bits: the received value, unchanged. Only then is it
// encoded with its received length.
func (k KeptBits) Keeps(data []byte, bitLength int) bool {
	if k.node == nil || k.node.list || bitLength != k.node.bitLength {
		return false
	}
	// The record holds exactly the octets of the received value (see
	// KeepBitString), so data must hold as many; both reads below stay
	// within that count.
	octets := len(k.node.value)
	if len(data) < octets {
		return false
	}
	whole := bitLength / 8
	if !bytes.Equal(data[:whole], k.node.value[:whole]) {
		return false
	}
	rest := bitLength % 8
	if rest == 0 {
		return true
	}
	mask := byte(0xff) << (8 - rest)
	return data[whole]&mask == k.node.value[whole]&mask
}

// List returns k when it records a list of length elements, and nothing
// otherwise: a list whose length changed keeps no received length.
func (k KeptBits) List(length int) KeptBits {
	if k.node == nil || !k.node.list || k.node.length != length {
		return KeptBits{}
	}
	return k
}

// ElementAt returns the record of element offset+index of the list k
// records, as a list encoder walks the elements of a fragment.
func (k KeptBits) ElementAt(offset int64, index int) KeptBits {
	if k.node == nil || !k.node.list || offset < 0 || index < 0 || offset >= int64(len(k.node.elements)) {
		return KeptBits{}
	}
	if int64(index) >= int64(len(k.node.elements))-offset {
		return KeptBits{}
	}
	return k.node.elements[offset+int64(index)]
}

// IsZero reports whether k records nothing.
func (k KeptBits) IsZero() bool { return k.node == nil }
