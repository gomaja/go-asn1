// Code generated from X2AP runtime source. DO NOT EDIT.

// Runtime source: runtime/oid.go; SHA-256 13d909ab487599aaa508510f08c8cb5f8560526d6d6e7f2c44ed5e6560743946.
package runtime

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"strconv"
	"strings"
)

// ErrInvalidOID marks an empty, non-minimal, or malformed identifier.
var ErrInvalidOID = errors.New("invalid object identifier")

// ErrTruncatedOID marks an unterminated base-128 subidentifier.
var ErrTruncatedOID = errors.New("truncated object identifier")

// Decimal conversion limits bound text parsing and formatting; they do not
// restrict encoded values or Bytes, Encoded, Arcs, and BigArcs. X.690 (02/2021)
// §§8.19–8.20 impose no arc-width limit. These are local resource limits.
const (
	MaxOIDTextLength = 65536
	MaxOIDArcDigits  = 1024
	MaxOIDArcs       = 4096
)

// MaxOIDJSONLength bounds JSON input before unescaping, allowing six bytes per
// text byte plus the two quotes. Leading/trailing JSON whitespace counts too.
const MaxOIDJSONLength = 6*MaxOIDTextLength + 2

// ErrOIDTextLimit marks a decimal conversion resource limit.
var ErrOIDTextLimit = errors.New("object identifier text resource limit")

// OIDTextLimitError identifies the resource whose maximum was exceeded.
type OIDTextLimitError struct {
	Resource string
	Limit    int
}

func (e *OIDTextLimitError) Error() string {
	return fmt.Sprintf("%s: %s exceeds %d", ErrOIDTextLimit, e.Resource, e.Limit)
}

func (e *OIDTextLimitError) Unwrap() error { return ErrOIDTextLimit }

func oidTextLimit(resource string, limit int) error {
	return &OIDTextLimitError{Resource: resource, Limit: limit}
}

// validateOIDContents checks X.690 (02/2021) §§8.19.2, 8.20.2 in one pass,
// independent of the numerical size of any arc. Neither clause limits arc width.
func validateOIDContents(s string) error {
	if len(s) == 0 {
		return fmt.Errorf("%w: empty contents", ErrInvalidOID)
	}
	start := true
	for i := range len(s) {
		if start && s[i] == 0x80 {
			// A lone continuation is truncated as well as non-minimal.
			if i == len(s)-1 {
				return ErrTruncatedOID
			}
			return fmt.Errorf("%w: non-minimal subidentifier at byte %d", ErrInvalidOID, i)
		}
		start = s[i]&0x80 == 0
	}
	if !start {
		return ErrTruncatedOID
	}
	return nil
}

// oidFromText accepts canonical unsigned dotted decimals. Leading zeros,
// signs, whitespace, and missing arcs are errors. This is the text API's
// syntax; X.690 §8.19 defines the wire representation.
func oidFromText(s string) (string, error) {
	if len(s) > MaxOIDTextLength {
		return "", oidTextLimit("text length", MaxOIDTextLength)
	}
	var out []byte
	var first uint64
	count := 0
	for part := range strings.SplitSeq(s, ".") {
		if count == MaxOIDArcs {
			return "", oidTextLimit("arc count", MaxOIDArcs)
		}
		if len(part) > MaxOIDArcDigits {
			return "", oidTextLimit("digits per arc", MaxOIDArcDigits)
		}
		if part == "" || (len(part) > 1 && part[0] == '0') {
			return "", fmt.Errorf("%w: empty arc or leading zero", ErrInvalidOID)
		}
		for i := range len(part) {
			if part[i] < '0' || part[i] > '9' {
				return "", fmt.Errorf("%w: non-decimal arc %d", ErrInvalidOID, count)
			}
		}
		if count == 0 {
			if len(part) != 1 || part[0] > '2' {
				return "", fmt.Errorf("%w: first arc exceeds 2", ErrInvalidOID)
			}
			first = uint64(part[0] - '0')
			count++
			continue
		}
		n, err := strconv.ParseUint(part, 10, 64)
		if count == 1 && first < 2 && (err != nil || n > 39) {
			return "", fmt.Errorf("%w: second arc exceeds 39", ErrInvalidOID)
		}
		if err == nil && (count != 1 || n <= math.MaxUint64-first*40) {
			if count == 1 {
				n += first * 40
			}
			out = appendOIDUint(out, n)
		} else {
			z, ok := new(big.Int).SetString(part, 10)
			if !ok {
				return "", ErrInvalidOID
			}
			if count == 1 {
				z.Add(z, new(big.Int).SetUint64(first*40))
			}
			out = appendOIDBig(out, z)
		}
		count++
	}
	if count < 2 {
		return "", fmt.Errorf("%w: need at least two arcs", ErrInvalidOID)
	}
	return string(out), nil
}

func oidFromArcs(arcs []uint64) (string, error) {
	if len(arcs) < 2 {
		return "", fmt.Errorf("%w: too few arcs", ErrInvalidOID)
	}
	var out []byte

	if arcs[0] > 2 || (arcs[0] < 2 && arcs[1] > 39) {
		return "", fmt.Errorf("%w: invalid root arcs", ErrInvalidOID)
	}
	if arcs[1] > math.MaxUint64-arcs[0]*40 {
		z := new(big.Int).SetUint64(arcs[1])
		z.Add(z, new(big.Int).SetUint64(arcs[0]*40))
		out = appendOIDBig(out, z)
	} else {
		out = appendOIDUint(out, arcs[0]*40+arcs[1])
	}

	for _, n := range arcs[2:] {
		out = appendOIDUint(out, n)
	}
	return string(out), nil
}

func appendOIDUint(out []byte, n uint64) []byte {
	var buf [10]byte
	i := len(buf) - 1
	buf[i] = byte(n & 127)
	for n >>= 7; n != 0; n >>= 7 {
		i--
		buf[i] = byte(n&127) | 128
	}
	return append(out, buf[i:]...)
}

// appendOIDBig packs the unsigned binary magnitude into seven-bit groups in
// linear time. Repeated shifts of a growing big.Int would be quadratic.
func appendOIDBig(out []byte, n *big.Int) []byte {
	if n.IsUint64() {
		return appendOIDUint(out, n.Uint64())
	}
	magnitude := n.Bytes()
	groups := (n.BitLen()-1)/7 + 1
	for g := groups - 1; g >= 0; g-- {
		var octet byte
		for bit := 0; bit < 7; bit++ {
			pos := g*7 + bit
			idx := len(magnitude) - 1 - pos/8
			if idx >= 0 {
				octet |= ((magnitude[idx] >> uint(pos%8)) & 1) << uint(bit)
			}
		}
		if g != 0 {
			octet |= 128
		}
		out = append(out, octet)
	}
	return out
}

func oidSubidentifierBig(s string) *big.Int {
	// Pack in one pass with at most fourteen pending bits. Splitting the
	// length quotient avoids multiplying an input length by seven.
	size := (len(s)/8)*7 + ((len(s)%8)*7+7)/8
	magnitude := make([]byte, 0, size)
	available := uint((8 - (len(s)%8)*7%8) % 8)
	var pending uint16
	for i := range len(s) {
		pending = (pending << 7) | uint16(s[i]&127)
		available += 7
		if available >= 8 {
			available -= 8
			magnitude = append(magnitude, byte(pending>>available))
			pending &= (1 << available) - 1
		}
	}
	return new(big.Int).SetBytes(magnitude)
}

func oidBigArcs(s string) []*big.Int {
	var out []*big.Int
	start := 0
	for i := range len(s) {
		if s[i]&128 != 0 {
			continue
		}
		n := oidSubidentifierBig(s[start : i+1])
		if start == 0 {
			root := int64(2)
			offset := int64(80)
			if n.Cmp(big.NewInt(40)) < 0 {
				root = 0
				offset = 0
			} else if n.Cmp(big.NewInt(80)) < 0 {
				root = 1
				offset = 40
			}
			out = append(out, big.NewInt(root))
			n.Sub(n, big.NewInt(offset))
		}
		out = append(out, n)
		start = i + 1
	}
	return out
}

// oidArcsInto uses caller storage for common short identifiers. The combined
// first subidentifier may be uint64+80 even when both root arcs fit uint64.
func oidArcsInto(out []uint64, s string) ([]uint64, bool) {
	if s == "" {
		return nil, false
	}
	start := 0
	var n uint64
	overflow := false
	for i := range len(s) {
		payload := uint64(s[i] & 127)
		if n > (math.MaxUint64-payload)/128 {
			overflow = true
		}
		// Retain the low word on overflow solely to split a 65-bit combined root.
		// All other overflows are rejected below, never returned as truncated arcs.
		n = n*128 + payload
		if s[i]&128 != 0 {
			continue
		}
		if overflow {
			if start != 0 || i != 9 || s[0]&127 != 2 || n >= 80 {
				return nil, false
			}
			// Here the full value is 2^64+n, with n<80: subtraction gives a
			// representable second arc by unsigned modular arithmetic.
			out = append(out, 2, n-80)
		} else if start == 0 {
			if n < 80 {
				out = append(out, n/40, n%40)
			} else {
				out = append(out, 2, n-80)
			}
		} else {
			out = append(out, n)
		}
		start = i + 1
		n = 0
		overflow = false
	}
	return out, true
}

func oidArcs(s string) ([]uint64, bool) {
	return oidArcsInto(nil, s)
}

// oidFormattingBounds rejects excessive arc counts and binary widths before
// allocating big.Ints. 3322/1000 is an upper bound for log2(10), so an arc with
// more than ceil(MaxOIDArcDigits*3322/7000) groups cannot fit the digit limit.
// Exact decimal digit and aggregate text lengths are checked during formatting.
func oidFormattingBounds(s string) error {
	const maxGroups = (MaxOIDArcDigits*3322 + 6999) / 7000
	count := 0
	if s != "" {
		count = 1
	}
	start := 0
	for i := range len(s) {
		if i-start >= maxGroups {
			return oidTextLimit("digits per arc", MaxOIDArcDigits)
		}
		if s[i]&128 == 0 {
			if count == MaxOIDArcs {
				return oidTextLimit("arc count", MaxOIDArcs)
			}
			count++
			start = i + 1
		}
	}
	return nil
}

func oidStringChecked(s string) (string, error) {
	if s == "" {
		return "", nil
	}
	if err := oidFormattingBounds(s); err != nil {
		return "", err
	}
	// Pre-check every arc before taking the uint64 formatting path. Common
	// identifiers use stack storage for both arcs and decimal digits.
	var arcStorage [32]uint64
	var textStorage [128]byte
	text := textStorage[:0]
	if arcs, ok := oidArcsInto(arcStorage[:0], s); ok {
		for i, n := range arcs {
			if i != 0 {
				text = append(text, '.')
			}
			text = strconv.AppendUint(text, n, 10)
			if len(text) > MaxOIDTextLength {
				return "", oidTextLimit("text length", MaxOIDTextLength)
			}
		}
	} else {
		for i, n := range oidBigArcs(s) {
			part := n.String()
			if len(part) > MaxOIDArcDigits {
				return "", oidTextLimit("digits per arc", MaxOIDArcDigits)
			}
			if i != 0 {
				if len(text) == MaxOIDTextLength {
					return "", oidTextLimit("text length", MaxOIDTextLength)
				}
				text = append(text, '.')
			}
			if len(part) > MaxOIDTextLength-len(text) {
				return "", oidTextLimit("text length", MaxOIDTextLength)
			}
			text = append(text, part...)
		}
	}
	return string(text), nil
}

func oidString(s string) string {
	text, err := oidStringChecked(s)
	if err != nil {
		panic(err)
	}
	return text
}

// ParseObjectIdentifier constructs an identifier from canonical dotted decimals.
// Decimal conversion is bounded by MaxOIDTextLength, MaxOIDArcDigits, and MaxOIDArcs.
func ParseObjectIdentifier(s string) (ObjectIdentifier, error) {
	enc, err := oidFromText(s)
	return ObjectIdentifier{enc: enc}, err
}

// ObjectIdentifierFromArcs constructs an identifier and copies the arcs into immutable contents.
func ObjectIdentifierFromArcs(arcs ...uint64) (ObjectIdentifier, error) {
	enc, err := oidFromArcs(arcs)
	return ObjectIdentifier{enc: enc}, err
}

// ObjectIdentifierFromEncoded validates canonical X.690 contents and retains the immutable string.
func ObjectIdentifierFromEncoded(s string) (ObjectIdentifier, error) {
	if err := validateOIDContents(s); err != nil {
		return ObjectIdentifier{}, err
	}
	return ObjectIdentifier{enc: s}, nil
}

// MustObjectIdentifier panics on invalid dotted text; intended for constant accessors.
func MustObjectIdentifier(s string) ObjectIdentifier {
	v, err := ParseObjectIdentifier(s)
	if err != nil {
		panic(err)
	}
	return v
}

// MustObjectIdentifierFromArcs panics if the arcs are invalid.
func MustObjectIdentifierFromArcs(arcs ...uint64) ObjectIdentifier {
	v, err := ObjectIdentifierFromArcs(arcs...)
	if err != nil {
		panic(err)
	}
	return v
}

// MustObjectIdentifierFromEncoded validates precomputed constant contents without allocation.
func MustObjectIdentifierFromEncoded(s string) ObjectIdentifier {
	v, err := ObjectIdentifierFromEncoded(s)
	if err != nil {
		panic(err)
	}
	return v
}

// IsZero reports the absent/invalid zero value.
func (v ObjectIdentifier) IsZero() bool { return v.enc == "" }

// Encoded returns immutable X.690 contents; the zero value returns an empty string.
func (v ObjectIdentifier) Encoded() string { return v.enc }

// Bytes returns an independent copy of the X.690 contents.
func (v ObjectIdentifier) Bytes() []byte { return []byte(v.enc) }

// Equal compares ASN.1 values, including two absent zero values. It is equivalent to ==.
func (v ObjectIdentifier) Equal(other ObjectIdentifier) bool { return v == other }

// Arcs returns a fresh slice, or nil,false if absent or any arc exceeds uint64.
func (v ObjectIdentifier) Arcs() ([]uint64, bool) { return oidArcs(v.enc) }

// BigArcs returns independently owned arbitrary-precision arcs (nil for the zero value).
func (v ObjectIdentifier) BigArcs() []*big.Int { return oidBigArcs(v.enc) }

// String returns canonical dotted decimals (empty for the zero value).
// It panics with *OIDTextLimitError when decimal conversion exceeds a limit.
// Use StringChecked, MarshalText, or MarshalJSON for an error return.
func (v ObjectIdentifier) String() string { return oidString(v.enc) }

// StringChecked formats canonical dotted decimals, returning *OIDTextLimitError
// when decimal conversion exceeds a limit. The zero value returns empty text.
func (v ObjectIdentifier) StringChecked() (string, error) { return oidStringChecked(v.enc) }

// MarshalText rejects the absent zero value.
func (v ObjectIdentifier) MarshalText() ([]byte, error) {
	if v.IsZero() {
		return nil, ErrInvalidOID
	}
	text, err := v.StringChecked()
	if err != nil {
		return nil, err
	}
	return []byte(text), nil
}

// UnmarshalText replaces the receiver only on success.
func (v *ObjectIdentifier) UnmarshalText(text []byte) error {
	if len(text) > MaxOIDTextLength {
		return oidTextLimit("text length", MaxOIDTextLength)
	}
	next, err := ParseObjectIdentifier(string(text))
	if err == nil {
		*v = next
	}
	return err
}

// MarshalJSON writes a dotted decimal JSON string.
func (v ObjectIdentifier) MarshalJSON() ([]byte, error) {
	if v.IsZero() {
		return nil, ErrInvalidOID
	}
	text, err := v.StringChecked()
	if err != nil {
		return nil, err
	}
	return json.Marshal(text)
}

// UnmarshalJSON accepts only dotted decimal JSON strings and is transactional.
func (v *ObjectIdentifier) UnmarshalJSON(data []byte) error {
	if len(data) > MaxOIDJSONLength {
		return oidTextLimit("JSON length", MaxOIDJSONLength)
	}
	data = bytes.TrimSpace(data)
	var text string
	if len(data) == 0 || data[0] != '"' {
		return ErrInvalidOID
	}
	if err := json.Unmarshal(data, &text); err != nil {
		return err
	}
	return v.UnmarshalText([]byte(text))
}
