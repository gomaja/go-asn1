// Code generated from LTE RRC runtime source. DO NOT EDIT.

// Runtime source: runtime/uper/bitbuffer.go; SHA-256 b5afb1ac966e5b6f7509d90901d138c804a3e46f1084f329e3eb309da3f9c3d3.
package uper

import (
	"fmt"
	"math"
)

// BitBuffer provides bit-level read/write operations for PER encoding.
type BitBuffer struct {
	data          []byte
	bitPos        int  // current read position (read) or total bits written (write)
	bitLen        int  // total bits available (read mode only)
	invalidLength bool // input octets cannot be represented as an int bit length
	contained     ContainedDecoding
	// outermost is set on the buffer of a top-level decode under
	// TruncatedExtensionTolerance: only the end of its input can cut an
	// extension addition short. A nested buffer, bounded by an open type or
	// contained string that arrived in full, never has it.
	outermost bool
	// zeroWidthLimit is DecodeOptions.MaxZeroWidthCharacters; zero selects
	// DefaultMaxZeroWidthCharacters.
	zeroWidthLimit uint32
	budget         *DecodeBudget // shared by every buffer in this decode
	trace          *decodeTrace  // non-nil only for a decode with tolerance or deferral
}

// DecodeOptions configures receiver behaviour for PER decoding: tolerance for
// non-conformant senders and the treatment of contained values. The zero
// value decodes strictly and eagerly.
type DecodeOptions struct {
	// Limits are operational ceilings for a complete decode. Zero fields use
	// DefaultDecodeLimits, matching BER's decode option semantics.
	Limits DecodeLimits
	// Usage, when non-nil, receives live per-decode resource metrics. It must
	// not be shared between concurrent decodes.
	Usage *DecodeUsage
	// TrailingBitsTolerance, when non-nil, accepts the bit runs of
	// ToleratedTrailingBits and ToleratedContainedBits and records each one
	// in the log, with its field path, offset and bits. X.691 (02/2021)
	// 11.1.3.1 and 11.1.3.2 forbid them. RRC receivers must accept them:
	// TS 25.331 V19.0.1 12.1.3 any bit string after a PDU's basic production,
	// TS 36.331 V19.4.0 8.1 any extraneous bits after a PDU or a value in a
	// BIT STRING or OCTET STRING (CONTAINING ...). 3GPP-conformant RRC
	// decoding therefore requires this option; the default is strict X.691.
	// Decoded values keep the accepted bits, so they re-encode to the
	// original octets. Generated APER decoders reject it.
	TrailingBitsTolerance *ToleranceLog
	// TruncatedExtensionTolerance, when non-nil, accepts an extension
	// addition or extension addition group of a SEQUENCE or SET whose open
	// type, length determinant or contents, the end of the input cuts short
	// after the extension bitmap was read in full, and records it in the log
	// as ToleratedTruncatedExtension (go-asn1#114). X.691 (02/2021) 19.9 and
	// 11.2.1 make it an error, and the default stays strict; the option is
	// for receivers of PDUs cut in transmission, such as trace analysers.
	//
	// The root and every addition decoded before the cut are kept. The cut
	// addition and every later one are absent: no value is built from
	// missing bits. Only the end of the input given to the decode counts. A
	// cut in the root or in the extension bitmap, in an open type or
	// contained value that arrived with its full length, or in a CHOICE
	// extension alternative, which cannot be absent, is still an error. The
	// contents of a deferred OCTET STRING are decoded later as an input of
	// their own; they arrived with their full length, so leave the option
	// off for them.
	//
	// A decoded value that is re-encoded unchanged reproduces the received,
	// cut octets. An edited value is encoded as a new one: the cut additions
	// are omitted and their bitmap bits cleared, and the extension bit is
	// cleared too when no addition remains, so the result is a conformant
	// encoding (X.691 (02/2021) 19.1, 19.7 and 19.8).
	TruncatedExtensionTolerance *ToleranceLog
	// ExtensionRecoveryTolerance accepts only nested truncation of a known
	// SEQUENCE or SET addition whose bounded open type arrived in full.
	// X.691 (02/2021) 11.2.1–11.2.2 and 19.9 require a complete value; the
	// default rejects this error. A recovered addition commits no typed
	// fields; later additions still decode. Records are published only on
	// overall success, as ToleratedIncompleteExtension. Unchanged values
	// replay exactly; edits omit failed additions and encode typed fields.
	// This is independent of TruncatedExtensionTolerance (go-asn1#114).
	// Re-reads after a rolled-back candidate and provenance scans are limited
	// to four times this decode's input bit length. First-pass reads are free
	// against that extra-work ceiling. Limits.MaxWork counts all examined bits.
	// Exhaustion fails with ErrResourceLimit and publishes no records. This
	// is an operational limit, independent of the X.691 wire rules.
	ExtensionRecoveryTolerance *ToleranceLog
	// ContainedDecoding selects how values carried in a BIT STRING or OCTET
	// STRING (CONTAINING ...) are decoded. The zero value, Eager, decodes
	// them with the enclosing value. DeferOnError and DeferAll keep some or
	// all of them as raw encodings (see ContainedDecoding), as TS 36.331
	// V19.4.0 8.1 and TS 38.331 V19.4.0 8.1 recommend for RRC receivers.
	ContainedDecoding ContainedDecoding
	// Deferrals receives a record of each contained value that a successful
	// decode kept raw. DeferOnError and DeferAll require it: a decode that
	// sets either without a log fails, so no deferral goes unreported.
	Deferrals *DeferralLog
	// MaxZeroWidthCharacters bounds the characters decoded through a length
	// determinant for a permitted alphabet of one character, whose UNALIGNED
	// characters take no bits (X.691 (02/2021) 30.5.2), so each length
	// octet can stand for up to 64K characters. Zero selects
	// DefaultMaxZeroWidthCharacters. This is an operational limit, not an
	// X.691 rule; fixed and constrained lengths below 64K never reach it.
	MaxZeroWidthCharacters uint32
}

// DefaultMaxZeroWidthCharacters is the default MaxZeroWidthCharacters.
const DefaultMaxZeroWidthCharacters = 1 << 20

// SetDecodeOptions starts a top-level decode with validated options. bb reads
// the outermost input, whose end alone can cut an extension addition short
// under TruncatedExtensionTolerance.
func (bb *BitBuffer) SetDecodeOptions(options DecodeOptions) error {
	limits, err := effectiveDecodeLimits(options.Limits)
	if err != nil {
		*bb.decodeBudget() = DecodeBudget{limits: DefaultDecodeLimits(), err: err}
		return err
	}
	*bb.decodeBudget() = DecodeBudget{limits: limits, report: options.Usage}
	bb.budget.publish()
	bb.contained, bb.trace = options.ContainedDecoding, nil
	bb.zeroWidthLimit, bb.outermost = options.MaxZeroWidthCharacters, options.TruncatedExtensionTolerance != nil
	if options.TrailingBitsTolerance != nil || options.ContainedDecoding != Eager || options.TruncatedExtensionTolerance != nil || options.ExtensionRecoveryTolerance != nil {
		bb.trace = &decodeTrace{trailing: options.TrailingBitsTolerance, deferrals: options.Deferrals, truncated: options.TruncatedExtensionTolerance, recovery: options.ExtensionRecoveryTolerance}
		if options.ExtensionRecoveryTolerance != nil && !bb.invalidLength && bb.bitLen >= 0 {
			limit := uint64(bb.bitLen)
			if limit > math.MaxUint64/recoveryWorkInputMultiple {
				limit = math.MaxUint64
			} else {
				limit *= recoveryWorkInputMultiple
			}
			bb.trace.work = &recoveryWork{limit: limit}
		}
	}
	return nil
}

// SetDecodeOptionsAligned starts a top-level APER decode with options.
// Generated APER decoders decode contained values eagerly and accept only the
// final padding of X.691 (02/2021) 11.1.3.1, so TrailingBitsTolerance and a
// ContainedDecoding other than Eager are rejected rather than ignored.

// InheritDecodeOptions starts a contained decode with the parent's receiver
// options, shared resource budget, field path and pending records. For an
// open type, use InheritOpenTypeDecodeOptions.
func (bb *BitBuffer) InheritDecodeOptions(parent *BitBuffer) {
	bb.contained, bb.trace = parent.contained, parent.trace
	bb.zeroWidthLimit, bb.outermost = parent.zeroWidthLimit, false
	bb.budget = parent.decodeBudget()
}

// NewBitBuffer creates a write-mode buffer.
func NewBitBuffer() *BitBuffer {
	return &BitBuffer{}
}

// NewBitBufferFromBytes creates a read-mode buffer from encoded bytes.
func NewBitBufferFromBytes(data []byte) *BitBuffer {
	return NewDecodeBuffer(data, nil)
}

// NewDecodeBuffer creates a read buffer with caller-owned budget storage.
// Generated entry points keep this storage on the stack; nested buffers share
// it. A nil budget is allocated lazily on the first read.
func NewDecodeBuffer(data []byte, budget *DecodeBudget) *BitBuffer {
	if budget != nil {
		*budget = DecodeBudget{limits: DefaultDecodeLimits()}
	}
	if len(data) > math.MaxInt/8 {
		return &BitBuffer{data: data, invalidLength: true, budget: budget}
	}
	return &BitBuffer{
		data:   data,
		bitLen: len(data) * 8,
		budget: budget,
	}
}

// NewBitBufferFromBits bounds a nested PER encoding carried in a BIT STRING
// to its declared bit length. X.691 (02/2021) 11.1.1(b) permits a complete
// unaligned encoding in a BIT STRING without octet padding.
func NewBitBufferFromBits(data []byte, bitLen int) (*BitBuffer, error) {
	bb := NewBitBufferFromBytes(data)
	if err := bb.SetReadBitLength(bitLen); err != nil {
		return nil, err
	}
	return bb, nil
}

// SetReadBitLength bounds a new read buffer to a BIT STRING's declared length,
// including checking its unused bits (X.691 (02/2021) §11.1.1(b)).
func (bb *BitBuffer) SetReadBitLength(bitLen int) error {
	if bitLen < 0 {
		return fmt.Errorf("%w: negative bit-string length %d", ErrInvalidValue, bitLen)
	}
	required, err := octetsForBitLength(bitLen)
	if err != nil {
		return fmt.Errorf("bit-string length: %w", err)
	}
	if len(bb.data) != required {
		return fmt.Errorf("%w: bit-string length %d bits requires %d octets, source has %d octets", ErrInvalidValue, bitLen, required, len(bb.data))
	}
	if bitLen%8 != 0 && bb.data[len(bb.data)-1]&byte((1<<uint(8-bitLen%8))-1) != 0 {
		return fmt.Errorf("%w: nonzero unused BIT STRING bits", ErrInvalidValue)
	}
	bb.bitLen, bb.invalidLength = bitLen, false
	return nil
}

// NewNestedDecodeBuffer inherits the shared budget and receiver options while
// constructing a child. Initializing the pointer in the literal lets both the
// buffer and the budget stay on the stack in generated decoders.
func NewNestedDecodeBuffer(data []byte, parent *BitBuffer) *BitBuffer {
	invalid := len(data) > math.MaxInt/8
	length := 0
	if !invalid {
		length = len(data) * 8
	}
	return &BitBuffer{data: data, bitLen: length, invalidLength: invalid,
		contained: parent.contained, zeroWidthLimit: parent.zeroWidthLimit,
		trace: parent.trace, budget: parent.decodeBudget()}
}

// WriteBit writes a single bit (0 or 1).
func (bb *BitBuffer) WriteBit(bit uint8) error {
	if bb.bitPos < 0 {
		return fmt.Errorf("%w: negative PER bit position %d", ErrInvalidValue, bb.bitPos)
	}
	if bb.bitPos == math.MaxInt {
		return fmt.Errorf("%w: PER bit position exceeds int", ErrInvalidValue)
	}
	byteIdx := bb.bitPos / 8
	bitIdx := uint(7 - bb.bitPos%8)
	if bitIdx > 7 {
		return fmt.Errorf("%w: invalid PER bit index %d", ErrInvalidValue, bitIdx)
	}

	// Grow buffer if needed.
	for byteIdx >= len(bb.data) {
		bb.data = append(bb.data, 0)
	}

	if bit != 0 {
		bb.data[byteIdx] |= 1 << bitIdx
	}
	bb.bitPos++
	return nil
}

// WriteBits writes the lowest n bits from val (MSB first). n can be 0..64.
func (bb *BitBuffer) WriteBits(val uint64, n int) error {
	if n < 0 || n > 64 {
		return fmt.Errorf("%w: WriteBits n=%d is outside [0..64]", ErrInvalidValue, n)
	}
	for i := n; i > 0; {
		i--
		bit := uint8((val >> uint(i)) & 1)
		if err := bb.WriteBit(bit); err != nil {
			return err
		}
	}
	return nil
}

// ReadBit reads a single bit.
func (bb *BitBuffer) ReadBit() (uint8, error) {
	if err := bb.checkRecoveryBits(0); err != nil {
		return 0, err
	}
	if bb.invalidLength {
		return 0, fmt.Errorf("%w: PER input bit length exceeds int", ErrInvalidValue)
	}
	if bb.bitPos < 0 {
		return 0, fmt.Errorf("%w: negative PER bit position %d", ErrInvalidValue, bb.bitPos)
	}
	if bb.bitPos >= bb.bitLen {
		return 0, ErrTruncated
	}
	if err := bb.examineRecoveryBits(1); err != nil {
		return 0, err
	}
	byteIdx := bb.bitPos / 8
	bitIdx := uint(7 - bb.bitPos%8)
	if bitIdx > 7 {
		return 0, fmt.Errorf("%w: invalid PER bit index %d", ErrInvalidValue, bitIdx)
	}
	bit := (bb.data[byteIdx] >> bitIdx) & 1
	bb.bitPos++
	return bit, nil
}

// ReadBits reads n bits and returns them right-aligned in a uint64.
func (bb *BitBuffer) ReadBits(n int) (uint64, error) {
	if err := bb.checkRecoveryBits(0); err != nil {
		return 0, err
	}
	if bb.invalidLength {
		return 0, fmt.Errorf("%w: PER input bit length exceeds int", ErrInvalidValue)
	}
	if n < 0 || n > 64 {
		return 0, fmt.Errorf("%w: ReadBits n=%d is outside [0..64]", ErrInvalidValue, n)
	}
	if n == 0 {
		return 0, nil
	}
	if bb.bitPos < 0 {
		return 0, fmt.Errorf("%w: negative PER bit position %d", ErrInvalidValue, bb.bitPos)
	}
	// Charge a whole read once. A truncated read examines only the available
	// prefix, preserving the bit position of the single-bit reader.
	available := min(n, max(0, bb.BitsRemaining()))
	if err := bb.examineRecoveryBits(uint64(available)); err != nil {
		return 0, err
	}
	var val uint64
	for left := available; left > 0; {
		shift := uint(bb.bitPos % 8)
		width := min(left, 8-int(shift))
		part := bb.data[bb.bitPos/8] >> uint(8-int(shift)-width)
		val = val<<uint(width) | uint64(part&byte((1<<uint(width))-1))
		bb.bitPos += width
		left -= width
	}
	if available != n {
		return 0, ErrTruncated
	}
	return val, nil
}

// WriteBytes writes raw bytes (8*len bits).
func (bb *BitBuffer) WriteBytes(data []byte) error {
	for _, b := range data {
		if err := bb.WriteBits(uint64(b), 8); err != nil {
			return err
		}
	}
	return nil
}

// ReadBytes reads n bytes (8*n bits).
func (bb *BitBuffer) ReadBytes(n int) ([]byte, error) {
	if err := bb.checkRecoveryBits(0); err != nil {
		return nil, err
	}
	if bb.invalidLength {
		return nil, fmt.Errorf("%w: PER input bit length exceeds int", ErrInvalidValue)
	}
	if n < 0 {
		return nil, fmt.Errorf("%w: ReadBytes called with negative n=%d", ErrInvalidValue, n)
	}
	if bb.bitPos < 0 {
		return nil, fmt.Errorf("%w: negative PER bit position %d", ErrInvalidValue, bb.bitPos)
	}
	if n > bb.BitsRemaining()/8 {
		return nil, fmt.Errorf("%w: requested %d bytes with %d bits remaining", ErrTruncated, n, bb.BitsRemaining())
	}
	if err := bb.examineRecoveryBits(uint64(n) * 8); err != nil {
		return nil, err
	}
	result := make([]byte, n)
	if n == 0 {
		return result, nil
	}
	start, shift := bb.bitPos/8, uint(bb.bitPos%8)
	if shift == 0 {
		copy(result, bb.data[start:start+n])
	} else {
		for i := range result {
			result[i] = bb.data[start+i]<<shift | bb.data[start+i+1]>>(8-shift)
		}
	}
	bb.bitPos += n * 8
	return result, nil
}

// Bytes returns the underlying byte slice, with the last byte zero-padded.
func (bb *BitBuffer) Bytes() []byte {
	return bb.data
}

// CompleteBytes returns a complete PER encoding. X.691 (02/2021), clauses
// 11.1.3.1 and 11.1.4 require a zero-bit outermost encoding to be represented
// by one zero octet.
func (bb *BitBuffer) CompleteBytes() []byte {
	if bb.bitPos == 0 && len(bb.data) == 0 {
		return []byte{0}
	}
	return bb.data
}

// CompletePadding retains terminal bits observed when decoding a complete PER
// encoding. X.691 (02/2021) 11.1.3.1 and 11.1.4 require encoders to emit zero
// bits here; decoded input may carry other values that a lossless re-encode
// must retain. All-zero padding is what an encoder emits anyway, so it is not
// retained: the zero value stands for it.
type CompletePadding struct {
	bits  uint8
	count uint8
}

// TrailingBits retains non-conformant bits after a complete PER value.
// Bytes are MSB-first, with unused low bits zero.
type TrailingBits struct {
	Bytes     []byte
	BitLength int
}

// completeBytesWithTrailing reproduces a tolerated top-level suffix. The
// suffix belongs to the received encoding: unless bb holds the value encoding
// it followed, bit for bit, the value is completed as a new one, with the
// zero padding of X.691 (02/2021) 11.1.3.1 and 11.1.4.
func (bb *BitBuffer) completeBytesWithTrailing(kept *finalBits) ([]byte, error) {
	trailing := kept.trailing
	if trailing.BitLength <= 0 {
		return nil, fmt.Errorf("%w: invalid trailing bits", ErrInvalidValue)
	}
	if !kept.follows(bb) {
		return bb.CompleteBytes(), nil
	}
	// A zero-bit value keeps its mandated zero octet before the suffix
	// (X.691 (02/2021) 11.1.3.1 and 11.1.4), as CaptureFinalBits read it.
	if bb.bitPos == 0 {
		if err := bb.WriteBits(0, 8); err != nil {
			return nil, err
		}
	}
	if err := bb.WriteBitsFromBytes(trailing.Bytes, trailing.BitLength); err != nil {
		return nil, err
	}
	if bb.bitPos%8 != 0 {
		return nil, fmt.Errorf("%w: invalid trailing bits", ErrInvalidValue)
	}
	return bb.CompleteBytes(), nil
}

// CompleteValue carries a primitive open-type value and its observed padding.
// ITU-T X.691 (02/2021) 11.2.1 makes open-type contents a complete encoding.
type CompleteValue[T any] struct {
	Value       T
	PERPadding_ CompletePadding `json:"-"`
}

// Bits returns the observed terminal bits right-aligned and their width.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require zero padding on encode.
// Observed all-zero padding is not retained, so its width is reported as 0.
func (p CompletePadding) Bits() (value, count uint8) {
	return p.bits, p.count
}

// IsZero reports whether every observed terminal bit is zero.
func (p CompletePadding) IsZero() bool {
	return p.bits == 0
}

// CompleteBytesWithPadding returns a complete encoding with observed terminal
// bits. A newly constructed value has zero padding (X.691 (02/2021) 11.1.3.1
// and 11.1.4). Observed padding is kept while it still fills the final octet
// exactly, so an unchanged decoded value re-encodes byte-exactly. Once an edit
// changes the number of padding bits the encoding needs, the observed bits no
// longer belong to it, and the value is padded with zero bits as a new one.
//
// Nonzero padding comes only from a non-conformant sender. Only its width is
// kept, so an edit that keeps the bit length modulo eight keeps those bits;
// padding carries no value (11.1.3.1, 11.1.4), so the result still decodes.
//
// Only applying retained nonzero padding copies the encoding, one allocation;
// otherwise the result is bb's storage, as from CompleteBytes, with none.
func (bb *BitBuffer) CompleteBytesWithPadding(padding CompletePadding) ([]byte, error) {
	if padding.bits == 0 {
		return bb.CompleteBytes(), nil
	}
	if bb.bitPos < 0 || padding.count > 7 {
		return nil, fmt.Errorf("%w: invalid complete-encoding padding", ErrInvalidValue)
	}
	if padding.bits >= 1<<padding.count {
		return nil, fmt.Errorf("%w: invalid complete-encoding padding", ErrInvalidValue)
	}
	if bb.bitPos == 0 || int(padding.count) != (8-bb.bitPos%8)%8 {
		return bb.CompleteBytes(), nil
	}
	out := append([]byte(nil), bb.CompleteBytes()...)
	out[len(out)-1] |= padding.bits
	return out, nil
}

// BitsWritten returns the total number of bits written.
func (bb *BitBuffer) BitsWritten() int {
	return bb.bitPos
}

// BitsRemaining returns bits left to read.
func (bb *BitBuffer) BitsRemaining() int {
	return bb.bitLen - bb.bitPos
}

// BitPos returns the current bit position.
func (bb *BitBuffer) BitPos() int {
	return bb.bitPos
}

// CaptureOpenTypePadding consumes terminal bits of a complete PER encoding in
// an open type. X.691 (02/2021) 11.2.1 requires an octet-aligned encoding.
func CaptureOpenTypePadding(bb *BitBuffer) (CompletePadding, error) {
	return captureTrailingPadding(bb, "open type")
}

// CaptureFinalPadding consumes terminal bits after a complete top-level value.
func CaptureFinalPadding(bb *BitBuffer) (CompletePadding, error) {
	return captureTrailingPadding(bb, "top-level value")
}

// ValidateOpenTypePadding consumes terminal bits of a complete open type.
func ValidateOpenTypePadding(bb *BitBuffer) error {
	_, err := CaptureOpenTypePadding(bb)
	return err
}

// ValidateFinalPadding consumes terminal bits and rejects appended data.
func ValidateFinalPadding(bb *BitBuffer) error {
	_, err := CaptureFinalPadding(bb)
	return err
}

func captureTrailingPadding(bb *BitBuffer, context string) (CompletePadding, error) {
	if bb.invalidLength {
		return CompletePadding{}, fmt.Errorf("%w: PER input bit length exceeds int", ErrInvalidValue)
	}
	remaining := bb.BitsRemaining()
	if remaining < 0 || remaining > 8 {
		return CompletePadding{}, fmt.Errorf("%w: %s has %d unconsumed bits", ErrExtraData, context, remaining)
	}
	if bb.BitPos() == 0 {
		switch {
		case remaining == 0:
			return CompletePadding{}, fmt.Errorf("%w: %s complete encoding is empty", ErrTruncated, context)
		case remaining < 8:
			return CompletePadding{}, fmt.Errorf("%w: %s zero-bit complete encoding has %d bits", ErrTruncated, context, remaining)
		case remaining > 8:
			return CompletePadding{}, fmt.Errorf("%w: %s has %d unconsumed bits", ErrExtraData, context, remaining)
		}
	}
	if remaining > 7 {
		if bb.BitPos() != 0 {
			return CompletePadding{}, fmt.Errorf("%w: %s has %d unconsumed bits", ErrExtraData, context, remaining)
		}
	}
	padding, err := bb.ReadBits(remaining)
	if err != nil {
		return CompletePadding{}, err
	}
	if bb.BitPos() == 8 && remaining == 8 && padding != 0 {
		return CompletePadding{}, fmt.Errorf("%w: %s zero-bit complete encoding is nonzero", ErrInvalidValue, context)
	}
	// Zero padding, and the zero octet of an empty value, are what a new
	// encoding has, so nothing is retained.
	if remaining == 8 || padding == 0 {
		return CompletePadding{}, nil
	}
	if padding > math.MaxUint8 {
		return CompletePadding{}, fmt.Errorf("%w: padding value exceeds byte", ErrInvalidValue)
	}
	return CompletePadding{bits: uint8(padding), count: uint8(remaining)}, nil
}

// WriteBitsFromBytes writes exactly bitLen bits from the given byte slice (MSB first).
func (bb *BitBuffer) WriteBitsFromBytes(data []byte, bitLen int) error {
	required, err := octetsForBitLength(bitLen)
	if err != nil {
		return fmt.Errorf("WriteBitsFromBytes: %w", err)
	}
	if required > len(data) {
		return fmt.Errorf("%w: WriteBitsFromBytes %d bits requires %d octets, source has %d octets", ErrInvalidValue, bitLen, required, len(data))
	}
	for i := 0; i < bitLen; {
		byteIdx := i / 8
		bitIdx := uint(7 - i%8)
		bit := (data[byteIdx] >> bitIdx) & 1
		if err := bb.WriteBit(bit); err != nil {
			return err
		}
		i++
	}
	return nil
}

// AlignToOctetWrite pads the write position to the next octet boundary (APER).
func (bb *BitBuffer) AlignToOctetWrite() error {
	rem := bb.bitPos % 8
	if rem != 0 {
		for i := 0; i < 8-rem; i++ {
			if err := bb.WriteBit(0); err != nil {
				return err
			}
		}
	}
	return nil
}

// AlignToOctetRead consumes and validates zero-valued APER alignment padding.
func (bb *BitBuffer) AlignToOctetRead() error {
	rem := bb.bitPos % 8
	if rem == 0 {
		return nil
	}
	padding, err := bb.ReadBits(8 - rem)
	if err != nil {
		return fmt.Errorf("APER alignment padding: %w", err)
	}
	if padding != 0 {
		return fmt.Errorf("%w: non-zero APER alignment padding", ErrInvalidValue)
	}
	return nil
}

// ReadBitsToBytes reads bitLen bits and returns them packed into bytes (MSB first).
func (bb *BitBuffer) ReadBitsToBytes(bitLen int) ([]byte, error) {
	if err := bb.checkRecoveryBits(0); err != nil {
		return nil, err
	}
	if bb.invalidLength {
		return nil, fmt.Errorf("%w: PER input bit length exceeds int", ErrInvalidValue)
	}
	if bb.bitPos < 0 {
		return nil, fmt.Errorf("%w: negative PER bit position %d", ErrInvalidValue, bb.bitPos)
	}
	if bitLen < 0 {
		return nil, fmt.Errorf("%w: ReadBitsToBytes called with negative bitLen=%d", ErrInvalidValue, bitLen)
	}
	if bitLen > bb.BitsRemaining() {
		return nil, fmt.Errorf("%w: requested %d bits with %d bits remaining", ErrTruncated, bitLen, bb.BitsRemaining())
	}
	// Reserve the entire read before allocating its copy, and charge once.
	if err := bb.examineRecoveryBits(uint64(bitLen)); err != nil {
		return nil, err
	}
	numBytes, err := octetsForBitLength(bitLen)
	if err != nil {
		return nil, err
	}
	result := make([]byte, numBytes)
	for i := range result {
		width := min(8, bitLen-i*8)
		start, shift := bb.bitPos/8, uint(bb.bitPos%8)
		part := bb.data[start] << shift
		if width > 8-int(shift) {
			part |= bb.data[start+1] >> (8 - shift)
		}
		result[i] = part & byte(0xff<<uint(8-width))
		bb.bitPos += width
	}
	return result, nil
}

func octetsForBitLength(bitLen int) (int, error) {
	if bitLen < 0 {
		return 0, fmt.Errorf("%w: negative bit length %d", ErrInvalidValue, bitLen)
	}
	octets := bitLen / 8
	if bitLen%8 != 0 {
		if octets == math.MaxInt {
			return 0, fmt.Errorf("%w: bit length exceeds host int", ErrInvalidValue)
		}
		octets++
	}
	return octets, nil
}
