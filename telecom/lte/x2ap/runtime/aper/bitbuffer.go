// Code generated from X2AP runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/bitbuffer.go; SHA-256 c3e09d9fcd37b7bd59383e91c310339beafe3fadb1e8766870ae38c736d6fd30.
package aper

import (
	"fmt"
	"math"
)

// BitBuffer provides bit-level read/write operations for PER encoding.
type BitBuffer struct {
	data          []byte
	bitPos        int  // current read position (read) or total bits written (write)
	bitLen        int  // total bits available (read mode only)
	sourceReader  bool // cursor belongs to received input, never an internal writer
	invalidLength bool // input octets cannot be represented as an int bit length
	// outermost is set on the buffer of a top-level decode under
	// TruncatedExtensionTolerance: only the end of its input can cut an
	// extension addition short. A nested buffer, bounded by an open type or
	// contained string that arrived in full, never has it.
	outermost  bool
	nested     bool          // cursor positions are relative to a bounded open value
	ownedInput bool          // this reader borrows the operation owner's immutable image
	budget     *DecodeBudget // shared by every buffer in this decode
	trace      *decodeTrace  // non-nil only for a decode with tolerance or deferral
}

// decodeSettings configures receiver behaviour for PER decoding: tolerance for
// non-conformant senders and the treatment of contained values. The zero
// value decodes strictly and eagerly.
type decodeSettings struct {
	callReport            *DecodeReport
	operationLimits       Limits
	operation             *DecodeBudget
	hasOperationLimits    bool
	invalidReceiverPolicy bool
	// Limits are operational ceilings for a complete decode. Zero fields use
	// defaultLegacyLimits.
	Limits decodeLimits
	// Usage, when non-nil, receives live per-decode resource metrics. It must
	// not be shared between concurrent decodes.
	Usage *DecodeUsage
	// TrailingBitsTolerance is retained as an option carrier. APER entry
	// points reject a non-nil log instead of accepting trailing data.
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
	// ContainedDecoding is retained to reject policies other than Eager at
	// APER entry points. X2AP has no formal contained values.
	ContainedDecoding ContainedDecoding
	// Deferrals is the reporting carrier associated with ContainedDecoding.
	Deferrals *DeferralLog
	// MaxZeroWidthCharacters preserves the option carrier. X2AP's
	// VisibleString uses eight aligned bits per character, so it never
	// consumes this zero-width option.
	MaxZeroWidthCharacters uint32
}

// setDecodeSettings starts a top-level decode with validated options. bb reads
// the outermost input, whose end alone can cut an extension addition short
// under TruncatedExtensionTolerance.
func (bb *BitBuffer) setDecodeSettings(options decodeSettings) error {
	if options.operation != nil {
		bb.budget = options.operation
		if bb.budget.nonzeroTerminalPadding {
			if err := bb.startPaddingTrace(); err != nil {
				return err
			}
		}
		if owner := bb.budget.owner; bb.sourceReader && !bb.ownedInput && owner != nil {
			bb.ownedInput = len(bb.data) == len(owner.original) && (len(bb.data) == 0 || &bb.data[0] == &owner.original[0])
		}
		if bb.budget.err != nil {
			return bb.budget.err
		}
		if uint64(len(bb.data)) > bb.budget.operational.MaxInputBytes {
			return bb.resourceError("input bytes exceeded")
		}
		return nil
	}
	limits, err := effectiveDecodeLimits(options.Limits)
	if err != nil {
		*bb.decodeBudget() = DecodeBudget{limits: defaultLegacyLimits(), err: err}
		return err
	}
	*bb.decodeBudget() = DecodeBudget{reading: true, limits: limits, report: options.Usage, callReport: options.callReport}
	if options.hasOperationLimits {
		operational, err := effectiveLimits(options.operationLimits)
		if err != nil {
			bb.budget.err = err
			return err
		}
		bb.budget.operational = operational
		bb.budget.limits = decodeLimits{MaxDepth: int(operational.MaxDepth), MaxElements: int(operational.MaxElements), MaxOpenTypeDepth: int(operational.MaxDepth), MaxWork: int(operational.MaxWork)}
		if uint64(len(bb.data)) > operational.MaxInputBytes {
			return bb.resourceError("input bytes exceeded")
		}
	}
	bb.budget.publish()
	bb.trace = nil
	bb.outermost = options.TruncatedExtensionTolerance != nil
	if options.TruncatedExtensionTolerance != nil || options.ExtensionRecoveryTolerance != nil {
		bb.trace = &decodeTrace{truncated: options.TruncatedExtensionTolerance, recovery: options.ExtensionRecoveryTolerance}
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

// setDecodeSettingsAligned starts a top-level APER decode with options.
// Generated APER decoders decode contained values eagerly and accept only the
// final padding of X.691 (02/2021) 11.1.4, so TrailingBitsTolerance and a
// ContainedDecoding other than Eager are rejected rather than ignored.
func (bb *BitBuffer) setDecodeSettingsAligned(options decodeSettings) error {
	if options.invalidReceiverPolicy {
		return &DecodeError{Kind: InvalidOptions, Err: ErrInvalidOptions}
	}
	if options.TrailingBitsTolerance != nil {
		return fmt.Errorf("%w: TrailingBitsTolerance is not supported by APER decoders", ErrInvalidValue)
	}
	if options.ContainedDecoding != Eager {
		return fmt.Errorf("%w: ContainedDecoding %v is not supported by APER decoders", ErrInvalidValue, options.ContainedDecoding)
	}
	return bb.setDecodeSettings(options)
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
		*budget = DecodeBudget{limits: defaultLegacyLimits()}
	}
	if len(data) > math.MaxInt/8 {
		return &BitBuffer{invalidLength: true, sourceReader: true, budget: budget}
	}
	return &BitBuffer{
		sourceReader: true,
		data:         data,
		bitLen:       len(data) * 8,
		budget:       budget,
	}
}

// NewNestedDecodeBuffer inherits the shared budget and receiver options while
// constructing a child. Low-level callers may keep the reader and supplied
// budget on the stack; sealed complete codecs use NewOwnedNestedDecodeBuffer.
func NewNestedDecodeBuffer(data []byte, parent *BitBuffer) *BitBuffer {
	invalid := len(data) > math.MaxInt/8
	length := 0
	if !invalid {
		length = len(data) * 8
	}
	return &BitBuffer{sourceReader: true, data: data, bitLen: length, invalidLength: invalid, nested: true,
		trace: parent.trace, budget: parent.decodeBudget()}
}

// WriteBit writes a single bit (0 or 1).
func (bb *BitBuffer) WriteBit(bit uint8) error {
	if err := bb.prepareInputWrite(); err != nil {
		return err
	}
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

	if bb.budget != nil && bb.budget.operational != (Limits{}) {
		if err := bb.ChargeWork(1); err != nil {
			return err
		}
		if err := bb.CheckOutput(uint64(byteIdx) + 1); err != nil {
			return err
		}
	}
	if byteIdx >= len(bb.data) {
		next, err := AppendValues(bb, bb.data, byte(0))
		if err != nil {
			return err
		}
		bb.data = next
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
	bit := (bb.readOctet(byteIdx) >> bitIdx) & 1
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
		part := bb.readOctet(bb.bitPos/8) >> uint(8-int(shift)-width)
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
	if err := bb.prepareInputWrite(); err != nil {
		return err
	}
	if len(data) != 0 && bb.bitPos >= 0 && bb.bitPos%8 == 0 {
		if len(data) > (math.MaxInt-bb.bitPos)/8 {
			return ErrInvalidValue
		}
		start := bb.bitPos / 8
		if bb.budget != nil && bb.budget.operational != (Limits{}) {
			if err := bb.ChargeWork(uint64(len(data)) * 8); err != nil {
				return err
			}
			if err := bb.CheckOutput(uint64(start) + uint64(len(data))); err != nil {
				return err
			}
		}
		if start > len(bb.data) {
			next, err := AppendValues(bb, bb.data, make([]byte, start-len(bb.data))...)
			if err != nil {
				return err
			}
			bb.data = next
		}
		overlap := min(len(data), len(bb.data)-start)
		for i := range overlap {
			bb.data[start+i] |= data[i]
		}
		next, err := AppendValues(bb, bb.data, data[overlap:]...)
		if err != nil {
			return err
		}
		bb.data = next
		bb.bitPos += len(data) * 8
		return nil
	}
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
	if err := bb.ChargeAllocation(uint64(n), 1); err != nil {
		return nil, err
	}
	result := make([]byte, n)
	if n == 0 {
		return result, nil
	}
	start, shift := bb.bitPos/8, uint(bb.bitPos%8)
	if shift == 0 {
		bb.copyOctets(result, start)
	} else {
		for i := range result {
			result[i] = bb.readOctet(start+i)<<shift | bb.readOctet(start+i+1)>>(8-shift)
		}
	}
	bb.bitPos += n * 8
	return result, nil
}

// Bytes returns the underlying byte slice, with the last byte zero-padded.
func (bb *BitBuffer) Bytes() []byte {
	if bb.sourceReader && (bb.nested || bb.ownsInput()) {
		data, _ := bb.copyInputOctets()
		return data
	}
	return bb.data
}

// CompleteBytes returns a complete APER encoding. X.691 (02/2021) §11.1.4
// requires a zero-bit outermost encoding to be represented by one zero octet.
func (bb *BitBuffer) CompleteBytes() []byte {
	if bb.bitPos == 0 && len(bb.data) == 0 {
		if err := bb.ChargeAllocation(1, 1); err != nil {
			return nil
		}
		return []byte{0}
	}
	return bb.Bytes()
}

// CompletePadding carries terminal-padding state for a complete PER encoding.
// APER decoders require zero padding (X.691 (02/2021) §11.1.4) and return the
// zero value without retaining its width. Its private fields cannot be set by
// callers outside this package.
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

// CompleteValue carries a primitive open-type value and its padding state.
// X.691 (02/2021) §11.2.1 makes open-type contents a complete encoding;
// successful APER decoding leaves the padding state zero.
type CompleteValue[T any] struct {
	Value   T
	padding CompletePadding
}

// CompleteOpenTypeValue checks that an open type has only zero terminal
// padding and no trailing data, then wraps value with zero padding state
// (X.691 (02/2021) §§11.1.4, 11.2.1).
func CompleteOpenTypeValue[T any](bb *BitBuffer, value T) (*CompleteValue[T], error) {
	padding, err := capturePrimitivePadding[T](bb)
	if err != nil {
		return nil, err
	}
	if err := ChargeValue(bb, CompleteValue[T]{}); err != nil {
		return nil, err
	}
	return &CompleteValue[T]{Value: value, padding: padding}, nil
}

// ReceivedPadding returns the complete value's padding state, which is zero
// after successful APER decoding (X.691 (02/2021) §§11.1.4, 11.2.1).
func (v CompleteValue[T]) ReceivedPadding() CompletePadding { return v.padding }

// Bits returns the stored terminal bits right-aligned and their width.
// Successful APER decoding returns (0, 0): zero padding is not retained
// (X.691 (02/2021) §11.1.4).
func (p CompletePadding) Bits() (value, count uint8) {
	return p.bits, p.count
}

// IsZero reports whether every stored terminal bit is zero.
func (p CompletePadding) IsZero() bool {
	return p.bits == 0
}

// CompleteBytesWithPadding returns a complete encoding, applying stored
// non-zero padding only when its width exactly fills the final octet. Otherwise
// it uses CompleteBytes; X.691 (02/2021) §11.1.4 requires zero terminal padding.
//
// APER decoders return only zero padding state, and exported APIs cannot create
// non-zero state. The non-zero branch remains available to package-internal
// callers; it copies the encoding once and can produce non-conforming output
// that strict APER decoding rejects. The zero-padding path uses CompleteBytes
// without copying existing storage.
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
	return captureNamedPadding(bb, context, context)
}

func captureNamedPadding(bb *BitBuffer, context, path string) (CompletePadding, error) {
	if bb.invalidLength {
		return CompletePadding{}, fmt.Errorf("%w: PER input bit length exceeds int", ErrInvalidValue)
	}
	start, remaining := bb.BitPos(), bb.BitsRemaining()
	// X.691 (02/2021) §11.1.4 permits only the terminal zero bits needed
	// to finish the octet. §11.2.1 applies this complete boundary to open types.
	if remaining < 0 || remaining > 8 || remaining == 8 && start != 0 {
		return CompletePadding{}, bb.syntaxError(start, "§11.1.4", fmt.Sprintf("%s has %d unconsumed bits", context, remaining), ErrExtraData)
	}
	if start == 0 && remaining != 8 {
		message := fmt.Sprintf("%s zero-bit complete encoding has %d bits", context, remaining)
		if remaining == 0 {
			message = context + " complete encoding is empty"
		}
		return CompletePadding{}, bb.syntaxError(start, "§11.1.4", message, ErrTruncated)
	}
	padding, err := bb.ReadBits(remaining)
	if err != nil {
		return CompletePadding{}, err
	}
	if padding != 0 {
		if bb.budget != nil && bb.budget.nonzeroTerminalPadding {
			if err := bb.observeTerminalPadding(start, remaining, uint8(padding), path, context == "open type" || bb.nested); err != nil {
				return CompletePadding{}, err
			}
			return CompletePadding{}, nil
		}
		failure := bb.syntaxError(start, "§11.1.4", context+" has non-zero terminal padding", ErrInvalidValue).(*DecodeError)
		failure.Location.Path = Path(path)
		return CompletePadding{}, failure
	}
	return CompletePadding{}, nil
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
	start := bb.BitPos()
	padding, err := bb.ReadBits(8 - rem)
	if err != nil {
		return fmt.Errorf("APER alignment padding: %w", err)
	}
	if padding != 0 {
		// X.691 (02/2021) §11.1.4 requires zero internal alignment bits.
		return bb.syntaxError(start, "§11.1.4", "non-zero APER alignment padding", ErrInvalidValue)
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
	if err := bb.ChargeAllocation(uint64(numBytes), 1); err != nil {
		return nil, err
	}
	result := make([]byte, numBytes)
	for i := range result {
		width := min(8, bitLen-i*8)
		start, shift := bb.bitPos/8, uint(bb.bitPos%8)
		part := bb.readOctet(start) << shift
		if width > 8-int(shift) {
			part |= bb.readOctet(start+1) >> (8 - shift)
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

func (bb *BitBuffer) InheritDecodeOptions(parent *BitBuffer) {
	bb.trace = parent.trace
	bb.outermost = false
	bb.budget = parent.decodeBudget()
}

// Input readers may borrow immutable original spans. Byte views copy on demand,
// and the first writer operation gives the cursor independent writable storage.
func (bb *BitBuffer) copyInputOctets() ([]byte, error) {
	if bb.invalidLength || bb.bitLen < 0 || bb.bitLen%8 != 0 {
		return nil, ErrInvalidValue
	}
	octets := bb.bitLen / 8
	if err := bb.ChargeAllocation(uint64(octets), 1); err != nil {
		return nil, err
	}
	out := make([]byte, octets)
	bb.copyOctets(out, 0)
	return out, nil
}
func (bb *BitBuffer) prepareInputWrite() error {
	if !bb.sourceReader || !(bb.nested || bb.ownsInput()) {
		return nil
	}
	data, err := bb.copyInputOctets()
	if err != nil {
		return err
	}
	bb.data = data
	bb.sourceReader = false
	return nil
}
