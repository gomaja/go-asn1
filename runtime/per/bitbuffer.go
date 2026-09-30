package per

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
	decodeOptions DecodeOptions
}

// DecodeOptions enables receiver tolerance for non-conformant PER senders.
// X.691 (02/2021) 11.1.3.2 forbids padding inside BIT STRING (CONTAINING).
// TS 25.331 V19.0.1 12.1.3 requires tolerant RRC receivers.
type DecodeOptions struct {
	AllowNonstandardTrailingBits bool
}

// SetDecodeOptions applies options to this decoder and its nested decoders.
func (bb *BitBuffer) SetDecodeOptions(options DecodeOptions) { bb.decodeOptions = options }

// Options returns the options to pass to a nested decoder.
func (bb *BitBuffer) Options() DecodeOptions { return bb.decodeOptions }

// NewBitBuffer creates a write-mode buffer.
func NewBitBuffer() *BitBuffer {
	return &BitBuffer{}
}

// NewBitBufferFromBytes creates a read-mode buffer from encoded bytes.
func NewBitBufferFromBytes(data []byte) *BitBuffer {
	if len(data) > math.MaxInt/8 {
		return &BitBuffer{invalidLength: true}
	}
	return &BitBuffer{
		data:   data,
		bitLen: len(data) * 8,
	}
}

// NewBitBufferFromBits bounds a nested PER encoding carried in a BIT STRING
// to its declared bit length. X.691 (02/2021) 11.1.1(b) permits a complete
// unaligned encoding in a BIT STRING without octet padding.
func NewBitBufferFromBits(data []byte, bitLen int) (*BitBuffer, error) {
	if bitLen < 0 {
		return nil, fmt.Errorf("%w: negative bit-string length %d", ErrInvalidValue, bitLen)
	}
	required, err := octetsForBitLength(bitLen)
	if err != nil || len(data) != required {
		return nil, fmt.Errorf("%w: invalid bit-string length %d for %d octets", ErrInvalidValue, bitLen, len(data))
	}
	if bitLen%8 != 0 && data[len(data)-1]&byte((1<<uint(8-bitLen%8))-1) != 0 {
		return nil, fmt.Errorf("%w: nonzero unused BIT STRING bits", ErrInvalidValue)
	}
	return &BitBuffer{data: data, bitLen: bitLen}, nil
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
		return fmt.Errorf("per: WriteBits n=%d out of range", n)
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
	if bb.invalidLength {
		return 0, fmt.Errorf("%w: PER input bit length exceeds int", ErrInvalidValue)
	}
	if bb.bitPos < 0 {
		return 0, fmt.Errorf("%w: negative PER bit position %d", ErrInvalidValue, bb.bitPos)
	}
	if bb.bitPos >= bb.bitLen {
		return 0, ErrTruncated
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
	if bb.invalidLength {
		return 0, fmt.Errorf("%w: PER input bit length exceeds int", ErrInvalidValue)
	}
	if n < 0 || n > 64 {
		return 0, fmt.Errorf("per: ReadBits n=%d out of range", n)
	}
	if n == 0 {
		return 0, nil
	}
	var val uint64
	for i := 0; i < n; {
		bit, err := bb.ReadBit()
		if err != nil {
			return 0, err
		}
		if val > math.MaxUint64>>1 {
			return 0, fmt.Errorf("%w: PER bit field exceeds uint64", ErrInvalidValue)
		}
		val = (val << 1) | uint64(bit)
		i++
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
// must retain.
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

// CaptureContainedZeroPadding accepts only zero bits inside a BIT STRING
// (CONTAINING ...) when receiver tolerance is explicitly enabled.
// X.691 (02/2021) 11.1.3.2 otherwise requires no padding bits.
func CaptureContainedZeroPadding(bb *BitBuffer) (CompletePadding, error) {
	remaining := bb.BitsRemaining()
	if remaining < 0 || remaining > 7 {
		return CompletePadding{}, fmt.Errorf("%w: contained value has %d trailing bits", ErrExtraData, remaining)
	}
	value, err := bb.ReadBits(remaining)
	if err != nil {
		return CompletePadding{}, err
	}
	if value != 0 {
		return CompletePadding{}, fmt.Errorf("%w: contained value has nonzero padding", ErrInvalidValue)
	}
	return CompletePadding{count: uint8(remaining)}, nil
}

// AppendContainedZeroPadding reproduces observed non-conformant padding.
func AppendContainedZeroPadding(bb *BitBuffer, padding CompletePadding) error {
	if padding.count > 7 || padding.bits != 0 {
		return fmt.Errorf("%w: invalid contained padding", ErrInvalidValue)
	}
	for range padding.count {
		if err := bb.WriteBit(0); err != nil {
			return err
		}
	}
	return nil
}

// CaptureFinalPaddingWithOptions retains trailing bits from a non-conformant
// top-level value when explicitly allowed. X.691 (02/2021) 11.1.3.1 permits
// only the terminal 1-7 padding bits; TS 25.331 V19.0.1 12.1.3 motivates
// receiver tolerance for extra extension and padding bits.
func CaptureFinalPaddingWithOptions(bb *BitBuffer) (CompletePadding, TrailingBits, error) {
	if !bb.decodeOptions.AllowNonstandardTrailingBits || bb.BitsRemaining() <= 7 {
		padding, err := CaptureFinalPadding(bb)
		return padding, TrailingBits{}, err
	}
	remaining := bb.BitsRemaining()
	bytes, err := bb.ReadBitsToBytes(remaining)
	if err != nil {
		return CompletePadding{}, TrailingBits{}, err
	}
	return CompletePadding{}, TrailingBits{Bytes: bytes, BitLength: remaining}, nil
}

// CompleteBytesWithTrailing reproduces a tolerated top-level suffix.
func (bb *BitBuffer) CompleteBytesWithTrailing(padding CompletePadding, trailing TrailingBits) ([]byte, error) {
	if trailing.BitLength == 0 {
		return bb.CompleteBytesWithPadding(padding)
	}
	if padding.count != 0 || trailing.BitLength < 0 {
		return nil, fmt.Errorf("%w: incompatible trailing bits", ErrInvalidValue)
	}
	if err := bb.WriteBitsFromBytes(trailing.Bytes, trailing.BitLength); err != nil {
		return nil, err
	}
	if bb.bitPos%8 != 0 {
		return nil, fmt.Errorf("%w: stale trailing bits", ErrInvalidValue)
	}
	return bb.CompleteBytes(), nil
}

// CompleteValue carries a primitive open-type value and its observed padding.
// ITU-T X.691 (02/2021) 11.2.1 makes open-type contents a complete encoding.
type CompleteValue[T any] struct {
	Value       T
	PERPadding_ CompletePadding `json:"-"`
}

// CompleteOpenTypeValue checks that an open type has no trailing data and
// retains its observed terminal bits. ITU-T X.691 (02/2021) 11.2.1 and 11.1.
func CompleteOpenTypeValue[T any](bb *BitBuffer, value T) (*CompleteValue[T], error) {
	padding, err := CaptureOpenTypePadding(bb)
	if err != nil {
		return nil, err
	}
	return &CompleteValue[T]{Value: value, PERPadding_: padding}, nil
}

// Bits returns the observed terminal bits right-aligned and their width.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require zero padding on encode.
func (p CompletePadding) Bits() (value, count uint8) {
	return p.bits, p.count
}

// IsZero reports whether every observed terminal bit is zero.
func (p CompletePadding) IsZero() bool {
	return p.bits == 0
}

// CompleteBytesWithPadding returns a complete encoding with observed terminal
// bits. A newly constructed value has zero padding. If a decoded value changes
// bit length, its old padding cannot be applied to the new encoding.
func (bb *BitBuffer) CompleteBytesWithPadding(padding CompletePadding) ([]byte, error) {
	out := append([]byte(nil), bb.CompleteBytes()...)
	if padding.count == 0 {
		return out, nil
	}
	if bb.bitPos < 0 || padding.count > 7 {
		return nil, fmt.Errorf("%w: invalid complete-encoding padding", ErrInvalidValue)
	}
	want := (8 - bb.bitPos%8) % 8
	if bb.bitPos == 0 || int(padding.count) != want || padding.bits >= 1<<padding.count {
		return nil, fmt.Errorf("%w: stale complete-encoding padding", ErrInvalidValue)
	}
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
	if remaining == 8 {
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
	if err != nil || required > len(data) {
		return fmt.Errorf("%w: WriteBitsFromBytes bitLen %d out of range for %d bytes", ErrInvalidValue, bitLen, len(data))
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
	if bb.invalidLength {
		return nil, fmt.Errorf("%w: PER input bit length exceeds int", ErrInvalidValue)
	}
	if bitLen < 0 {
		return nil, fmt.Errorf("%w: ReadBitsToBytes called with negative bitLen=%d", ErrInvalidValue, bitLen)
	}
	if bitLen > bb.BitsRemaining() {
		return nil, fmt.Errorf("%w: requested %d bits with %d bits remaining", ErrTruncated, bitLen, bb.BitsRemaining())
	}
	numBytes, err := octetsForBitLength(bitLen)
	if err != nil {
		return nil, err
	}
	result := make([]byte, numBytes)
	for i := 0; i < bitLen; {
		bit, err := bb.ReadBit()
		if err != nil {
			return nil, err
		}
		byteIdx := i / 8
		bitIdx := uint(7 - i%8)
		if bitIdx > 7 {
			return nil, fmt.Errorf("%w: invalid PER bit index %d", ErrInvalidValue, bitIdx)
		}
		if bit != 0 {
			result[byteIdx] |= 1 << bitIdx
		}
		i++
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
