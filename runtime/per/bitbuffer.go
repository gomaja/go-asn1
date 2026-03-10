package per

import "fmt"

// BitBuffer provides bit-level read/write operations for PER encoding.
type BitBuffer struct {
	data   []byte
	bitPos int // current read position (read) or total bits written (write)
	bitLen int // total bits available (read mode only)
}

// NewBitBuffer creates a write-mode buffer.
func NewBitBuffer() *BitBuffer {
	return &BitBuffer{}
}

// NewBitBufferFromBytes creates a read-mode buffer from encoded bytes.
func NewBitBufferFromBytes(data []byte) *BitBuffer {
	return &BitBuffer{
		data:   data,
		bitLen: len(data) * 8,
	}
}

// WriteBit writes a single bit (0 or 1).
func (bb *BitBuffer) WriteBit(bit uint8) error {
	byteIdx := bb.bitPos / 8
	bitIdx := uint(7 - bb.bitPos%8)

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
	for i := n - 1; i >= 0; i-- {
		bit := uint8((val >> uint(i)) & 1)
		if err := bb.WriteBit(bit); err != nil {
			return err
		}
	}
	return nil
}

// ReadBit reads a single bit.
func (bb *BitBuffer) ReadBit() (uint8, error) {
	if bb.bitPos >= bb.bitLen {
		return 0, ErrTruncated
	}
	byteIdx := bb.bitPos / 8
	bitIdx := uint(7 - bb.bitPos%8)
	bit := (bb.data[byteIdx] >> bitIdx) & 1
	bb.bitPos++
	return bit, nil
}

// ReadBits reads n bits and returns them right-aligned in a uint64.
func (bb *BitBuffer) ReadBits(n int) (uint64, error) {
	if n < 0 || n > 64 {
		return 0, fmt.Errorf("per: ReadBits n=%d out of range", n)
	}
	if n == 0 {
		return 0, nil
	}
	var val uint64
	for i := 0; i < n; i++ {
		bit, err := bb.ReadBit()
		if err != nil {
			return 0, err
		}
		val = (val << 1) | uint64(bit)
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
	result := make([]byte, n)
	for i := 0; i < n; i++ {
		val, err := bb.ReadBits(8)
		if err != nil {
			return nil, err
		}
		result[i] = byte(val)
	}
	return result, nil
}

// Bytes returns the underlying byte slice, with the last byte zero-padded.
func (bb *BitBuffer) Bytes() []byte {
	return bb.data
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

// WriteBitsFromBytes writes exactly bitLen bits from the given byte slice (MSB first).
func (bb *BitBuffer) WriteBitsFromBytes(data []byte, bitLen int) error {
	for i := 0; i < bitLen; i++ {
		byteIdx := i / 8
		bitIdx := uint(7 - i%8)
		bit := (data[byteIdx] >> bitIdx) & 1
		if err := bb.WriteBit(bit); err != nil {
			return err
		}
	}
	return nil
}

// AlignToOctetWrite pads the write position to the next octet boundary (APER).
func (bb *BitBuffer) AlignToOctetWrite() {
	rem := bb.bitPos % 8
	if rem != 0 {
		for i := 0; i < 8-rem; i++ {
			_ = bb.WriteBit(0)
		}
	}
}

// AlignToOctetRead advances the read position to the next octet boundary (APER).
func (bb *BitBuffer) AlignToOctetRead() {
	rem := bb.bitPos % 8
	if rem != 0 {
		bb.bitPos += 8 - rem
	}
}

// ReadBitsToBytes reads bitLen bits and returns them packed into bytes (MSB first).
func (bb *BitBuffer) ReadBitsToBytes(bitLen int) ([]byte, error) {
	numBytes := (bitLen + 7) / 8
	result := make([]byte, numBytes)
	for i := 0; i < bitLen; i++ {
		bit, err := bb.ReadBit()
		if err != nil {
			return nil, err
		}
		byteIdx := i / 8
		bitIdx := uint(7 - i%8)
		if bit != 0 {
			result[byteIdx] |= 1 << bitIdx
		}
	}
	return result, nil
}
