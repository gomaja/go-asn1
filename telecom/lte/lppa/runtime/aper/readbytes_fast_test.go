// Code generated from LPPa runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/readbytes_fast_test.go; SHA-256 97a338e8b049c202b649b7a0d67623ccb3ed9d77fa3cb4d8af802c07d0cccb0a.
package aper

import (
	"bytes"
	"errors"
	"fmt"
	"testing"
)

func readBytesBitOracle(bb *BitBuffer, n int) ([]byte, error) {
	if n < 0 {
		return nil, ErrInvalidValue
	}
	if n > bb.BitsRemaining()/8 {
		return nil, ErrTruncated
	}
	out := make([]byte, n)
	for i := range out {
		for bit := 0; bit < 8; bit++ {
			v, err := bb.ReadBit()
			if err != nil {
				return nil, err
			}
			out[i] = out[i]<<1 | v
		}
	}
	return out, nil
}

func TestReadBytesAgainstBitOracle(t *testing.T) {
	for offset := 0; offset < 8; offset++ {
		for size := 0; size <= 18; size++ {
			input := make([]byte, size)
			for i := range input {
				input[i] = byte(i*37 + 19)
			}
			for n := -1; n <= size+1; n++ {
				t.Run(fmt.Sprintf("offset=%d/size=%d/n=%d", offset, size, n), func(t *testing.T) {
					fast := NewBitBufferFromBytes(input)
					slow := NewBitBufferFromBytes(input)
					fast.bitPos, slow.bitPos = offset, offset
					got, err := fast.ReadBytes(n)
					want, wantErr := readBytesBitOracle(slow, n)
					if !bytes.Equal(got, want) || !errors.Is(err, wantErr) || fast.bitPos != slow.bitPos {
						t.Fatalf("got %x, %v, pos %d; want %x, %v, pos %d", got, err, fast.bitPos, want, wantErr, slow.bitPos)
					}
				})
			}
		}
	}
}
