package per

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

func FuzzReadBytesAgainstBitOracle(f *testing.F) {
	for _, data := range [][]byte{nil, {0x00}, {0xff, 0x36}, bytes.Repeat([]byte{0xa5}, 17)} {
		for offset := byte(0); offset < 8; offset++ {
			f.Add(data, offset, uint16(len(data)))
		}
	}
	f.Fuzz(func(t *testing.T, data []byte, offset byte, n uint16) {
		fast := NewBitBufferFromBytes(data)
		slow := NewBitBufferFromBytes(data)
		start := int(offset % 8)
		if start > fast.bitLen {
			start = fast.bitLen
		}
		fast.bitPos, slow.bitPos = start, start
		got, err := fast.ReadBytes(int(n))
		want, wantErr := readBytesBitOracle(slow, int(n))
		if !bytes.Equal(got, want) || !errors.Is(err, wantErr) || fast.bitPos != slow.bitPos {
			t.Fatalf("got %x, %v, pos %d; want %x, %v, pos %d", got, err, fast.bitPos, want, wantErr, slow.bitPos)
		}
	})
}

func BenchmarkReadBytes4096(b *testing.B) {
	data := bytes.Repeat([]byte{0xa5}, 4097)
	for _, offset := range []int{0, 3} {
		b.Run(fmt.Sprintf("offset=%d", offset), func(b *testing.B) {
			b.SetBytes(4096)
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				bb := NewBitBufferFromBytes(data)
				bb.bitPos = offset
				if _, err := bb.ReadBytes(4096); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
