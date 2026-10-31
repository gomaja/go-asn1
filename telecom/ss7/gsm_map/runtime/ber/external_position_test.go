// Code generated from MAP runtime source. DO NOT EDIT.

// Runtime source: runtime/ber/external_position_test.go; SHA-256 60c834556bebf340e98e5eecb95c683b37819904a864ea5315521e169ab6a893.
package ber

import (
	"bytes"
	"errors"
	"fmt"
	"testing"
	"unsafe"
)

// X.690 (02/2021) §8.18.1 selects encoding after UNIVERSAL 6, 2, 7
// in that order. Only encoding's [0] is EXPLICIT (X.680 §31.2.7 b)).
func TestExternalEncodingPosition(t *testing.T) {
	optional := [][]byte{{6, 3, 42, 3, 4}, {2, 1, 1}, {7, 1, 'x'}}
	type probe struct {
		name                   string
		prefix, encoding, tail []byte
		scan, decode           error
	}
	var probes []probe
	for mask := 0; mask < 8; mask++ {
		var prefix []byte
		for i, p := range optional {
			if mask&(1<<i) != 0 {
				prefix = append(prefix, p...)
			}
		}
		want := error(ErrInvalidTag)
		if mask&3 == 0 {
			want = ErrInvalidValue
		}
		probes = append(probes, probe{fmt.Sprintf("ordered-%d", mask), prefix, []byte{0x80, 0}, nil, ErrInvalidTag, want})
	}
	for _, order := range [][]int{{1, 0}, {2, 0}, {2, 1}, {0, 2, 1}, {1, 2, 0}, {2, 1, 0}, {0, 0}, {1, 1}, {2, 2}} {
		var prefix []byte
		for _, i := range order {
			prefix = append(prefix, optional[i]...)
		}
		want := error(ErrUnexpectedElement)
		if order[0] == 2 {
			want = ErrInvalidValue
		}
		probes = append(probes, probe{fmt.Sprint("out-of-order-", order), prefix, []byte{0x80, 0}, nil, nil, want})
	}
	probes = append(probes, probe{"unknown-encoding", optional[0], []byte{0x83, 0}, []byte{0x80, 0}, nil, ErrUnexpectedElement})
	for i, encoding := range [][]byte{{0xa0, 2, 5, 0}, {0x81, 1, 0}, {0x82, 1, 0}} {
		probes = append(probes, probe{fmt.Sprintf("trailing-%d", i), optional[0], encoding, []byte{0x80, 0}, nil, ErrUnexpectedElement})
	}
	// Two simultaneous violations intentionally retain the entry points' order:
	// the scan sees the form; the decoder checks reference and trailing data first.
	probes = append(probes, probe{"primitive-and-trailing", optional[0], []byte{0x80, 0}, []byte{5, 0}, ErrInvalidTag, ErrUnexpectedElement})
	for _, p := range probes {
		for _, indefinite := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/indefinite-%t", p.name, indefinite), func(t *testing.T) {
				body := bytes.Join([][]byte{p.prefix, p.encoding, p.tail}, nil)
				data := append([]byte{0x28, byte(len(body))}, body...)
				if indefinite {
					data[1] = 0x80
					data = append(data, 0, 0)
				}
				for _, opts := range [][]DecodeOption{nil, {WithTolerance(new(ViolationLog))}} {
					check := func(err, want error) {
						t.Helper()
						if want == nil && err != nil {
							t.Fatal(err)
						}
						for _, sent := range []error{ErrTruncated, ErrInvalidTag, ErrUnexpectedElement, ErrInvalidLength, ErrIndefiniteLength, ErrExtraData, ErrInvalidValue, ErrUnsupported, ErrResourceLimit, ErrInvalidCodec, ErrInvalidBinding} {
							if errors.Is(err, sent) != (sent == want) {
								t.Fatalf("%x: %v errors.Is(%v), want %v", data, err, sent, want)
							}
						}
					}
					check(ValidateBERElement(data, opts...), p.scan)
					_, _, err := DecodeExternal(data, opts...)
					check(err, p.decode)
				}
			})
		}
	}
}

func TestAssociatedScanFrameSize(t *testing.T) {
	want := uintptr(80)
	if unsafe.Sizeof(int(0)) == 4 {
		want = 40
	}
	if got := unsafe.Sizeof(berScanFrame{}); got != want {
		t.Fatalf("scan frame=%d, want %d", got, want)
	}
	t.Logf("scan frame: %d bytes", want)
}
