package ros

import (
	"bytes"
	"errors"
	"fmt"
	"testing"

	rt "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime"
	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime/ber"
)

// X.680 (02/2021) §31.2.7(c); X.690 (02/2021) §8.14.3.
func TestBindUnbindExplicitOpenValues(t *testing.T) {
	sentinels := []error{ber.ErrTruncated, ber.ErrInvalidTag, ber.ErrUnexpectedElement, ber.ErrInvalidLength, ber.ErrIndefiniteLength, ber.ErrExtraData, ber.ErrInvalidValue, ber.ErrUnsupported, ber.ErrResourceLimit, ber.ErrInvalidCodec, ber.ErrInvalidBinding}
	for number := 16; number <= 21; number++ {
		root := "Bind"
		if number >= 19 {
			root = "Unbind"
		}
		for _, row := range []struct {
			name      string
			contents  []byte
			primitive bool
			want      error
		}{
			{"null", []byte{5, 0}, false, nil},
			{"sequence", []byte{0x30, 0x80, 5, 0, 0, 0}, false, nil},
			{"primitive-empty", nil, true, ber.ErrInvalidTag},
			{"primitive-bytes", []byte{0x61, 0x62, 0x63}, true, ber.ErrInvalidTag},
			{"empty", nil, false, ber.ErrUnexpectedElement},
			{"two-values", []byte{5, 0, 5, 0}, false, ber.ErrUnexpectedElement},
			{"truncated", []byte{5}, false, ber.ErrTruncated},
			{"malformed-tag", []byte{0x1f, 0x80, 0}, false, ber.ErrInvalidTag},
		} {
			t.Run(fmt.Sprintf("%s/%d/%s", root, number, row.name), func(t *testing.T) {
				id := byte(0xa0 + number)
				if row.primitive {
					id &^= 0x20
				}
				wire := append([]byte{id, byte(len(row.contents))}, row.contents...)
				check := func(err, want error) {
					t.Helper()
					if want == nil && err != nil {
						t.Fatal(err)
					}
					for _, sent := range sentinels {
						if errors.Is(err, sent) != (sent == want) {
							t.Fatalf("%x: %v errors.Is(%v), want %v", wire, err, sent, want)
						}
					}
				}

				for _, opts := range [][]ber.DecodeOption{nil, {ber.WithTolerance(new(ber.ViolationLog))}} {
					var value interface {
						UnmarshalBER([]byte, ...ber.DecodeOption) error
						MarshalBER(...ber.EncodeOption) ([]byte, error)
					}
					var inner *rt.RawValue
					if root == "Bind" {
						v := new(Bind)
						value = v
						check(v.UnmarshalBER(wire, opts...), row.want)
						switch number {
						case 16:
							inner = v.BindInvoke
						case 17:
							inner = v.BindResult
						case 18:
							inner = v.BindError
						}
					} else {
						v := new(Unbind)
						value = v
						check(v.UnmarshalBER(wire, opts...), row.want)
						switch number {
						case 19:
							inner = v.UnbindInvoke
						case 20:
							inner = v.UnbindResult
						case 21:
							inner = v.UnbindError
						}
					}
					if row.want != nil {
						continue
					}
					if inner == nil || !bytes.Equal(inner.Bytes, row.contents) {
						t.Fatalf("open value %+v, want %x", inner, row.contents)
					}
					out, err := value.MarshalBER()
					if err != nil || !bytes.Equal(out, wire) {
						t.Fatalf("replay %x, %v, want %x", out, err, wire)
					}
					// A newly constructed value has no received wrapper to replay.
					var fresh interface {
						MarshalBER(...ber.EncodeOption) ([]byte, error)
					}
					switch number {
					case 16:
						v := NewBindBindInvoke(*inner)
						fresh = &v
					case 17:
						v := NewBindBindResult(*inner)
						fresh = &v
					case 18:
						v := NewBindBindError(*inner)
						fresh = &v
					case 19:
						v := NewUnbindUnbindInvoke(*inner)
						fresh = &v
					case 20:
						v := NewUnbindUnbindResult(*inner)
						fresh = &v
					case 21:
						v := NewUnbindUnbindError(*inner)
						fresh = &v
					}
					out, err = fresh.MarshalBER()
					if err != nil || !bytes.Equal(out, wire) {
						t.Fatalf("fresh encoding %x, %v, want %x", out, err, wire)
					}
				}
			})
		}
	}
}
