package validation

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"

	gm "github.com/gomaja/go-asn1/telecom/ss7/gsm_map"
	mb "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime/ber"
)

// X.690 (02/2021) §§8.14.3, 8.24.1 and X.680 (02/2021)
// §§31.2.7 c), 44.5 require one identification alternative, even in extType.
func TestMAPPrivateExtensionAssociatedCardinality(t *testing.T) {

	type probe struct {
		hex   string
		valid bool
	}
	rows := []probe{{"3020301ea41ca51a30188001018202f121b10fa00d300b06032a03043d04a0008200", false}}
	tlv := func(tag byte, contents []byte) []byte { return append([]byte{tag, byte(len(contents))}, contents...) }
	for _, outer := range []byte{0x28, 0x2b, 0x3d} {
		for count := 0; count <= 2; count++ {
			inner := []byte{0x85, 0}
			if outer == 0x28 {
				inner = []byte{5, 0}
			}
			contents := tlv(0xa0, bytes.Repeat(inner, count))
			if outer == 0x28 {
				contents = append([]byte{6, 3, 0x2a, 3, 4}, contents...)
			} else {
				contents = append(contents, 0x82, 0)
			}
			value := tlv(outer, contents)
			extension := tlv(0x30, append([]byte{6, 3, 0x2a, 3, 4}, value...))
			container := tlv(0xb1, tlv(0xa0, extension))
			context := tlv(0x30, append([]byte{0x80, 1, 1, 0x82, 2, 0xf1, 0x21}, container...))
			wire := tlv(0x30, tlv(0x30, tlv(0xa4, tlv(0xa5, context))))
			rows = append(rows, probe{hex.EncodeToString(wire), count == 1})
		}
	}
	for _, row := range rows {
		wire, err := hex.DecodeString(row.hex)
		if err != nil {
			t.Fatal(err)
		}
		for _, tolerant := range []bool{false, true} {
			var opts []mb.DecodeOption
			log := new(mb.ViolationLog)
			if tolerant {
				opts = append(opts, mb.WithTolerance(log))
			}
			var v gm.AnyTimeInterrogationRes
			err = v.UnmarshalBER(wire, opts...)
			path := ""
			var located interface{ ASN1BERPath() string }
			if errors.As(err, &located) {
				path = located.ASN1BERPath()
			}
			t.Logf("valid=%t tolerant=%t path=%q err=%v report=%+v", row.valid, tolerant, path, err, log.Snapshot())
			if row.valid {
				if err != nil {
					t.Fatal(err)
				}
				replay, e := v.MarshalBER()
				if e != nil || !bytes.Equal(replay, wire) {
					t.Fatalf("replay=%x: %v", replay, e)
				}
			} else if !errors.Is(err, mb.ErrUnexpectedElement) {
				t.Fatalf("error=%v, want ErrUnexpectedElement", err)
			}
			for _, sent := range []error{mb.ErrTruncated, mb.ErrInvalidTag, mb.ErrUnexpectedElement, mb.ErrInvalidLength, mb.ErrIndefiniteLength, mb.ErrExtraData, mb.ErrInvalidValue, mb.ErrUnsupported, mb.ErrResourceLimit, mb.ErrInvalidCodec, mb.ErrInvalidBinding} {
				if errors.Is(err, sent) != (!row.valid && sent == mb.ErrUnexpectedElement) {
					t.Fatalf("error=%v errors.Is(%v)", err, sent)
				}
			}
		}
	}
}
