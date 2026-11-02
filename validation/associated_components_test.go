package validation

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"

	gm "github.com/gomaja/go-asn1/telecom/ss7/gsm_map"
	mb "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime/ber"
	tc "github.com/gomaja/go-asn1/telecom/ss7/tcap"
	tb "github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime/ber"
)

// X.690 (02/2021) §§8.9.2, 8.17.1, 8.18.4 Table 2, 8.24.1;
// X.680 (02/2021) §§36.5, 44.5 apply inside foreign open values too (§8.15).
func TestAssociatedComponentsNestedOpenValues(t *testing.T) {
	tlv := func(i byte, v []byte) []byte { return append(append([]byte{i}, mb.EncodeLength(len(v))...), v...) }
	for _, row := range []struct {
		value        string
		invalid      bool
		invalidValue bool
	}{
		{"2804a0020500", true, true}, {"2807070164a0020500", true, true},
		{"2b0ba00581032a030481008200", true, false}, {"2b06a00286008200", true, false},
		{"2b08a004820200018200", true, true}, {"2b07a00581032a0304", true, false}, {"2b0ba00581032a030482008200", true, false},
		{"3d0ba00581032a030481008200", true, false}, {"3d06a00286008200", true, false},
		{"3d08a004820200018200", true, true}, {"3d07a00581032a0304", true, false}, {"3d0ba00581032a030482008200", true, false},
		{"280906032a0304a0020500", false, false}, {"2b09a00581032a03048200", false, false},
		{"3d09a00581032a03048200", false, false}, {"3d07a0028500820141", false, false},
	} {
		t.Run(row.value, func(t *testing.T) {
			value, err := hex.DecodeString(row.value)
			if err != nil {
				t.Fatal(err)
			}
			extension := tlv(0x30, append([]byte{6, 3, 0x2a, 3, 4}, value...))
			container := tlv(0xb1, tlv(0xa0, extension))
			context := tlv(0x30, append([]byte{0x80, 1, 1, 0x82, 2, 0xf1, 0x21}, container...))
			mapWire := tlv(0x30, tlv(0x30, tlv(0xa4, tlv(0xa5, context))))
			invoke := tlv(0xa1, append([]byte{2, 1, 1, 2, 1, 0x2d}, value...))
			tcapWire := tlv(0x62, append([]byte{0x48, 1, 1}, tlv(0x6c, invoke)...))
			for _, tolerant := range []bool{false, true} {
				var opts []mb.DecodeOption
				log := new(mb.ViolationLog)
				if tolerant {
					opts = append(opts, mb.WithTolerance(log))
				}
				var v gm.AnyTimeInterrogationRes
				err = v.UnmarshalBER(mapWire, opts...)
				want := error(nil)
				if row.invalid {
					want = mb.ErrUnexpectedElement
					if row.invalidValue {
						want = mb.ErrInvalidValue
					}
				}
				for _, sent := range []error{mb.ErrTruncated, mb.ErrInvalidTag, mb.ErrUnexpectedElement, mb.ErrInvalidLength, mb.ErrIndefiniteLength, mb.ErrExtraData, mb.ErrInvalidValue, mb.ErrUnsupported, mb.ErrResourceLimit, mb.ErrInvalidCodec, mb.ErrInvalidBinding} {
					if errors.Is(err, sent) != (sent == want) {
						t.Fatalf("MAP: %v errors.Is(%v), want %v", err, sent, want)
					}
				}
				var located interface{ ASN1BERPath() string }
				path := ""
				if errors.As(err, &located) {
					path = located.ASN1BERPath()
				}
				if len(log.Snapshot()) != 0 {
					t.Fatalf("MAP tolerance records: %+v", log.Snapshot())
				}
				if row.invalid {
					wantPath := "child[0].child[0].child[0].child[0].child[2].child[0].child[0].child[1]"
					switch row.value {
					case "2b06a00286008200", "3d06a00286008200":
						wantPath += ".child[0]"
					case "2b08a004820200018200", "3d08a004820200018200":
						wantPath += ".child[0].child[0]"
					}
					if path != wantPath {
						t.Fatalf("MAP path=%q want %q", path, wantPath)
					}
				} else {
					if err != nil {
						t.Fatal(err)
					}
					replay, e := v.MarshalBER()
					if e != nil || !bytes.Equal(replay, mapWire) {
						t.Fatalf("MAP replay: %v", e)
					}
				}
				t.Logf("MAP value=%s tolerant=%t path=%q error=%v records=%+v", row.value, tolerant, path, err, log.Snapshot())
				var top []tb.DecodeOption
				tlog := new(tb.ViolationLog)
				if tolerant {
					top = append(top, tb.WithTolerance(tlog))
				}
				var tv tc.TCMessage
				terr := tv.UnmarshalBER(tcapWire, top...)
				twant := error(nil)
				if row.invalid {
					twant = tb.ErrUnexpectedElement
					if row.invalidValue {
						twant = tb.ErrInvalidValue
					}
				}
				for _, sent := range []error{tb.ErrTruncated, tb.ErrInvalidTag, tb.ErrUnexpectedElement, tb.ErrInvalidLength, tb.ErrIndefiniteLength, tb.ErrExtraData, tb.ErrInvalidValue, tb.ErrUnsupported, tb.ErrResourceLimit} {
					if errors.Is(terr, sent) != (sent == twant) {
						t.Fatalf("TCAP: %v errors.Is(%v), want %v", terr, sent, twant)
					}
				}
				var wrongRoot tc.TCMessage
				wrongErr := wrongRoot.UnmarshalBER(value, top...)
				wrongWant := error(tb.ErrUnexpectedElement)
				if row.invalid && row.invalidValue {
					wrongWant = tb.ErrInvalidValue
				}
				for _, sent := range []error{tb.ErrTruncated, tb.ErrInvalidTag, tb.ErrUnexpectedElement, tb.ErrInvalidLength, tb.ErrIndefiniteLength, tb.ErrExtraData, tb.ErrInvalidValue, tb.ErrUnsupported, tb.ErrResourceLimit} {
					if errors.Is(wrongErr, sent) != (sent == wrongWant) {
						t.Fatalf("unadmitted TCAP root: %v errors.Is(%v), want %v", wrongErr, sent, wrongWant)
					}
				}
				if len(tlog.Snapshot()) != 0 {
					t.Fatalf("TCAP records: %+v", tlog.Snapshot())
				}
				if !row.invalid {
					if terr != nil {
						t.Fatal(terr)
					}
					replay, e := tv.MarshalBER()
					if e != nil || !bytes.Equal(replay, tcapWire) {
						t.Fatalf("TCAP replay: %v", e)
					}
				}
			}
		})
	}
}
