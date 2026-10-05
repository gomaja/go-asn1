package ber

import (
	"encoding/hex"
	"testing"
)

// formDecoders are the exported TLV decoders that accept DecodeOptions. Each
// must record, through TrackBERForm, a valid BER form that DER re-encodes
// differently (X.690 (02/2021) §§8.1.3, 8.2.2, 8.5.7, 8.6.2, 8.7.3, 8.23,
// 10.1, 10.2, 11.1, 11.3, 11.7, 11.8).
var formDecoders = map[string]func([]byte, ...DecodeOption) (int, error){
	"DecodeTLV": func(data []byte, options ...DecodeOption) (int, error) {
		_, n, _, err := DecodeTLV(data, options...)
		return n, err
	},
	"DecodeBoolean": func(data []byte, options ...DecodeOption) (int, error) {
		_, _, n, err := DecodeBoolean(data, options...)
		return n, err
	},
	"DecodeInteger": func(data []byte, options ...DecodeOption) (int, error) {
		_, n, err := DecodeInteger(data, options...)
		return n, err
	},
	"DecodeUint64": func(data []byte, options ...DecodeOption) (int, error) {
		_, n, err := DecodeUint64(data, options...)
		return n, err
	},
	"DecodeBigInt": func(data []byte, options ...DecodeOption) (int, error) {
		_, n, err := DecodeBigInt(data, options...)
		return n, err
	},
	"DecodeEnumerated": func(data []byte, options ...DecodeOption) (int, error) {
		_, n, err := DecodeEnumerated(data, options...)
		return n, err
	},
	"DecodeReal": func(data []byte, options ...DecodeOption) (int, error) {
		_, n, err := DecodeReal(data, options...)
		return n, err
	},
	"DecodeBitString": func(data []byte, options ...DecodeOption) (int, error) {
		_, _, n, err := DecodeBitString(data, options...)
		return n, err
	},
	"DecodeOctetString": func(data []byte, options ...DecodeOption) (int, error) {
		_, n, err := DecodeOctetString(data, options...)
		return n, err
	},
	"DecodeNull": func(data []byte, options ...DecodeOption) (int, error) {
		return DecodeNull(data, options...)
	},
	"DecodeObjectIdentifier": func(data []byte, options ...DecodeOption) (int, error) {
		_, n, err := DecodeObjectIdentifier(data, options...)
		return n, err
	},
	"DecodeIA5String": func(data []byte, options ...DecodeOption) (int, error) {
		_, n, err := DecodeString(data, 22, options...)
		return n, err
	},
	"DecodeUTCTime": func(data []byte, options ...DecodeOption) (int, error) {
		_, n, err := DecodeUTCTime(data, options...)
		return n, err
	},
	"DecodeGeneralizedTime": func(data []byte, options ...DecodeOption) (int, error) {
		_, n, err := DecodeGeneralizedTime(data, options...)
		return n, err
	},
	"DecodeSequenceContent": func(data []byte, options ...DecodeOption) (int, error) {
		_, n, err := DecodeSequenceContent(data, options...)
		return n, err
	},
}

func TestTypedDecodersTrackBERForm(t *testing.T) {
	tests := []struct {
		decoder   string
		canonical string
		ber       string
	}{
		// X.690 (02/2021) §8.5.7: 1 as mantissa 2, exponent -1 is valid BER;
		// §11.3.1 requires DER's normalised mantissa 1, exponent 0.
		{"DecodeReal", "0903800001", "090380ff02"},
		{"DecodeReal", "0903800001", "09820003800001"},
		// §8.2.2 permits any nonzero TRUE octet; §11.1 requires 0xFF.
		{"DecodeBoolean", "0101ff", "010101"},
		// §§8.1.3.5, 10.1: a long-form length that the short form can carry.
		{"DecodeInteger", "020105", "02810105"},
		{"DecodeUint64", "020105", "0282000105"},
		{"DecodeBigInt", "020105", "02810105"},
		{"DecodeEnumerated", "0a0101", "0a810101"},
		{"DecodeNull", "0500", "058100"},
		{"DecodeObjectIdentifier", "06022a03", "0681022a03"},
		{"DecodeTLV", "0400", "048100"},
		// §§8.6.2, 8.7.3, 8.23: constructed strings are BER; §10.2 forbids them in DER.
		{"DecodeOctetString", "040107", "2403040107"},
		{"DecodeOctetString", "040107", "24800401070000"},
		{"DecodeOctetString", "040107", "04810107"},
		{"DecodeOctetString", "04020708", "2406040107040108"},
		{"DecodeBitString", "030200ff", "2304030200ff"},
		{"DecodeBitString", "030200ff", "03810200ff"},
		{"DecodeIA5String", "160141", "3603040141"},
		// §8.23.6: a constructed time is BER; the decoded value keeps any
		// X.680 (02/2021) §46.3/§47.3 lexical form, so a noncanonical
		// primitive form needs no preservation (TestTimeLexicalFormNeedsNoPreservation).
		{"DecodeUTCTime", "170d3939313233313233353935395a", "3711" + "0406393931323331" + "04073233353935395a"},
		{"DecodeGeneralizedTime", "180f32303230303130313030303030305a", "3813" + "04083230323030313031" + "04073030303030305a"},
		{"DecodeUTCTime", "170d3939313233313233353935395a", "17810d3939313233313233353935395a"},
		{"DecodeSequenceContent", "3003020105", "3080020105" + "0000"},
	}
	for _, test := range tests {
		decode := formDecoders[test.decoder]
		if decode == nil {
			t.Fatalf("no decoder %s", test.decoder)
		}
		for _, input := range []struct {
			hex  string
			want bool
		}{{test.canonical, false}, {test.ber, true}} {
			data, err := hex.DecodeString(input.hex)
			if err != nil {
				t.Fatal(err)
			}
			options := TrackBERForm(nil)
			n, err := decode(data, options...)
			if err != nil || n != len(data) {
				t.Fatalf("%s(%s) = %d, %v", test.decoder, input.hex, n, err)
			}
			if got := BERNeedsPreservation(options); got != input.want {
				t.Errorf("%s(%s) preservation = %v, want %v", test.decoder, input.hex, got, input.want)
			}
			// The scanner run by generated entry points must agree.
			validated := TrackBERForm(nil)
			if err := ValidateBERElement(data, validated...); err != nil {
				t.Fatalf("ValidateBERElement(%s) = %v", input.hex, err)
			}
			if got := BERNeedsPreservation(validated); got != input.want {
				t.Errorf("ValidateBERElement(%s) preservation = %v, want %v", input.hex, got, input.want)
			}
		}
	}
}

// A decoder given the options of an outer decode must keep its limits and
// its form marker together.
func TestConstructedStringKeepsLimitsWithFormTracking(t *testing.T) {
	data := nestedOctets(t, 3, []byte{1})
	options := TrackBERForm([]DecodeOption{WithDecodeLimits(DecodeLimits{MaxDepth: 2})})
	if _, _, err := DecodeOctetString(data, options...); err == nil {
		t.Fatal("depth limit ignored with form tracking")
	}
	options = TrackBERForm([]DecodeOption{WithDecodeLimits(DecodeLimits{MaxDepth: 8})})
	if _, _, err := DecodeOctetString(data, options...); err != nil || !BERNeedsPreservation(options) {
		t.Fatalf("nested constructed OCTET STRING = %v, preservation %v", err, BERNeedsPreservation(options))
	}
	// A raised limit must reach the indefinite-length scan of every segment,
	// not only the recursion depth check.
	deep := nestedOctets(t, DefaultDecodeLimits().MaxDepth+8, []byte{1})
	options = TrackBERForm([]DecodeOption{WithDecodeLimits(DecodeLimits{MaxDepth: 2 * DefaultDecodeLimits().MaxDepth})})
	if _, _, err := DecodeOctetString(deep, options...); err != nil || !BERNeedsPreservation(options) {
		t.Fatalf("raised depth limit = %v, preservation %v", err, BERNeedsPreservation(options))
	}
	bits := []byte{0x03, 0x02, 0x00, 0xff}
	for range DefaultDecodeLimits().MaxDepth + 8 {
		bits = append(append([]byte{0x23, 0x80}, bits...), 0, 0)
	}
	options = TrackBERForm([]DecodeOption{WithDecodeLimits(DecodeLimits{MaxDepth: 2 * DefaultDecodeLimits().MaxDepth})})
	if _, _, _, err := DecodeBitString(bits, options...); err != nil || !BERNeedsPreservation(options) {
		t.Fatalf("raised depth limit for BIT STRING = %v, preservation %v", err, BERNeedsPreservation(options))
	}
}

// FuzzTypedDecoderFormAgreesWithValidator checks that a typed decoder records
// exactly the BER forms the whole-element scanner records, for every input
// that both accept.
func FuzzTypedDecoderFormAgreesWithValidator(f *testing.F) {
	for _, seed := range []string{
		"090380ff02", "010101", "02810105", "2403040107", "24800401070000", "2304030200ff",
		"3603040141", "1711393931323331323335393539" + "2b30313030", "181132303230303130313030303030302e305a",
		"0903800001", "0101ff", "040107", "3003020105", "3080020105" + "0000", "0a810101", "058100",
	} {
		data, _ := hex.DecodeString(seed)
		f.Add(data)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		validated := TrackBERForm(nil)
		if ValidateBERElement(data, validated...) != nil {
			return
		}
		for name, decode := range formDecoders {
			options := TrackBERForm(nil)
			n, err := decode(data, options...)
			if err != nil || n != len(data) {
				continue
			}
			if name == "DecodeTLV" || name == "DecodeSequenceContent" {
				// These read one header; a constructed value's children are
				// decoded, and marked, by their own decoders.
				if BERNeedsPreservation(options) && !BERNeedsPreservation(validated) {
					t.Fatalf("%s marked %x that the scanner accepts as DER", name, data)
				}
				continue
			}
			if BERNeedsPreservation(options) != BERNeedsPreservation(validated) {
				t.Fatalf("%s(%x) preservation = %v, scanner %v", name, data, BERNeedsPreservation(options), BERNeedsPreservation(validated))
			}
		}
	})
}
