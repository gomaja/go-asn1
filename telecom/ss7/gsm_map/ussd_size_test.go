package gsm_map

import (
	"bytes"
	"testing"
)

// TS 29.002 V19.1.0 17.7.4 and 17.7.8 constrain these MAP fields;
// X.680 (02/2021) 51.5 applies SIZE on both encode and decode.
func TestUSSDArgBERSizeConstraints(t *testing.T) {
	tlv := func(tag byte, value []byte) []byte {
		if len(value) < 128 {
			return append([]byte{tag, byte(len(value))}, value...)
		}
		return append([]byte{tag, 0x81, byte(len(value))}, value...)
	}
	seq := func(parts ...[]byte) []byte { return tlv(0x30, bytes.Join(parts, nil)) }
	dcs := tlv(0x04, []byte{0x0f})
	text := tlv(0x04, []byte{0xaa, 0x18})
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"empty DCS", seq(tlv(0x04, nil), text)},
		{"long DCS", seq(tlv(0x04, []byte{0x0f, 0}), text)},
		{"empty string", seq(dcs, tlv(0x04, nil))},
		{"long string", seq(dcs, tlv(0x04, bytes.Repeat([]byte{0x41}, 161)))},
		{"long alerting pattern", seq(dcs, text, tlv(0x04, []byte{1, 2}))},
		{"empty MSISDN", seq(dcs, text, tlv(0x80, nil))},
		{"long MSISDN", seq(dcs, text, tlv(0x80, bytes.Repeat([]byte{0x11}, 10)))},
	} {
		t.Run("decode "+tc.name, func(t *testing.T) {
			var value USSDArg
			if err := value.UnmarshalBER(tc.data); err == nil {
				t.Fatal("accepted out-of-range SIZE")
			}
		})
	}
	msisdn := ISDNAddressString(bytes.Repeat([]byte{0x11}, 10))
	for _, tc := range []struct {
		name  string
		value USSDArg
	}{
		{"long DCS", USSDArg{UssdDataCodingScheme: []byte{1, 2}, UssdString: []byte{1}}},
		{"empty string", USSDArg{UssdDataCodingScheme: []byte{0x0f}}},
		{"long string", USSDArg{UssdDataCodingScheme: []byte{0x0f}, UssdString: bytes.Repeat([]byte{1}, 161)}},
		{"long MSISDN", USSDArg{UssdDataCodingScheme: []byte{0x0f}, UssdString: []byte{1}, Msisdn: &msisdn}},
	} {
		t.Run("encode "+tc.name, func(t *testing.T) {
			if _, err := tc.value.MarshalBER(); err == nil {
				t.Fatal("encoded out-of-range SIZE")
			}
		})
	}
}
