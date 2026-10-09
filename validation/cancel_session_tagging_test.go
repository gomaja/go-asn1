package validation

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/gomaja/go-asn1/telecom/esim/sgp22"
	"github.com/gomaja/go-asn1/telecom/esim/sgp32"
)

// The cancelSessionResponse component of CancelSessionRequestEs9 (SGP.22 and
// SGP.32) and CancelSessionRequestEsipa (SGP.32) carries the automatic tag
// [1] over a tagged CHOICE ([65]). ITU-T X.680 (02/2021) §§25.10, 31.2.7
// make that tag implicit. GSMA SGP.22 v2.7 Table 45 NOTE 1 and SGP.32 v1.3
// Table 27 NOTE 1 require the field to carry an encoded CancelSessionResponse
// data object, the BF41 TLV, which is the explicit form. The value below is
// {transactionId '010203'H, cancelSessionResponse cancelSessionResponseError
// invalidTransactionId (5)} in both forms:
//
//	explicit: bf41 0d 80 03 010203 a1 06 bf41 03 81 01 05
//	implicit: bf41 0a 80 03 010203 a1 03       81 01 05
//
// pycrate 0.7.11 encodes the explicit form, and OSS ASN-1Step 10.2.1 the
// implicit one (go-asn1#89).
//
// Both decode to the same value and re-encode as received. DER, a value built
// in code and an edited value encode the explicit form.
const (
	cancelSessionExplicit = "bf410d8003010203a106bf4103810105"
	cancelSessionImplicit = "bf410a8003010203a103810105"
)

func TestCancelSessionResponseTagForms(t *testing.T) {
	transactionID := []byte{0x01, 0x02, 0x03}
	cases := []struct {
		name  string
		fresh func() berValue
		built berValue
	}{
		{
			name:  "SGP.22 CancelSessionRequestEs9",
			fresh: func() berValue { return &sgp22.CancelSessionRequestEs9{} },
			built: &sgp22.CancelSessionRequestEs9{
				TransactionId: transactionID,
				CancelSessionResponse: sgp22.NewCancelSessionResponseCancelSessionResponseError(
					sgp22.NewCancelSessionResponseCancelSessionResponseErrorValueInt64(
						sgp22.CancelSessionResponseCancelSessionResponseErrorValueInvalidTransactionId)),
			},
		},
		{
			name:  "SGP.32 CancelSessionRequestEs9",
			fresh: func() berValue { return &sgp32.CancelSessionRequestEs9{} },
			built: &sgp32.CancelSessionRequestEs9{
				TransactionId: transactionID,
				CancelSessionResponse: sgp32.NewCancelSessionResponseCancelSessionResponseError(
					sgp32.NewCancelSessionResponseCancelSessionResponseErrorValueInt64(
						sgp32.CancelSessionResponseCancelSessionResponseErrorValueInvalidTransactionId)),
			},
		},
		{
			name:  "SGP.32 CancelSessionRequestEsipa",
			fresh: func() berValue { return &sgp32.CancelSessionRequestEsipa{} },
			built: &sgp32.CancelSessionRequestEsipa{
				TransactionId: transactionID,
				CancelSessionResponse: sgp32.NewSGPCancelSessionResponseCancelSessionResponseError(
					sgp32.NewSGPCancelSessionResponseCancelSessionResponseErrorValueInt64(
						sgp32.SGPCancelSessionResponseCancelSessionResponseErrorValueInvalidTransactionId)),
			},
		},
	}
	explicit := mustHex(t, cancelSessionExplicit)
	implicit := mustHex(t, cancelSessionImplicit)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			want, err := json.Marshal(c.built)
			if err != nil {
				t.Fatal(err)
			}
			for form, wire := range map[string][]byte{"explicit": explicit, "implicit": implicit} {
				value := c.fresh()
				if err := value.UnmarshalBER(wire); err != nil {
					t.Fatalf("%s decode: %v", form, err)
				}
				if got, err := json.Marshal(value); err != nil || !bytes.Equal(got, want) {
					t.Fatalf("%s decode = %s, %v; want %s", form, got, err, want)
				}
				if out, err := value.MarshalBER(); err != nil || !bytes.Equal(out, wire) {
					t.Fatalf("%s replay = %x, %v; want %x", form, out, err, wire)
				}
				if out, err := value.MarshalDER(); err != nil || !bytes.Equal(out, explicit) {
					t.Fatalf("%s DER = %x, %v; want %x", form, out, err, explicit)
				}
			}
			for kind, encode := range map[string]func() ([]byte, error){
				"BER": func() ([]byte, error) { return c.built.MarshalBER() },
				"DER": c.built.MarshalDER,
			} {
				if out, err := encode(); err != nil || !bytes.Equal(out, explicit) {
					t.Fatalf("built value %s = %x, %v; want %x", kind, out, err, explicit)
				}
			}
		})
	}
}

func TestCancelSessionResponseEditEncodesExplicit(t *testing.T) {
	var request sgp22.CancelSessionRequestEs9
	if err := request.UnmarshalBER(mustHex(t, cancelSessionImplicit)); err != nil {
		t.Fatal(err)
	}
	request.TransactionId = []byte{0x09}
	want := mustHex(t, "bf410b800109a106bf4103810105")
	if out, err := request.MarshalBER(); err != nil || !bytes.Equal(out, want) {
		t.Fatalf("edited value = %x, %v; want %x", out, err, want)
	}
}
