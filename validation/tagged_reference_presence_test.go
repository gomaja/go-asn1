package validation

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/gomaja/go-asn1/telecom/esim/sgp22"
	"github.com/gomaja/go-asn1/telecom/esim/sgp32"
)

// An OPTIONAL component whose type is a reference to a tagged type is
// present when the referenced type's own tag is received (ITU-T X.680
// (02/2021) §31; X.690 (02/2021) §8.14). The vectors below are synthetic
// and derived by hand from X.690; both modules use AUTOMATIC TAGS with
// written context tags, which are therefore implicit.

// InitiateAuthenticationRequestEsipa ([57], tag BF39) with euiccChallenge,
// euiccInfo1 (EUICCInfo1 ::= [32] SEQUENCE, tag BF20) and eimTransactionId.
// tshark 4.6.8 dissects it, carried in an HTTP request of media type
// application/x-gsma-rsp-asn1, with euiccInfo1 present and no expert item.
func initiateAuthenticationRequestEsipaHex() string {
	challenge := "8110" + "000102030405060708090a0b0c0d0e0f"
	verification := "a916" + "0414" + strings.Repeat("11", 20)
	signing := "aa16" + "0414" + strings.Repeat("22", 20)
	info1 := "bf2035" + "8203020300" + verification + signing
	transaction := "820101"
	return "bf394d" + challenge + info1 + transaction
}

func TestTaggedReferenceOptionalPresence(t *testing.T) {
	wire, err := hex.DecodeString(initiateAuthenticationRequestEsipaHex())
	if err != nil {
		t.Fatal(err)
	}
	var request sgp32.InitiateAuthenticationRequestEsipa
	if err := request.UnmarshalBER(wire); err != nil {
		t.Fatal(err)
	}
	info := request.EuiccInfo1
	if info == nil {
		t.Fatal("euiccInfo1 decoded as absent")
	}
	if !bytes.Equal(info.Svn, []byte{2, 3, 0}) {
		t.Fatalf("svn = %x", info.Svn)
	}
	if info.EuiccCiPKIdListForVerification == nil || len(info.EuiccCiPKIdListForVerification.Values) != 1 ||
		!bytes.Equal(info.EuiccCiPKIdListForVerification.Values[0], bytes.Repeat([]byte{0x11}, 20)) {
		t.Fatalf("verification list = %+v", info.EuiccCiPKIdListForVerification)
	}
	if info.EuiccCiPKIdListForSigning == nil || len(info.EuiccCiPKIdListForSigning.Values) != 1 ||
		!bytes.Equal(info.EuiccCiPKIdListForSigning.Values[0], bytes.Repeat([]byte{0x22}, 20)) {
		t.Fatalf("signing list = %+v", info.EuiccCiPKIdListForSigning)
	}
	if request.SmdpAddress != nil || request.EimTransactionId == nil || !bytes.Equal(*request.EimTransactionId, []byte{1}) {
		t.Fatalf("smdpAddress = %v, eimTransactionId = %v", request.SmdpAddress, request.EimTransactionId)
	}
	for name, encode := range map[string]func() ([]byte, error){
		"BER": func() ([]byte, error) { return request.MarshalBER() },
		"DER": request.MarshalDER,
	} {
		if out, err := encode(); err != nil || !bytes.Equal(out, wire) {
			t.Fatalf("%s = %x, %v; want %x", name, out, err, wire)
		}
	}
}

// BuiltInStandardAttributes with country-name ([APPLICATION 1] CHOICE, an
// explicit tag over the CHOICE) holding the iso-3166-alpha2-code
// PrintableString "US" (RFC 5280 Appendix A.1).
func TestTaggedReferenceCountryName(t *testing.T) {
	wire, err := hex.DecodeString("3006610413025553")
	if err != nil {
		t.Fatal(err)
	}
	var a22 sgp22.BuiltInStandardAttributes
	if err := a22.UnmarshalBER(wire); err != nil {
		t.Fatal(err)
	}
	if a22.CountryName == nil || a22.CountryName.Iso3166Alpha2Code == nil || *a22.CountryName.Iso3166Alpha2Code != "US" {
		t.Fatalf("sgp22 country-name = %+v", a22.CountryName)
	}
	if out, err := a22.MarshalBER(); err != nil || !bytes.Equal(out, wire) {
		t.Fatalf("sgp22 re-encode = %x, %v", out, err)
	}
	var a32 sgp32.BuiltInStandardAttributes
	if err := a32.UnmarshalBER(wire); err != nil {
		t.Fatal(err)
	}
	if a32.CountryName == nil || a32.CountryName.Iso3166Alpha2Code == nil || *a32.CountryName.Iso3166Alpha2Code != "US" {
		t.Fatalf("sgp32 country-name = %+v", a32.CountryName)
	}
	if out, err := a32.MarshalBER(); err != nil || !bytes.Equal(out, wire) {
		t.Fatalf("sgp32 re-encode = %x, %v", out, err)
	}
}
