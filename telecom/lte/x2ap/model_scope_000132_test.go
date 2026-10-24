// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	s12 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s12"
	s16 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s16"
	testing "testing"
)

// X.691 (02/2021) §30.5.3 assigns VisibleString codes 32 through 126;
// §30.5.4(a) retains those codes in the aligned octet.
func TestURIVisibleAlphabetIsStrict(t *testing.T) {
	for _, code := range []byte{0, 31, 127, 128, 255} {
		if _, _, err := s16.URIAddressCodec().DecodeAPER([]byte{1, code}); err == nil {
			t.Fatalf("VisibleString accepted code %d", code)
		}
		if _, err := s16.URIAddressCodec().New(s12.URIAddress(string([]byte{code}))); err == nil {
			t.Fatalf("VisibleString encoded code %d", code)
		}
	}
	for _, code := range []byte{32, 126} {
		if _, _, err := s16.URIAddressCodec().DecodeAPER([]byte{1, code}); err != nil {
			t.Fatal(err)
		}
	}
}
