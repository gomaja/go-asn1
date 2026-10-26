// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	bytes "bytes"
	s00 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s00"
	s13 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s13"
	s16 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s16"
	testing "testing"
)

func TestReplayHonorsCompleteCodecContext(t *testing.T) {
	message := s13.X2APMessageCodec()
	wire := listByteapiMust(message.EncodeAPER(x2APMessageAPERValueapiMust(message.New([]byte{1, 2, 3}))))
	decoded, _, err := message.DecodeAPER(wire)
	if err != nil {
		t.Fatal(err)
	}
	// Concrete holders are source-specific. Exercise the same mismatch by
	// retaining the received holder while selecting the PLMN encoder/context.
	plmn := message
	*s13.X2apInternalX2APMessageValueCodecFieldContext(&plmn) = s00.X2apInternalPLMNIdentityValueCodecFieldContextRead(s16.PLMNIdentityCodec())
	*s13.X2apInternalX2APMessageValueCodecFieldEncode(&plmn) = s00.X2apInternalPLMNIdentityValueCodecFieldEncodeRead(s16.PLMNIdentityCodec())
	got := listByteapiMust(plmn.EncodeAPER(decoded))
	want := listByteapiMust(plmn.EncodeAPER(x2APMessageAPERValueapiMust(plmn.New([]byte{1, 2, 3}))))
	if !bytes.Equal(got, want) || bytes.Equal(got, wire) {
		t.Fatal("replayed framing from a different source constraint")
	}
}
