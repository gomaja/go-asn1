// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	bytes "bytes"
	s00 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s00"
	aper "github.com/gomaja/go-asn1/telecom/lte/x2ap/runtime/aper"
	testing "testing"
)

// The callback counter separates semantic capture from encoding, including
// after caller input reuse and edit/restore (X.691 (02/2021) §§11.1–11.2).
func expectedActivityPeriodsemanticEditRestore(t *testing.T, c s00.ExpectedActivityPeriodValueCodec, initial s00.ExpectedActivityPeriod, edit, restore func(*s00.ExpectedActivityPeriod)) {
	t.Helper()
	encoder := *s00.X2apInternalExpectedActivityPeriodValueCodecFieldEncode(&c)
	calls := 0
	*s00.X2apInternalExpectedActivityPeriodValueCodecFieldEncode(&c) = func(v s00.ExpectedActivityPeriod, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		calls++
		return encoder(v, fresh, budget)
	}
	wire := listByteapiMust(c.EncodeAPER(expectedActivityPeriodAPERValueapiMust(c.New(initial))))
	original := bytes.Clone(wire)
	calls = 0
	v, _, err := c.DecodeAPER(wire)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 0 {
		t.Fatal("decode called value encoder")
	}
	for i := range wire {
		wire[i] ^= 0xff
	}
	got := listByteapiMust(c.EncodeAPER(v))
	if !bytes.Equal(got, original) || calls != 0 {
		t.Fatal("unchanged encode called encoder or borrowed input")
	}
	got[0] ^= 0xff
	if !bytes.Equal(listByteapiMust(c.EncodeAPER(v)), original) {
		t.Fatal("encode exposed received storage")
	}
	edit(&v.Value)
	got = listByteapiMust(c.EncodeAPER(v))
	want := listByteapiMust(c.EncodeAPER(v, aper.WithoutReplay()))
	if bytes.Equal(got, original) || !bytes.Equal(got, want) {
		t.Fatal("edit did not reach encoder")
	}
	before := calls
	restore(&v.Value)
	if !bytes.Equal(listByteapiMust(c.EncodeAPER(v)), original) || calls != before {
		t.Fatal("restored encode called value encoder")
	}
}
