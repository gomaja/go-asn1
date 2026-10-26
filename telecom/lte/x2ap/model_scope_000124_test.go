// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	bytes "bytes"
	aper "github.com/gomaja/go-asn1/telecom/lte/x2ap/runtime/aper"
	testing "testing"
)

func TestValueDecodeAndUnchangedEncodeCallNoEncoder(t *testing.T) {
	calls := 0
	c := Int64ValueCodec{decode: func(data []byte, _ aper.DecodeState) (int64, error) { return int64(data[0]), nil }, encode: func(v int64, _ bool, _ *aper.DecodeBudget) ([]byte, error) { calls++; return []byte{byte(v)}, nil }, capture: func(v int64, state aper.DecodeState) (int64, aper.Snapshot) {
		s := aper.SemanticCaptureFor(state)
		f := s.Begin()
		s.Int(v)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v int64, root aper.Snapshot, budget aper.DecodeBudget) aper.ReplayPlan {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s.Int(v)
		s.End(f, root, false)
		return s.Plan()
	}}
	v, _, err := c.DecodeAPER([]byte{42})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 0 {
		t.Fatal("decode called encoder")
	}
	got := listByteapiMust(c.EncodeAPER(v))
	if calls != 0 || !bytes.Equal(got, []byte{42}) {
		t.Fatal("unchanged encode called encoder")
	}
	got[0] = 9
	if listByteapiMust(c.EncodeAPER(v))[0] != 42 {
		t.Fatal("output aliases original")
	}
	v.Value = 43
	if listByteapiMust(c.EncodeAPER(v))[0] != 43 || calls != 1 {
		t.Fatal("edited encode did not call encoder once")
	}
	v.Value = 42
	if listByteapiMust(c.EncodeAPER(v))[0] != 42 || calls != 1 {
		t.Fatal("restored encode called encoder")
	}
	listByteapiMust(c.EncodeAPER(v.WithoutReplay()))
	if calls != 2 {
		t.Fatal("fresh encode did not call encoder")
	}
}
