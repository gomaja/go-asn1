// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	s06 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s06"
	s14 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s14"
	testing "testing"
)

func replayListWire(t *testing.T, n int) []byte {
	t.Helper()
	return listByteapiMust((&s14.CriticalityDiagnosticsIEListComplete{Value: make(s06.CriticalityDiagnosticsIEList, n)}).MarshalAPER())
}
