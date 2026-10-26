// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	s00 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s00"
	aper "github.com/gomaja/go-asn1/telecom/lte/x2ap/runtime/aper"
)

// Int64APERValue is the concrete APERValue[int64].
type Int64APERValue struct {
	context s00.X2apInternalCodecContext
	Value   int64

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}
