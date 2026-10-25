// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	s00 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s00"
	aper "github.com/gomaja/go-asn1/telecom/lte/x2ap/runtime/aper"
)

// Int64ValueCodec is the concrete ValueCodec[int64].
type Int64ValueCodec struct {
	context s00.X2apInternalCodecContext
	capture func(int64, aper.DecodeState,

	) (int64, aper.Snapshot,

	)
	compare func(int64, aper.Snapshot, aper.DecodeBudget,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (int64,

		error)
	encode func(int64,

		bool, *aper.DecodeBudget) ([]byte, error)
}
