// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	aper "github.com/gomaja/go-asn1/telecom/lte/x2ap/runtime/aper"
)

type censusComplete interface {
	UnmarshalAPER([]byte, ...aper.DecodeOption) (aper.DecodeReport, error)
	MarshalAPER(...aper.EncodeOption) ([]byte, error)
	ReceivedForm() aper.ReceivedForm
}
