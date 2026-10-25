// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	fmt "fmt"
	s00 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s00"
	aper "github.com/gomaja/go-asn1/telecom/lte/x2ap/runtime/aper"
)

func IntNewPayloadCodec(
	decode func([]byte, s00.PayloadLimits) (int, s00.PayloadReport,

		error),
	encode func(int, s00.PayloadLimits,

	) ([]byte, error),
) (IntPayloadCodec, error) {
	if decode == nil || encode == nil {
		return IntPayloadCodec{}, aper.OperationError(aper.OperationError(fmt.Errorf("%w: payload binding: nil callback", aper.ErrInvalidValue), "Payload.binding"), "PayloadCodec")
	}
	return IntPayloadCodec{decode: decode, encode: encode}, aper.OperationError(nil, "PayloadCodec")
}
