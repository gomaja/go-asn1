// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	s00 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s00"
)

// ListBytePayloadCodec is the concrete PayloadCodec[[]byte].
type ListBytePayloadCodec struct {
	decode func([]byte, s00.PayloadLimits) ([]byte, s00.PayloadReport,

		error)
	encode func([]byte, s00.PayloadLimits,

	) ([]byte, error)
}
