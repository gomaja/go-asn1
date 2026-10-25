// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	fmt "fmt"
	s00 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s00"
	aper "github.com/gomaja/go-asn1/telecom/lte/x2ap/runtime/aper"
)

func IntEncodePayload(value int,

	codec IntPayloadCodec, limits s00.PayloadLimits) ([]byte, error) {
	if codec.decode == nil || codec.encode == nil {
		return nil, aper.OperationError(fmt.Errorf("%w: payload binding: zero codec", aper.ErrInvalidValue), "Payload.binding")
	}
	limits = s00.X2apInternalEffectivePayloadLimits(limits)
	wire, err := codec.encode(value, limits)
	if err != nil {
		return nil, fmt.Errorf("payload encode: %w", err)
	}
	if uint64(len(wire)) > limits.MaxOutputBytes {
		return nil, aper.OperationError(fmt.Errorf("%w: payload output: %d bytes exceed limit %d", aper.ErrLimit, len(wire), limits.MaxOutputBytes), "Payload.output")
	}
	if uint64(len(wire)) > limits.MaxAllocatedBytes {
		return nil, aper.OperationError(fmt.Errorf("%w: payload output copy: %d bytes exceed allocation limit %d", aper.ErrLimit, len(wire), limits.MaxAllocatedBytes), "Payload.output")
	}
	if uint64(len(wire)) > limits.MaxWork {
		return nil, aper.OperationError(fmt.Errorf("%w: payload output copy work", aper.ErrLimit), "Payload.output")
	}
	return append([]byte(nil), wire...), nil
}
