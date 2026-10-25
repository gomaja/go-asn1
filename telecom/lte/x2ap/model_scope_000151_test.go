// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	fmt "fmt"
	s00 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s00"
	aper "github.com/gomaja/go-asn1/telecom/lte/x2ap/runtime/aper"
)

func ListByteDecodePayload(data []byte, codec ListBytePayloadCodec, limits s00.PayloadLimits) ([]byte, s00.PayloadReport,

	error) {
	var zero []byte

	if codec.decode == nil || codec.encode == nil {
		return zero, s00.PayloadReport{}, aper.OperationError(fmt.Errorf("%w: payload binding: zero codec", aper.ErrInvalidValue), "Payload.binding")
	}
	limits = s00.X2apInternalEffectivePayloadLimits(limits)
	if uint64(len(data)) > limits.MaxInputBytes {
		return zero, s00.PayloadReport{}, aper.OperationError(fmt.Errorf("%w: payload input: %d bytes exceed limit %d", aper.ErrLimit, len(data), limits.MaxInputBytes), "Payload.input")
	}
	if uint64(len(data)) > limits.MaxAllocatedBytes {
		return zero, s00.PayloadReport{}, aper.OperationError(fmt.Errorf("%w: payload input copy: %d bytes exceed allocation limit %d", aper.ErrLimit, len(data), limits.MaxAllocatedBytes), "Payload.input")
	}
	if uint64(len(data)) > limits.MaxWork {
		return zero, s00.PayloadReport{}, aper.OperationError(fmt.Errorf("%w: payload input copy work", aper.ErrLimit), "Payload.input")
	}
	owned := append([]byte(nil), data...)
	value, report, err := codec.decode(owned, limits)
	if err != nil {
		return zero, report, fmt.Errorf("payload decode: %w", err)
	}
	if uint64(len(report.Deviations)) > limits.MaxReports {
		return zero, s00.PayloadReport{}, aper.OperationError(fmt.Errorf("%w: payload report: %d deviations exceed limit %d", aper.ErrLimit, len(report.Deviations), limits.MaxReports), "Payload.report")
	}
	return value, report, nil
}
