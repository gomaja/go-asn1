// Code generated from formal ASN.1 objects and values. DO NOT EDIT.

package v21_map_errors

import (
	"fmt"

	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime/ber"
	__asn1pkg_v21_map_er_datatypes "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes"
	__asn1pkg_v21_map_ss_datatypes "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_ss_datatypes"
)

// SourceRef identifies the formal source assignment, not procedure policy.
type SourceRef struct{ Document, Edition, Clause, Module, Assignment, SHA256 string }
type TypeRef struct{ ModuleOID, ASN1Name, GoPackage, GoName string }

// NoParameter denotes an absent source type field. It has no NULL codec.
type NoParameter struct{}

// ErrorValue preserves carrying-component presence independently of source type.
type ErrorValue[P any] struct{ Parameter *P }
type errorBinding[P, I, C any] struct {
	code      C
	info      func() I
	parameter ValueCodec[P]
}

func (d errorBinding[P, I, C]) Code() C { return d.code }
func (d errorBinding[P, I, C]) Info() I {
	if d.info == nil {
		var zero I
		return zero
	}
	return d.info()
}
func (d errorBinding[P, I, C]) Parameter() (ValueCodec[P], bool) {
	return d.parameter, d.parameter.valid()
}
func decodeErrorParameter[P any](data []byte, present bool, codec ValueCodec[P], opts ...ber.DecodeOption) (*ErrorValue[P], error) {
	if !present {
		if len(data) != 0 {
			return nil, fmt.Errorf("%w: absent parameter has bytes", ber.ErrInvalidBinding)
		}
		return &ErrorValue[P]{}, nil
	}
	if !codec.valid() {
		return nil, fmt.Errorf("%w: source error has no PARAMETER", ber.ErrInvalidBinding)
	}
	v, err := codec.DecodeBER(data, opts...)
	if err != nil {
		return nil, err
	}
	return &ErrorValue[P]{Parameter: &v}, nil
}
func encodeErrorParameter[P any](value *ErrorValue[P], codec ValueCodec[P], opts ...ber.EncodeOption) ([]byte, bool, error) {
	if value.Parameter == nil {
		return nil, false, nil
	}
	if !codec.valid() {
		return nil, false, fmt.Errorf("%w: source error has no PARAMETER", ber.ErrInvalidBinding)
	}
	data, err := codec.EncodeBER(*value.Parameter, opts...)
	if err != nil {
		return nil, false, err
	}
	return data, true, nil
}
func adaptValueCodec[T any](codec interface {
	DecodeBER([]byte, ...ber.DecodeOption) (T, error)
	EncodeBER(T, ...ber.EncodeOption) ([]byte, error)
	EncodeDER(T) ([]byte, error)
}) ValueCodec[T] {
	return ValueCodec[T]{decode: codec.DecodeBER, encode: codec.EncodeBER, der: codec.EncodeDER}
}

func apiBool(v bool) *bool { return &v }

type HistoricalMAPErrorInfo struct {
	Name              string
	Code              HistoricalMAPErrorCode
	Parameter         *TypeRef
	ParameterOptional *bool
	Source            SourceRef
}
type HistoricalMAPErrorDescriptor[P any] struct {
	errorBinding[P, HistoricalMAPErrorInfo, HistoricalMAPErrorCode]
}

// HistoricalMAPErrorsAbsentSubscriberErrorDescriptor binds the formal ERROR object MAP-Errors.absentSubscriber (X.880 §8.3).
func HistoricalMAPErrorsAbsentSubscriberErrorDescriptor() HistoricalMAPErrorDescriptor[__asn1pkg_v21_map_er_datatypes.ERAbsentSubscriberParam] {
	return HistoricalMAPErrorDescriptor[__asn1pkg_v21_map_er_datatypes.ERAbsentSubscriberParam]{errorBinding[__asn1pkg_v21_map_er_datatypes.ERAbsentSubscriberParam, HistoricalMAPErrorInfo, HistoricalMAPErrorCode]{code: HistoricalMAPErrorsAbsentSubscriber, info: infoHistoricalMAPErrorsAbsentSubscriberError, parameter: adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERAbsentSubscriberParam](__asn1pkg_v21_map_er_datatypes.ERAbsentSubscriberParamCodec())}}
}
func infoHistoricalMAPErrorsAbsentSubscriberError() HistoricalMAPErrorInfo {
	return HistoricalMAPErrorInfo{Name: "absentSubscriber", Code: HistoricalMAPErrorsAbsentSubscriber, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "AbsentSubscriberParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERAbsentSubscriberParam"}, ParameterOptional: nil, Source: sourceInfo0("absentSubscriber", "17.6.6")}
}

// HistoricalMAPErrorsAbsentSubscriberSMErrorDescriptor binds the formal ERROR object MAP-Errors.absentSubscriberSM (X.880 §8.3).
func HistoricalMAPErrorsAbsentSubscriberSMErrorDescriptor() HistoricalMAPErrorDescriptor[__asn1pkg_v21_map_er_datatypes.ERAbsentSubscriberSMParam] {
	return HistoricalMAPErrorDescriptor[__asn1pkg_v21_map_er_datatypes.ERAbsentSubscriberSMParam]{errorBinding[__asn1pkg_v21_map_er_datatypes.ERAbsentSubscriberSMParam, HistoricalMAPErrorInfo, HistoricalMAPErrorCode]{code: HistoricalMAPErrorsAbsentSubscriberSM, info: infoHistoricalMAPErrorsAbsentSubscriberSMError, parameter: adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERAbsentSubscriberSMParam](__asn1pkg_v21_map_er_datatypes.ERAbsentSubscriberSMParamCodec())}}
}
func infoHistoricalMAPErrorsAbsentSubscriberSMError() HistoricalMAPErrorInfo {
	return HistoricalMAPErrorInfo{Name: "absentSubscriberSM", Code: HistoricalMAPErrorsAbsentSubscriberSM, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "AbsentSubscriberSM-Param", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERAbsentSubscriberSMParam"}, ParameterOptional: nil, Source: sourceInfo0("absentSubscriberSM", "17.6.6")}
}

// HistoricalMAPErrorsAtiNotAllowedErrorDescriptor binds the formal ERROR object MAP-Errors.ati-NotAllowed (X.880 §8.3).
func HistoricalMAPErrorsAtiNotAllowedErrorDescriptor() HistoricalMAPErrorDescriptor[__asn1pkg_v21_map_er_datatypes.ERATINotAllowedParam] {
	return HistoricalMAPErrorDescriptor[__asn1pkg_v21_map_er_datatypes.ERATINotAllowedParam]{errorBinding[__asn1pkg_v21_map_er_datatypes.ERATINotAllowedParam, HistoricalMAPErrorInfo, HistoricalMAPErrorCode]{code: HistoricalMAPErrorsAtiNotAllowed, info: infoHistoricalMAPErrorsAtiNotAllowedError, parameter: adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERATINotAllowedParam](__asn1pkg_v21_map_er_datatypes.ERATINotAllowedParamCodec())}}
}
func infoHistoricalMAPErrorsAtiNotAllowedError() HistoricalMAPErrorInfo {
	return HistoricalMAPErrorInfo{Name: "ati-NotAllowed", Code: HistoricalMAPErrorsAtiNotAllowed, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "ATI-NotAllowedParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERATINotAllowedParam"}, ParameterOptional: nil, Source: sourceInfo0("ati-NotAllowed", "17.6.6")}
}

// HistoricalMAPErrorsAtmNotAllowedErrorDescriptor binds the formal ERROR object MAP-Errors.atm-NotAllowed (X.880 §8.3).
func HistoricalMAPErrorsAtmNotAllowedErrorDescriptor() HistoricalMAPErrorDescriptor[__asn1pkg_v21_map_er_datatypes.ERATMNotAllowedParam] {
	return HistoricalMAPErrorDescriptor[__asn1pkg_v21_map_er_datatypes.ERATMNotAllowedParam]{errorBinding[__asn1pkg_v21_map_er_datatypes.ERATMNotAllowedParam, HistoricalMAPErrorInfo, HistoricalMAPErrorCode]{code: HistoricalMAPErrorsAtmNotAllowed, info: infoHistoricalMAPErrorsAtmNotAllowedError, parameter: adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERATMNotAllowedParam](__asn1pkg_v21_map_er_datatypes.ERATMNotAllowedParamCodec())}}
}
func infoHistoricalMAPErrorsAtmNotAllowedError() HistoricalMAPErrorInfo {
	return HistoricalMAPErrorInfo{Name: "atm-NotAllowed", Code: HistoricalMAPErrorsAtmNotAllowed, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "ATM-NotAllowedParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERATMNotAllowedParam"}, ParameterOptional: nil, Source: sourceInfo0("atm-NotAllowed", "17.6.6")}
}

// HistoricalMAPErrorsAtsiNotAllowedErrorDescriptor binds the formal ERROR object MAP-Errors.atsi-NotAllowed (X.880 §8.3).
func HistoricalMAPErrorsAtsiNotAllowedErrorDescriptor() HistoricalMAPErrorDescriptor[__asn1pkg_v21_map_er_datatypes.ERATSINotAllowedParam] {
	return HistoricalMAPErrorDescriptor[__asn1pkg_v21_map_er_datatypes.ERATSINotAllowedParam]{errorBinding[__asn1pkg_v21_map_er_datatypes.ERATSINotAllowedParam, HistoricalMAPErrorInfo, HistoricalMAPErrorCode]{code: HistoricalMAPErrorsAtsiNotAllowed, info: infoHistoricalMAPErrorsAtsiNotAllowedError, parameter: adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERATSINotAllowedParam](__asn1pkg_v21_map_er_datatypes.ERATSINotAllowedParamCodec())}}
}
func infoHistoricalMAPErrorsAtsiNotAllowedError() HistoricalMAPErrorInfo {
	return HistoricalMAPErrorInfo{Name: "atsi-NotAllowed", Code: HistoricalMAPErrorsAtsiNotAllowed, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "ATSI-NotAllowedParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERATSINotAllowedParam"}, ParameterOptional: nil, Source: sourceInfo0("atsi-NotAllowed", "17.6.6")}
}

// HistoricalMAPErrorsBearerServiceNotProvisionedErrorDescriptor binds the formal ERROR object MAP-Errors.bearerServiceNotProvisioned (X.880 §8.3).
func HistoricalMAPErrorsBearerServiceNotProvisionedErrorDescriptor() HistoricalMAPErrorDescriptor[__asn1pkg_v21_map_er_datatypes.ERBearerServNotProvParam] {
	return HistoricalMAPErrorDescriptor[__asn1pkg_v21_map_er_datatypes.ERBearerServNotProvParam]{errorBinding[__asn1pkg_v21_map_er_datatypes.ERBearerServNotProvParam, HistoricalMAPErrorInfo, HistoricalMAPErrorCode]{code: HistoricalMAPErrorsBearerServiceNotProvisioned, info: infoHistoricalMAPErrorsBearerServiceNotProvisionedError, parameter: adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERBearerServNotProvParam](__asn1pkg_v21_map_er_datatypes.ERBearerServNotProvParamCodec())}}
}
func infoHistoricalMAPErrorsBearerServiceNotProvisionedError() HistoricalMAPErrorInfo {
	return HistoricalMAPErrorInfo{Name: "bearerServiceNotProvisioned", Code: HistoricalMAPErrorsBearerServiceNotProvisioned, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "BearerServNotProvParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERBearerServNotProvParam"}, ParameterOptional: nil, Source: sourceInfo0("bearerServiceNotProvisioned", "17.6.6")}
}

// HistoricalMAPErrorsBusySubscriberErrorDescriptor binds the formal ERROR object MAP-Errors.busySubscriber (X.880 §8.3).
func HistoricalMAPErrorsBusySubscriberErrorDescriptor() HistoricalMAPErrorDescriptor[__asn1pkg_v21_map_er_datatypes.ERBusySubscriberParam] {
	return HistoricalMAPErrorDescriptor[__asn1pkg_v21_map_er_datatypes.ERBusySubscriberParam]{errorBinding[__asn1pkg_v21_map_er_datatypes.ERBusySubscriberParam, HistoricalMAPErrorInfo, HistoricalMAPErrorCode]{code: HistoricalMAPErrorsBusySubscriber, info: infoHistoricalMAPErrorsBusySubscriberError, parameter: adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERBusySubscriberParam](__asn1pkg_v21_map_er_datatypes.ERBusySubscriberParamCodec())}}
}
func infoHistoricalMAPErrorsBusySubscriberError() HistoricalMAPErrorInfo {
	return HistoricalMAPErrorInfo{Name: "busySubscriber", Code: HistoricalMAPErrorsBusySubscriber, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "BusySubscriberParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERBusySubscriberParam"}, ParameterOptional: nil, Source: sourceInfo0("busySubscriber", "17.6.6")}
}

// HistoricalMAPErrorsCallBarredErrorDescriptor binds the formal ERROR object MAP-Errors.callBarred (X.880 §8.3).
func HistoricalMAPErrorsCallBarredErrorDescriptor() HistoricalMAPErrorDescriptor[__asn1pkg_v21_map_er_datatypes.ERCallBarredParam] {
	return HistoricalMAPErrorDescriptor[__asn1pkg_v21_map_er_datatypes.ERCallBarredParam]{errorBinding[__asn1pkg_v21_map_er_datatypes.ERCallBarredParam, HistoricalMAPErrorInfo, HistoricalMAPErrorCode]{code: HistoricalMAPErrorsCallBarred, info: infoHistoricalMAPErrorsCallBarredError, parameter: adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERCallBarredParam](__asn1pkg_v21_map_er_datatypes.ERCallBarredParamCodec())}}
}
func infoHistoricalMAPErrorsCallBarredError() HistoricalMAPErrorInfo {
	return HistoricalMAPErrorInfo{Name: "callBarred", Code: HistoricalMAPErrorsCallBarred, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "CallBarredParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERCallBarredParam"}, ParameterOptional: nil, Source: sourceInfo0("callBarred", "17.6.6")}
}

// HistoricalMAPErrorsCugRejectErrorDescriptor binds the formal ERROR object MAP-Errors.cug-Reject (X.880 §8.3).
func HistoricalMAPErrorsCugRejectErrorDescriptor() HistoricalMAPErrorDescriptor[__asn1pkg_v21_map_er_datatypes.ERCUGRejectParam] {
	return HistoricalMAPErrorDescriptor[__asn1pkg_v21_map_er_datatypes.ERCUGRejectParam]{errorBinding[__asn1pkg_v21_map_er_datatypes.ERCUGRejectParam, HistoricalMAPErrorInfo, HistoricalMAPErrorCode]{code: HistoricalMAPErrorsCugReject, info: infoHistoricalMAPErrorsCugRejectError, parameter: adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERCUGRejectParam](__asn1pkg_v21_map_er_datatypes.ERCUGRejectParamCodec())}}
}
func infoHistoricalMAPErrorsCugRejectError() HistoricalMAPErrorInfo {
	return HistoricalMAPErrorInfo{Name: "cug-Reject", Code: HistoricalMAPErrorsCugReject, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "CUG-RejectParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERCUGRejectParam"}, ParameterOptional: nil, Source: sourceInfo0("cug-Reject", "17.6.6")}
}

// HistoricalMAPErrorsDataMissingErrorDescriptor binds the formal ERROR object MAP-Errors.dataMissing (X.880 §8.3).
func HistoricalMAPErrorsDataMissingErrorDescriptor() HistoricalMAPErrorDescriptor[__asn1pkg_v21_map_er_datatypes.ERDataMissingParam] {
	return HistoricalMAPErrorDescriptor[__asn1pkg_v21_map_er_datatypes.ERDataMissingParam]{errorBinding[__asn1pkg_v21_map_er_datatypes.ERDataMissingParam, HistoricalMAPErrorInfo, HistoricalMAPErrorCode]{code: HistoricalMAPErrorsDataMissing, info: infoHistoricalMAPErrorsDataMissingError, parameter: adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERDataMissingParam](__asn1pkg_v21_map_er_datatypes.ERDataMissingParamCodec())}}
}
func infoHistoricalMAPErrorsDataMissingError() HistoricalMAPErrorInfo {
	return HistoricalMAPErrorInfo{Name: "dataMissing", Code: HistoricalMAPErrorsDataMissing, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "DataMissingParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERDataMissingParam"}, ParameterOptional: nil, Source: sourceInfo0("dataMissing", "17.6.6")}
}

// HistoricalMAPErrorsFacilityNotSupportedErrorDescriptor binds the formal ERROR object MAP-Errors.facilityNotSupported (X.880 §8.3).
func HistoricalMAPErrorsFacilityNotSupportedErrorDescriptor() HistoricalMAPErrorDescriptor[__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParam] {
	return HistoricalMAPErrorDescriptor[__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParam]{errorBinding[__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParam, HistoricalMAPErrorInfo, HistoricalMAPErrorCode]{code: HistoricalMAPErrorsFacilityNotSupported, info: infoHistoricalMAPErrorsFacilityNotSupportedError, parameter: adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParam](__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParamCodec())}}
}
func infoHistoricalMAPErrorsFacilityNotSupportedError() HistoricalMAPErrorInfo {
	return HistoricalMAPErrorInfo{Name: "facilityNotSupported", Code: HistoricalMAPErrorsFacilityNotSupported, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "FacilityNotSupParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERFacilityNotSupParam"}, ParameterOptional: nil, Source: sourceInfo0("facilityNotSupported", "17.6.6")}
}

// HistoricalMAPErrorsForwardingFailedErrorDescriptor binds the formal ERROR object MAP-Errors.forwardingFailed (X.880 §8.3).
func HistoricalMAPErrorsForwardingFailedErrorDescriptor() HistoricalMAPErrorDescriptor[__asn1pkg_v21_map_er_datatypes.ERForwardingFailedParam] {
	return HistoricalMAPErrorDescriptor[__asn1pkg_v21_map_er_datatypes.ERForwardingFailedParam]{errorBinding[__asn1pkg_v21_map_er_datatypes.ERForwardingFailedParam, HistoricalMAPErrorInfo, HistoricalMAPErrorCode]{code: HistoricalMAPErrorsForwardingFailed, info: infoHistoricalMAPErrorsForwardingFailedError, parameter: adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERForwardingFailedParam](__asn1pkg_v21_map_er_datatypes.ERForwardingFailedParamCodec())}}
}
func infoHistoricalMAPErrorsForwardingFailedError() HistoricalMAPErrorInfo {
	return HistoricalMAPErrorInfo{Name: "forwardingFailed", Code: HistoricalMAPErrorsForwardingFailed, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "ForwardingFailedParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERForwardingFailedParam"}, ParameterOptional: nil, Source: sourceInfo0("forwardingFailed", "17.6.6")}
}

// HistoricalMAPErrorsForwardingViolationErrorDescriptor binds the formal ERROR object MAP-Errors.forwardingViolation (X.880 §8.3).
func HistoricalMAPErrorsForwardingViolationErrorDescriptor() HistoricalMAPErrorDescriptor[__asn1pkg_v21_map_er_datatypes.ERForwardingViolationParam] {
	return HistoricalMAPErrorDescriptor[__asn1pkg_v21_map_er_datatypes.ERForwardingViolationParam]{errorBinding[__asn1pkg_v21_map_er_datatypes.ERForwardingViolationParam, HistoricalMAPErrorInfo, HistoricalMAPErrorCode]{code: HistoricalMAPErrorsForwardingViolation, info: infoHistoricalMAPErrorsForwardingViolationError, parameter: adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERForwardingViolationParam](__asn1pkg_v21_map_er_datatypes.ERForwardingViolationParamCodec())}}
}
func infoHistoricalMAPErrorsForwardingViolationError() HistoricalMAPErrorInfo {
	return HistoricalMAPErrorInfo{Name: "forwardingViolation", Code: HistoricalMAPErrorsForwardingViolation, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "ForwardingViolationParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERForwardingViolationParam"}, ParameterOptional: nil, Source: sourceInfo0("forwardingViolation", "17.6.6")}
}

// HistoricalMAPErrorsIllegalEquipmentErrorDescriptor binds the formal ERROR object MAP-Errors.illegalEquipment (X.880 §8.3).
func HistoricalMAPErrorsIllegalEquipmentErrorDescriptor() HistoricalMAPErrorDescriptor[__asn1pkg_v21_map_er_datatypes.ERIllegalEquipmentParam] {
	return HistoricalMAPErrorDescriptor[__asn1pkg_v21_map_er_datatypes.ERIllegalEquipmentParam]{errorBinding[__asn1pkg_v21_map_er_datatypes.ERIllegalEquipmentParam, HistoricalMAPErrorInfo, HistoricalMAPErrorCode]{code: HistoricalMAPErrorsIllegalEquipment, info: infoHistoricalMAPErrorsIllegalEquipmentError, parameter: adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERIllegalEquipmentParam](__asn1pkg_v21_map_er_datatypes.ERIllegalEquipmentParamCodec())}}
}
func infoHistoricalMAPErrorsIllegalEquipmentError() HistoricalMAPErrorInfo {
	return HistoricalMAPErrorInfo{Name: "illegalEquipment", Code: HistoricalMAPErrorsIllegalEquipment, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "IllegalEquipmentParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERIllegalEquipmentParam"}, ParameterOptional: nil, Source: sourceInfo0("illegalEquipment", "17.6.6")}
}

// HistoricalMAPErrorsIllegalSSOperationErrorDescriptor binds the formal ERROR object MAP-Errors.illegalSS-Operation (X.880 §8.3).
func HistoricalMAPErrorsIllegalSSOperationErrorDescriptor() HistoricalMAPErrorDescriptor[__asn1pkg_v21_map_er_datatypes.ERIllegalSSOperationParam] {
	return HistoricalMAPErrorDescriptor[__asn1pkg_v21_map_er_datatypes.ERIllegalSSOperationParam]{errorBinding[__asn1pkg_v21_map_er_datatypes.ERIllegalSSOperationParam, HistoricalMAPErrorInfo, HistoricalMAPErrorCode]{code: HistoricalMAPErrorsIllegalSSOperation, info: infoHistoricalMAPErrorsIllegalSSOperationError, parameter: adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERIllegalSSOperationParam](__asn1pkg_v21_map_er_datatypes.ERIllegalSSOperationParamCodec())}}
}
func infoHistoricalMAPErrorsIllegalSSOperationError() HistoricalMAPErrorInfo {
	return HistoricalMAPErrorInfo{Name: "illegalSS-Operation", Code: HistoricalMAPErrorsIllegalSSOperation, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "IllegalSS-OperationParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERIllegalSSOperationParam"}, ParameterOptional: nil, Source: sourceInfo0("illegalSS-Operation", "17.6.6")}
}

// HistoricalMAPErrorsIllegalSubscriberErrorDescriptor binds the formal ERROR object MAP-Errors.illegalSubscriber (X.880 §8.3).
func HistoricalMAPErrorsIllegalSubscriberErrorDescriptor() HistoricalMAPErrorDescriptor[__asn1pkg_v21_map_er_datatypes.ERIllegalSubscriberParam] {
	return HistoricalMAPErrorDescriptor[__asn1pkg_v21_map_er_datatypes.ERIllegalSubscriberParam]{errorBinding[__asn1pkg_v21_map_er_datatypes.ERIllegalSubscriberParam, HistoricalMAPErrorInfo, HistoricalMAPErrorCode]{code: HistoricalMAPErrorsIllegalSubscriber, info: infoHistoricalMAPErrorsIllegalSubscriberError, parameter: adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERIllegalSubscriberParam](__asn1pkg_v21_map_er_datatypes.ERIllegalSubscriberParamCodec())}}
}
func infoHistoricalMAPErrorsIllegalSubscriberError() HistoricalMAPErrorInfo {
	return HistoricalMAPErrorInfo{Name: "illegalSubscriber", Code: HistoricalMAPErrorsIllegalSubscriber, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "IllegalSubscriberParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERIllegalSubscriberParam"}, ParameterOptional: nil, Source: sourceInfo0("illegalSubscriber", "17.6.6")}
}

// HistoricalMAPErrorsIncompatibleTerminalErrorDescriptor binds the formal ERROR object MAP-Errors.incompatibleTerminal (X.880 §8.3).
func HistoricalMAPErrorsIncompatibleTerminalErrorDescriptor() HistoricalMAPErrorDescriptor[__asn1pkg_v21_map_er_datatypes.ERIncompatibleTerminalParam] {
	return HistoricalMAPErrorDescriptor[__asn1pkg_v21_map_er_datatypes.ERIncompatibleTerminalParam]{errorBinding[__asn1pkg_v21_map_er_datatypes.ERIncompatibleTerminalParam, HistoricalMAPErrorInfo, HistoricalMAPErrorCode]{code: HistoricalMAPErrorsIncompatibleTerminal, info: infoHistoricalMAPErrorsIncompatibleTerminalError, parameter: adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERIncompatibleTerminalParam](__asn1pkg_v21_map_er_datatypes.ERIncompatibleTerminalParamCodec())}}
}
func infoHistoricalMAPErrorsIncompatibleTerminalError() HistoricalMAPErrorInfo {
	return HistoricalMAPErrorInfo{Name: "incompatibleTerminal", Code: HistoricalMAPErrorsIncompatibleTerminal, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "IncompatibleTerminalParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERIncompatibleTerminalParam"}, ParameterOptional: nil, Source: sourceInfo0("incompatibleTerminal", "17.6.6")}
}

// HistoricalMAPErrorsInformationNotAvailableErrorDescriptor binds the formal ERROR object MAP-Errors.informationNotAvailable (X.880 §8.3).
func HistoricalMAPErrorsInformationNotAvailableErrorDescriptor() HistoricalMAPErrorDescriptor[__asn1pkg_v21_map_er_datatypes.ERInformationNotAvailableParam] {
	return HistoricalMAPErrorDescriptor[__asn1pkg_v21_map_er_datatypes.ERInformationNotAvailableParam]{errorBinding[__asn1pkg_v21_map_er_datatypes.ERInformationNotAvailableParam, HistoricalMAPErrorInfo, HistoricalMAPErrorCode]{code: HistoricalMAPErrorsInformationNotAvailable, info: infoHistoricalMAPErrorsInformationNotAvailableError, parameter: adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERInformationNotAvailableParam](__asn1pkg_v21_map_er_datatypes.ERInformationNotAvailableParamCodec())}}
}
func infoHistoricalMAPErrorsInformationNotAvailableError() HistoricalMAPErrorInfo {
	return HistoricalMAPErrorInfo{Name: "informationNotAvailable", Code: HistoricalMAPErrorsInformationNotAvailable, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "InformationNotAvailableParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERInformationNotAvailableParam"}, ParameterOptional: nil, Source: sourceInfo0("informationNotAvailable", "17.6.6")}
}

// HistoricalMAPErrorsLongTermDenialErrorDescriptor binds the formal ERROR object MAP-Errors.longTermDenial (X.880 §8.3).
func HistoricalMAPErrorsLongTermDenialErrorDescriptor() HistoricalMAPErrorDescriptor[__asn1pkg_v21_map_er_datatypes.ERLongTermDenialParam] {
	return HistoricalMAPErrorDescriptor[__asn1pkg_v21_map_er_datatypes.ERLongTermDenialParam]{errorBinding[__asn1pkg_v21_map_er_datatypes.ERLongTermDenialParam, HistoricalMAPErrorInfo, HistoricalMAPErrorCode]{code: HistoricalMAPErrorsLongTermDenial, info: infoHistoricalMAPErrorsLongTermDenialError, parameter: adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERLongTermDenialParam](__asn1pkg_v21_map_er_datatypes.ERLongTermDenialParamCodec())}}
}
func infoHistoricalMAPErrorsLongTermDenialError() HistoricalMAPErrorInfo {
	return HistoricalMAPErrorInfo{Name: "longTermDenial", Code: HistoricalMAPErrorsLongTermDenial, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "LongTermDenialParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERLongTermDenialParam"}, ParameterOptional: nil, Source: sourceInfo0("longTermDenial", "17.6.6")}
}

// HistoricalMAPErrorsMessageWaitingListFullErrorDescriptor binds the formal ERROR object MAP-Errors.messageWaitingListFull (X.880 §8.3).
func HistoricalMAPErrorsMessageWaitingListFullErrorDescriptor() HistoricalMAPErrorDescriptor[__asn1pkg_v21_map_er_datatypes.ERMessageWaitListFullParam] {
	return HistoricalMAPErrorDescriptor[__asn1pkg_v21_map_er_datatypes.ERMessageWaitListFullParam]{errorBinding[__asn1pkg_v21_map_er_datatypes.ERMessageWaitListFullParam, HistoricalMAPErrorInfo, HistoricalMAPErrorCode]{code: HistoricalMAPErrorsMessageWaitingListFull, info: infoHistoricalMAPErrorsMessageWaitingListFullError, parameter: adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERMessageWaitListFullParam](__asn1pkg_v21_map_er_datatypes.ERMessageWaitListFullParamCodec())}}
}
func infoHistoricalMAPErrorsMessageWaitingListFullError() HistoricalMAPErrorInfo {
	return HistoricalMAPErrorInfo{Name: "messageWaitingListFull", Code: HistoricalMAPErrorsMessageWaitingListFull, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "MessageWaitListFullParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERMessageWaitListFullParam"}, ParameterOptional: nil, Source: sourceInfo0("messageWaitingListFull", "17.6.6")}
}

// HistoricalMAPErrorsMmEventNotSupportedErrorDescriptor binds the formal ERROR object MAP-Errors.mm-EventNotSupported (X.880 §8.3).
func HistoricalMAPErrorsMmEventNotSupportedErrorDescriptor() HistoricalMAPErrorDescriptor[__asn1pkg_v21_map_er_datatypes.ERMMEventNotSupportedParam] {
	return HistoricalMAPErrorDescriptor[__asn1pkg_v21_map_er_datatypes.ERMMEventNotSupportedParam]{errorBinding[__asn1pkg_v21_map_er_datatypes.ERMMEventNotSupportedParam, HistoricalMAPErrorInfo, HistoricalMAPErrorCode]{code: HistoricalMAPErrorsMmEventNotSupported, info: infoHistoricalMAPErrorsMmEventNotSupportedError, parameter: adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERMMEventNotSupportedParam](__asn1pkg_v21_map_er_datatypes.ERMMEventNotSupportedParamCodec())}}
}
func infoHistoricalMAPErrorsMmEventNotSupportedError() HistoricalMAPErrorInfo {
	return HistoricalMAPErrorInfo{Name: "mm-EventNotSupported", Code: HistoricalMAPErrorsMmEventNotSupported, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "MM-EventNotSupported-Param", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERMMEventNotSupportedParam"}, ParameterOptional: nil, Source: sourceInfo0("mm-EventNotSupported", "17.6.6")}
}

// HistoricalMAPErrorsNegativePWCheckErrorDescriptor binds the formal ERROR object MAP-Errors.negativePW-Check (X.880 §8.3).
func HistoricalMAPErrorsNegativePWCheckErrorDescriptor() HistoricalMAPErrorDescriptor[NoParameter] {
	return HistoricalMAPErrorDescriptor[NoParameter]{errorBinding[NoParameter, HistoricalMAPErrorInfo, HistoricalMAPErrorCode]{code: HistoricalMAPErrorsNegativePWCheck, info: infoHistoricalMAPErrorsNegativePWCheckError, parameter: ValueCodec[NoParameter]{}}}
}
func infoHistoricalMAPErrorsNegativePWCheckError() HistoricalMAPErrorInfo {
	return HistoricalMAPErrorInfo{Name: "negativePW-Check", Code: HistoricalMAPErrorsNegativePWCheck, Parameter: nil, ParameterOptional: nil, Source: sourceInfo0("negativePW-Check", "17.6.6")}
}

// HistoricalMAPErrorsNoGroupCallNumberAvailableErrorDescriptor binds the formal ERROR object MAP-Errors.noGroupCallNumberAvailable (X.880 §8.3).
func HistoricalMAPErrorsNoGroupCallNumberAvailableErrorDescriptor() HistoricalMAPErrorDescriptor[__asn1pkg_v21_map_er_datatypes.ERNoGroupCallNbParam] {
	return HistoricalMAPErrorDescriptor[__asn1pkg_v21_map_er_datatypes.ERNoGroupCallNbParam]{errorBinding[__asn1pkg_v21_map_er_datatypes.ERNoGroupCallNbParam, HistoricalMAPErrorInfo, HistoricalMAPErrorCode]{code: HistoricalMAPErrorsNoGroupCallNumberAvailable, info: infoHistoricalMAPErrorsNoGroupCallNumberAvailableError, parameter: adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERNoGroupCallNbParam](__asn1pkg_v21_map_er_datatypes.ERNoGroupCallNbParamCodec())}}
}
func infoHistoricalMAPErrorsNoGroupCallNumberAvailableError() HistoricalMAPErrorInfo {
	return HistoricalMAPErrorInfo{Name: "noGroupCallNumberAvailable", Code: HistoricalMAPErrorsNoGroupCallNumberAvailable, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "NoGroupCallNbParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERNoGroupCallNbParam"}, ParameterOptional: nil, Source: sourceInfo0("noGroupCallNumberAvailable", "17.6.6")}
}

// HistoricalMAPErrorsNoHandoverNumberAvailableErrorDescriptor binds the formal ERROR object MAP-Errors.noHandoverNumberAvailable (X.880 §8.3).
func HistoricalMAPErrorsNoHandoverNumberAvailableErrorDescriptor() HistoricalMAPErrorDescriptor[NoParameter] {
	return HistoricalMAPErrorDescriptor[NoParameter]{errorBinding[NoParameter, HistoricalMAPErrorInfo, HistoricalMAPErrorCode]{code: HistoricalMAPErrorsNoHandoverNumberAvailable, info: infoHistoricalMAPErrorsNoHandoverNumberAvailableError, parameter: ValueCodec[NoParameter]{}}}
}
func infoHistoricalMAPErrorsNoHandoverNumberAvailableError() HistoricalMAPErrorInfo {
	return HistoricalMAPErrorInfo{Name: "noHandoverNumberAvailable", Code: HistoricalMAPErrorsNoHandoverNumberAvailable, Parameter: nil, ParameterOptional: nil, Source: sourceInfo0("noHandoverNumberAvailable", "17.6.6")}
}

// HistoricalMAPErrorsNoRoamingNumberAvailableErrorDescriptor binds the formal ERROR object MAP-Errors.noRoamingNumberAvailable (X.880 §8.3).
func HistoricalMAPErrorsNoRoamingNumberAvailableErrorDescriptor() HistoricalMAPErrorDescriptor[__asn1pkg_v21_map_er_datatypes.ERNoRoamingNbParam] {
	return HistoricalMAPErrorDescriptor[__asn1pkg_v21_map_er_datatypes.ERNoRoamingNbParam]{errorBinding[__asn1pkg_v21_map_er_datatypes.ERNoRoamingNbParam, HistoricalMAPErrorInfo, HistoricalMAPErrorCode]{code: HistoricalMAPErrorsNoRoamingNumberAvailable, info: infoHistoricalMAPErrorsNoRoamingNumberAvailableError, parameter: adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERNoRoamingNbParam](__asn1pkg_v21_map_er_datatypes.ERNoRoamingNbParamCodec())}}
}
func infoHistoricalMAPErrorsNoRoamingNumberAvailableError() HistoricalMAPErrorInfo {
	return HistoricalMAPErrorInfo{Name: "noRoamingNumberAvailable", Code: HistoricalMAPErrorsNoRoamingNumberAvailable, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "NoRoamingNbParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERNoRoamingNbParam"}, ParameterOptional: nil, Source: sourceInfo0("noRoamingNumberAvailable", "17.6.6")}
}

// HistoricalMAPErrorsNoSubscriberReplyErrorDescriptor binds the formal ERROR object MAP-Errors.noSubscriberReply (X.880 §8.3).
func HistoricalMAPErrorsNoSubscriberReplyErrorDescriptor() HistoricalMAPErrorDescriptor[__asn1pkg_v21_map_er_datatypes.ERNoSubscriberReplyParam] {
	return HistoricalMAPErrorDescriptor[__asn1pkg_v21_map_er_datatypes.ERNoSubscriberReplyParam]{errorBinding[__asn1pkg_v21_map_er_datatypes.ERNoSubscriberReplyParam, HistoricalMAPErrorInfo, HistoricalMAPErrorCode]{code: HistoricalMAPErrorsNoSubscriberReply, info: infoHistoricalMAPErrorsNoSubscriberReplyError, parameter: adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERNoSubscriberReplyParam](__asn1pkg_v21_map_er_datatypes.ERNoSubscriberReplyParamCodec())}}
}
func infoHistoricalMAPErrorsNoSubscriberReplyError() HistoricalMAPErrorInfo {
	return HistoricalMAPErrorInfo{Name: "noSubscriberReply", Code: HistoricalMAPErrorsNoSubscriberReply, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "NoSubscriberReplyParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERNoSubscriberReplyParam"}, ParameterOptional: nil, Source: sourceInfo0("noSubscriberReply", "17.6.6")}
}

// HistoricalMAPErrorsNumberChangedErrorDescriptor binds the formal ERROR object MAP-Errors.numberChanged (X.880 §8.3).
func HistoricalMAPErrorsNumberChangedErrorDescriptor() HistoricalMAPErrorDescriptor[__asn1pkg_v21_map_er_datatypes.ERNumberChangedParam] {
	return HistoricalMAPErrorDescriptor[__asn1pkg_v21_map_er_datatypes.ERNumberChangedParam]{errorBinding[__asn1pkg_v21_map_er_datatypes.ERNumberChangedParam, HistoricalMAPErrorInfo, HistoricalMAPErrorCode]{code: HistoricalMAPErrorsNumberChanged, info: infoHistoricalMAPErrorsNumberChangedError, parameter: adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERNumberChangedParam](__asn1pkg_v21_map_er_datatypes.ERNumberChangedParamCodec())}}
}
func infoHistoricalMAPErrorsNumberChangedError() HistoricalMAPErrorInfo {
	return HistoricalMAPErrorInfo{Name: "numberChanged", Code: HistoricalMAPErrorsNumberChanged, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "NumberChangedParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERNumberChangedParam"}, ParameterOptional: nil, Source: sourceInfo0("numberChanged", "17.6.6")}
}

// HistoricalMAPErrorsNumberOfPWAttemptsViolationErrorDescriptor binds the formal ERROR object MAP-Errors.numberOfPW-AttemptsViolation (X.880 §8.3).
func HistoricalMAPErrorsNumberOfPWAttemptsViolationErrorDescriptor() HistoricalMAPErrorDescriptor[NoParameter] {
	return HistoricalMAPErrorDescriptor[NoParameter]{errorBinding[NoParameter, HistoricalMAPErrorInfo, HistoricalMAPErrorCode]{code: HistoricalMAPErrorsNumberOfPWAttemptsViolation, info: infoHistoricalMAPErrorsNumberOfPWAttemptsViolationError, parameter: ValueCodec[NoParameter]{}}}
}
func infoHistoricalMAPErrorsNumberOfPWAttemptsViolationError() HistoricalMAPErrorInfo {
	return HistoricalMAPErrorInfo{Name: "numberOfPW-AttemptsViolation", Code: HistoricalMAPErrorsNumberOfPWAttemptsViolation, Parameter: nil, ParameterOptional: nil, Source: sourceInfo0("numberOfPW-AttemptsViolation", "17.6.6")}
}

// HistoricalMAPErrorsOngoingGroupCallErrorDescriptor binds the formal ERROR object MAP-Errors.ongoingGroupCall (X.880 §8.3).
func HistoricalMAPErrorsOngoingGroupCallErrorDescriptor() HistoricalMAPErrorDescriptor[__asn1pkg_v21_map_er_datatypes.EROngoingGroupCallParam] {
	return HistoricalMAPErrorDescriptor[__asn1pkg_v21_map_er_datatypes.EROngoingGroupCallParam]{errorBinding[__asn1pkg_v21_map_er_datatypes.EROngoingGroupCallParam, HistoricalMAPErrorInfo, HistoricalMAPErrorCode]{code: HistoricalMAPErrorsOngoingGroupCall, info: infoHistoricalMAPErrorsOngoingGroupCallError, parameter: adaptValueCodec[__asn1pkg_v21_map_er_datatypes.EROngoingGroupCallParam](__asn1pkg_v21_map_er_datatypes.EROngoingGroupCallParamCodec())}}
}
func infoHistoricalMAPErrorsOngoingGroupCallError() HistoricalMAPErrorInfo {
	return HistoricalMAPErrorInfo{Name: "ongoingGroupCall", Code: HistoricalMAPErrorsOngoingGroupCall, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "OngoingGroupCallParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "EROngoingGroupCallParam"}, ParameterOptional: nil, Source: sourceInfo0("ongoingGroupCall", "17.6.6")}
}

// HistoricalMAPErrorsOrNotAllowedErrorDescriptor binds the formal ERROR object MAP-Errors.or-NotAllowed (X.880 §8.3).
func HistoricalMAPErrorsOrNotAllowedErrorDescriptor() HistoricalMAPErrorDescriptor[__asn1pkg_v21_map_er_datatypes.ERORNotAllowedParam] {
	return HistoricalMAPErrorDescriptor[__asn1pkg_v21_map_er_datatypes.ERORNotAllowedParam]{errorBinding[__asn1pkg_v21_map_er_datatypes.ERORNotAllowedParam, HistoricalMAPErrorInfo, HistoricalMAPErrorCode]{code: HistoricalMAPErrorsOrNotAllowed, info: infoHistoricalMAPErrorsOrNotAllowedError, parameter: adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERORNotAllowedParam](__asn1pkg_v21_map_er_datatypes.ERORNotAllowedParamCodec())}}
}
func infoHistoricalMAPErrorsOrNotAllowedError() HistoricalMAPErrorInfo {
	return HistoricalMAPErrorInfo{Name: "or-NotAllowed", Code: HistoricalMAPErrorsOrNotAllowed, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "OR-NotAllowedParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERORNotAllowedParam"}, ParameterOptional: nil, Source: sourceInfo0("or-NotAllowed", "17.6.6")}
}

// HistoricalMAPErrorsPositionMethodFailureErrorDescriptor binds the formal ERROR object MAP-Errors.positionMethodFailure (X.880 §8.3).
func HistoricalMAPErrorsPositionMethodFailureErrorDescriptor() HistoricalMAPErrorDescriptor[__asn1pkg_v21_map_er_datatypes.ERPositionMethodFailureParam] {
	return HistoricalMAPErrorDescriptor[__asn1pkg_v21_map_er_datatypes.ERPositionMethodFailureParam]{errorBinding[__asn1pkg_v21_map_er_datatypes.ERPositionMethodFailureParam, HistoricalMAPErrorInfo, HistoricalMAPErrorCode]{code: HistoricalMAPErrorsPositionMethodFailure, info: infoHistoricalMAPErrorsPositionMethodFailureError, parameter: adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERPositionMethodFailureParam](__asn1pkg_v21_map_er_datatypes.ERPositionMethodFailureParamCodec())}}
}
func infoHistoricalMAPErrorsPositionMethodFailureError() HistoricalMAPErrorInfo {
	return HistoricalMAPErrorInfo{Name: "positionMethodFailure", Code: HistoricalMAPErrorsPositionMethodFailure, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "PositionMethodFailure-Param", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERPositionMethodFailureParam"}, ParameterOptional: nil, Source: sourceInfo0("positionMethodFailure", "17.6.6")}
}

// HistoricalMAPErrorsPwRegistrationFailureErrorDescriptor binds the formal ERROR object MAP-Errors.pw-RegistrationFailure (X.880 §8.3).
func HistoricalMAPErrorsPwRegistrationFailureErrorDescriptor() HistoricalMAPErrorDescriptor[__asn1pkg_v21_map_er_datatypes.BERValue[__asn1pkg_v21_map_er_datatypes.ERPWRegistrationFailureCause]] {
	return HistoricalMAPErrorDescriptor[__asn1pkg_v21_map_er_datatypes.BERValue[__asn1pkg_v21_map_er_datatypes.ERPWRegistrationFailureCause]]{errorBinding[__asn1pkg_v21_map_er_datatypes.BERValue[__asn1pkg_v21_map_er_datatypes.ERPWRegistrationFailureCause], HistoricalMAPErrorInfo, HistoricalMAPErrorCode]{code: HistoricalMAPErrorsPwRegistrationFailure, info: infoHistoricalMAPErrorsPwRegistrationFailureError, parameter: adaptValueCodec[__asn1pkg_v21_map_er_datatypes.BERValue[__asn1pkg_v21_map_er_datatypes.ERPWRegistrationFailureCause]](__asn1pkg_v21_map_er_datatypes.ERPWRegistrationFailureCauseCodec())}}
}
func infoHistoricalMAPErrorsPwRegistrationFailureError() HistoricalMAPErrorInfo {
	return HistoricalMAPErrorInfo{Name: "pw-RegistrationFailure", Code: HistoricalMAPErrorsPwRegistrationFailure, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "PW-RegistrationFailureCause", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERPWRegistrationFailureCause"}, ParameterOptional: nil, Source: sourceInfo0("pw-RegistrationFailure", "17.6.6")}
}

// HistoricalMAPErrorsResourceLimitationErrorDescriptor binds the formal ERROR object MAP-Errors.resourceLimitation (X.880 §8.3).
func HistoricalMAPErrorsResourceLimitationErrorDescriptor() HistoricalMAPErrorDescriptor[__asn1pkg_v21_map_er_datatypes.ERResourceLimitationParam] {
	return HistoricalMAPErrorDescriptor[__asn1pkg_v21_map_er_datatypes.ERResourceLimitationParam]{errorBinding[__asn1pkg_v21_map_er_datatypes.ERResourceLimitationParam, HistoricalMAPErrorInfo, HistoricalMAPErrorCode]{code: HistoricalMAPErrorsResourceLimitation, info: infoHistoricalMAPErrorsResourceLimitationError, parameter: adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERResourceLimitationParam](__asn1pkg_v21_map_er_datatypes.ERResourceLimitationParamCodec())}}
}
func infoHistoricalMAPErrorsResourceLimitationError() HistoricalMAPErrorInfo {
	return HistoricalMAPErrorInfo{Name: "resourceLimitation", Code: HistoricalMAPErrorsResourceLimitation, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "ResourceLimitationParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERResourceLimitationParam"}, ParameterOptional: nil, Source: sourceInfo0("resourceLimitation", "17.6.6")}
}

// HistoricalMAPErrorsRoamingNotAllowedErrorDescriptor binds the formal ERROR object MAP-Errors.roamingNotAllowed (X.880 §8.3).
func HistoricalMAPErrorsRoamingNotAllowedErrorDescriptor() HistoricalMAPErrorDescriptor[__asn1pkg_v21_map_er_datatypes.ERRoamingNotAllowedParam] {
	return HistoricalMAPErrorDescriptor[__asn1pkg_v21_map_er_datatypes.ERRoamingNotAllowedParam]{errorBinding[__asn1pkg_v21_map_er_datatypes.ERRoamingNotAllowedParam, HistoricalMAPErrorInfo, HistoricalMAPErrorCode]{code: HistoricalMAPErrorsRoamingNotAllowed, info: infoHistoricalMAPErrorsRoamingNotAllowedError, parameter: adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERRoamingNotAllowedParam](__asn1pkg_v21_map_er_datatypes.ERRoamingNotAllowedParamCodec())}}
}
func infoHistoricalMAPErrorsRoamingNotAllowedError() HistoricalMAPErrorInfo {
	return HistoricalMAPErrorInfo{Name: "roamingNotAllowed", Code: HistoricalMAPErrorsRoamingNotAllowed, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "RoamingNotAllowedParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERRoamingNotAllowedParam"}, ParameterOptional: nil, Source: sourceInfo0("roamingNotAllowed", "17.6.6")}
}

// HistoricalMAPErrorsShortTermDenialErrorDescriptor binds the formal ERROR object MAP-Errors.shortTermDenial (X.880 §8.3).
func HistoricalMAPErrorsShortTermDenialErrorDescriptor() HistoricalMAPErrorDescriptor[__asn1pkg_v21_map_er_datatypes.ERShortTermDenialParam] {
	return HistoricalMAPErrorDescriptor[__asn1pkg_v21_map_er_datatypes.ERShortTermDenialParam]{errorBinding[__asn1pkg_v21_map_er_datatypes.ERShortTermDenialParam, HistoricalMAPErrorInfo, HistoricalMAPErrorCode]{code: HistoricalMAPErrorsShortTermDenial, info: infoHistoricalMAPErrorsShortTermDenialError, parameter: adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERShortTermDenialParam](__asn1pkg_v21_map_er_datatypes.ERShortTermDenialParamCodec())}}
}
func infoHistoricalMAPErrorsShortTermDenialError() HistoricalMAPErrorInfo {
	return HistoricalMAPErrorInfo{Name: "shortTermDenial", Code: HistoricalMAPErrorsShortTermDenial, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "ShortTermDenialParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERShortTermDenialParam"}, ParameterOptional: nil, Source: sourceInfo0("shortTermDenial", "17.6.6")}
}

// HistoricalMAPErrorsSmDeliveryFailureErrorDescriptor binds the formal ERROR object MAP-Errors.sm-DeliveryFailure (X.880 §8.3).
func HistoricalMAPErrorsSmDeliveryFailureErrorDescriptor() HistoricalMAPErrorDescriptor[__asn1pkg_v21_map_er_datatypes.ERSMDeliveryFailureCause] {
	return HistoricalMAPErrorDescriptor[__asn1pkg_v21_map_er_datatypes.ERSMDeliveryFailureCause]{errorBinding[__asn1pkg_v21_map_er_datatypes.ERSMDeliveryFailureCause, HistoricalMAPErrorInfo, HistoricalMAPErrorCode]{code: HistoricalMAPErrorsSmDeliveryFailure, info: infoHistoricalMAPErrorsSmDeliveryFailureError, parameter: adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSMDeliveryFailureCause](__asn1pkg_v21_map_er_datatypes.ERSMDeliveryFailureCauseCodec())}}
}
func infoHistoricalMAPErrorsSmDeliveryFailureError() HistoricalMAPErrorInfo {
	return HistoricalMAPErrorInfo{Name: "sm-DeliveryFailure", Code: HistoricalMAPErrorsSmDeliveryFailure, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "SM-DeliveryFailureCause", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERSMDeliveryFailureCause"}, ParameterOptional: nil, Source: sourceInfo0("sm-DeliveryFailure", "17.6.6")}
}

// HistoricalMAPErrorsSsErrorStatusErrorDescriptor binds the formal ERROR object MAP-Errors.ss-ErrorStatus (X.880 §8.3).
func HistoricalMAPErrorsSsErrorStatusErrorDescriptor() HistoricalMAPErrorDescriptor[__asn1pkg_v21_map_ss_datatypes.BERValue[__asn1pkg_v21_map_ss_datatypes.SSSSStatus]] {
	return HistoricalMAPErrorDescriptor[__asn1pkg_v21_map_ss_datatypes.BERValue[__asn1pkg_v21_map_ss_datatypes.SSSSStatus]]{errorBinding[__asn1pkg_v21_map_ss_datatypes.BERValue[__asn1pkg_v21_map_ss_datatypes.SSSSStatus], HistoricalMAPErrorInfo, HistoricalMAPErrorCode]{code: HistoricalMAPErrorsSsErrorStatus, info: infoHistoricalMAPErrorsSsErrorStatusError, parameter: adaptValueCodec[__asn1pkg_v21_map_ss_datatypes.BERValue[__asn1pkg_v21_map_ss_datatypes.SSSSStatus]](__asn1pkg_v21_map_ss_datatypes.SSSSStatusCodec())}}
}
func infoHistoricalMAPErrorsSsErrorStatusError() HistoricalMAPErrorInfo {
	return HistoricalMAPErrorInfo{Name: "ss-ErrorStatus", Code: HistoricalMAPErrorsSsErrorStatus, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.14.21", ASN1Name: "SS-Status", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_ss_datatypes", GoName: "SSSSStatus"}, ParameterOptional: nil, Source: sourceInfo0("ss-ErrorStatus", "17.6.6")}
}

// HistoricalMAPErrorsSsIncompatibilityErrorDescriptor binds the formal ERROR object MAP-Errors.ss-Incompatibility (X.880 §8.3).
func HistoricalMAPErrorsSsIncompatibilityErrorDescriptor() HistoricalMAPErrorDescriptor[__asn1pkg_v21_map_er_datatypes.ERSSIncompatibilityCause] {
	return HistoricalMAPErrorDescriptor[__asn1pkg_v21_map_er_datatypes.ERSSIncompatibilityCause]{errorBinding[__asn1pkg_v21_map_er_datatypes.ERSSIncompatibilityCause, HistoricalMAPErrorInfo, HistoricalMAPErrorCode]{code: HistoricalMAPErrorsSsIncompatibility, info: infoHistoricalMAPErrorsSsIncompatibilityError, parameter: adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSSIncompatibilityCause](__asn1pkg_v21_map_er_datatypes.ERSSIncompatibilityCauseCodec())}}
}
func infoHistoricalMAPErrorsSsIncompatibilityError() HistoricalMAPErrorInfo {
	return HistoricalMAPErrorInfo{Name: "ss-Incompatibility", Code: HistoricalMAPErrorsSsIncompatibility, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "SS-IncompatibilityCause", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERSSIncompatibilityCause"}, ParameterOptional: nil, Source: sourceInfo0("ss-Incompatibility", "17.6.6")}
}

// HistoricalMAPErrorsSsNotAvailableErrorDescriptor binds the formal ERROR object MAP-Errors.ss-NotAvailable (X.880 §8.3).
func HistoricalMAPErrorsSsNotAvailableErrorDescriptor() HistoricalMAPErrorDescriptor[__asn1pkg_v21_map_er_datatypes.ERSSNotAvailableParam] {
	return HistoricalMAPErrorDescriptor[__asn1pkg_v21_map_er_datatypes.ERSSNotAvailableParam]{errorBinding[__asn1pkg_v21_map_er_datatypes.ERSSNotAvailableParam, HistoricalMAPErrorInfo, HistoricalMAPErrorCode]{code: HistoricalMAPErrorsSsNotAvailable, info: infoHistoricalMAPErrorsSsNotAvailableError, parameter: adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSSNotAvailableParam](__asn1pkg_v21_map_er_datatypes.ERSSNotAvailableParamCodec())}}
}
func infoHistoricalMAPErrorsSsNotAvailableError() HistoricalMAPErrorInfo {
	return HistoricalMAPErrorInfo{Name: "ss-NotAvailable", Code: HistoricalMAPErrorsSsNotAvailable, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "SS-NotAvailableParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERSSNotAvailableParam"}, ParameterOptional: nil, Source: sourceInfo0("ss-NotAvailable", "17.6.6")}
}

// HistoricalMAPErrorsSsSubscriptionViolationErrorDescriptor binds the formal ERROR object MAP-Errors.ss-SubscriptionViolation (X.880 §8.3).
func HistoricalMAPErrorsSsSubscriptionViolationErrorDescriptor() HistoricalMAPErrorDescriptor[__asn1pkg_v21_map_er_datatypes.ERSSSubscriptionViolationParam] {
	return HistoricalMAPErrorDescriptor[__asn1pkg_v21_map_er_datatypes.ERSSSubscriptionViolationParam]{errorBinding[__asn1pkg_v21_map_er_datatypes.ERSSSubscriptionViolationParam, HistoricalMAPErrorInfo, HistoricalMAPErrorCode]{code: HistoricalMAPErrorsSsSubscriptionViolation, info: infoHistoricalMAPErrorsSsSubscriptionViolationError, parameter: adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSSSubscriptionViolationParam](__asn1pkg_v21_map_er_datatypes.ERSSSubscriptionViolationParamCodec())}}
}
func infoHistoricalMAPErrorsSsSubscriptionViolationError() HistoricalMAPErrorInfo {
	return HistoricalMAPErrorInfo{Name: "ss-SubscriptionViolation", Code: HistoricalMAPErrorsSsSubscriptionViolation, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "SS-SubscriptionViolationParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERSSSubscriptionViolationParam"}, ParameterOptional: nil, Source: sourceInfo0("ss-SubscriptionViolation", "17.6.6")}
}

// HistoricalMAPErrorsSubscriberBusyForMTSMSErrorDescriptor binds the formal ERROR object MAP-Errors.subscriberBusyForMT-SMS (X.880 §8.3).
func HistoricalMAPErrorsSubscriberBusyForMTSMSErrorDescriptor() HistoricalMAPErrorDescriptor[__asn1pkg_v21_map_er_datatypes.ERSubBusyForMTSMSParam] {
	return HistoricalMAPErrorDescriptor[__asn1pkg_v21_map_er_datatypes.ERSubBusyForMTSMSParam]{errorBinding[__asn1pkg_v21_map_er_datatypes.ERSubBusyForMTSMSParam, HistoricalMAPErrorInfo, HistoricalMAPErrorCode]{code: HistoricalMAPErrorsSubscriberBusyForMTSMS, info: infoHistoricalMAPErrorsSubscriberBusyForMTSMSError, parameter: adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSubBusyForMTSMSParam](__asn1pkg_v21_map_er_datatypes.ERSubBusyForMTSMSParamCodec())}}
}
func infoHistoricalMAPErrorsSubscriberBusyForMTSMSError() HistoricalMAPErrorInfo {
	return HistoricalMAPErrorInfo{Name: "subscriberBusyForMT-SMS", Code: HistoricalMAPErrorsSubscriberBusyForMTSMS, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "SubBusyForMT-SMS-Param", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERSubBusyForMTSMSParam"}, ParameterOptional: nil, Source: sourceInfo0("subscriberBusyForMT-SMS", "17.6.6")}
}

// HistoricalMAPErrorsSubsequentHandoverFailureErrorDescriptor binds the formal ERROR object MAP-Errors.subsequentHandoverFailure (X.880 §8.3).
func HistoricalMAPErrorsSubsequentHandoverFailureErrorDescriptor() HistoricalMAPErrorDescriptor[NoParameter] {
	return HistoricalMAPErrorDescriptor[NoParameter]{errorBinding[NoParameter, HistoricalMAPErrorInfo, HistoricalMAPErrorCode]{code: HistoricalMAPErrorsSubsequentHandoverFailure, info: infoHistoricalMAPErrorsSubsequentHandoverFailureError, parameter: ValueCodec[NoParameter]{}}}
}
func infoHistoricalMAPErrorsSubsequentHandoverFailureError() HistoricalMAPErrorInfo {
	return HistoricalMAPErrorInfo{Name: "subsequentHandoverFailure", Code: HistoricalMAPErrorsSubsequentHandoverFailure, Parameter: nil, ParameterOptional: nil, Source: sourceInfo0("subsequentHandoverFailure", "17.6.6")}
}

// HistoricalMAPErrorsSystemFailureErrorDescriptor binds the formal ERROR object MAP-Errors.systemFailure (X.880 §8.3).
func HistoricalMAPErrorsSystemFailureErrorDescriptor() HistoricalMAPErrorDescriptor[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam] {
	return HistoricalMAPErrorDescriptor[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam]{errorBinding[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam, HistoricalMAPErrorInfo, HistoricalMAPErrorCode]{code: HistoricalMAPErrorsSystemFailure, info: infoHistoricalMAPErrorsSystemFailureError, parameter: adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam](__asn1pkg_v21_map_er_datatypes.ERSystemFailureParamCodec())}}
}
func infoHistoricalMAPErrorsSystemFailureError() HistoricalMAPErrorInfo {
	return HistoricalMAPErrorInfo{Name: "systemFailure", Code: HistoricalMAPErrorsSystemFailure, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "SystemFailureParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERSystemFailureParam"}, ParameterOptional: nil, Source: sourceInfo0("systemFailure", "17.6.6")}
}

// HistoricalMAPErrorsTargetCellOutsideGroupCallAreaErrorDescriptor binds the formal ERROR object MAP-Errors.targetCellOutsideGroupCallArea (X.880 §8.3).
func HistoricalMAPErrorsTargetCellOutsideGroupCallAreaErrorDescriptor() HistoricalMAPErrorDescriptor[__asn1pkg_v21_map_er_datatypes.ERTargetCellOutsideGCAParam] {
	return HistoricalMAPErrorDescriptor[__asn1pkg_v21_map_er_datatypes.ERTargetCellOutsideGCAParam]{errorBinding[__asn1pkg_v21_map_er_datatypes.ERTargetCellOutsideGCAParam, HistoricalMAPErrorInfo, HistoricalMAPErrorCode]{code: HistoricalMAPErrorsTargetCellOutsideGroupCallArea, info: infoHistoricalMAPErrorsTargetCellOutsideGroupCallAreaError, parameter: adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERTargetCellOutsideGCAParam](__asn1pkg_v21_map_er_datatypes.ERTargetCellOutsideGCAParamCodec())}}
}
func infoHistoricalMAPErrorsTargetCellOutsideGroupCallAreaError() HistoricalMAPErrorInfo {
	return HistoricalMAPErrorInfo{Name: "targetCellOutsideGroupCallArea", Code: HistoricalMAPErrorsTargetCellOutsideGroupCallArea, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "TargetCellOutsideGCA-Param", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERTargetCellOutsideGCAParam"}, ParameterOptional: nil, Source: sourceInfo0("targetCellOutsideGroupCallArea", "17.6.6")}
}

// HistoricalMAPErrorsTeleserviceNotProvisionedErrorDescriptor binds the formal ERROR object MAP-Errors.teleserviceNotProvisioned (X.880 §8.3).
func HistoricalMAPErrorsTeleserviceNotProvisionedErrorDescriptor() HistoricalMAPErrorDescriptor[__asn1pkg_v21_map_er_datatypes.ERTeleservNotProvParam] {
	return HistoricalMAPErrorDescriptor[__asn1pkg_v21_map_er_datatypes.ERTeleservNotProvParam]{errorBinding[__asn1pkg_v21_map_er_datatypes.ERTeleservNotProvParam, HistoricalMAPErrorInfo, HistoricalMAPErrorCode]{code: HistoricalMAPErrorsTeleserviceNotProvisioned, info: infoHistoricalMAPErrorsTeleserviceNotProvisionedError, parameter: adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERTeleservNotProvParam](__asn1pkg_v21_map_er_datatypes.ERTeleservNotProvParamCodec())}}
}
func infoHistoricalMAPErrorsTeleserviceNotProvisionedError() HistoricalMAPErrorInfo {
	return HistoricalMAPErrorInfo{Name: "teleserviceNotProvisioned", Code: HistoricalMAPErrorsTeleserviceNotProvisioned, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "TeleservNotProvParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERTeleservNotProvParam"}, ParameterOptional: nil, Source: sourceInfo0("teleserviceNotProvisioned", "17.6.6")}
}

// HistoricalMAPErrorsTracingBufferFullErrorDescriptor binds the formal ERROR object MAP-Errors.tracingBufferFull (X.880 §8.3).
func HistoricalMAPErrorsTracingBufferFullErrorDescriptor() HistoricalMAPErrorDescriptor[__asn1pkg_v21_map_er_datatypes.ERTracingBufferFullParam] {
	return HistoricalMAPErrorDescriptor[__asn1pkg_v21_map_er_datatypes.ERTracingBufferFullParam]{errorBinding[__asn1pkg_v21_map_er_datatypes.ERTracingBufferFullParam, HistoricalMAPErrorInfo, HistoricalMAPErrorCode]{code: HistoricalMAPErrorsTracingBufferFull, info: infoHistoricalMAPErrorsTracingBufferFullError, parameter: adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERTracingBufferFullParam](__asn1pkg_v21_map_er_datatypes.ERTracingBufferFullParamCodec())}}
}
func infoHistoricalMAPErrorsTracingBufferFullError() HistoricalMAPErrorInfo {
	return HistoricalMAPErrorInfo{Name: "tracingBufferFull", Code: HistoricalMAPErrorsTracingBufferFull, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "TracingBufferFullParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERTracingBufferFullParam"}, ParameterOptional: nil, Source: sourceInfo0("tracingBufferFull", "17.6.6")}
}

// HistoricalMAPErrorsUnauthorizedLCSClientErrorDescriptor binds the formal ERROR object MAP-Errors.unauthorizedLCSClient (X.880 §8.3).
func HistoricalMAPErrorsUnauthorizedLCSClientErrorDescriptor() HistoricalMAPErrorDescriptor[__asn1pkg_v21_map_er_datatypes.ERUnauthorizedLCSClientParam] {
	return HistoricalMAPErrorDescriptor[__asn1pkg_v21_map_er_datatypes.ERUnauthorizedLCSClientParam]{errorBinding[__asn1pkg_v21_map_er_datatypes.ERUnauthorizedLCSClientParam, HistoricalMAPErrorInfo, HistoricalMAPErrorCode]{code: HistoricalMAPErrorsUnauthorizedLCSClient, info: infoHistoricalMAPErrorsUnauthorizedLCSClientError, parameter: adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERUnauthorizedLCSClientParam](__asn1pkg_v21_map_er_datatypes.ERUnauthorizedLCSClientParamCodec())}}
}
func infoHistoricalMAPErrorsUnauthorizedLCSClientError() HistoricalMAPErrorInfo {
	return HistoricalMAPErrorInfo{Name: "unauthorizedLCSClient", Code: HistoricalMAPErrorsUnauthorizedLCSClient, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "UnauthorizedLCSClient-Param", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERUnauthorizedLCSClientParam"}, ParameterOptional: nil, Source: sourceInfo0("unauthorizedLCSClient", "17.6.6")}
}

// HistoricalMAPErrorsUnauthorizedRequestingNetworkErrorDescriptor binds the formal ERROR object MAP-Errors.unauthorizedRequestingNetwork (X.880 §8.3).
func HistoricalMAPErrorsUnauthorizedRequestingNetworkErrorDescriptor() HistoricalMAPErrorDescriptor[__asn1pkg_v21_map_er_datatypes.ERUnauthorizedRequestingNetworkParam] {
	return HistoricalMAPErrorDescriptor[__asn1pkg_v21_map_er_datatypes.ERUnauthorizedRequestingNetworkParam]{errorBinding[__asn1pkg_v21_map_er_datatypes.ERUnauthorizedRequestingNetworkParam, HistoricalMAPErrorInfo, HistoricalMAPErrorCode]{code: HistoricalMAPErrorsUnauthorizedRequestingNetwork, info: infoHistoricalMAPErrorsUnauthorizedRequestingNetworkError, parameter: adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERUnauthorizedRequestingNetworkParam](__asn1pkg_v21_map_er_datatypes.ERUnauthorizedRequestingNetworkParamCodec())}}
}
func infoHistoricalMAPErrorsUnauthorizedRequestingNetworkError() HistoricalMAPErrorInfo {
	return HistoricalMAPErrorInfo{Name: "unauthorizedRequestingNetwork", Code: HistoricalMAPErrorsUnauthorizedRequestingNetwork, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "UnauthorizedRequestingNetwork-Param", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERUnauthorizedRequestingNetworkParam"}, ParameterOptional: nil, Source: sourceInfo0("unauthorizedRequestingNetwork", "17.6.6")}
}

// HistoricalMAPErrorsUnexpectedDataValueErrorDescriptor binds the formal ERROR object MAP-Errors.unexpectedDataValue (X.880 §8.3).
func HistoricalMAPErrorsUnexpectedDataValueErrorDescriptor() HistoricalMAPErrorDescriptor[__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParam] {
	return HistoricalMAPErrorDescriptor[__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParam]{errorBinding[__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParam, HistoricalMAPErrorInfo, HistoricalMAPErrorCode]{code: HistoricalMAPErrorsUnexpectedDataValue, info: infoHistoricalMAPErrorsUnexpectedDataValueError, parameter: adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParam](__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParamCodec())}}
}
func infoHistoricalMAPErrorsUnexpectedDataValueError() HistoricalMAPErrorInfo {
	return HistoricalMAPErrorInfo{Name: "unexpectedDataValue", Code: HistoricalMAPErrorsUnexpectedDataValue, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "UnexpectedDataParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERUnexpectedDataParam"}, ParameterOptional: nil, Source: sourceInfo0("unexpectedDataValue", "17.6.6")}
}

// HistoricalMAPErrorsUnidentifiedSubscriberErrorDescriptor binds the formal ERROR object MAP-Errors.unidentifiedSubscriber (X.880 §8.3).
func HistoricalMAPErrorsUnidentifiedSubscriberErrorDescriptor() HistoricalMAPErrorDescriptor[__asn1pkg_v21_map_er_datatypes.ERUnidentifiedSubParam] {
	return HistoricalMAPErrorDescriptor[__asn1pkg_v21_map_er_datatypes.ERUnidentifiedSubParam]{errorBinding[__asn1pkg_v21_map_er_datatypes.ERUnidentifiedSubParam, HistoricalMAPErrorInfo, HistoricalMAPErrorCode]{code: HistoricalMAPErrorsUnidentifiedSubscriber, info: infoHistoricalMAPErrorsUnidentifiedSubscriberError, parameter: adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERUnidentifiedSubParam](__asn1pkg_v21_map_er_datatypes.ERUnidentifiedSubParamCodec())}}
}
func infoHistoricalMAPErrorsUnidentifiedSubscriberError() HistoricalMAPErrorInfo {
	return HistoricalMAPErrorInfo{Name: "unidentifiedSubscriber", Code: HistoricalMAPErrorsUnidentifiedSubscriber, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "UnidentifiedSubParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERUnidentifiedSubParam"}, ParameterOptional: nil, Source: sourceInfo0("unidentifiedSubscriber", "17.6.6")}
}

// HistoricalMAPErrorsUnknownAlphabetErrorDescriptor binds the formal ERROR object MAP-Errors.unknownAlphabet (X.880 §8.3).
func HistoricalMAPErrorsUnknownAlphabetErrorDescriptor() HistoricalMAPErrorDescriptor[NoParameter] {
	return HistoricalMAPErrorDescriptor[NoParameter]{errorBinding[NoParameter, HistoricalMAPErrorInfo, HistoricalMAPErrorCode]{code: HistoricalMAPErrorsUnknownAlphabet, info: infoHistoricalMAPErrorsUnknownAlphabetError, parameter: ValueCodec[NoParameter]{}}}
}
func infoHistoricalMAPErrorsUnknownAlphabetError() HistoricalMAPErrorInfo {
	return HistoricalMAPErrorInfo{Name: "unknownAlphabet", Code: HistoricalMAPErrorsUnknownAlphabet, Parameter: nil, ParameterOptional: nil, Source: sourceInfo0("unknownAlphabet", "17.6.6")}
}

// HistoricalMAPErrorsUnknownEquipmentErrorDescriptor binds the formal ERROR object MAP-Errors.unknownEquipment (X.880 §8.3).
func HistoricalMAPErrorsUnknownEquipmentErrorDescriptor() HistoricalMAPErrorDescriptor[NoParameter] {
	return HistoricalMAPErrorDescriptor[NoParameter]{errorBinding[NoParameter, HistoricalMAPErrorInfo, HistoricalMAPErrorCode]{code: HistoricalMAPErrorsUnknownEquipment, info: infoHistoricalMAPErrorsUnknownEquipmentError, parameter: ValueCodec[NoParameter]{}}}
}
func infoHistoricalMAPErrorsUnknownEquipmentError() HistoricalMAPErrorInfo {
	return HistoricalMAPErrorInfo{Name: "unknownEquipment", Code: HistoricalMAPErrorsUnknownEquipment, Parameter: nil, ParameterOptional: nil, Source: sourceInfo0("unknownEquipment", "17.6.6")}
}

// HistoricalMAPErrorsUnknownMSCErrorDescriptor binds the formal ERROR object MAP-Errors.unknownMSC (X.880 §8.3).
func HistoricalMAPErrorsUnknownMSCErrorDescriptor() HistoricalMAPErrorDescriptor[NoParameter] {
	return HistoricalMAPErrorDescriptor[NoParameter]{errorBinding[NoParameter, HistoricalMAPErrorInfo, HistoricalMAPErrorCode]{code: HistoricalMAPErrorsUnknownMSC, info: infoHistoricalMAPErrorsUnknownMSCError, parameter: ValueCodec[NoParameter]{}}}
}
func infoHistoricalMAPErrorsUnknownMSCError() HistoricalMAPErrorInfo {
	return HistoricalMAPErrorInfo{Name: "unknownMSC", Code: HistoricalMAPErrorsUnknownMSC, Parameter: nil, ParameterOptional: nil, Source: sourceInfo0("unknownMSC", "17.6.6")}
}

// HistoricalMAPErrorsUnknownOrUnreachableLCSClientErrorDescriptor binds the formal ERROR object MAP-Errors.unknownOrUnreachableLCSClient (X.880 §8.3).
func HistoricalMAPErrorsUnknownOrUnreachableLCSClientErrorDescriptor() HistoricalMAPErrorDescriptor[__asn1pkg_v21_map_er_datatypes.ERUnknownOrUnreachableLCSClientParam] {
	return HistoricalMAPErrorDescriptor[__asn1pkg_v21_map_er_datatypes.ERUnknownOrUnreachableLCSClientParam]{errorBinding[__asn1pkg_v21_map_er_datatypes.ERUnknownOrUnreachableLCSClientParam, HistoricalMAPErrorInfo, HistoricalMAPErrorCode]{code: HistoricalMAPErrorsUnknownOrUnreachableLCSClient, info: infoHistoricalMAPErrorsUnknownOrUnreachableLCSClientError, parameter: adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERUnknownOrUnreachableLCSClientParam](__asn1pkg_v21_map_er_datatypes.ERUnknownOrUnreachableLCSClientParamCodec())}}
}
func infoHistoricalMAPErrorsUnknownOrUnreachableLCSClientError() HistoricalMAPErrorInfo {
	return HistoricalMAPErrorInfo{Name: "unknownOrUnreachableLCSClient", Code: HistoricalMAPErrorsUnknownOrUnreachableLCSClient, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "UnknownOrUnreachableLCSClient-Param", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERUnknownOrUnreachableLCSClientParam"}, ParameterOptional: nil, Source: sourceInfo0("unknownOrUnreachableLCSClient", "17.6.6")}
}

// HistoricalMAPErrorsUnknownSubscriberErrorDescriptor binds the formal ERROR object MAP-Errors.unknownSubscriber (X.880 §8.3).
func HistoricalMAPErrorsUnknownSubscriberErrorDescriptor() HistoricalMAPErrorDescriptor[__asn1pkg_v21_map_er_datatypes.ERUnknownSubscriberParam] {
	return HistoricalMAPErrorDescriptor[__asn1pkg_v21_map_er_datatypes.ERUnknownSubscriberParam]{errorBinding[__asn1pkg_v21_map_er_datatypes.ERUnknownSubscriberParam, HistoricalMAPErrorInfo, HistoricalMAPErrorCode]{code: HistoricalMAPErrorsUnknownSubscriber, info: infoHistoricalMAPErrorsUnknownSubscriberError, parameter: adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERUnknownSubscriberParam](__asn1pkg_v21_map_er_datatypes.ERUnknownSubscriberParamCodec())}}
}
func infoHistoricalMAPErrorsUnknownSubscriberError() HistoricalMAPErrorInfo {
	return HistoricalMAPErrorInfo{Name: "unknownSubscriber", Code: HistoricalMAPErrorsUnknownSubscriber, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "UnknownSubscriberParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERUnknownSubscriberParam"}, ParameterOptional: nil, Source: sourceInfo0("unknownSubscriber", "17.6.6")}
}

// HistoricalMAPErrorsUssdBusyErrorDescriptor binds the formal ERROR object MAP-Errors.ussd-Busy (X.880 §8.3).
func HistoricalMAPErrorsUssdBusyErrorDescriptor() HistoricalMAPErrorDescriptor[NoParameter] {
	return HistoricalMAPErrorDescriptor[NoParameter]{errorBinding[NoParameter, HistoricalMAPErrorInfo, HistoricalMAPErrorCode]{code: HistoricalMAPErrorsUssdBusy, info: infoHistoricalMAPErrorsUssdBusyError, parameter: ValueCodec[NoParameter]{}}}
}
func infoHistoricalMAPErrorsUssdBusyError() HistoricalMAPErrorInfo {
	return HistoricalMAPErrorInfo{Name: "ussd-Busy", Code: HistoricalMAPErrorsUssdBusy, Parameter: nil, ParameterOptional: nil, Source: sourceInfo0("ussd-Busy", "17.6.6")}
}
func HistoricalMAPErrors() []HistoricalMAPErrorInfo {
	return []HistoricalMAPErrorInfo{infoHistoricalMAPErrorsAbsentSubscriberError(), infoHistoricalMAPErrorsAbsentSubscriberSMError(), infoHistoricalMAPErrorsAtiNotAllowedError(), infoHistoricalMAPErrorsAtmNotAllowedError(), infoHistoricalMAPErrorsAtsiNotAllowedError(), infoHistoricalMAPErrorsBearerServiceNotProvisionedError(), infoHistoricalMAPErrorsBusySubscriberError(), infoHistoricalMAPErrorsCallBarredError(), infoHistoricalMAPErrorsCugRejectError(), infoHistoricalMAPErrorsDataMissingError(), infoHistoricalMAPErrorsFacilityNotSupportedError(), infoHistoricalMAPErrorsForwardingFailedError(), infoHistoricalMAPErrorsForwardingViolationError(), infoHistoricalMAPErrorsIllegalEquipmentError(), infoHistoricalMAPErrorsIllegalSSOperationError(), infoHistoricalMAPErrorsIllegalSubscriberError(), infoHistoricalMAPErrorsIncompatibleTerminalError(), infoHistoricalMAPErrorsInformationNotAvailableError(), infoHistoricalMAPErrorsLongTermDenialError(), infoHistoricalMAPErrorsMessageWaitingListFullError(), infoHistoricalMAPErrorsMmEventNotSupportedError(), infoHistoricalMAPErrorsNegativePWCheckError(), infoHistoricalMAPErrorsNoGroupCallNumberAvailableError(), infoHistoricalMAPErrorsNoHandoverNumberAvailableError(), infoHistoricalMAPErrorsNoRoamingNumberAvailableError(), infoHistoricalMAPErrorsNoSubscriberReplyError(), infoHistoricalMAPErrorsNumberChangedError(), infoHistoricalMAPErrorsNumberOfPWAttemptsViolationError(), infoHistoricalMAPErrorsOngoingGroupCallError(), infoHistoricalMAPErrorsOrNotAllowedError(), infoHistoricalMAPErrorsPositionMethodFailureError(), infoHistoricalMAPErrorsPwRegistrationFailureError(), infoHistoricalMAPErrorsResourceLimitationError(), infoHistoricalMAPErrorsRoamingNotAllowedError(), infoHistoricalMAPErrorsShortTermDenialError(), infoHistoricalMAPErrorsSmDeliveryFailureError(), infoHistoricalMAPErrorsSsErrorStatusError(), infoHistoricalMAPErrorsSsIncompatibilityError(), infoHistoricalMAPErrorsSsNotAvailableError(), infoHistoricalMAPErrorsSsSubscriptionViolationError(), infoHistoricalMAPErrorsSubscriberBusyForMTSMSError(), infoHistoricalMAPErrorsSubsequentHandoverFailureError(), infoHistoricalMAPErrorsSystemFailureError(), infoHistoricalMAPErrorsTargetCellOutsideGroupCallAreaError(), infoHistoricalMAPErrorsTeleserviceNotProvisionedError(), infoHistoricalMAPErrorsTracingBufferFullError(), infoHistoricalMAPErrorsUnauthorizedLCSClientError(), infoHistoricalMAPErrorsUnauthorizedRequestingNetworkError(), infoHistoricalMAPErrorsUnexpectedDataValueError(), infoHistoricalMAPErrorsUnidentifiedSubscriberError(), infoHistoricalMAPErrorsUnknownAlphabetError(), infoHistoricalMAPErrorsUnknownEquipmentError(), infoHistoricalMAPErrorsUnknownMSCError(), infoHistoricalMAPErrorsUnknownOrUnreachableLCSClientError(), infoHistoricalMAPErrorsUnknownSubscriberError(), infoHistoricalMAPErrorsUssdBusyError()}
}
func LookupHistoricalMAPError(code HistoricalMAPErrorCode) (HistoricalMAPErrorInfo, bool) {
	switch code {
	case HistoricalMAPErrorsAbsentSubscriber:
		return infoHistoricalMAPErrorsAbsentSubscriberError(), true
	case HistoricalMAPErrorsAbsentSubscriberSM:
		return infoHistoricalMAPErrorsAbsentSubscriberSMError(), true
	case HistoricalMAPErrorsAtiNotAllowed:
		return infoHistoricalMAPErrorsAtiNotAllowedError(), true
	case HistoricalMAPErrorsAtmNotAllowed:
		return infoHistoricalMAPErrorsAtmNotAllowedError(), true
	case HistoricalMAPErrorsAtsiNotAllowed:
		return infoHistoricalMAPErrorsAtsiNotAllowedError(), true
	case HistoricalMAPErrorsBearerServiceNotProvisioned:
		return infoHistoricalMAPErrorsBearerServiceNotProvisionedError(), true
	case HistoricalMAPErrorsBusySubscriber:
		return infoHistoricalMAPErrorsBusySubscriberError(), true
	case HistoricalMAPErrorsCallBarred:
		return infoHistoricalMAPErrorsCallBarredError(), true
	case HistoricalMAPErrorsCugReject:
		return infoHistoricalMAPErrorsCugRejectError(), true
	case HistoricalMAPErrorsDataMissing:
		return infoHistoricalMAPErrorsDataMissingError(), true
	case HistoricalMAPErrorsFacilityNotSupported:
		return infoHistoricalMAPErrorsFacilityNotSupportedError(), true
	case HistoricalMAPErrorsForwardingFailed:
		return infoHistoricalMAPErrorsForwardingFailedError(), true
	case HistoricalMAPErrorsForwardingViolation:
		return infoHistoricalMAPErrorsForwardingViolationError(), true
	case HistoricalMAPErrorsIllegalEquipment:
		return infoHistoricalMAPErrorsIllegalEquipmentError(), true
	case HistoricalMAPErrorsIllegalSSOperation:
		return infoHistoricalMAPErrorsIllegalSSOperationError(), true
	case HistoricalMAPErrorsIllegalSubscriber:
		return infoHistoricalMAPErrorsIllegalSubscriberError(), true
	case HistoricalMAPErrorsIncompatibleTerminal:
		return infoHistoricalMAPErrorsIncompatibleTerminalError(), true
	case HistoricalMAPErrorsInformationNotAvailable:
		return infoHistoricalMAPErrorsInformationNotAvailableError(), true
	case HistoricalMAPErrorsLongTermDenial:
		return infoHistoricalMAPErrorsLongTermDenialError(), true
	case HistoricalMAPErrorsMessageWaitingListFull:
		return infoHistoricalMAPErrorsMessageWaitingListFullError(), true
	case HistoricalMAPErrorsMmEventNotSupported:
		return infoHistoricalMAPErrorsMmEventNotSupportedError(), true
	case HistoricalMAPErrorsNegativePWCheck:
		return infoHistoricalMAPErrorsNegativePWCheckError(), true
	case HistoricalMAPErrorsNoGroupCallNumberAvailable:
		return infoHistoricalMAPErrorsNoGroupCallNumberAvailableError(), true
	case HistoricalMAPErrorsNoHandoverNumberAvailable:
		return infoHistoricalMAPErrorsNoHandoverNumberAvailableError(), true
	case HistoricalMAPErrorsNoRoamingNumberAvailable:
		return infoHistoricalMAPErrorsNoRoamingNumberAvailableError(), true
	case HistoricalMAPErrorsNoSubscriberReply:
		return infoHistoricalMAPErrorsNoSubscriberReplyError(), true
	case HistoricalMAPErrorsNumberChanged:
		return infoHistoricalMAPErrorsNumberChangedError(), true
	case HistoricalMAPErrorsNumberOfPWAttemptsViolation:
		return infoHistoricalMAPErrorsNumberOfPWAttemptsViolationError(), true
	case HistoricalMAPErrorsOngoingGroupCall:
		return infoHistoricalMAPErrorsOngoingGroupCallError(), true
	case HistoricalMAPErrorsOrNotAllowed:
		return infoHistoricalMAPErrorsOrNotAllowedError(), true
	case HistoricalMAPErrorsPositionMethodFailure:
		return infoHistoricalMAPErrorsPositionMethodFailureError(), true
	case HistoricalMAPErrorsPwRegistrationFailure:
		return infoHistoricalMAPErrorsPwRegistrationFailureError(), true
	case HistoricalMAPErrorsResourceLimitation:
		return infoHistoricalMAPErrorsResourceLimitationError(), true
	case HistoricalMAPErrorsRoamingNotAllowed:
		return infoHistoricalMAPErrorsRoamingNotAllowedError(), true
	case HistoricalMAPErrorsShortTermDenial:
		return infoHistoricalMAPErrorsShortTermDenialError(), true
	case HistoricalMAPErrorsSmDeliveryFailure:
		return infoHistoricalMAPErrorsSmDeliveryFailureError(), true
	case HistoricalMAPErrorsSsErrorStatus:
		return infoHistoricalMAPErrorsSsErrorStatusError(), true
	case HistoricalMAPErrorsSsIncompatibility:
		return infoHistoricalMAPErrorsSsIncompatibilityError(), true
	case HistoricalMAPErrorsSsNotAvailable:
		return infoHistoricalMAPErrorsSsNotAvailableError(), true
	case HistoricalMAPErrorsSsSubscriptionViolation:
		return infoHistoricalMAPErrorsSsSubscriptionViolationError(), true
	case HistoricalMAPErrorsSubscriberBusyForMTSMS:
		return infoHistoricalMAPErrorsSubscriberBusyForMTSMSError(), true
	case HistoricalMAPErrorsSubsequentHandoverFailure:
		return infoHistoricalMAPErrorsSubsequentHandoverFailureError(), true
	case HistoricalMAPErrorsSystemFailure:
		return infoHistoricalMAPErrorsSystemFailureError(), true
	case HistoricalMAPErrorsTargetCellOutsideGroupCallArea:
		return infoHistoricalMAPErrorsTargetCellOutsideGroupCallAreaError(), true
	case HistoricalMAPErrorsTeleserviceNotProvisioned:
		return infoHistoricalMAPErrorsTeleserviceNotProvisionedError(), true
	case HistoricalMAPErrorsTracingBufferFull:
		return infoHistoricalMAPErrorsTracingBufferFullError(), true
	case HistoricalMAPErrorsUnauthorizedLCSClient:
		return infoHistoricalMAPErrorsUnauthorizedLCSClientError(), true
	case HistoricalMAPErrorsUnauthorizedRequestingNetwork:
		return infoHistoricalMAPErrorsUnauthorizedRequestingNetworkError(), true
	case HistoricalMAPErrorsUnexpectedDataValue:
		return infoHistoricalMAPErrorsUnexpectedDataValueError(), true
	case HistoricalMAPErrorsUnidentifiedSubscriber:
		return infoHistoricalMAPErrorsUnidentifiedSubscriberError(), true
	case HistoricalMAPErrorsUnknownAlphabet:
		return infoHistoricalMAPErrorsUnknownAlphabetError(), true
	case HistoricalMAPErrorsUnknownEquipment:
		return infoHistoricalMAPErrorsUnknownEquipmentError(), true
	case HistoricalMAPErrorsUnknownMSC:
		return infoHistoricalMAPErrorsUnknownMSCError(), true
	case HistoricalMAPErrorsUnknownOrUnreachableLCSClient:
		return infoHistoricalMAPErrorsUnknownOrUnreachableLCSClientError(), true
	case HistoricalMAPErrorsUnknownSubscriber:
		return infoHistoricalMAPErrorsUnknownSubscriberError(), true
	case HistoricalMAPErrorsUssdBusy:
		return infoHistoricalMAPErrorsUssdBusyError(), true
	default:
		return HistoricalMAPErrorInfo{}, false
	}
}
func sourceInfo0(assignment, clause string) SourceRef {
	return SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: clause, Module: "MAP-Errors", Assignment: assignment, SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}
}
