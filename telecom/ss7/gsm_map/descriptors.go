// Code generated from formal ASN.1 objects and values. DO NOT EDIT.

package gsm_map

import (
	"fmt"

	runtime "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime"
	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime/ber"
	__asn1pkg_v21_map_er_datatypes "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes"
	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_ss_datatypes"
)

// SourceRef identifies the formal source assignment, not procedure policy.
type SourceRef struct{ Document, Edition, Clause, Module, Assignment, SHA256 string }
type TypeRef struct{ ModuleOID, ASN1Name, GoPackage, GoName string }

// NoParameter denotes an absent source type field. It has no NULL codec.
type NoParameter struct{}

// ErrorValue preserves carrying-component presence independently of source type.
type ErrorValue[P any] struct{ Parameter *P }

type operationBinding[A, R, E, I, C, W any] struct {
	code     C
	info     func() I
	argument ValueCodec[A]
	result   ValueCodec[R]
	decode   func(int64, []byte, bool, ...ber.DecodeOption) (E, error)
	encode   func(E, ...ber.EncodeOption) (W, error)
}

func (d operationBinding[A, R, E, I, C, W]) Code() C { return d.code }
func (d operationBinding[A, R, E, I, C, W]) Info() I {
	if d.info == nil {
		var zero I
		return zero
	}
	return d.info()
}
func (d operationBinding[A, R, E, I, C, W]) Argument() (ValueCodec[A], bool) {
	return d.argument, d.argument.valid()
}
func (d operationBinding[A, R, E, I, C, W]) Result() (ValueCodec[R], bool) {
	return d.result, d.result.valid()
}
func (d operationBinding[A, R, E, I, C, W]) encodeError(v E, opts ...ber.EncodeOption) (W, error) {
	if d.encode == nil {
		var zero W
		return zero, ber.ErrInvalidBinding
	}
	return d.encode(v, opts...)
}
func (d operationBinding[A, R, E, I, C, W]) decodeError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (E, error) {
	if d.decode == nil {
		var zero E
		return zero, ber.ErrInvalidBinding
	}
	return d.decode(code, data, present, opts...)
}

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

type ErrorInfo struct {
	Name              string
	Code              MAPErrorCode
	Parameter         *TypeRef
	ParameterOptional *bool
	Source            SourceRef
}
type ErrorDescriptor[P any] struct {
	errorBinding[P, ErrorInfo, MAPErrorCode]
}

// AbsentSubscriberErrorDescriptor binds the formal ERROR object MAP-Errors.absentSubscriber (X.880 §8.3).
func AbsentSubscriberErrorDescriptor() ErrorDescriptor[AbsentSubscriberParam] {
	return ErrorDescriptor[AbsentSubscriberParam]{errorBinding[AbsentSubscriberParam, ErrorInfo, MAPErrorCode]{code: AbsentSubscriber, info: infoAbsentSubscriberError, parameter: AbsentSubscriberParamCodec()}}
}
func infoAbsentSubscriberError() ErrorInfo {
	return ErrorInfo{Name: "absentSubscriber", Code: AbsentSubscriber, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.22", ASN1Name: "AbsentSubscriberParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "AbsentSubscriberParam"}, ParameterOptional: nil, Source: sourceInfo0("absentSubscriber", "17.6.6")}
}

// AbsentSubscriberSMErrorDescriptor binds the formal ERROR object MAP-Errors.absentSubscriberSM (X.880 §8.3).
func AbsentSubscriberSMErrorDescriptor() ErrorDescriptor[AbsentSubscriberSMParam] {
	return ErrorDescriptor[AbsentSubscriberSMParam]{errorBinding[AbsentSubscriberSMParam, ErrorInfo, MAPErrorCode]{code: AbsentSubscriberSM, info: infoAbsentSubscriberSMError, parameter: AbsentSubscriberSMParamCodec()}}
}
func infoAbsentSubscriberSMError() ErrorInfo {
	return ErrorInfo{Name: "absentSubscriberSM", Code: AbsentSubscriberSM, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.22", ASN1Name: "AbsentSubscriberSM-Param", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "AbsentSubscriberSMParam"}, ParameterOptional: nil, Source: sourceInfo0("absentSubscriberSM", "17.6.6")}
}

// AtiNotAllowedErrorDescriptor binds the formal ERROR object MAP-Errors.ati-NotAllowed (X.880 §8.3).
func AtiNotAllowedErrorDescriptor() ErrorDescriptor[ATINotAllowedParam] {
	return ErrorDescriptor[ATINotAllowedParam]{errorBinding[ATINotAllowedParam, ErrorInfo, MAPErrorCode]{code: AtiNotAllowed, info: infoAtiNotAllowedError, parameter: ATINotAllowedParamCodec()}}
}
func infoAtiNotAllowedError() ErrorInfo {
	return ErrorInfo{Name: "ati-NotAllowed", Code: AtiNotAllowed, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.22", ASN1Name: "ATI-NotAllowedParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "ATINotAllowedParam"}, ParameterOptional: nil, Source: sourceInfo0("ati-NotAllowed", "17.6.6")}
}

// AtmNotAllowedErrorDescriptor binds the formal ERROR object MAP-Errors.atm-NotAllowed (X.880 §8.3).
func AtmNotAllowedErrorDescriptor() ErrorDescriptor[ATMNotAllowedParam] {
	return ErrorDescriptor[ATMNotAllowedParam]{errorBinding[ATMNotAllowedParam, ErrorInfo, MAPErrorCode]{code: AtmNotAllowed, info: infoAtmNotAllowedError, parameter: ATMNotAllowedParamCodec()}}
}
func infoAtmNotAllowedError() ErrorInfo {
	return ErrorInfo{Name: "atm-NotAllowed", Code: AtmNotAllowed, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.22", ASN1Name: "ATM-NotAllowedParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "ATMNotAllowedParam"}, ParameterOptional: nil, Source: sourceInfo0("atm-NotAllowed", "17.6.6")}
}

// AtsiNotAllowedErrorDescriptor binds the formal ERROR object MAP-Errors.atsi-NotAllowed (X.880 §8.3).
func AtsiNotAllowedErrorDescriptor() ErrorDescriptor[ATSINotAllowedParam] {
	return ErrorDescriptor[ATSINotAllowedParam]{errorBinding[ATSINotAllowedParam, ErrorInfo, MAPErrorCode]{code: AtsiNotAllowed, info: infoAtsiNotAllowedError, parameter: ATSINotAllowedParamCodec()}}
}
func infoAtsiNotAllowedError() ErrorInfo {
	return ErrorInfo{Name: "atsi-NotAllowed", Code: AtsiNotAllowed, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.22", ASN1Name: "ATSI-NotAllowedParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "ATSINotAllowedParam"}, ParameterOptional: nil, Source: sourceInfo0("atsi-NotAllowed", "17.6.6")}
}

// BearerServiceNotProvisionedErrorDescriptor binds the formal ERROR object MAP-Errors.bearerServiceNotProvisioned (X.880 §8.3).
func BearerServiceNotProvisionedErrorDescriptor() ErrorDescriptor[BearerServNotProvParam] {
	return ErrorDescriptor[BearerServNotProvParam]{errorBinding[BearerServNotProvParam, ErrorInfo, MAPErrorCode]{code: BearerServiceNotProvisioned, info: infoBearerServiceNotProvisionedError, parameter: BearerServNotProvParamCodec()}}
}
func infoBearerServiceNotProvisionedError() ErrorInfo {
	return ErrorInfo{Name: "bearerServiceNotProvisioned", Code: BearerServiceNotProvisioned, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.22", ASN1Name: "BearerServNotProvParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "BearerServNotProvParam"}, ParameterOptional: nil, Source: sourceInfo0("bearerServiceNotProvisioned", "17.6.6")}
}

// BusySubscriberErrorDescriptor binds the formal ERROR object MAP-Errors.busySubscriber (X.880 §8.3).
func BusySubscriberErrorDescriptor() ErrorDescriptor[BusySubscriberParam] {
	return ErrorDescriptor[BusySubscriberParam]{errorBinding[BusySubscriberParam, ErrorInfo, MAPErrorCode]{code: BusySubscriber, info: infoBusySubscriberError, parameter: BusySubscriberParamCodec()}}
}
func infoBusySubscriberError() ErrorInfo {
	return ErrorInfo{Name: "busySubscriber", Code: BusySubscriber, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.22", ASN1Name: "BusySubscriberParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "BusySubscriberParam"}, ParameterOptional: nil, Source: sourceInfo0("busySubscriber", "17.6.6")}
}

// CallBarredErrorDescriptor binds the formal ERROR object MAP-Errors.callBarred (X.880 §8.3).
func CallBarredErrorDescriptor() ErrorDescriptor[CallBarredParam] {
	return ErrorDescriptor[CallBarredParam]{errorBinding[CallBarredParam, ErrorInfo, MAPErrorCode]{code: CallBarred, info: infoCallBarredError, parameter: CallBarredParamCodec()}}
}
func infoCallBarredError() ErrorInfo {
	return ErrorInfo{Name: "callBarred", Code: CallBarred, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.22", ASN1Name: "CallBarredParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "CallBarredParam"}, ParameterOptional: nil, Source: sourceInfo0("callBarred", "17.6.6")}
}

// CugRejectErrorDescriptor binds the formal ERROR object MAP-Errors.cug-Reject (X.880 §8.3).
func CugRejectErrorDescriptor() ErrorDescriptor[CUGRejectParam] {
	return ErrorDescriptor[CUGRejectParam]{errorBinding[CUGRejectParam, ErrorInfo, MAPErrorCode]{code: CugReject, info: infoCugRejectError, parameter: CUGRejectParamCodec()}}
}
func infoCugRejectError() ErrorInfo {
	return ErrorInfo{Name: "cug-Reject", Code: CugReject, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.22", ASN1Name: "CUG-RejectParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "CUGRejectParam"}, ParameterOptional: nil, Source: sourceInfo0("cug-Reject", "17.6.6")}
}

// DataMissingErrorDescriptor binds the formal ERROR object MAP-Errors.dataMissing (X.880 §8.3).
func DataMissingErrorDescriptor() ErrorDescriptor[DataMissingParam] {
	return ErrorDescriptor[DataMissingParam]{errorBinding[DataMissingParam, ErrorInfo, MAPErrorCode]{code: DataMissing, info: infoDataMissingError, parameter: DataMissingParamCodec()}}
}
func infoDataMissingError() ErrorInfo {
	return ErrorInfo{Name: "dataMissing", Code: DataMissing, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.22", ASN1Name: "DataMissingParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "DataMissingParam"}, ParameterOptional: nil, Source: sourceInfo0("dataMissing", "17.6.6")}
}

// FacilityNotSupportedErrorDescriptor binds the formal ERROR object MAP-Errors.facilityNotSupported (X.880 §8.3).
func FacilityNotSupportedErrorDescriptor() ErrorDescriptor[FacilityNotSupParam] {
	return ErrorDescriptor[FacilityNotSupParam]{errorBinding[FacilityNotSupParam, ErrorInfo, MAPErrorCode]{code: FacilityNotSupported, info: infoFacilityNotSupportedError, parameter: FacilityNotSupParamCodec()}}
}
func infoFacilityNotSupportedError() ErrorInfo {
	return ErrorInfo{Name: "facilityNotSupported", Code: FacilityNotSupported, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.22", ASN1Name: "FacilityNotSupParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "FacilityNotSupParam"}, ParameterOptional: nil, Source: sourceInfo0("facilityNotSupported", "17.6.6")}
}

// ForwardingFailedErrorDescriptor binds the formal ERROR object MAP-Errors.forwardingFailed (X.880 §8.3).
func ForwardingFailedErrorDescriptor() ErrorDescriptor[ForwardingFailedParam] {
	return ErrorDescriptor[ForwardingFailedParam]{errorBinding[ForwardingFailedParam, ErrorInfo, MAPErrorCode]{code: ForwardingFailed, info: infoForwardingFailedError, parameter: ForwardingFailedParamCodec()}}
}
func infoForwardingFailedError() ErrorInfo {
	return ErrorInfo{Name: "forwardingFailed", Code: ForwardingFailed, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.22", ASN1Name: "ForwardingFailedParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "ForwardingFailedParam"}, ParameterOptional: nil, Source: sourceInfo0("forwardingFailed", "17.6.6")}
}

// ForwardingViolationErrorDescriptor binds the formal ERROR object MAP-Errors.forwardingViolation (X.880 §8.3).
func ForwardingViolationErrorDescriptor() ErrorDescriptor[ForwardingViolationParam] {
	return ErrorDescriptor[ForwardingViolationParam]{errorBinding[ForwardingViolationParam, ErrorInfo, MAPErrorCode]{code: ForwardingViolation, info: infoForwardingViolationError, parameter: ForwardingViolationParamCodec()}}
}
func infoForwardingViolationError() ErrorInfo {
	return ErrorInfo{Name: "forwardingViolation", Code: ForwardingViolation, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.22", ASN1Name: "ForwardingViolationParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "ForwardingViolationParam"}, ParameterOptional: nil, Source: sourceInfo0("forwardingViolation", "17.6.6")}
}

// IllegalEquipmentErrorDescriptor binds the formal ERROR object MAP-Errors.illegalEquipment (X.880 §8.3).
func IllegalEquipmentErrorDescriptor() ErrorDescriptor[IllegalEquipmentParam] {
	return ErrorDescriptor[IllegalEquipmentParam]{errorBinding[IllegalEquipmentParam, ErrorInfo, MAPErrorCode]{code: IllegalEquipment, info: infoIllegalEquipmentError, parameter: IllegalEquipmentParamCodec()}}
}
func infoIllegalEquipmentError() ErrorInfo {
	return ErrorInfo{Name: "illegalEquipment", Code: IllegalEquipment, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.22", ASN1Name: "IllegalEquipmentParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "IllegalEquipmentParam"}, ParameterOptional: nil, Source: sourceInfo0("illegalEquipment", "17.6.6")}
}

// IllegalSSOperationErrorDescriptor binds the formal ERROR object MAP-Errors.illegalSS-Operation (X.880 §8.3).
func IllegalSSOperationErrorDescriptor() ErrorDescriptor[IllegalSSOperationParam] {
	return ErrorDescriptor[IllegalSSOperationParam]{errorBinding[IllegalSSOperationParam, ErrorInfo, MAPErrorCode]{code: IllegalSSOperation, info: infoIllegalSSOperationError, parameter: IllegalSSOperationParamCodec()}}
}
func infoIllegalSSOperationError() ErrorInfo {
	return ErrorInfo{Name: "illegalSS-Operation", Code: IllegalSSOperation, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.22", ASN1Name: "IllegalSS-OperationParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "IllegalSSOperationParam"}, ParameterOptional: nil, Source: sourceInfo0("illegalSS-Operation", "17.6.6")}
}

// IllegalSubscriberErrorDescriptor binds the formal ERROR object MAP-Errors.illegalSubscriber (X.880 §8.3).
func IllegalSubscriberErrorDescriptor() ErrorDescriptor[IllegalSubscriberParam] {
	return ErrorDescriptor[IllegalSubscriberParam]{errorBinding[IllegalSubscriberParam, ErrorInfo, MAPErrorCode]{code: IllegalSubscriber, info: infoIllegalSubscriberError, parameter: IllegalSubscriberParamCodec()}}
}
func infoIllegalSubscriberError() ErrorInfo {
	return ErrorInfo{Name: "illegalSubscriber", Code: IllegalSubscriber, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.22", ASN1Name: "IllegalSubscriberParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "IllegalSubscriberParam"}, ParameterOptional: nil, Source: sourceInfo0("illegalSubscriber", "17.6.6")}
}

// IncompatibleTerminalErrorDescriptor binds the formal ERROR object MAP-Errors.incompatibleTerminal (X.880 §8.3).
func IncompatibleTerminalErrorDescriptor() ErrorDescriptor[IncompatibleTerminalParam] {
	return ErrorDescriptor[IncompatibleTerminalParam]{errorBinding[IncompatibleTerminalParam, ErrorInfo, MAPErrorCode]{code: IncompatibleTerminal, info: infoIncompatibleTerminalError, parameter: IncompatibleTerminalParamCodec()}}
}
func infoIncompatibleTerminalError() ErrorInfo {
	return ErrorInfo{Name: "incompatibleTerminal", Code: IncompatibleTerminal, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.22", ASN1Name: "IncompatibleTerminalParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "IncompatibleTerminalParam"}, ParameterOptional: nil, Source: sourceInfo0("incompatibleTerminal", "17.6.6")}
}

// InformationNotAvailableErrorDescriptor binds the formal ERROR object MAP-Errors.informationNotAvailable (X.880 §8.3).
func InformationNotAvailableErrorDescriptor() ErrorDescriptor[InformationNotAvailableParam] {
	return ErrorDescriptor[InformationNotAvailableParam]{errorBinding[InformationNotAvailableParam, ErrorInfo, MAPErrorCode]{code: InformationNotAvailable, info: infoInformationNotAvailableError, parameter: InformationNotAvailableParamCodec()}}
}
func infoInformationNotAvailableError() ErrorInfo {
	return ErrorInfo{Name: "informationNotAvailable", Code: InformationNotAvailable, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.22", ASN1Name: "InformationNotAvailableParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "InformationNotAvailableParam"}, ParameterOptional: nil, Source: sourceInfo0("informationNotAvailable", "17.6.6")}
}

// LongTermDenialErrorDescriptor binds the formal ERROR object MAP-Errors.longTermDenial (X.880 §8.3).
func LongTermDenialErrorDescriptor() ErrorDescriptor[LongTermDenialParam] {
	return ErrorDescriptor[LongTermDenialParam]{errorBinding[LongTermDenialParam, ErrorInfo, MAPErrorCode]{code: LongTermDenial, info: infoLongTermDenialError, parameter: LongTermDenialParamCodec()}}
}
func infoLongTermDenialError() ErrorInfo {
	return ErrorInfo{Name: "longTermDenial", Code: LongTermDenial, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.22", ASN1Name: "LongTermDenialParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "LongTermDenialParam"}, ParameterOptional: nil, Source: sourceInfo0("longTermDenial", "17.6.6")}
}

// MessageWaitingListFullErrorDescriptor binds the formal ERROR object MAP-Errors.messageWaitingListFull (X.880 §8.3).
func MessageWaitingListFullErrorDescriptor() ErrorDescriptor[MessageWaitListFullParam] {
	return ErrorDescriptor[MessageWaitListFullParam]{errorBinding[MessageWaitListFullParam, ErrorInfo, MAPErrorCode]{code: MessageWaitingListFull, info: infoMessageWaitingListFullError, parameter: MessageWaitListFullParamCodec()}}
}
func infoMessageWaitingListFullError() ErrorInfo {
	return ErrorInfo{Name: "messageWaitingListFull", Code: MessageWaitingListFull, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.22", ASN1Name: "MessageWaitListFullParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "MessageWaitListFullParam"}, ParameterOptional: nil, Source: sourceInfo0("messageWaitingListFull", "17.6.6")}
}

// MmEventNotSupportedErrorDescriptor binds the formal ERROR object MAP-Errors.mm-EventNotSupported (X.880 §8.3).
func MmEventNotSupportedErrorDescriptor() ErrorDescriptor[MMEventNotSupportedParam] {
	return ErrorDescriptor[MMEventNotSupportedParam]{errorBinding[MMEventNotSupportedParam, ErrorInfo, MAPErrorCode]{code: MmEventNotSupported, info: infoMmEventNotSupportedError, parameter: MMEventNotSupportedParamCodec()}}
}
func infoMmEventNotSupportedError() ErrorInfo {
	return ErrorInfo{Name: "mm-EventNotSupported", Code: MmEventNotSupported, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.22", ASN1Name: "MM-EventNotSupported-Param", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "MMEventNotSupportedParam"}, ParameterOptional: nil, Source: sourceInfo0("mm-EventNotSupported", "17.6.6")}
}

// NegativePWCheckErrorDescriptor binds the formal ERROR object MAP-Errors.negativePW-Check (X.880 §8.3).
func NegativePWCheckErrorDescriptor() ErrorDescriptor[NoParameter] {
	return ErrorDescriptor[NoParameter]{errorBinding[NoParameter, ErrorInfo, MAPErrorCode]{code: NegativePWCheck, info: infoNegativePWCheckError, parameter: ValueCodec[NoParameter]{}}}
}
func infoNegativePWCheckError() ErrorInfo {
	return ErrorInfo{Name: "negativePW-Check", Code: NegativePWCheck, Parameter: nil, ParameterOptional: nil, Source: sourceInfo0("negativePW-Check", "17.6.6")}
}

// NoGroupCallNumberAvailableErrorDescriptor binds the formal ERROR object MAP-Errors.noGroupCallNumberAvailable (X.880 §8.3).
func NoGroupCallNumberAvailableErrorDescriptor() ErrorDescriptor[NoGroupCallNbParam] {
	return ErrorDescriptor[NoGroupCallNbParam]{errorBinding[NoGroupCallNbParam, ErrorInfo, MAPErrorCode]{code: NoGroupCallNumberAvailable, info: infoNoGroupCallNumberAvailableError, parameter: NoGroupCallNbParamCodec()}}
}
func infoNoGroupCallNumberAvailableError() ErrorInfo {
	return ErrorInfo{Name: "noGroupCallNumberAvailable", Code: NoGroupCallNumberAvailable, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.22", ASN1Name: "NoGroupCallNbParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "NoGroupCallNbParam"}, ParameterOptional: nil, Source: sourceInfo0("noGroupCallNumberAvailable", "17.6.6")}
}

// NoHandoverNumberAvailableErrorDescriptor binds the formal ERROR object MAP-Errors.noHandoverNumberAvailable (X.880 §8.3).
func NoHandoverNumberAvailableErrorDescriptor() ErrorDescriptor[NoParameter] {
	return ErrorDescriptor[NoParameter]{errorBinding[NoParameter, ErrorInfo, MAPErrorCode]{code: NoHandoverNumberAvailable, info: infoNoHandoverNumberAvailableError, parameter: ValueCodec[NoParameter]{}}}
}
func infoNoHandoverNumberAvailableError() ErrorInfo {
	return ErrorInfo{Name: "noHandoverNumberAvailable", Code: NoHandoverNumberAvailable, Parameter: nil, ParameterOptional: nil, Source: sourceInfo0("noHandoverNumberAvailable", "17.6.6")}
}

// NoRoamingNumberAvailableErrorDescriptor binds the formal ERROR object MAP-Errors.noRoamingNumberAvailable (X.880 §8.3).
func NoRoamingNumberAvailableErrorDescriptor() ErrorDescriptor[NoRoamingNbParam] {
	return ErrorDescriptor[NoRoamingNbParam]{errorBinding[NoRoamingNbParam, ErrorInfo, MAPErrorCode]{code: NoRoamingNumberAvailable, info: infoNoRoamingNumberAvailableError, parameter: NoRoamingNbParamCodec()}}
}
func infoNoRoamingNumberAvailableError() ErrorInfo {
	return ErrorInfo{Name: "noRoamingNumberAvailable", Code: NoRoamingNumberAvailable, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.22", ASN1Name: "NoRoamingNbParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "NoRoamingNbParam"}, ParameterOptional: nil, Source: sourceInfo0("noRoamingNumberAvailable", "17.6.6")}
}

// NoSubscriberReplyErrorDescriptor binds the formal ERROR object MAP-Errors.noSubscriberReply (X.880 §8.3).
func NoSubscriberReplyErrorDescriptor() ErrorDescriptor[NoSubscriberReplyParam] {
	return ErrorDescriptor[NoSubscriberReplyParam]{errorBinding[NoSubscriberReplyParam, ErrorInfo, MAPErrorCode]{code: NoSubscriberReply, info: infoNoSubscriberReplyError, parameter: NoSubscriberReplyParamCodec()}}
}
func infoNoSubscriberReplyError() ErrorInfo {
	return ErrorInfo{Name: "noSubscriberReply", Code: NoSubscriberReply, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.22", ASN1Name: "NoSubscriberReplyParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "NoSubscriberReplyParam"}, ParameterOptional: nil, Source: sourceInfo0("noSubscriberReply", "17.6.6")}
}

// NumberChangedErrorDescriptor binds the formal ERROR object MAP-Errors.numberChanged (X.880 §8.3).
func NumberChangedErrorDescriptor() ErrorDescriptor[NumberChangedParam] {
	return ErrorDescriptor[NumberChangedParam]{errorBinding[NumberChangedParam, ErrorInfo, MAPErrorCode]{code: NumberChanged, info: infoNumberChangedError, parameter: NumberChangedParamCodec()}}
}
func infoNumberChangedError() ErrorInfo {
	return ErrorInfo{Name: "numberChanged", Code: NumberChanged, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.22", ASN1Name: "NumberChangedParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "NumberChangedParam"}, ParameterOptional: nil, Source: sourceInfo0("numberChanged", "17.6.6")}
}

// NumberOfPWAttemptsViolationErrorDescriptor binds the formal ERROR object MAP-Errors.numberOfPW-AttemptsViolation (X.880 §8.3).
func NumberOfPWAttemptsViolationErrorDescriptor() ErrorDescriptor[NoParameter] {
	return ErrorDescriptor[NoParameter]{errorBinding[NoParameter, ErrorInfo, MAPErrorCode]{code: NumberOfPWAttemptsViolation, info: infoNumberOfPWAttemptsViolationError, parameter: ValueCodec[NoParameter]{}}}
}
func infoNumberOfPWAttemptsViolationError() ErrorInfo {
	return ErrorInfo{Name: "numberOfPW-AttemptsViolation", Code: NumberOfPWAttemptsViolation, Parameter: nil, ParameterOptional: nil, Source: sourceInfo0("numberOfPW-AttemptsViolation", "17.6.6")}
}

// OngoingGroupCallErrorDescriptor binds the formal ERROR object MAP-Errors.ongoingGroupCall (X.880 §8.3).
func OngoingGroupCallErrorDescriptor() ErrorDescriptor[OngoingGroupCallParam] {
	return ErrorDescriptor[OngoingGroupCallParam]{errorBinding[OngoingGroupCallParam, ErrorInfo, MAPErrorCode]{code: OngoingGroupCall, info: infoOngoingGroupCallError, parameter: OngoingGroupCallParamCodec()}}
}
func infoOngoingGroupCallError() ErrorInfo {
	return ErrorInfo{Name: "ongoingGroupCall", Code: OngoingGroupCall, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.22", ASN1Name: "OngoingGroupCallParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "OngoingGroupCallParam"}, ParameterOptional: nil, Source: sourceInfo0("ongoingGroupCall", "17.6.6")}
}

// OrNotAllowedErrorDescriptor binds the formal ERROR object MAP-Errors.or-NotAllowed (X.880 §8.3).
func OrNotAllowedErrorDescriptor() ErrorDescriptor[ORNotAllowedParam] {
	return ErrorDescriptor[ORNotAllowedParam]{errorBinding[ORNotAllowedParam, ErrorInfo, MAPErrorCode]{code: OrNotAllowed, info: infoOrNotAllowedError, parameter: ORNotAllowedParamCodec()}}
}
func infoOrNotAllowedError() ErrorInfo {
	return ErrorInfo{Name: "or-NotAllowed", Code: OrNotAllowed, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.22", ASN1Name: "OR-NotAllowedParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "ORNotAllowedParam"}, ParameterOptional: nil, Source: sourceInfo0("or-NotAllowed", "17.6.6")}
}

// PositionMethodFailureErrorDescriptor binds the formal ERROR object MAP-Errors.positionMethodFailure (X.880 §8.3).
func PositionMethodFailureErrorDescriptor() ErrorDescriptor[PositionMethodFailureParam] {
	return ErrorDescriptor[PositionMethodFailureParam]{errorBinding[PositionMethodFailureParam, ErrorInfo, MAPErrorCode]{code: PositionMethodFailure, info: infoPositionMethodFailureError, parameter: PositionMethodFailureParamCodec()}}
}
func infoPositionMethodFailureError() ErrorInfo {
	return ErrorInfo{Name: "positionMethodFailure", Code: PositionMethodFailure, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.22", ASN1Name: "PositionMethodFailure-Param", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "PositionMethodFailureParam"}, ParameterOptional: nil, Source: sourceInfo0("positionMethodFailure", "17.6.6")}
}

// PwRegistrationFailureErrorDescriptor binds the formal ERROR object MAP-Errors.pw-RegistrationFailure (X.880 §8.3).
func PwRegistrationFailureErrorDescriptor() ErrorDescriptor[BERValue[PWRegistrationFailureCause]] {
	return ErrorDescriptor[BERValue[PWRegistrationFailureCause]]{errorBinding[BERValue[PWRegistrationFailureCause], ErrorInfo, MAPErrorCode]{code: PwRegistrationFailure, info: infoPwRegistrationFailureError, parameter: PWRegistrationFailureCauseCodec()}}
}
func infoPwRegistrationFailureError() ErrorInfo {
	return ErrorInfo{Name: "pw-RegistrationFailure", Code: PwRegistrationFailure, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.22", ASN1Name: "PW-RegistrationFailureCause", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "PWRegistrationFailureCause"}, ParameterOptional: nil, Source: sourceInfo0("pw-RegistrationFailure", "17.6.6")}
}

// ResourceLimitationErrorDescriptor binds the formal ERROR object MAP-Errors.resourceLimitation (X.880 §8.3).
func ResourceLimitationErrorDescriptor() ErrorDescriptor[ResourceLimitationParam] {
	return ErrorDescriptor[ResourceLimitationParam]{errorBinding[ResourceLimitationParam, ErrorInfo, MAPErrorCode]{code: ResourceLimitation, info: infoResourceLimitationError, parameter: ResourceLimitationParamCodec()}}
}
func infoResourceLimitationError() ErrorInfo {
	return ErrorInfo{Name: "resourceLimitation", Code: ResourceLimitation, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.22", ASN1Name: "ResourceLimitationParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "ResourceLimitationParam"}, ParameterOptional: nil, Source: sourceInfo0("resourceLimitation", "17.6.6")}
}

// RoamingNotAllowedErrorDescriptor binds the formal ERROR object MAP-Errors.roamingNotAllowed (X.880 §8.3).
func RoamingNotAllowedErrorDescriptor() ErrorDescriptor[RoamingNotAllowedParam] {
	return ErrorDescriptor[RoamingNotAllowedParam]{errorBinding[RoamingNotAllowedParam, ErrorInfo, MAPErrorCode]{code: RoamingNotAllowed, info: infoRoamingNotAllowedError, parameter: RoamingNotAllowedParamCodec()}}
}
func infoRoamingNotAllowedError() ErrorInfo {
	return ErrorInfo{Name: "roamingNotAllowed", Code: RoamingNotAllowed, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.22", ASN1Name: "RoamingNotAllowedParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "RoamingNotAllowedParam"}, ParameterOptional: nil, Source: sourceInfo0("roamingNotAllowed", "17.6.6")}
}

// ShortTermDenialErrorDescriptor binds the formal ERROR object MAP-Errors.shortTermDenial (X.880 §8.3).
func ShortTermDenialErrorDescriptor() ErrorDescriptor[ShortTermDenialParam] {
	return ErrorDescriptor[ShortTermDenialParam]{errorBinding[ShortTermDenialParam, ErrorInfo, MAPErrorCode]{code: ShortTermDenial, info: infoShortTermDenialError, parameter: ShortTermDenialParamCodec()}}
}
func infoShortTermDenialError() ErrorInfo {
	return ErrorInfo{Name: "shortTermDenial", Code: ShortTermDenial, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.22", ASN1Name: "ShortTermDenialParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "ShortTermDenialParam"}, ParameterOptional: nil, Source: sourceInfo0("shortTermDenial", "17.6.6")}
}

// SmDeliveryFailureErrorDescriptor binds the formal ERROR object MAP-Errors.sm-DeliveryFailure (X.880 §8.3).
func SmDeliveryFailureErrorDescriptor() ErrorDescriptor[SMDeliveryFailureCause] {
	return ErrorDescriptor[SMDeliveryFailureCause]{errorBinding[SMDeliveryFailureCause, ErrorInfo, MAPErrorCode]{code: SmDeliveryFailure, info: infoSmDeliveryFailureError, parameter: SMDeliveryFailureCauseCodec()}}
}
func infoSmDeliveryFailureError() ErrorInfo {
	return ErrorInfo{Name: "sm-DeliveryFailure", Code: SmDeliveryFailure, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.22", ASN1Name: "SM-DeliveryFailureCause", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "SMDeliveryFailureCause"}, ParameterOptional: nil, Source: sourceInfo0("sm-DeliveryFailure", "17.6.6")}
}

// SsErrorStatusErrorDescriptor binds the formal ERROR object MAP-Errors.ss-ErrorStatus (X.880 §8.3).
func SsErrorStatusErrorDescriptor() ErrorDescriptor[BERValue[SSStatus]] {
	return ErrorDescriptor[BERValue[SSStatus]]{errorBinding[BERValue[SSStatus], ErrorInfo, MAPErrorCode]{code: SsErrorStatus, info: infoSsErrorStatusError, parameter: SSStatusCodec()}}
}
func infoSsErrorStatusError() ErrorInfo {
	return ErrorInfo{Name: "ss-ErrorStatus", Code: SsErrorStatus, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.14.22", ASN1Name: "SS-Status", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "SSStatus"}, ParameterOptional: nil, Source: sourceInfo0("ss-ErrorStatus", "17.6.6")}
}

// SsIncompatibilityErrorDescriptor binds the formal ERROR object MAP-Errors.ss-Incompatibility (X.880 §8.3).
func SsIncompatibilityErrorDescriptor() ErrorDescriptor[SSIncompatibilityCause] {
	return ErrorDescriptor[SSIncompatibilityCause]{errorBinding[SSIncompatibilityCause, ErrorInfo, MAPErrorCode]{code: SsIncompatibility, info: infoSsIncompatibilityError, parameter: SSIncompatibilityCauseCodec()}}
}
func infoSsIncompatibilityError() ErrorInfo {
	return ErrorInfo{Name: "ss-Incompatibility", Code: SsIncompatibility, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.22", ASN1Name: "SS-IncompatibilityCause", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "SSIncompatibilityCause"}, ParameterOptional: nil, Source: sourceInfo0("ss-Incompatibility", "17.6.6")}
}

// SsNotAvailableErrorDescriptor binds the formal ERROR object MAP-Errors.ss-NotAvailable (X.880 §8.3).
func SsNotAvailableErrorDescriptor() ErrorDescriptor[SSNotAvailableParam] {
	return ErrorDescriptor[SSNotAvailableParam]{errorBinding[SSNotAvailableParam, ErrorInfo, MAPErrorCode]{code: SsNotAvailable, info: infoSsNotAvailableError, parameter: SSNotAvailableParamCodec()}}
}
func infoSsNotAvailableError() ErrorInfo {
	return ErrorInfo{Name: "ss-NotAvailable", Code: SsNotAvailable, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.22", ASN1Name: "SS-NotAvailableParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "SSNotAvailableParam"}, ParameterOptional: nil, Source: sourceInfo0("ss-NotAvailable", "17.6.6")}
}

// SsSubscriptionViolationErrorDescriptor binds the formal ERROR object MAP-Errors.ss-SubscriptionViolation (X.880 §8.3).
func SsSubscriptionViolationErrorDescriptor() ErrorDescriptor[SSSubscriptionViolationParam] {
	return ErrorDescriptor[SSSubscriptionViolationParam]{errorBinding[SSSubscriptionViolationParam, ErrorInfo, MAPErrorCode]{code: SsSubscriptionViolation, info: infoSsSubscriptionViolationError, parameter: SSSubscriptionViolationParamCodec()}}
}
func infoSsSubscriptionViolationError() ErrorInfo {
	return ErrorInfo{Name: "ss-SubscriptionViolation", Code: SsSubscriptionViolation, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.22", ASN1Name: "SS-SubscriptionViolationParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "SSSubscriptionViolationParam"}, ParameterOptional: nil, Source: sourceInfo0("ss-SubscriptionViolation", "17.6.6")}
}

// SubscriberBusyForMTSMSErrorDescriptor binds the formal ERROR object MAP-Errors.subscriberBusyForMT-SMS (X.880 §8.3).
func SubscriberBusyForMTSMSErrorDescriptor() ErrorDescriptor[SubBusyForMTSMSParam] {
	return ErrorDescriptor[SubBusyForMTSMSParam]{errorBinding[SubBusyForMTSMSParam, ErrorInfo, MAPErrorCode]{code: SubscriberBusyForMTSMS, info: infoSubscriberBusyForMTSMSError, parameter: SubBusyForMTSMSParamCodec()}}
}
func infoSubscriberBusyForMTSMSError() ErrorInfo {
	return ErrorInfo{Name: "subscriberBusyForMT-SMS", Code: SubscriberBusyForMTSMS, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.22", ASN1Name: "SubBusyForMT-SMS-Param", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "SubBusyForMTSMSParam"}, ParameterOptional: nil, Source: sourceInfo0("subscriberBusyForMT-SMS", "17.6.6")}
}

// SubsequentHandoverFailureErrorDescriptor binds the formal ERROR object MAP-Errors.subsequentHandoverFailure (X.880 §8.3).
func SubsequentHandoverFailureErrorDescriptor() ErrorDescriptor[NoParameter] {
	return ErrorDescriptor[NoParameter]{errorBinding[NoParameter, ErrorInfo, MAPErrorCode]{code: SubsequentHandoverFailure, info: infoSubsequentHandoverFailureError, parameter: ValueCodec[NoParameter]{}}}
}
func infoSubsequentHandoverFailureError() ErrorInfo {
	return ErrorInfo{Name: "subsequentHandoverFailure", Code: SubsequentHandoverFailure, Parameter: nil, ParameterOptional: nil, Source: sourceInfo0("subsequentHandoverFailure", "17.6.6")}
}

// SystemFailureErrorDescriptor binds the formal ERROR object MAP-Errors.systemFailure (X.880 §8.3).
func SystemFailureErrorDescriptor() ErrorDescriptor[SystemFailureParam] {
	return ErrorDescriptor[SystemFailureParam]{errorBinding[SystemFailureParam, ErrorInfo, MAPErrorCode]{code: SystemFailure, info: infoSystemFailureError, parameter: SystemFailureParamCodec()}}
}
func infoSystemFailureError() ErrorInfo {
	return ErrorInfo{Name: "systemFailure", Code: SystemFailure, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.22", ASN1Name: "SystemFailureParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "SystemFailureParam"}, ParameterOptional: nil, Source: sourceInfo0("systemFailure", "17.6.6")}
}

// TargetCellOutsideGroupCallAreaErrorDescriptor binds the formal ERROR object MAP-Errors.targetCellOutsideGroupCallArea (X.880 §8.3).
func TargetCellOutsideGroupCallAreaErrorDescriptor() ErrorDescriptor[TargetCellOutsideGCAParam] {
	return ErrorDescriptor[TargetCellOutsideGCAParam]{errorBinding[TargetCellOutsideGCAParam, ErrorInfo, MAPErrorCode]{code: TargetCellOutsideGroupCallArea, info: infoTargetCellOutsideGroupCallAreaError, parameter: TargetCellOutsideGCAParamCodec()}}
}
func infoTargetCellOutsideGroupCallAreaError() ErrorInfo {
	return ErrorInfo{Name: "targetCellOutsideGroupCallArea", Code: TargetCellOutsideGroupCallArea, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.22", ASN1Name: "TargetCellOutsideGCA-Param", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "TargetCellOutsideGCAParam"}, ParameterOptional: nil, Source: sourceInfo0("targetCellOutsideGroupCallArea", "17.6.6")}
}

// TeleserviceNotProvisionedErrorDescriptor binds the formal ERROR object MAP-Errors.teleserviceNotProvisioned (X.880 §8.3).
func TeleserviceNotProvisionedErrorDescriptor() ErrorDescriptor[TeleservNotProvParam] {
	return ErrorDescriptor[TeleservNotProvParam]{errorBinding[TeleservNotProvParam, ErrorInfo, MAPErrorCode]{code: TeleserviceNotProvisioned, info: infoTeleserviceNotProvisionedError, parameter: TeleservNotProvParamCodec()}}
}
func infoTeleserviceNotProvisionedError() ErrorInfo {
	return ErrorInfo{Name: "teleserviceNotProvisioned", Code: TeleserviceNotProvisioned, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.22", ASN1Name: "TeleservNotProvParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "TeleservNotProvParam"}, ParameterOptional: nil, Source: sourceInfo0("teleserviceNotProvisioned", "17.6.6")}
}

// TracingBufferFullErrorDescriptor binds the formal ERROR object MAP-Errors.tracingBufferFull (X.880 §8.3).
func TracingBufferFullErrorDescriptor() ErrorDescriptor[TracingBufferFullParam] {
	return ErrorDescriptor[TracingBufferFullParam]{errorBinding[TracingBufferFullParam, ErrorInfo, MAPErrorCode]{code: TracingBufferFull, info: infoTracingBufferFullError, parameter: TracingBufferFullParamCodec()}}
}
func infoTracingBufferFullError() ErrorInfo {
	return ErrorInfo{Name: "tracingBufferFull", Code: TracingBufferFull, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.22", ASN1Name: "TracingBufferFullParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "TracingBufferFullParam"}, ParameterOptional: nil, Source: sourceInfo0("tracingBufferFull", "17.6.6")}
}

// UnauthorizedLCSClientErrorDescriptor binds the formal ERROR object MAP-Errors.unauthorizedLCSClient (X.880 §8.3).
func UnauthorizedLCSClientErrorDescriptor() ErrorDescriptor[UnauthorizedLCSClientParam] {
	return ErrorDescriptor[UnauthorizedLCSClientParam]{errorBinding[UnauthorizedLCSClientParam, ErrorInfo, MAPErrorCode]{code: UnauthorizedLCSClient, info: infoUnauthorizedLCSClientError, parameter: UnauthorizedLCSClientParamCodec()}}
}
func infoUnauthorizedLCSClientError() ErrorInfo {
	return ErrorInfo{Name: "unauthorizedLCSClient", Code: UnauthorizedLCSClient, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.22", ASN1Name: "UnauthorizedLCSClient-Param", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "UnauthorizedLCSClientParam"}, ParameterOptional: nil, Source: sourceInfo0("unauthorizedLCSClient", "17.6.6")}
}

// UnauthorizedRequestingNetworkErrorDescriptor binds the formal ERROR object MAP-Errors.unauthorizedRequestingNetwork (X.880 §8.3).
func UnauthorizedRequestingNetworkErrorDescriptor() ErrorDescriptor[UnauthorizedRequestingNetworkParam] {
	return ErrorDescriptor[UnauthorizedRequestingNetworkParam]{errorBinding[UnauthorizedRequestingNetworkParam, ErrorInfo, MAPErrorCode]{code: UnauthorizedRequestingNetwork, info: infoUnauthorizedRequestingNetworkError, parameter: UnauthorizedRequestingNetworkParamCodec()}}
}
func infoUnauthorizedRequestingNetworkError() ErrorInfo {
	return ErrorInfo{Name: "unauthorizedRequestingNetwork", Code: UnauthorizedRequestingNetwork, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.22", ASN1Name: "UnauthorizedRequestingNetwork-Param", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "UnauthorizedRequestingNetworkParam"}, ParameterOptional: nil, Source: sourceInfo0("unauthorizedRequestingNetwork", "17.6.6")}
}

// UnexpectedDataValueErrorDescriptor binds the formal ERROR object MAP-Errors.unexpectedDataValue (X.880 §8.3).
func UnexpectedDataValueErrorDescriptor() ErrorDescriptor[UnexpectedDataParam] {
	return ErrorDescriptor[UnexpectedDataParam]{errorBinding[UnexpectedDataParam, ErrorInfo, MAPErrorCode]{code: UnexpectedDataValue, info: infoUnexpectedDataValueError, parameter: UnexpectedDataParamCodec()}}
}
func infoUnexpectedDataValueError() ErrorInfo {
	return ErrorInfo{Name: "unexpectedDataValue", Code: UnexpectedDataValue, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.22", ASN1Name: "UnexpectedDataParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "UnexpectedDataParam"}, ParameterOptional: nil, Source: sourceInfo0("unexpectedDataValue", "17.6.6")}
}

// UnidentifiedSubscriberErrorDescriptor binds the formal ERROR object MAP-Errors.unidentifiedSubscriber (X.880 §8.3).
func UnidentifiedSubscriberErrorDescriptor() ErrorDescriptor[UnidentifiedSubParam] {
	return ErrorDescriptor[UnidentifiedSubParam]{errorBinding[UnidentifiedSubParam, ErrorInfo, MAPErrorCode]{code: UnidentifiedSubscriber, info: infoUnidentifiedSubscriberError, parameter: UnidentifiedSubParamCodec()}}
}
func infoUnidentifiedSubscriberError() ErrorInfo {
	return ErrorInfo{Name: "unidentifiedSubscriber", Code: UnidentifiedSubscriber, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.22", ASN1Name: "UnidentifiedSubParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "UnidentifiedSubParam"}, ParameterOptional: nil, Source: sourceInfo0("unidentifiedSubscriber", "17.6.6")}
}

// UnknownAlphabetErrorDescriptor binds the formal ERROR object MAP-Errors.unknownAlphabet (X.880 §8.3).
func UnknownAlphabetErrorDescriptor() ErrorDescriptor[NoParameter] {
	return ErrorDescriptor[NoParameter]{errorBinding[NoParameter, ErrorInfo, MAPErrorCode]{code: UnknownAlphabet, info: infoUnknownAlphabetError, parameter: ValueCodec[NoParameter]{}}}
}
func infoUnknownAlphabetError() ErrorInfo {
	return ErrorInfo{Name: "unknownAlphabet", Code: UnknownAlphabet, Parameter: nil, ParameterOptional: nil, Source: sourceInfo0("unknownAlphabet", "17.6.6")}
}

// UnknownEquipmentErrorDescriptor binds the formal ERROR object MAP-Errors.unknownEquipment (X.880 §8.3).
func UnknownEquipmentErrorDescriptor() ErrorDescriptor[NoParameter] {
	return ErrorDescriptor[NoParameter]{errorBinding[NoParameter, ErrorInfo, MAPErrorCode]{code: UnknownEquipment, info: infoUnknownEquipmentError, parameter: ValueCodec[NoParameter]{}}}
}
func infoUnknownEquipmentError() ErrorInfo {
	return ErrorInfo{Name: "unknownEquipment", Code: UnknownEquipment, Parameter: nil, ParameterOptional: nil, Source: sourceInfo0("unknownEquipment", "17.6.6")}
}

// UnknownMSCErrorDescriptor binds the formal ERROR object MAP-Errors.unknownMSC (X.880 §8.3).
func UnknownMSCErrorDescriptor() ErrorDescriptor[NoParameter] {
	return ErrorDescriptor[NoParameter]{errorBinding[NoParameter, ErrorInfo, MAPErrorCode]{code: UnknownMSC, info: infoUnknownMSCError, parameter: ValueCodec[NoParameter]{}}}
}
func infoUnknownMSCError() ErrorInfo {
	return ErrorInfo{Name: "unknownMSC", Code: UnknownMSC, Parameter: nil, ParameterOptional: nil, Source: sourceInfo0("unknownMSC", "17.6.6")}
}

// UnknownOrUnreachableLCSClientErrorDescriptor binds the formal ERROR object MAP-Errors.unknownOrUnreachableLCSClient (X.880 §8.3).
func UnknownOrUnreachableLCSClientErrorDescriptor() ErrorDescriptor[UnknownOrUnreachableLCSClientParam] {
	return ErrorDescriptor[UnknownOrUnreachableLCSClientParam]{errorBinding[UnknownOrUnreachableLCSClientParam, ErrorInfo, MAPErrorCode]{code: UnknownOrUnreachableLCSClient, info: infoUnknownOrUnreachableLCSClientError, parameter: UnknownOrUnreachableLCSClientParamCodec()}}
}
func infoUnknownOrUnreachableLCSClientError() ErrorInfo {
	return ErrorInfo{Name: "unknownOrUnreachableLCSClient", Code: UnknownOrUnreachableLCSClient, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.22", ASN1Name: "UnknownOrUnreachableLCSClient-Param", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "UnknownOrUnreachableLCSClientParam"}, ParameterOptional: nil, Source: sourceInfo0("unknownOrUnreachableLCSClient", "17.6.6")}
}

// UnknownSubscriberErrorDescriptor binds the formal ERROR object MAP-Errors.unknownSubscriber (X.880 §8.3).
func UnknownSubscriberErrorDescriptor() ErrorDescriptor[UnknownSubscriberParam] {
	return ErrorDescriptor[UnknownSubscriberParam]{errorBinding[UnknownSubscriberParam, ErrorInfo, MAPErrorCode]{code: UnknownSubscriber, info: infoUnknownSubscriberError, parameter: UnknownSubscriberParamCodec()}}
}
func infoUnknownSubscriberError() ErrorInfo {
	return ErrorInfo{Name: "unknownSubscriber", Code: UnknownSubscriber, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.22", ASN1Name: "UnknownSubscriberParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "UnknownSubscriberParam"}, ParameterOptional: nil, Source: sourceInfo0("unknownSubscriber", "17.6.6")}
}

// UssdBusyErrorDescriptor binds the formal ERROR object MAP-Errors.ussd-Busy (X.880 §8.3).
func UssdBusyErrorDescriptor() ErrorDescriptor[NoParameter] {
	return ErrorDescriptor[NoParameter]{errorBinding[NoParameter, ErrorInfo, MAPErrorCode]{code: UssdBusy, info: infoUssdBusyError, parameter: ValueCodec[NoParameter]{}}}
}
func infoUssdBusyError() ErrorInfo {
	return ErrorInfo{Name: "ussd-Busy", Code: UssdBusy, Parameter: nil, ParameterOptional: nil, Source: sourceInfo0("ussd-Busy", "17.6.6")}
}
func Errors() []ErrorInfo {
	return []ErrorInfo{infoAbsentSubscriberError(), infoAbsentSubscriberSMError(), infoAtiNotAllowedError(), infoAtmNotAllowedError(), infoAtsiNotAllowedError(), infoBearerServiceNotProvisionedError(), infoBusySubscriberError(), infoCallBarredError(), infoCugRejectError(), infoDataMissingError(), infoFacilityNotSupportedError(), infoForwardingFailedError(), infoForwardingViolationError(), infoIllegalEquipmentError(), infoIllegalSSOperationError(), infoIllegalSubscriberError(), infoIncompatibleTerminalError(), infoInformationNotAvailableError(), infoLongTermDenialError(), infoMessageWaitingListFullError(), infoMmEventNotSupportedError(), infoNegativePWCheckError(), infoNoGroupCallNumberAvailableError(), infoNoHandoverNumberAvailableError(), infoNoRoamingNumberAvailableError(), infoNoSubscriberReplyError(), infoNumberChangedError(), infoNumberOfPWAttemptsViolationError(), infoOngoingGroupCallError(), infoOrNotAllowedError(), infoPositionMethodFailureError(), infoPwRegistrationFailureError(), infoResourceLimitationError(), infoRoamingNotAllowedError(), infoShortTermDenialError(), infoSmDeliveryFailureError(), infoSsErrorStatusError(), infoSsIncompatibilityError(), infoSsNotAvailableError(), infoSsSubscriptionViolationError(), infoSubscriberBusyForMTSMSError(), infoSubsequentHandoverFailureError(), infoSystemFailureError(), infoTargetCellOutsideGroupCallAreaError(), infoTeleserviceNotProvisionedError(), infoTracingBufferFullError(), infoUnauthorizedLCSClientError(), infoUnauthorizedRequestingNetworkError(), infoUnexpectedDataValueError(), infoUnidentifiedSubscriberError(), infoUnknownAlphabetError(), infoUnknownEquipmentError(), infoUnknownMSCError(), infoUnknownOrUnreachableLCSClientError(), infoUnknownSubscriberError(), infoUssdBusyError()}
}
func LookupError(code MAPErrorCode) (ErrorInfo, bool) {
	switch code {
	case AbsentSubscriber:
		return infoAbsentSubscriberError(), true
	case AbsentSubscriberSM:
		return infoAbsentSubscriberSMError(), true
	case AtiNotAllowed:
		return infoAtiNotAllowedError(), true
	case AtmNotAllowed:
		return infoAtmNotAllowedError(), true
	case AtsiNotAllowed:
		return infoAtsiNotAllowedError(), true
	case BearerServiceNotProvisioned:
		return infoBearerServiceNotProvisionedError(), true
	case BusySubscriber:
		return infoBusySubscriberError(), true
	case CallBarred:
		return infoCallBarredError(), true
	case CugReject:
		return infoCugRejectError(), true
	case DataMissing:
		return infoDataMissingError(), true
	case FacilityNotSupported:
		return infoFacilityNotSupportedError(), true
	case ForwardingFailed:
		return infoForwardingFailedError(), true
	case ForwardingViolation:
		return infoForwardingViolationError(), true
	case IllegalEquipment:
		return infoIllegalEquipmentError(), true
	case IllegalSSOperation:
		return infoIllegalSSOperationError(), true
	case IllegalSubscriber:
		return infoIllegalSubscriberError(), true
	case IncompatibleTerminal:
		return infoIncompatibleTerminalError(), true
	case InformationNotAvailable:
		return infoInformationNotAvailableError(), true
	case LongTermDenial:
		return infoLongTermDenialError(), true
	case MessageWaitingListFull:
		return infoMessageWaitingListFullError(), true
	case MmEventNotSupported:
		return infoMmEventNotSupportedError(), true
	case NegativePWCheck:
		return infoNegativePWCheckError(), true
	case NoGroupCallNumberAvailable:
		return infoNoGroupCallNumberAvailableError(), true
	case NoHandoverNumberAvailable:
		return infoNoHandoverNumberAvailableError(), true
	case NoRoamingNumberAvailable:
		return infoNoRoamingNumberAvailableError(), true
	case NoSubscriberReply:
		return infoNoSubscriberReplyError(), true
	case NumberChanged:
		return infoNumberChangedError(), true
	case NumberOfPWAttemptsViolation:
		return infoNumberOfPWAttemptsViolationError(), true
	case OngoingGroupCall:
		return infoOngoingGroupCallError(), true
	case OrNotAllowed:
		return infoOrNotAllowedError(), true
	case PositionMethodFailure:
		return infoPositionMethodFailureError(), true
	case PwRegistrationFailure:
		return infoPwRegistrationFailureError(), true
	case ResourceLimitation:
		return infoResourceLimitationError(), true
	case RoamingNotAllowed:
		return infoRoamingNotAllowedError(), true
	case ShortTermDenial:
		return infoShortTermDenialError(), true
	case SmDeliveryFailure:
		return infoSmDeliveryFailureError(), true
	case SsErrorStatus:
		return infoSsErrorStatusError(), true
	case SsIncompatibility:
		return infoSsIncompatibilityError(), true
	case SsNotAvailable:
		return infoSsNotAvailableError(), true
	case SsSubscriptionViolation:
		return infoSsSubscriptionViolationError(), true
	case SubscriberBusyForMTSMS:
		return infoSubscriberBusyForMTSMSError(), true
	case SubsequentHandoverFailure:
		return infoSubsequentHandoverFailureError(), true
	case SystemFailure:
		return infoSystemFailureError(), true
	case TargetCellOutsideGroupCallArea:
		return infoTargetCellOutsideGroupCallAreaError(), true
	case TeleserviceNotProvisioned:
		return infoTeleserviceNotProvisionedError(), true
	case TracingBufferFull:
		return infoTracingBufferFullError(), true
	case UnauthorizedLCSClient:
		return infoUnauthorizedLCSClientError(), true
	case UnauthorizedRequestingNetwork:
		return infoUnauthorizedRequestingNetworkError(), true
	case UnexpectedDataValue:
		return infoUnexpectedDataValueError(), true
	case UnidentifiedSubscriber:
		return infoUnidentifiedSubscriberError(), true
	case UnknownAlphabet:
		return infoUnknownAlphabetError(), true
	case UnknownEquipment:
		return infoUnknownEquipmentError(), true
	case UnknownMSC:
		return infoUnknownMSCError(), true
	case UnknownOrUnreachableLCSClient:
		return infoUnknownOrUnreachableLCSClientError(), true
	case UnknownSubscriber:
		return infoUnknownSubscriberError(), true
	case UssdBusy:
		return infoUssdBusyError(), true
	default:
		return ErrorInfo{}, false
	}
}

type EncodedError struct {
	Code         MAPErrorCode
	Parameter    []byte
	HasParameter bool
}

func encodeMAPErrorMember[P any](code MAPErrorCode, value *ErrorValue[P], codec ValueCodec[P], opts ...ber.EncodeOption) (EncodedError, error) {
	data, present, err := encodeErrorParameter(value, codec, opts...)
	if err != nil {
		return EncodedError{}, err
	}
	return EncodedError{Code: code, Parameter: data, HasParameter: present}, nil
}

type OperationInfo struct {
	Name                               string
	Code                               MAPOperationCode
	Argument, Result                   *TypeRef
	ArgumentOptional, ResultOptional   *bool
	ReturnResult, ReturnResultExplicit bool
	Errors                             []ErrorInfo
	Source                             SourceRef
	Linked                             []MAPOperationCode
}
type Operation[A, R, E any] struct {
	operationBinding[A, R, E, OperationInfo, MAPOperationCode, EncodedError]
}

func (d Operation[A, R, E]) DecodeError(code MAPErrorCode, data []byte, present bool, opts ...ber.DecodeOption) (E, error) {
	return d.decodeError(int64(code), data, present, opts...)
}
func (d Operation[A, R, E]) EncodeError(v E, opts ...ber.EncodeOption) (EncodedError, error) {
	return d.encodeError(v, opts...)
}

// ActivateSSErrors selects exactly the formal ERRORS set of MAP-SupplementaryServiceOperations.activateSS.
type ActivateSSErrors struct {
	SystemFailure               *ErrorValue[SystemFailureParam]
	DataMissing                 *ErrorValue[DataMissingParam]
	UnexpectedDataValue         *ErrorValue[UnexpectedDataParam]
	BearerServiceNotProvisioned *ErrorValue[BearerServNotProvParam]
	TeleserviceNotProvisioned   *ErrorValue[TeleservNotProvParam]
	CallBarred                  *ErrorValue[CallBarredParam]
	IllegalSSOperation          *ErrorValue[IllegalSSOperationParam]
	SsErrorStatus               *ErrorValue[BERValue[SSStatus]]
	SsSubscriptionViolation     *ErrorValue[SSSubscriptionViolationParam]
	SsIncompatibility           *ErrorValue[SSIncompatibilityCause]
	NegativePWCheck             *ErrorValue[NoParameter]
	NumberOfPWAttemptsViolation *ErrorValue[NoParameter]
}

func infoActivateSSOperation() OperationInfo {
	return OperationInfo{Name: "activateSS", Code: ActivateSS, Argument: &TypeRef{ModuleOID: "0.4.0.0.1.3.14.22", ASN1Name: "SS-ForBS-Code", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "SSForBSCode"}, Result: &TypeRef{ModuleOID: "0.4.0.0.1.3.14.22", ASN1Name: "SS-Info", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "SSInfo"}, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: false, Source: sourceInfo1("activateSS", "17.6.4"), Errors: []ErrorInfo{infoSystemFailureError(), infoDataMissingError(), infoUnexpectedDataValueError(), infoBearerServiceNotProvisionedError(), infoTeleserviceNotProvisionedError(), infoCallBarredError(), infoIllegalSSOperationError(), infoSsErrorStatusError(), infoSsSubscriptionViolationError(), infoSsIncompatibilityError(), infoNegativePWCheckError(), infoNumberOfPWAttemptsViolationError()}, Linked: []MAPOperationCode{}}
}

// ActivateSSOperation binds the formal object in TS 29.002 V19.1.0 §17.6.4 (X.880 §§8.2–8.3).
func ActivateSSOperation() Operation[SSForBSCode, SSInfo, ActivateSSErrors] {
	return Operation[SSForBSCode, SSInfo, ActivateSSErrors]{operationBinding[SSForBSCode, SSInfo, ActivateSSErrors, OperationInfo, MAPOperationCode, EncodedError]{code: ActivateSS, info: infoActivateSSOperation, argument: SSForBSCodeCodec(), result: SSInfoCodec(), decode: decodeActivateSSError, encode: encodeActivateSSError}}
}
func decodeActivateSSError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (ActivateSSErrors, error) {
	switch code {
	case 34:
		p, err := decodeErrorParameter(data, present, SystemFailureParamCodec(), opts...)
		if err != nil {
			return ActivateSSErrors{}, err
		}
		return ActivateSSErrors{SystemFailure: p}, nil
	case 35:
		p, err := decodeErrorParameter(data, present, DataMissingParamCodec(), opts...)
		if err != nil {
			return ActivateSSErrors{}, err
		}
		return ActivateSSErrors{DataMissing: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return ActivateSSErrors{}, err
		}
		return ActivateSSErrors{UnexpectedDataValue: p}, nil
	case 10:
		p, err := decodeErrorParameter(data, present, BearerServNotProvParamCodec(), opts...)
		if err != nil {
			return ActivateSSErrors{}, err
		}
		return ActivateSSErrors{BearerServiceNotProvisioned: p}, nil
	case 11:
		p, err := decodeErrorParameter(data, present, TeleservNotProvParamCodec(), opts...)
		if err != nil {
			return ActivateSSErrors{}, err
		}
		return ActivateSSErrors{TeleserviceNotProvisioned: p}, nil
	case 13:
		p, err := decodeErrorParameter(data, present, CallBarredParamCodec(), opts...)
		if err != nil {
			return ActivateSSErrors{}, err
		}
		return ActivateSSErrors{CallBarred: p}, nil
	case 16:
		p, err := decodeErrorParameter(data, present, IllegalSSOperationParamCodec(), opts...)
		if err != nil {
			return ActivateSSErrors{}, err
		}
		return ActivateSSErrors{IllegalSSOperation: p}, nil
	case 17:
		p, err := decodeErrorParameter(data, present, SSStatusCodec(), opts...)
		if err != nil {
			return ActivateSSErrors{}, err
		}
		return ActivateSSErrors{SsErrorStatus: p}, nil
	case 19:
		p, err := decodeErrorParameter(data, present, SSSubscriptionViolationParamCodec(), opts...)
		if err != nil {
			return ActivateSSErrors{}, err
		}
		return ActivateSSErrors{SsSubscriptionViolation: p}, nil
	case 20:
		p, err := decodeErrorParameter(data, present, SSIncompatibilityCauseCodec(), opts...)
		if err != nil {
			return ActivateSSErrors{}, err
		}
		return ActivateSSErrors{SsIncompatibility: p}, nil
	case 38:
		p, err := decodeErrorParameter(data, present, ValueCodec[NoParameter]{}, opts...)
		if err != nil {
			return ActivateSSErrors{}, err
		}
		return ActivateSSErrors{NegativePWCheck: p}, nil
	case 43:
		p, err := decodeErrorParameter(data, present, ValueCodec[NoParameter]{}, opts...)
		if err != nil {
			return ActivateSSErrors{}, err
		}
		return ActivateSSErrors{NumberOfPWAttemptsViolation: p}, nil
	default:
		return ActivateSSErrors{}, fmt.Errorf("%w: error code %d is not in activateSS ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeActivateSSError(value ActivateSSErrors, opts ...ber.EncodeOption) (EncodedError, error) {
	selected := 0
	if value.SystemFailure != nil {
		selected++
	}
	if value.DataMissing != nil {
		selected++
	}
	if value.UnexpectedDataValue != nil {
		selected++
	}
	if value.BearerServiceNotProvisioned != nil {
		selected++
	}
	if value.TeleserviceNotProvisioned != nil {
		selected++
	}
	if value.CallBarred != nil {
		selected++
	}
	if value.IllegalSSOperation != nil {
		selected++
	}
	if value.SsErrorStatus != nil {
		selected++
	}
	if value.SsSubscriptionViolation != nil {
		selected++
	}
	if value.SsIncompatibility != nil {
		selected++
	}
	if value.NegativePWCheck != nil {
		selected++
	}
	if value.NumberOfPWAttemptsViolation != nil {
		selected++
	}
	if selected != 1 {
		return EncodedError{}, fmt.Errorf("%w: exactly one activateSS error arm is required", ber.ErrInvalidBinding)
	}
	if value.SystemFailure != nil {
		return encodeMAPErrorMember(SystemFailure, value.SystemFailure, SystemFailureParamCodec(), opts...)
	}
	if value.DataMissing != nil {
		return encodeMAPErrorMember(DataMissing, value.DataMissing, DataMissingParamCodec(), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	if value.BearerServiceNotProvisioned != nil {
		return encodeMAPErrorMember(BearerServiceNotProvisioned, value.BearerServiceNotProvisioned, BearerServNotProvParamCodec(), opts...)
	}
	if value.TeleserviceNotProvisioned != nil {
		return encodeMAPErrorMember(TeleserviceNotProvisioned, value.TeleserviceNotProvisioned, TeleservNotProvParamCodec(), opts...)
	}
	if value.CallBarred != nil {
		return encodeMAPErrorMember(CallBarred, value.CallBarred, CallBarredParamCodec(), opts...)
	}
	if value.IllegalSSOperation != nil {
		return encodeMAPErrorMember(IllegalSSOperation, value.IllegalSSOperation, IllegalSSOperationParamCodec(), opts...)
	}
	if value.SsErrorStatus != nil {
		return encodeMAPErrorMember(SsErrorStatus, value.SsErrorStatus, SSStatusCodec(), opts...)
	}
	if value.SsSubscriptionViolation != nil {
		return encodeMAPErrorMember(SsSubscriptionViolation, value.SsSubscriptionViolation, SSSubscriptionViolationParamCodec(), opts...)
	}
	if value.SsIncompatibility != nil {
		return encodeMAPErrorMember(SsIncompatibility, value.SsIncompatibility, SSIncompatibilityCauseCodec(), opts...)
	}
	if value.NegativePWCheck != nil {
		return encodeMAPErrorMember(NegativePWCheck, value.NegativePWCheck, ValueCodec[NoParameter]{}, opts...)
	}
	if value.NumberOfPWAttemptsViolation != nil {
		return encodeMAPErrorMember(NumberOfPWAttemptsViolation, value.NumberOfPWAttemptsViolation, ValueCodec[NoParameter]{}, opts...)
	}
	return EncodedError{}, fmt.Errorf("%w: no selected activateSS error", ber.ErrInvalidBinding)
}

// ActivateTraceModeErrors selects exactly the formal ERRORS set of MAP-OperationAndMaintenanceOperations.activateTraceMode.
type ActivateTraceModeErrors struct {
	SystemFailure          *ErrorValue[SystemFailureParam]
	DataMissing            *ErrorValue[DataMissingParam]
	UnexpectedDataValue    *ErrorValue[UnexpectedDataParam]
	FacilityNotSupported   *ErrorValue[FacilityNotSupParam]
	UnidentifiedSubscriber *ErrorValue[UnidentifiedSubParam]
	TracingBufferFull      *ErrorValue[TracingBufferFullParam]
}

func infoActivateTraceModeOperation() OperationInfo {
	return OperationInfo{Name: "activateTraceMode", Code: ActivateTraceMode, Argument: &TypeRef{ModuleOID: "0.4.0.0.1.3.12.22", ASN1Name: "ActivateTraceModeArg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "ActivateTraceModeArg"}, Result: &TypeRef{ModuleOID: "0.4.0.0.1.3.12.22", ASN1Name: "ActivateTraceModeRes", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "ActivateTraceModeRes"}, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: false, Source: sourceInfo2("activateTraceMode", "17.6.2"), Errors: []ErrorInfo{infoSystemFailureError(), infoDataMissingError(), infoUnexpectedDataValueError(), infoFacilityNotSupportedError(), infoUnidentifiedSubscriberError(), infoTracingBufferFullError()}, Linked: []MAPOperationCode{}}
}

// ActivateTraceModeOperation binds the formal object in TS 29.002 V19.1.0 §17.6.2 (X.880 §§8.2–8.3).
func ActivateTraceModeOperation() Operation[ActivateTraceModeArg, ActivateTraceModeRes, ActivateTraceModeErrors] {
	return Operation[ActivateTraceModeArg, ActivateTraceModeRes, ActivateTraceModeErrors]{operationBinding[ActivateTraceModeArg, ActivateTraceModeRes, ActivateTraceModeErrors, OperationInfo, MAPOperationCode, EncodedError]{code: ActivateTraceMode, info: infoActivateTraceModeOperation, argument: ActivateTraceModeArgCodec(), result: ActivateTraceModeResCodec(), decode: decodeActivateTraceModeError, encode: encodeActivateTraceModeError}}
}
func decodeActivateTraceModeError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (ActivateTraceModeErrors, error) {
	switch code {
	case 34:
		p, err := decodeErrorParameter(data, present, SystemFailureParamCodec(), opts...)
		if err != nil {
			return ActivateTraceModeErrors{}, err
		}
		return ActivateTraceModeErrors{SystemFailure: p}, nil
	case 35:
		p, err := decodeErrorParameter(data, present, DataMissingParamCodec(), opts...)
		if err != nil {
			return ActivateTraceModeErrors{}, err
		}
		return ActivateTraceModeErrors{DataMissing: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return ActivateTraceModeErrors{}, err
		}
		return ActivateTraceModeErrors{UnexpectedDataValue: p}, nil
	case 21:
		p, err := decodeErrorParameter(data, present, FacilityNotSupParamCodec(), opts...)
		if err != nil {
			return ActivateTraceModeErrors{}, err
		}
		return ActivateTraceModeErrors{FacilityNotSupported: p}, nil
	case 5:
		p, err := decodeErrorParameter(data, present, UnidentifiedSubParamCodec(), opts...)
		if err != nil {
			return ActivateTraceModeErrors{}, err
		}
		return ActivateTraceModeErrors{UnidentifiedSubscriber: p}, nil
	case 40:
		p, err := decodeErrorParameter(data, present, TracingBufferFullParamCodec(), opts...)
		if err != nil {
			return ActivateTraceModeErrors{}, err
		}
		return ActivateTraceModeErrors{TracingBufferFull: p}, nil
	default:
		return ActivateTraceModeErrors{}, fmt.Errorf("%w: error code %d is not in activateTraceMode ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeActivateTraceModeError(value ActivateTraceModeErrors, opts ...ber.EncodeOption) (EncodedError, error) {
	selected := 0
	if value.SystemFailure != nil {
		selected++
	}
	if value.DataMissing != nil {
		selected++
	}
	if value.UnexpectedDataValue != nil {
		selected++
	}
	if value.FacilityNotSupported != nil {
		selected++
	}
	if value.UnidentifiedSubscriber != nil {
		selected++
	}
	if value.TracingBufferFull != nil {
		selected++
	}
	if selected != 1 {
		return EncodedError{}, fmt.Errorf("%w: exactly one activateTraceMode error arm is required", ber.ErrInvalidBinding)
	}
	if value.SystemFailure != nil {
		return encodeMAPErrorMember(SystemFailure, value.SystemFailure, SystemFailureParamCodec(), opts...)
	}
	if value.DataMissing != nil {
		return encodeMAPErrorMember(DataMissing, value.DataMissing, DataMissingParamCodec(), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	if value.FacilityNotSupported != nil {
		return encodeMAPErrorMember(FacilityNotSupported, value.FacilityNotSupported, FacilityNotSupParamCodec(), opts...)
	}
	if value.UnidentifiedSubscriber != nil {
		return encodeMAPErrorMember(UnidentifiedSubscriber, value.UnidentifiedSubscriber, UnidentifiedSubParamCodec(), opts...)
	}
	if value.TracingBufferFull != nil {
		return encodeMAPErrorMember(TracingBufferFull, value.TracingBufferFull, TracingBufferFullParamCodec(), opts...)
	}
	return EncodedError{}, fmt.Errorf("%w: no selected activateTraceMode error", ber.ErrInvalidBinding)
}

// AlertServiceCentreErrors selects exactly the formal ERRORS set of MAP-ShortMessageServiceOperations.alertServiceCentre.
type AlertServiceCentreErrors struct {
	SystemFailure       *ErrorValue[SystemFailureParam]
	DataMissing         *ErrorValue[DataMissingParam]
	UnexpectedDataValue *ErrorValue[UnexpectedDataParam]
}

func infoAlertServiceCentreOperation() OperationInfo {
	return OperationInfo{Name: "alertServiceCentre", Code: AlertServiceCentre, Argument: &TypeRef{ModuleOID: "0.4.0.0.1.3.16.22", ASN1Name: "AlertServiceCentreArg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "AlertServiceCentreArg"}, Result: nil, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: true, Source: sourceInfo3("alertServiceCentre", "17.6.5"), Errors: []ErrorInfo{infoSystemFailureError(), infoDataMissingError(), infoUnexpectedDataValueError()}, Linked: []MAPOperationCode{}}
}

// AlertServiceCentreOperation binds the formal object in TS 29.002 V19.1.0 §17.6.5 (X.880 §§8.2–8.3).
func AlertServiceCentreOperation() Operation[AlertServiceCentreArg, NoParameter, AlertServiceCentreErrors] {
	return Operation[AlertServiceCentreArg, NoParameter, AlertServiceCentreErrors]{operationBinding[AlertServiceCentreArg, NoParameter, AlertServiceCentreErrors, OperationInfo, MAPOperationCode, EncodedError]{code: AlertServiceCentre, info: infoAlertServiceCentreOperation, argument: AlertServiceCentreArgCodec(), result: ValueCodec[NoParameter]{}, decode: decodeAlertServiceCentreError, encode: encodeAlertServiceCentreError}}
}
func decodeAlertServiceCentreError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (AlertServiceCentreErrors, error) {
	switch code {
	case 34:
		p, err := decodeErrorParameter(data, present, SystemFailureParamCodec(), opts...)
		if err != nil {
			return AlertServiceCentreErrors{}, err
		}
		return AlertServiceCentreErrors{SystemFailure: p}, nil
	case 35:
		p, err := decodeErrorParameter(data, present, DataMissingParamCodec(), opts...)
		if err != nil {
			return AlertServiceCentreErrors{}, err
		}
		return AlertServiceCentreErrors{DataMissing: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return AlertServiceCentreErrors{}, err
		}
		return AlertServiceCentreErrors{UnexpectedDataValue: p}, nil
	default:
		return AlertServiceCentreErrors{}, fmt.Errorf("%w: error code %d is not in alertServiceCentre ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeAlertServiceCentreError(value AlertServiceCentreErrors, opts ...ber.EncodeOption) (EncodedError, error) {
	selected := 0
	if value.SystemFailure != nil {
		selected++
	}
	if value.DataMissing != nil {
		selected++
	}
	if value.UnexpectedDataValue != nil {
		selected++
	}
	if selected != 1 {
		return EncodedError{}, fmt.Errorf("%w: exactly one alertServiceCentre error arm is required", ber.ErrInvalidBinding)
	}
	if value.SystemFailure != nil {
		return encodeMAPErrorMember(SystemFailure, value.SystemFailure, SystemFailureParamCodec(), opts...)
	}
	if value.DataMissing != nil {
		return encodeMAPErrorMember(DataMissing, value.DataMissing, DataMissingParamCodec(), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	return EncodedError{}, fmt.Errorf("%w: no selected alertServiceCentre error", ber.ErrInvalidBinding)
}

// AnyTimeInterrogationErrors selects exactly the formal ERRORS set of MAP-MobileServiceOperations.anyTimeInterrogation.
type AnyTimeInterrogationErrors struct {
	SystemFailure       *ErrorValue[SystemFailureParam]
	AtiNotAllowed       *ErrorValue[ATINotAllowedParam]
	DataMissing         *ErrorValue[DataMissingParam]
	UnexpectedDataValue *ErrorValue[UnexpectedDataParam]
	UnknownSubscriber   *ErrorValue[UnknownSubscriberParam]
}

func infoAnyTimeInterrogationOperation() OperationInfo {
	return OperationInfo{Name: "anyTimeInterrogation", Code: AnyTimeInterrogation, Argument: &TypeRef{ModuleOID: "0.4.0.0.1.3.11.22", ASN1Name: "AnyTimeInterrogationArg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "AnyTimeInterrogationArg"}, Result: &TypeRef{ModuleOID: "0.4.0.0.1.3.11.22", ASN1Name: "AnyTimeInterrogationRes", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "AnyTimeInterrogationRes"}, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: false, Source: sourceInfo4("anyTimeInterrogation", "17.6.1"), Errors: []ErrorInfo{infoSystemFailureError(), infoAtiNotAllowedError(), infoDataMissingError(), infoUnexpectedDataValueError(), infoUnknownSubscriberError()}, Linked: []MAPOperationCode{}}
}

// AnyTimeInterrogationOperation binds the formal object in TS 29.002 V19.1.0 §17.6.1 (X.880 §§8.2–8.3).
func AnyTimeInterrogationOperation() Operation[AnyTimeInterrogationArg, AnyTimeInterrogationRes, AnyTimeInterrogationErrors] {
	return Operation[AnyTimeInterrogationArg, AnyTimeInterrogationRes, AnyTimeInterrogationErrors]{operationBinding[AnyTimeInterrogationArg, AnyTimeInterrogationRes, AnyTimeInterrogationErrors, OperationInfo, MAPOperationCode, EncodedError]{code: AnyTimeInterrogation, info: infoAnyTimeInterrogationOperation, argument: AnyTimeInterrogationArgCodec(), result: AnyTimeInterrogationResCodec(), decode: decodeAnyTimeInterrogationError, encode: encodeAnyTimeInterrogationError}}
}
func decodeAnyTimeInterrogationError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (AnyTimeInterrogationErrors, error) {
	switch code {
	case 34:
		p, err := decodeErrorParameter(data, present, SystemFailureParamCodec(), opts...)
		if err != nil {
			return AnyTimeInterrogationErrors{}, err
		}
		return AnyTimeInterrogationErrors{SystemFailure: p}, nil
	case 49:
		p, err := decodeErrorParameter(data, present, ATINotAllowedParamCodec(), opts...)
		if err != nil {
			return AnyTimeInterrogationErrors{}, err
		}
		return AnyTimeInterrogationErrors{AtiNotAllowed: p}, nil
	case 35:
		p, err := decodeErrorParameter(data, present, DataMissingParamCodec(), opts...)
		if err != nil {
			return AnyTimeInterrogationErrors{}, err
		}
		return AnyTimeInterrogationErrors{DataMissing: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return AnyTimeInterrogationErrors{}, err
		}
		return AnyTimeInterrogationErrors{UnexpectedDataValue: p}, nil
	case 1:
		p, err := decodeErrorParameter(data, present, UnknownSubscriberParamCodec(), opts...)
		if err != nil {
			return AnyTimeInterrogationErrors{}, err
		}
		return AnyTimeInterrogationErrors{UnknownSubscriber: p}, nil
	default:
		return AnyTimeInterrogationErrors{}, fmt.Errorf("%w: error code %d is not in anyTimeInterrogation ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeAnyTimeInterrogationError(value AnyTimeInterrogationErrors, opts ...ber.EncodeOption) (EncodedError, error) {
	selected := 0
	if value.SystemFailure != nil {
		selected++
	}
	if value.AtiNotAllowed != nil {
		selected++
	}
	if value.DataMissing != nil {
		selected++
	}
	if value.UnexpectedDataValue != nil {
		selected++
	}
	if value.UnknownSubscriber != nil {
		selected++
	}
	if selected != 1 {
		return EncodedError{}, fmt.Errorf("%w: exactly one anyTimeInterrogation error arm is required", ber.ErrInvalidBinding)
	}
	if value.SystemFailure != nil {
		return encodeMAPErrorMember(SystemFailure, value.SystemFailure, SystemFailureParamCodec(), opts...)
	}
	if value.AtiNotAllowed != nil {
		return encodeMAPErrorMember(AtiNotAllowed, value.AtiNotAllowed, ATINotAllowedParamCodec(), opts...)
	}
	if value.DataMissing != nil {
		return encodeMAPErrorMember(DataMissing, value.DataMissing, DataMissingParamCodec(), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	if value.UnknownSubscriber != nil {
		return encodeMAPErrorMember(UnknownSubscriber, value.UnknownSubscriber, UnknownSubscriberParamCodec(), opts...)
	}
	return EncodedError{}, fmt.Errorf("%w: no selected anyTimeInterrogation error", ber.ErrInvalidBinding)
}

// AnyTimeModificationErrors selects exactly the formal ERRORS set of MAP-MobileServiceOperations.anyTimeModification.
type AnyTimeModificationErrors struct {
	AtmNotAllowed               *ErrorValue[ATMNotAllowedParam]
	DataMissing                 *ErrorValue[DataMissingParam]
	UnexpectedDataValue         *ErrorValue[UnexpectedDataParam]
	UnknownSubscriber           *ErrorValue[UnknownSubscriberParam]
	BearerServiceNotProvisioned *ErrorValue[BearerServNotProvParam]
	TeleserviceNotProvisioned   *ErrorValue[TeleservNotProvParam]
	CallBarred                  *ErrorValue[CallBarredParam]
	IllegalSSOperation          *ErrorValue[IllegalSSOperationParam]
	SsSubscriptionViolation     *ErrorValue[SSSubscriptionViolationParam]
	SsErrorStatus               *ErrorValue[BERValue[SSStatus]]
	SsIncompatibility           *ErrorValue[SSIncompatibilityCause]
	InformationNotAvailable     *ErrorValue[InformationNotAvailableParam]
}

func infoAnyTimeModificationOperation() OperationInfo {
	return OperationInfo{Name: "anyTimeModification", Code: AnyTimeModification, Argument: &TypeRef{ModuleOID: "0.4.0.0.1.3.11.22", ASN1Name: "AnyTimeModificationArg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "AnyTimeModificationArg"}, Result: &TypeRef{ModuleOID: "0.4.0.0.1.3.11.22", ASN1Name: "AnyTimeModificationRes", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "AnyTimeModificationRes"}, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: false, Source: sourceInfo4("anyTimeModification", "17.6.1"), Errors: []ErrorInfo{infoAtmNotAllowedError(), infoDataMissingError(), infoUnexpectedDataValueError(), infoUnknownSubscriberError(), infoBearerServiceNotProvisionedError(), infoTeleserviceNotProvisionedError(), infoCallBarredError(), infoIllegalSSOperationError(), infoSsSubscriptionViolationError(), infoSsErrorStatusError(), infoSsIncompatibilityError(), infoInformationNotAvailableError()}, Linked: []MAPOperationCode{}}
}

// AnyTimeModificationOperation binds the formal object in TS 29.002 V19.1.0 §17.6.1 (X.880 §§8.2–8.3).
func AnyTimeModificationOperation() Operation[AnyTimeModificationArg, AnyTimeModificationRes, AnyTimeModificationErrors] {
	return Operation[AnyTimeModificationArg, AnyTimeModificationRes, AnyTimeModificationErrors]{operationBinding[AnyTimeModificationArg, AnyTimeModificationRes, AnyTimeModificationErrors, OperationInfo, MAPOperationCode, EncodedError]{code: AnyTimeModification, info: infoAnyTimeModificationOperation, argument: AnyTimeModificationArgCodec(), result: AnyTimeModificationResCodec(), decode: decodeAnyTimeModificationError, encode: encodeAnyTimeModificationError}}
}
func decodeAnyTimeModificationError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (AnyTimeModificationErrors, error) {
	switch code {
	case 61:
		p, err := decodeErrorParameter(data, present, ATMNotAllowedParamCodec(), opts...)
		if err != nil {
			return AnyTimeModificationErrors{}, err
		}
		return AnyTimeModificationErrors{AtmNotAllowed: p}, nil
	case 35:
		p, err := decodeErrorParameter(data, present, DataMissingParamCodec(), opts...)
		if err != nil {
			return AnyTimeModificationErrors{}, err
		}
		return AnyTimeModificationErrors{DataMissing: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return AnyTimeModificationErrors{}, err
		}
		return AnyTimeModificationErrors{UnexpectedDataValue: p}, nil
	case 1:
		p, err := decodeErrorParameter(data, present, UnknownSubscriberParamCodec(), opts...)
		if err != nil {
			return AnyTimeModificationErrors{}, err
		}
		return AnyTimeModificationErrors{UnknownSubscriber: p}, nil
	case 10:
		p, err := decodeErrorParameter(data, present, BearerServNotProvParamCodec(), opts...)
		if err != nil {
			return AnyTimeModificationErrors{}, err
		}
		return AnyTimeModificationErrors{BearerServiceNotProvisioned: p}, nil
	case 11:
		p, err := decodeErrorParameter(data, present, TeleservNotProvParamCodec(), opts...)
		if err != nil {
			return AnyTimeModificationErrors{}, err
		}
		return AnyTimeModificationErrors{TeleserviceNotProvisioned: p}, nil
	case 13:
		p, err := decodeErrorParameter(data, present, CallBarredParamCodec(), opts...)
		if err != nil {
			return AnyTimeModificationErrors{}, err
		}
		return AnyTimeModificationErrors{CallBarred: p}, nil
	case 16:
		p, err := decodeErrorParameter(data, present, IllegalSSOperationParamCodec(), opts...)
		if err != nil {
			return AnyTimeModificationErrors{}, err
		}
		return AnyTimeModificationErrors{IllegalSSOperation: p}, nil
	case 19:
		p, err := decodeErrorParameter(data, present, SSSubscriptionViolationParamCodec(), opts...)
		if err != nil {
			return AnyTimeModificationErrors{}, err
		}
		return AnyTimeModificationErrors{SsSubscriptionViolation: p}, nil
	case 17:
		p, err := decodeErrorParameter(data, present, SSStatusCodec(), opts...)
		if err != nil {
			return AnyTimeModificationErrors{}, err
		}
		return AnyTimeModificationErrors{SsErrorStatus: p}, nil
	case 20:
		p, err := decodeErrorParameter(data, present, SSIncompatibilityCauseCodec(), opts...)
		if err != nil {
			return AnyTimeModificationErrors{}, err
		}
		return AnyTimeModificationErrors{SsIncompatibility: p}, nil
	case 62:
		p, err := decodeErrorParameter(data, present, InformationNotAvailableParamCodec(), opts...)
		if err != nil {
			return AnyTimeModificationErrors{}, err
		}
		return AnyTimeModificationErrors{InformationNotAvailable: p}, nil
	default:
		return AnyTimeModificationErrors{}, fmt.Errorf("%w: error code %d is not in anyTimeModification ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeAnyTimeModificationError(value AnyTimeModificationErrors, opts ...ber.EncodeOption) (EncodedError, error) {
	selected := 0
	if value.AtmNotAllowed != nil {
		selected++
	}
	if value.DataMissing != nil {
		selected++
	}
	if value.UnexpectedDataValue != nil {
		selected++
	}
	if value.UnknownSubscriber != nil {
		selected++
	}
	if value.BearerServiceNotProvisioned != nil {
		selected++
	}
	if value.TeleserviceNotProvisioned != nil {
		selected++
	}
	if value.CallBarred != nil {
		selected++
	}
	if value.IllegalSSOperation != nil {
		selected++
	}
	if value.SsSubscriptionViolation != nil {
		selected++
	}
	if value.SsErrorStatus != nil {
		selected++
	}
	if value.SsIncompatibility != nil {
		selected++
	}
	if value.InformationNotAvailable != nil {
		selected++
	}
	if selected != 1 {
		return EncodedError{}, fmt.Errorf("%w: exactly one anyTimeModification error arm is required", ber.ErrInvalidBinding)
	}
	if value.AtmNotAllowed != nil {
		return encodeMAPErrorMember(AtmNotAllowed, value.AtmNotAllowed, ATMNotAllowedParamCodec(), opts...)
	}
	if value.DataMissing != nil {
		return encodeMAPErrorMember(DataMissing, value.DataMissing, DataMissingParamCodec(), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	if value.UnknownSubscriber != nil {
		return encodeMAPErrorMember(UnknownSubscriber, value.UnknownSubscriber, UnknownSubscriberParamCodec(), opts...)
	}
	if value.BearerServiceNotProvisioned != nil {
		return encodeMAPErrorMember(BearerServiceNotProvisioned, value.BearerServiceNotProvisioned, BearerServNotProvParamCodec(), opts...)
	}
	if value.TeleserviceNotProvisioned != nil {
		return encodeMAPErrorMember(TeleserviceNotProvisioned, value.TeleserviceNotProvisioned, TeleservNotProvParamCodec(), opts...)
	}
	if value.CallBarred != nil {
		return encodeMAPErrorMember(CallBarred, value.CallBarred, CallBarredParamCodec(), opts...)
	}
	if value.IllegalSSOperation != nil {
		return encodeMAPErrorMember(IllegalSSOperation, value.IllegalSSOperation, IllegalSSOperationParamCodec(), opts...)
	}
	if value.SsSubscriptionViolation != nil {
		return encodeMAPErrorMember(SsSubscriptionViolation, value.SsSubscriptionViolation, SSSubscriptionViolationParamCodec(), opts...)
	}
	if value.SsErrorStatus != nil {
		return encodeMAPErrorMember(SsErrorStatus, value.SsErrorStatus, SSStatusCodec(), opts...)
	}
	if value.SsIncompatibility != nil {
		return encodeMAPErrorMember(SsIncompatibility, value.SsIncompatibility, SSIncompatibilityCauseCodec(), opts...)
	}
	if value.InformationNotAvailable != nil {
		return encodeMAPErrorMember(InformationNotAvailable, value.InformationNotAvailable, InformationNotAvailableParamCodec(), opts...)
	}
	return EncodedError{}, fmt.Errorf("%w: no selected anyTimeModification error", ber.ErrInvalidBinding)
}

// AnyTimeSubscriptionInterrogationErrors selects exactly the formal ERRORS set of MAP-MobileServiceOperations.anyTimeSubscriptionInterrogation.
type AnyTimeSubscriptionInterrogationErrors struct {
	AtsiNotAllowed              *ErrorValue[ATSINotAllowedParam]
	DataMissing                 *ErrorValue[DataMissingParam]
	UnexpectedDataValue         *ErrorValue[UnexpectedDataParam]
	UnknownSubscriber           *ErrorValue[UnknownSubscriberParam]
	BearerServiceNotProvisioned *ErrorValue[BearerServNotProvParam]
	TeleserviceNotProvisioned   *ErrorValue[TeleservNotProvParam]
	CallBarred                  *ErrorValue[CallBarredParam]
	IllegalSSOperation          *ErrorValue[IllegalSSOperationParam]
	SsNotAvailable              *ErrorValue[SSNotAvailableParam]
	InformationNotAvailable     *ErrorValue[InformationNotAvailableParam]
}

func infoAnyTimeSubscriptionInterrogationOperation() OperationInfo {
	return OperationInfo{Name: "anyTimeSubscriptionInterrogation", Code: AnyTimeSubscriptionInterrogation, Argument: &TypeRef{ModuleOID: "0.4.0.0.1.3.11.22", ASN1Name: "AnyTimeSubscriptionInterrogationArg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "AnyTimeSubscriptionInterrogationArg"}, Result: &TypeRef{ModuleOID: "0.4.0.0.1.3.11.22", ASN1Name: "AnyTimeSubscriptionInterrogationRes", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "AnyTimeSubscriptionInterrogationRes"}, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: false, Source: sourceInfo4("anyTimeSubscriptionInterrogation", "17.6.1"), Errors: []ErrorInfo{infoAtsiNotAllowedError(), infoDataMissingError(), infoUnexpectedDataValueError(), infoUnknownSubscriberError(), infoBearerServiceNotProvisionedError(), infoTeleserviceNotProvisionedError(), infoCallBarredError(), infoIllegalSSOperationError(), infoSsNotAvailableError(), infoInformationNotAvailableError()}, Linked: []MAPOperationCode{}}
}

// AnyTimeSubscriptionInterrogationOperation binds the formal object in TS 29.002 V19.1.0 §17.6.1 (X.880 §§8.2–8.3).
func AnyTimeSubscriptionInterrogationOperation() Operation[AnyTimeSubscriptionInterrogationArg, AnyTimeSubscriptionInterrogationRes, AnyTimeSubscriptionInterrogationErrors] {
	return Operation[AnyTimeSubscriptionInterrogationArg, AnyTimeSubscriptionInterrogationRes, AnyTimeSubscriptionInterrogationErrors]{operationBinding[AnyTimeSubscriptionInterrogationArg, AnyTimeSubscriptionInterrogationRes, AnyTimeSubscriptionInterrogationErrors, OperationInfo, MAPOperationCode, EncodedError]{code: AnyTimeSubscriptionInterrogation, info: infoAnyTimeSubscriptionInterrogationOperation, argument: AnyTimeSubscriptionInterrogationArgCodec(), result: AnyTimeSubscriptionInterrogationResCodec(), decode: decodeAnyTimeSubscriptionInterrogationError, encode: encodeAnyTimeSubscriptionInterrogationError}}
}
func decodeAnyTimeSubscriptionInterrogationError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (AnyTimeSubscriptionInterrogationErrors, error) {
	switch code {
	case 60:
		p, err := decodeErrorParameter(data, present, ATSINotAllowedParamCodec(), opts...)
		if err != nil {
			return AnyTimeSubscriptionInterrogationErrors{}, err
		}
		return AnyTimeSubscriptionInterrogationErrors{AtsiNotAllowed: p}, nil
	case 35:
		p, err := decodeErrorParameter(data, present, DataMissingParamCodec(), opts...)
		if err != nil {
			return AnyTimeSubscriptionInterrogationErrors{}, err
		}
		return AnyTimeSubscriptionInterrogationErrors{DataMissing: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return AnyTimeSubscriptionInterrogationErrors{}, err
		}
		return AnyTimeSubscriptionInterrogationErrors{UnexpectedDataValue: p}, nil
	case 1:
		p, err := decodeErrorParameter(data, present, UnknownSubscriberParamCodec(), opts...)
		if err != nil {
			return AnyTimeSubscriptionInterrogationErrors{}, err
		}
		return AnyTimeSubscriptionInterrogationErrors{UnknownSubscriber: p}, nil
	case 10:
		p, err := decodeErrorParameter(data, present, BearerServNotProvParamCodec(), opts...)
		if err != nil {
			return AnyTimeSubscriptionInterrogationErrors{}, err
		}
		return AnyTimeSubscriptionInterrogationErrors{BearerServiceNotProvisioned: p}, nil
	case 11:
		p, err := decodeErrorParameter(data, present, TeleservNotProvParamCodec(), opts...)
		if err != nil {
			return AnyTimeSubscriptionInterrogationErrors{}, err
		}
		return AnyTimeSubscriptionInterrogationErrors{TeleserviceNotProvisioned: p}, nil
	case 13:
		p, err := decodeErrorParameter(data, present, CallBarredParamCodec(), opts...)
		if err != nil {
			return AnyTimeSubscriptionInterrogationErrors{}, err
		}
		return AnyTimeSubscriptionInterrogationErrors{CallBarred: p}, nil
	case 16:
		p, err := decodeErrorParameter(data, present, IllegalSSOperationParamCodec(), opts...)
		if err != nil {
			return AnyTimeSubscriptionInterrogationErrors{}, err
		}
		return AnyTimeSubscriptionInterrogationErrors{IllegalSSOperation: p}, nil
	case 18:
		p, err := decodeErrorParameter(data, present, SSNotAvailableParamCodec(), opts...)
		if err != nil {
			return AnyTimeSubscriptionInterrogationErrors{}, err
		}
		return AnyTimeSubscriptionInterrogationErrors{SsNotAvailable: p}, nil
	case 62:
		p, err := decodeErrorParameter(data, present, InformationNotAvailableParamCodec(), opts...)
		if err != nil {
			return AnyTimeSubscriptionInterrogationErrors{}, err
		}
		return AnyTimeSubscriptionInterrogationErrors{InformationNotAvailable: p}, nil
	default:
		return AnyTimeSubscriptionInterrogationErrors{}, fmt.Errorf("%w: error code %d is not in anyTimeSubscriptionInterrogation ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeAnyTimeSubscriptionInterrogationError(value AnyTimeSubscriptionInterrogationErrors, opts ...ber.EncodeOption) (EncodedError, error) {
	selected := 0
	if value.AtsiNotAllowed != nil {
		selected++
	}
	if value.DataMissing != nil {
		selected++
	}
	if value.UnexpectedDataValue != nil {
		selected++
	}
	if value.UnknownSubscriber != nil {
		selected++
	}
	if value.BearerServiceNotProvisioned != nil {
		selected++
	}
	if value.TeleserviceNotProvisioned != nil {
		selected++
	}
	if value.CallBarred != nil {
		selected++
	}
	if value.IllegalSSOperation != nil {
		selected++
	}
	if value.SsNotAvailable != nil {
		selected++
	}
	if value.InformationNotAvailable != nil {
		selected++
	}
	if selected != 1 {
		return EncodedError{}, fmt.Errorf("%w: exactly one anyTimeSubscriptionInterrogation error arm is required", ber.ErrInvalidBinding)
	}
	if value.AtsiNotAllowed != nil {
		return encodeMAPErrorMember(AtsiNotAllowed, value.AtsiNotAllowed, ATSINotAllowedParamCodec(), opts...)
	}
	if value.DataMissing != nil {
		return encodeMAPErrorMember(DataMissing, value.DataMissing, DataMissingParamCodec(), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	if value.UnknownSubscriber != nil {
		return encodeMAPErrorMember(UnknownSubscriber, value.UnknownSubscriber, UnknownSubscriberParamCodec(), opts...)
	}
	if value.BearerServiceNotProvisioned != nil {
		return encodeMAPErrorMember(BearerServiceNotProvisioned, value.BearerServiceNotProvisioned, BearerServNotProvParamCodec(), opts...)
	}
	if value.TeleserviceNotProvisioned != nil {
		return encodeMAPErrorMember(TeleserviceNotProvisioned, value.TeleserviceNotProvisioned, TeleservNotProvParamCodec(), opts...)
	}
	if value.CallBarred != nil {
		return encodeMAPErrorMember(CallBarred, value.CallBarred, CallBarredParamCodec(), opts...)
	}
	if value.IllegalSSOperation != nil {
		return encodeMAPErrorMember(IllegalSSOperation, value.IllegalSSOperation, IllegalSSOperationParamCodec(), opts...)
	}
	if value.SsNotAvailable != nil {
		return encodeMAPErrorMember(SsNotAvailable, value.SsNotAvailable, SSNotAvailableParamCodec(), opts...)
	}
	if value.InformationNotAvailable != nil {
		return encodeMAPErrorMember(InformationNotAvailable, value.InformationNotAvailable, InformationNotAvailableParamCodec(), opts...)
	}
	return EncodedError{}, fmt.Errorf("%w: no selected anyTimeSubscriptionInterrogation error", ber.ErrInvalidBinding)
}

// AuthenticationFailureReportErrors selects exactly the formal ERRORS set of MAP-MobileServiceOperations.authenticationFailureReport.
type AuthenticationFailureReportErrors struct {
	SystemFailure       *ErrorValue[SystemFailureParam]
	UnexpectedDataValue *ErrorValue[UnexpectedDataParam]
	UnknownSubscriber   *ErrorValue[UnknownSubscriberParam]
}

func infoAuthenticationFailureReportOperation() OperationInfo {
	return OperationInfo{Name: "authenticationFailureReport", Code: AuthenticationFailureReport, Argument: &TypeRef{ModuleOID: "0.4.0.0.1.3.11.22", ASN1Name: "AuthenticationFailureReportArg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "AuthenticationFailureReportArg"}, Result: &TypeRef{ModuleOID: "0.4.0.0.1.3.11.22", ASN1Name: "AuthenticationFailureReportRes", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "AuthenticationFailureReportRes"}, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: false, Source: sourceInfo4("authenticationFailureReport", "17.6.1"), Errors: []ErrorInfo{infoSystemFailureError(), infoUnexpectedDataValueError(), infoUnknownSubscriberError()}, Linked: []MAPOperationCode{}}
}

// AuthenticationFailureReportOperation binds the formal object in TS 29.002 V19.1.0 §17.6.1 (X.880 §§8.2–8.3).
func AuthenticationFailureReportOperation() Operation[AuthenticationFailureReportArg, AuthenticationFailureReportRes, AuthenticationFailureReportErrors] {
	return Operation[AuthenticationFailureReportArg, AuthenticationFailureReportRes, AuthenticationFailureReportErrors]{operationBinding[AuthenticationFailureReportArg, AuthenticationFailureReportRes, AuthenticationFailureReportErrors, OperationInfo, MAPOperationCode, EncodedError]{code: AuthenticationFailureReport, info: infoAuthenticationFailureReportOperation, argument: AuthenticationFailureReportArgCodec(), result: AuthenticationFailureReportResCodec(), decode: decodeAuthenticationFailureReportError, encode: encodeAuthenticationFailureReportError}}
}
func decodeAuthenticationFailureReportError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (AuthenticationFailureReportErrors, error) {
	switch code {
	case 34:
		p, err := decodeErrorParameter(data, present, SystemFailureParamCodec(), opts...)
		if err != nil {
			return AuthenticationFailureReportErrors{}, err
		}
		return AuthenticationFailureReportErrors{SystemFailure: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return AuthenticationFailureReportErrors{}, err
		}
		return AuthenticationFailureReportErrors{UnexpectedDataValue: p}, nil
	case 1:
		p, err := decodeErrorParameter(data, present, UnknownSubscriberParamCodec(), opts...)
		if err != nil {
			return AuthenticationFailureReportErrors{}, err
		}
		return AuthenticationFailureReportErrors{UnknownSubscriber: p}, nil
	default:
		return AuthenticationFailureReportErrors{}, fmt.Errorf("%w: error code %d is not in authenticationFailureReport ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeAuthenticationFailureReportError(value AuthenticationFailureReportErrors, opts ...ber.EncodeOption) (EncodedError, error) {
	selected := 0
	if value.SystemFailure != nil {
		selected++
	}
	if value.UnexpectedDataValue != nil {
		selected++
	}
	if value.UnknownSubscriber != nil {
		selected++
	}
	if selected != 1 {
		return EncodedError{}, fmt.Errorf("%w: exactly one authenticationFailureReport error arm is required", ber.ErrInvalidBinding)
	}
	if value.SystemFailure != nil {
		return encodeMAPErrorMember(SystemFailure, value.SystemFailure, SystemFailureParamCodec(), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	if value.UnknownSubscriber != nil {
		return encodeMAPErrorMember(UnknownSubscriber, value.UnknownSubscriber, UnknownSubscriberParamCodec(), opts...)
	}
	return EncodedError{}, fmt.Errorf("%w: no selected authenticationFailureReport error", ber.ErrInvalidBinding)
}

// CancelLocationErrors selects exactly the formal ERRORS set of MAP-MobileServiceOperations.cancelLocation.
type CancelLocationErrors struct {
	DataMissing         *ErrorValue[DataMissingParam]
	UnexpectedDataValue *ErrorValue[UnexpectedDataParam]
}

func infoCancelLocationOperation() OperationInfo {
	return OperationInfo{Name: "cancelLocation", Code: CancelLocation, Argument: &TypeRef{ModuleOID: "0.4.0.0.1.3.11.22", ASN1Name: "CancelLocationArg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "CancelLocationArg"}, Result: &TypeRef{ModuleOID: "0.4.0.0.1.3.11.22", ASN1Name: "CancelLocationRes", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "CancelLocationRes"}, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: false, Source: sourceInfo4("cancelLocation", "17.6.1"), Errors: []ErrorInfo{infoDataMissingError(), infoUnexpectedDataValueError()}, Linked: []MAPOperationCode{}}
}

// CancelLocationOperation binds the formal object in TS 29.002 V19.1.0 §17.6.1 (X.880 §§8.2–8.3).
func CancelLocationOperation() Operation[CancelLocationArg, CancelLocationRes, CancelLocationErrors] {
	return Operation[CancelLocationArg, CancelLocationRes, CancelLocationErrors]{operationBinding[CancelLocationArg, CancelLocationRes, CancelLocationErrors, OperationInfo, MAPOperationCode, EncodedError]{code: CancelLocation, info: infoCancelLocationOperation, argument: CancelLocationArgCodec(), result: CancelLocationResCodec(), decode: decodeCancelLocationError, encode: encodeCancelLocationError}}
}
func decodeCancelLocationError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (CancelLocationErrors, error) {
	switch code {
	case 35:
		p, err := decodeErrorParameter(data, present, DataMissingParamCodec(), opts...)
		if err != nil {
			return CancelLocationErrors{}, err
		}
		return CancelLocationErrors{DataMissing: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return CancelLocationErrors{}, err
		}
		return CancelLocationErrors{UnexpectedDataValue: p}, nil
	default:
		return CancelLocationErrors{}, fmt.Errorf("%w: error code %d is not in cancelLocation ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeCancelLocationError(value CancelLocationErrors, opts ...ber.EncodeOption) (EncodedError, error) {
	selected := 0
	if value.DataMissing != nil {
		selected++
	}
	if value.UnexpectedDataValue != nil {
		selected++
	}
	if selected != 1 {
		return EncodedError{}, fmt.Errorf("%w: exactly one cancelLocation error arm is required", ber.ErrInvalidBinding)
	}
	if value.DataMissing != nil {
		return encodeMAPErrorMember(DataMissing, value.DataMissing, DataMissingParamCodec(), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	return EncodedError{}, fmt.Errorf("%w: no selected cancelLocation error", ber.ErrInvalidBinding)
}

// CancelVcsgLocationErrors selects exactly the formal ERRORS set of MAP-MobileServiceOperations.cancelVcsgLocation.
type CancelVcsgLocationErrors struct {
	DataMissing         *ErrorValue[DataMissingParam]
	UnexpectedDataValue *ErrorValue[UnexpectedDataParam]
}

func infoCancelVcsgLocationOperation() OperationInfo {
	return OperationInfo{Name: "cancelVcsgLocation", Code: CancelVcsgLocation, Argument: &TypeRef{ModuleOID: "0.4.0.0.1.3.11.22", ASN1Name: "CancelVcsgLocationArg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "CancelVcsgLocationArg"}, Result: &TypeRef{ModuleOID: "0.4.0.0.1.3.11.22", ASN1Name: "CancelVcsgLocationRes", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "CancelVcsgLocationRes"}, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: false, Source: sourceInfo4("cancelVcsgLocation", "17.6.1"), Errors: []ErrorInfo{infoDataMissingError(), infoUnexpectedDataValueError()}, Linked: []MAPOperationCode{}}
}

// CancelVcsgLocationOperation binds the formal object in TS 29.002 V19.1.0 §17.6.1 (X.880 §§8.2–8.3).
func CancelVcsgLocationOperation() Operation[CancelVcsgLocationArg, CancelVcsgLocationRes, CancelVcsgLocationErrors] {
	return Operation[CancelVcsgLocationArg, CancelVcsgLocationRes, CancelVcsgLocationErrors]{operationBinding[CancelVcsgLocationArg, CancelVcsgLocationRes, CancelVcsgLocationErrors, OperationInfo, MAPOperationCode, EncodedError]{code: CancelVcsgLocation, info: infoCancelVcsgLocationOperation, argument: CancelVcsgLocationArgCodec(), result: CancelVcsgLocationResCodec(), decode: decodeCancelVcsgLocationError, encode: encodeCancelVcsgLocationError}}
}
func decodeCancelVcsgLocationError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (CancelVcsgLocationErrors, error) {
	switch code {
	case 35:
		p, err := decodeErrorParameter(data, present, DataMissingParamCodec(), opts...)
		if err != nil {
			return CancelVcsgLocationErrors{}, err
		}
		return CancelVcsgLocationErrors{DataMissing: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return CancelVcsgLocationErrors{}, err
		}
		return CancelVcsgLocationErrors{UnexpectedDataValue: p}, nil
	default:
		return CancelVcsgLocationErrors{}, fmt.Errorf("%w: error code %d is not in cancelVcsgLocation ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeCancelVcsgLocationError(value CancelVcsgLocationErrors, opts ...ber.EncodeOption) (EncodedError, error) {
	selected := 0
	if value.DataMissing != nil {
		selected++
	}
	if value.UnexpectedDataValue != nil {
		selected++
	}
	if selected != 1 {
		return EncodedError{}, fmt.Errorf("%w: exactly one cancelVcsgLocation error arm is required", ber.ErrInvalidBinding)
	}
	if value.DataMissing != nil {
		return encodeMAPErrorMember(DataMissing, value.DataMissing, DataMissingParamCodec(), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	return EncodedError{}, fmt.Errorf("%w: no selected cancelVcsgLocation error", ber.ErrInvalidBinding)
}

// CheckIMEIErrors selects exactly the formal ERRORS set of MAP-MobileServiceOperations.checkIMEI.
type CheckIMEIErrors struct {
	SystemFailure    *ErrorValue[SystemFailureParam]
	DataMissing      *ErrorValue[DataMissingParam]
	UnknownEquipment *ErrorValue[NoParameter]
}

func infoCheckIMEIOperation() OperationInfo {
	return OperationInfo{Name: "checkIMEI", Code: CheckIMEI, Argument: &TypeRef{ModuleOID: "0.4.0.0.1.3.11.22", ASN1Name: "CheckIMEI-Arg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "CheckIMEIArg"}, Result: &TypeRef{ModuleOID: "0.4.0.0.1.3.11.22", ASN1Name: "CheckIMEI-Res", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "CheckIMEIRes"}, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: false, Source: sourceInfo4("checkIMEI", "17.6.1"), Errors: []ErrorInfo{infoSystemFailureError(), infoDataMissingError(), infoUnknownEquipmentError()}, Linked: []MAPOperationCode{}}
}

// CheckIMEIOperation binds the formal object in TS 29.002 V19.1.0 §17.6.1 (X.880 §§8.2–8.3).
func CheckIMEIOperation() Operation[CheckIMEIArg, CheckIMEIRes, CheckIMEIErrors] {
	return Operation[CheckIMEIArg, CheckIMEIRes, CheckIMEIErrors]{operationBinding[CheckIMEIArg, CheckIMEIRes, CheckIMEIErrors, OperationInfo, MAPOperationCode, EncodedError]{code: CheckIMEI, info: infoCheckIMEIOperation, argument: CheckIMEIArgCodec(), result: CheckIMEIResCodec(), decode: decodeCheckIMEIError, encode: encodeCheckIMEIError}}
}
func decodeCheckIMEIError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (CheckIMEIErrors, error) {
	switch code {
	case 34:
		p, err := decodeErrorParameter(data, present, SystemFailureParamCodec(), opts...)
		if err != nil {
			return CheckIMEIErrors{}, err
		}
		return CheckIMEIErrors{SystemFailure: p}, nil
	case 35:
		p, err := decodeErrorParameter(data, present, DataMissingParamCodec(), opts...)
		if err != nil {
			return CheckIMEIErrors{}, err
		}
		return CheckIMEIErrors{DataMissing: p}, nil
	case 7:
		p, err := decodeErrorParameter(data, present, ValueCodec[NoParameter]{}, opts...)
		if err != nil {
			return CheckIMEIErrors{}, err
		}
		return CheckIMEIErrors{UnknownEquipment: p}, nil
	default:
		return CheckIMEIErrors{}, fmt.Errorf("%w: error code %d is not in checkIMEI ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeCheckIMEIError(value CheckIMEIErrors, opts ...ber.EncodeOption) (EncodedError, error) {
	selected := 0
	if value.SystemFailure != nil {
		selected++
	}
	if value.DataMissing != nil {
		selected++
	}
	if value.UnknownEquipment != nil {
		selected++
	}
	if selected != 1 {
		return EncodedError{}, fmt.Errorf("%w: exactly one checkIMEI error arm is required", ber.ErrInvalidBinding)
	}
	if value.SystemFailure != nil {
		return encodeMAPErrorMember(SystemFailure, value.SystemFailure, SystemFailureParamCodec(), opts...)
	}
	if value.DataMissing != nil {
		return encodeMAPErrorMember(DataMissing, value.DataMissing, DataMissingParamCodec(), opts...)
	}
	if value.UnknownEquipment != nil {
		return encodeMAPErrorMember(UnknownEquipment, value.UnknownEquipment, ValueCodec[NoParameter]{}, opts...)
	}
	return EncodedError{}, fmt.Errorf("%w: no selected checkIMEI error", ber.ErrInvalidBinding)
}

// DeactivateSSErrors selects exactly the formal ERRORS set of MAP-SupplementaryServiceOperations.deactivateSS.
type DeactivateSSErrors struct {
	SystemFailure               *ErrorValue[SystemFailureParam]
	DataMissing                 *ErrorValue[DataMissingParam]
	UnexpectedDataValue         *ErrorValue[UnexpectedDataParam]
	BearerServiceNotProvisioned *ErrorValue[BearerServNotProvParam]
	TeleserviceNotProvisioned   *ErrorValue[TeleservNotProvParam]
	CallBarred                  *ErrorValue[CallBarredParam]
	IllegalSSOperation          *ErrorValue[IllegalSSOperationParam]
	SsErrorStatus               *ErrorValue[BERValue[SSStatus]]
	SsSubscriptionViolation     *ErrorValue[SSSubscriptionViolationParam]
	NegativePWCheck             *ErrorValue[NoParameter]
	NumberOfPWAttemptsViolation *ErrorValue[NoParameter]
}

func infoDeactivateSSOperation() OperationInfo {
	return OperationInfo{Name: "deactivateSS", Code: DeactivateSS, Argument: &TypeRef{ModuleOID: "0.4.0.0.1.3.14.22", ASN1Name: "SS-ForBS-Code", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "SSForBSCode"}, Result: &TypeRef{ModuleOID: "0.4.0.0.1.3.14.22", ASN1Name: "SS-Info", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "SSInfo"}, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: false, Source: sourceInfo1("deactivateSS", "17.6.4"), Errors: []ErrorInfo{infoSystemFailureError(), infoDataMissingError(), infoUnexpectedDataValueError(), infoBearerServiceNotProvisionedError(), infoTeleserviceNotProvisionedError(), infoCallBarredError(), infoIllegalSSOperationError(), infoSsErrorStatusError(), infoSsSubscriptionViolationError(), infoNegativePWCheckError(), infoNumberOfPWAttemptsViolationError()}, Linked: []MAPOperationCode{}}
}

// DeactivateSSOperation binds the formal object in TS 29.002 V19.1.0 §17.6.4 (X.880 §§8.2–8.3).
func DeactivateSSOperation() Operation[SSForBSCode, SSInfo, DeactivateSSErrors] {
	return Operation[SSForBSCode, SSInfo, DeactivateSSErrors]{operationBinding[SSForBSCode, SSInfo, DeactivateSSErrors, OperationInfo, MAPOperationCode, EncodedError]{code: DeactivateSS, info: infoDeactivateSSOperation, argument: SSForBSCodeCodec(), result: SSInfoCodec(), decode: decodeDeactivateSSError, encode: encodeDeactivateSSError}}
}
func decodeDeactivateSSError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (DeactivateSSErrors, error) {
	switch code {
	case 34:
		p, err := decodeErrorParameter(data, present, SystemFailureParamCodec(), opts...)
		if err != nil {
			return DeactivateSSErrors{}, err
		}
		return DeactivateSSErrors{SystemFailure: p}, nil
	case 35:
		p, err := decodeErrorParameter(data, present, DataMissingParamCodec(), opts...)
		if err != nil {
			return DeactivateSSErrors{}, err
		}
		return DeactivateSSErrors{DataMissing: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return DeactivateSSErrors{}, err
		}
		return DeactivateSSErrors{UnexpectedDataValue: p}, nil
	case 10:
		p, err := decodeErrorParameter(data, present, BearerServNotProvParamCodec(), opts...)
		if err != nil {
			return DeactivateSSErrors{}, err
		}
		return DeactivateSSErrors{BearerServiceNotProvisioned: p}, nil
	case 11:
		p, err := decodeErrorParameter(data, present, TeleservNotProvParamCodec(), opts...)
		if err != nil {
			return DeactivateSSErrors{}, err
		}
		return DeactivateSSErrors{TeleserviceNotProvisioned: p}, nil
	case 13:
		p, err := decodeErrorParameter(data, present, CallBarredParamCodec(), opts...)
		if err != nil {
			return DeactivateSSErrors{}, err
		}
		return DeactivateSSErrors{CallBarred: p}, nil
	case 16:
		p, err := decodeErrorParameter(data, present, IllegalSSOperationParamCodec(), opts...)
		if err != nil {
			return DeactivateSSErrors{}, err
		}
		return DeactivateSSErrors{IllegalSSOperation: p}, nil
	case 17:
		p, err := decodeErrorParameter(data, present, SSStatusCodec(), opts...)
		if err != nil {
			return DeactivateSSErrors{}, err
		}
		return DeactivateSSErrors{SsErrorStatus: p}, nil
	case 19:
		p, err := decodeErrorParameter(data, present, SSSubscriptionViolationParamCodec(), opts...)
		if err != nil {
			return DeactivateSSErrors{}, err
		}
		return DeactivateSSErrors{SsSubscriptionViolation: p}, nil
	case 38:
		p, err := decodeErrorParameter(data, present, ValueCodec[NoParameter]{}, opts...)
		if err != nil {
			return DeactivateSSErrors{}, err
		}
		return DeactivateSSErrors{NegativePWCheck: p}, nil
	case 43:
		p, err := decodeErrorParameter(data, present, ValueCodec[NoParameter]{}, opts...)
		if err != nil {
			return DeactivateSSErrors{}, err
		}
		return DeactivateSSErrors{NumberOfPWAttemptsViolation: p}, nil
	default:
		return DeactivateSSErrors{}, fmt.Errorf("%w: error code %d is not in deactivateSS ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeDeactivateSSError(value DeactivateSSErrors, opts ...ber.EncodeOption) (EncodedError, error) {
	selected := 0
	if value.SystemFailure != nil {
		selected++
	}
	if value.DataMissing != nil {
		selected++
	}
	if value.UnexpectedDataValue != nil {
		selected++
	}
	if value.BearerServiceNotProvisioned != nil {
		selected++
	}
	if value.TeleserviceNotProvisioned != nil {
		selected++
	}
	if value.CallBarred != nil {
		selected++
	}
	if value.IllegalSSOperation != nil {
		selected++
	}
	if value.SsErrorStatus != nil {
		selected++
	}
	if value.SsSubscriptionViolation != nil {
		selected++
	}
	if value.NegativePWCheck != nil {
		selected++
	}
	if value.NumberOfPWAttemptsViolation != nil {
		selected++
	}
	if selected != 1 {
		return EncodedError{}, fmt.Errorf("%w: exactly one deactivateSS error arm is required", ber.ErrInvalidBinding)
	}
	if value.SystemFailure != nil {
		return encodeMAPErrorMember(SystemFailure, value.SystemFailure, SystemFailureParamCodec(), opts...)
	}
	if value.DataMissing != nil {
		return encodeMAPErrorMember(DataMissing, value.DataMissing, DataMissingParamCodec(), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	if value.BearerServiceNotProvisioned != nil {
		return encodeMAPErrorMember(BearerServiceNotProvisioned, value.BearerServiceNotProvisioned, BearerServNotProvParamCodec(), opts...)
	}
	if value.TeleserviceNotProvisioned != nil {
		return encodeMAPErrorMember(TeleserviceNotProvisioned, value.TeleserviceNotProvisioned, TeleservNotProvParamCodec(), opts...)
	}
	if value.CallBarred != nil {
		return encodeMAPErrorMember(CallBarred, value.CallBarred, CallBarredParamCodec(), opts...)
	}
	if value.IllegalSSOperation != nil {
		return encodeMAPErrorMember(IllegalSSOperation, value.IllegalSSOperation, IllegalSSOperationParamCodec(), opts...)
	}
	if value.SsErrorStatus != nil {
		return encodeMAPErrorMember(SsErrorStatus, value.SsErrorStatus, SSStatusCodec(), opts...)
	}
	if value.SsSubscriptionViolation != nil {
		return encodeMAPErrorMember(SsSubscriptionViolation, value.SsSubscriptionViolation, SSSubscriptionViolationParamCodec(), opts...)
	}
	if value.NegativePWCheck != nil {
		return encodeMAPErrorMember(NegativePWCheck, value.NegativePWCheck, ValueCodec[NoParameter]{}, opts...)
	}
	if value.NumberOfPWAttemptsViolation != nil {
		return encodeMAPErrorMember(NumberOfPWAttemptsViolation, value.NumberOfPWAttemptsViolation, ValueCodec[NoParameter]{}, opts...)
	}
	return EncodedError{}, fmt.Errorf("%w: no selected deactivateSS error", ber.ErrInvalidBinding)
}

// DeactivateTraceModeErrors selects exactly the formal ERRORS set of MAP-OperationAndMaintenanceOperations.deactivateTraceMode.
type DeactivateTraceModeErrors struct {
	SystemFailure          *ErrorValue[SystemFailureParam]
	DataMissing            *ErrorValue[DataMissingParam]
	UnexpectedDataValue    *ErrorValue[UnexpectedDataParam]
	FacilityNotSupported   *ErrorValue[FacilityNotSupParam]
	UnidentifiedSubscriber *ErrorValue[UnidentifiedSubParam]
}

func infoDeactivateTraceModeOperation() OperationInfo {
	return OperationInfo{Name: "deactivateTraceMode", Code: DeactivateTraceMode, Argument: &TypeRef{ModuleOID: "0.4.0.0.1.3.12.22", ASN1Name: "DeactivateTraceModeArg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "DeactivateTraceModeArg"}, Result: &TypeRef{ModuleOID: "0.4.0.0.1.3.12.22", ASN1Name: "DeactivateTraceModeRes", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "DeactivateTraceModeRes"}, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: false, Source: sourceInfo2("deactivateTraceMode", "17.6.2"), Errors: []ErrorInfo{infoSystemFailureError(), infoDataMissingError(), infoUnexpectedDataValueError(), infoFacilityNotSupportedError(), infoUnidentifiedSubscriberError()}, Linked: []MAPOperationCode{}}
}

// DeactivateTraceModeOperation binds the formal object in TS 29.002 V19.1.0 §17.6.2 (X.880 §§8.2–8.3).
func DeactivateTraceModeOperation() Operation[DeactivateTraceModeArg, DeactivateTraceModeRes, DeactivateTraceModeErrors] {
	return Operation[DeactivateTraceModeArg, DeactivateTraceModeRes, DeactivateTraceModeErrors]{operationBinding[DeactivateTraceModeArg, DeactivateTraceModeRes, DeactivateTraceModeErrors, OperationInfo, MAPOperationCode, EncodedError]{code: DeactivateTraceMode, info: infoDeactivateTraceModeOperation, argument: DeactivateTraceModeArgCodec(), result: DeactivateTraceModeResCodec(), decode: decodeDeactivateTraceModeError, encode: encodeDeactivateTraceModeError}}
}
func decodeDeactivateTraceModeError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (DeactivateTraceModeErrors, error) {
	switch code {
	case 34:
		p, err := decodeErrorParameter(data, present, SystemFailureParamCodec(), opts...)
		if err != nil {
			return DeactivateTraceModeErrors{}, err
		}
		return DeactivateTraceModeErrors{SystemFailure: p}, nil
	case 35:
		p, err := decodeErrorParameter(data, present, DataMissingParamCodec(), opts...)
		if err != nil {
			return DeactivateTraceModeErrors{}, err
		}
		return DeactivateTraceModeErrors{DataMissing: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return DeactivateTraceModeErrors{}, err
		}
		return DeactivateTraceModeErrors{UnexpectedDataValue: p}, nil
	case 21:
		p, err := decodeErrorParameter(data, present, FacilityNotSupParamCodec(), opts...)
		if err != nil {
			return DeactivateTraceModeErrors{}, err
		}
		return DeactivateTraceModeErrors{FacilityNotSupported: p}, nil
	case 5:
		p, err := decodeErrorParameter(data, present, UnidentifiedSubParamCodec(), opts...)
		if err != nil {
			return DeactivateTraceModeErrors{}, err
		}
		return DeactivateTraceModeErrors{UnidentifiedSubscriber: p}, nil
	default:
		return DeactivateTraceModeErrors{}, fmt.Errorf("%w: error code %d is not in deactivateTraceMode ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeDeactivateTraceModeError(value DeactivateTraceModeErrors, opts ...ber.EncodeOption) (EncodedError, error) {
	selected := 0
	if value.SystemFailure != nil {
		selected++
	}
	if value.DataMissing != nil {
		selected++
	}
	if value.UnexpectedDataValue != nil {
		selected++
	}
	if value.FacilityNotSupported != nil {
		selected++
	}
	if value.UnidentifiedSubscriber != nil {
		selected++
	}
	if selected != 1 {
		return EncodedError{}, fmt.Errorf("%w: exactly one deactivateTraceMode error arm is required", ber.ErrInvalidBinding)
	}
	if value.SystemFailure != nil {
		return encodeMAPErrorMember(SystemFailure, value.SystemFailure, SystemFailureParamCodec(), opts...)
	}
	if value.DataMissing != nil {
		return encodeMAPErrorMember(DataMissing, value.DataMissing, DataMissingParamCodec(), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	if value.FacilityNotSupported != nil {
		return encodeMAPErrorMember(FacilityNotSupported, value.FacilityNotSupported, FacilityNotSupParamCodec(), opts...)
	}
	if value.UnidentifiedSubscriber != nil {
		return encodeMAPErrorMember(UnidentifiedSubscriber, value.UnidentifiedSubscriber, UnidentifiedSubParamCodec(), opts...)
	}
	return EncodedError{}, fmt.Errorf("%w: no selected deactivateTraceMode error", ber.ErrInvalidBinding)
}

// DeleteSubscriberDataErrors selects exactly the formal ERRORS set of MAP-MobileServiceOperations.deleteSubscriberData.
type DeleteSubscriberDataErrors struct {
	DataMissing            *ErrorValue[DataMissingParam]
	UnexpectedDataValue    *ErrorValue[UnexpectedDataParam]
	UnidentifiedSubscriber *ErrorValue[UnidentifiedSubParam]
}

func infoDeleteSubscriberDataOperation() OperationInfo {
	return OperationInfo{Name: "deleteSubscriberData", Code: DeleteSubscriberData, Argument: &TypeRef{ModuleOID: "0.4.0.0.1.3.11.22", ASN1Name: "DeleteSubscriberDataArg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "DeleteSubscriberDataArg"}, Result: &TypeRef{ModuleOID: "0.4.0.0.1.3.11.22", ASN1Name: "DeleteSubscriberDataRes", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "DeleteSubscriberDataRes"}, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: false, Source: sourceInfo4("deleteSubscriberData", "17.6.1"), Errors: []ErrorInfo{infoDataMissingError(), infoUnexpectedDataValueError(), infoUnidentifiedSubscriberError()}, Linked: []MAPOperationCode{}}
}

// DeleteSubscriberDataOperation binds the formal object in TS 29.002 V19.1.0 §17.6.1 (X.880 §§8.2–8.3).
func DeleteSubscriberDataOperation() Operation[DeleteSubscriberDataArg, DeleteSubscriberDataRes, DeleteSubscriberDataErrors] {
	return Operation[DeleteSubscriberDataArg, DeleteSubscriberDataRes, DeleteSubscriberDataErrors]{operationBinding[DeleteSubscriberDataArg, DeleteSubscriberDataRes, DeleteSubscriberDataErrors, OperationInfo, MAPOperationCode, EncodedError]{code: DeleteSubscriberData, info: infoDeleteSubscriberDataOperation, argument: DeleteSubscriberDataArgCodec(), result: DeleteSubscriberDataResCodec(), decode: decodeDeleteSubscriberDataError, encode: encodeDeleteSubscriberDataError}}
}
func decodeDeleteSubscriberDataError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (DeleteSubscriberDataErrors, error) {
	switch code {
	case 35:
		p, err := decodeErrorParameter(data, present, DataMissingParamCodec(), opts...)
		if err != nil {
			return DeleteSubscriberDataErrors{}, err
		}
		return DeleteSubscriberDataErrors{DataMissing: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return DeleteSubscriberDataErrors{}, err
		}
		return DeleteSubscriberDataErrors{UnexpectedDataValue: p}, nil
	case 5:
		p, err := decodeErrorParameter(data, present, UnidentifiedSubParamCodec(), opts...)
		if err != nil {
			return DeleteSubscriberDataErrors{}, err
		}
		return DeleteSubscriberDataErrors{UnidentifiedSubscriber: p}, nil
	default:
		return DeleteSubscriberDataErrors{}, fmt.Errorf("%w: error code %d is not in deleteSubscriberData ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeDeleteSubscriberDataError(value DeleteSubscriberDataErrors, opts ...ber.EncodeOption) (EncodedError, error) {
	selected := 0
	if value.DataMissing != nil {
		selected++
	}
	if value.UnexpectedDataValue != nil {
		selected++
	}
	if value.UnidentifiedSubscriber != nil {
		selected++
	}
	if selected != 1 {
		return EncodedError{}, fmt.Errorf("%w: exactly one deleteSubscriberData error arm is required", ber.ErrInvalidBinding)
	}
	if value.DataMissing != nil {
		return encodeMAPErrorMember(DataMissing, value.DataMissing, DataMissingParamCodec(), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	if value.UnidentifiedSubscriber != nil {
		return encodeMAPErrorMember(UnidentifiedSubscriber, value.UnidentifiedSubscriber, UnidentifiedSubParamCodec(), opts...)
	}
	return EncodedError{}, fmt.Errorf("%w: no selected deleteSubscriberData error", ber.ErrInvalidBinding)
}

// EraseCCEntryErrors selects exactly the formal ERRORS set of MAP-SupplementaryServiceOperations.eraseCC-Entry.
type EraseCCEntryErrors struct {
	SystemFailure       *ErrorValue[SystemFailureParam]
	DataMissing         *ErrorValue[DataMissingParam]
	UnexpectedDataValue *ErrorValue[UnexpectedDataParam]
	CallBarred          *ErrorValue[CallBarredParam]
	IllegalSSOperation  *ErrorValue[IllegalSSOperationParam]
	SsErrorStatus       *ErrorValue[BERValue[SSStatus]]
}

func infoEraseCCEntryOperation() OperationInfo {
	return OperationInfo{Name: "eraseCC-Entry", Code: EraseCCEntry, Argument: &TypeRef{ModuleOID: "0.4.0.0.1.3.14.22", ASN1Name: "EraseCC-EntryArg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "EraseCCEntryArg"}, Result: &TypeRef{ModuleOID: "0.4.0.0.1.3.14.22", ASN1Name: "EraseCC-EntryRes", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "EraseCCEntryRes"}, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: false, Source: sourceInfo1("eraseCC-Entry", "17.6.4"), Errors: []ErrorInfo{infoSystemFailureError(), infoDataMissingError(), infoUnexpectedDataValueError(), infoCallBarredError(), infoIllegalSSOperationError(), infoSsErrorStatusError()}, Linked: []MAPOperationCode{}}
}

// EraseCCEntryOperation binds the formal object in TS 29.002 V19.1.0 §17.6.4 (X.880 §§8.2–8.3).
func EraseCCEntryOperation() Operation[EraseCCEntryArg, EraseCCEntryRes, EraseCCEntryErrors] {
	return Operation[EraseCCEntryArg, EraseCCEntryRes, EraseCCEntryErrors]{operationBinding[EraseCCEntryArg, EraseCCEntryRes, EraseCCEntryErrors, OperationInfo, MAPOperationCode, EncodedError]{code: EraseCCEntry, info: infoEraseCCEntryOperation, argument: EraseCCEntryArgCodec(), result: EraseCCEntryResCodec(), decode: decodeEraseCCEntryError, encode: encodeEraseCCEntryError}}
}
func decodeEraseCCEntryError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (EraseCCEntryErrors, error) {
	switch code {
	case 34:
		p, err := decodeErrorParameter(data, present, SystemFailureParamCodec(), opts...)
		if err != nil {
			return EraseCCEntryErrors{}, err
		}
		return EraseCCEntryErrors{SystemFailure: p}, nil
	case 35:
		p, err := decodeErrorParameter(data, present, DataMissingParamCodec(), opts...)
		if err != nil {
			return EraseCCEntryErrors{}, err
		}
		return EraseCCEntryErrors{DataMissing: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return EraseCCEntryErrors{}, err
		}
		return EraseCCEntryErrors{UnexpectedDataValue: p}, nil
	case 13:
		p, err := decodeErrorParameter(data, present, CallBarredParamCodec(), opts...)
		if err != nil {
			return EraseCCEntryErrors{}, err
		}
		return EraseCCEntryErrors{CallBarred: p}, nil
	case 16:
		p, err := decodeErrorParameter(data, present, IllegalSSOperationParamCodec(), opts...)
		if err != nil {
			return EraseCCEntryErrors{}, err
		}
		return EraseCCEntryErrors{IllegalSSOperation: p}, nil
	case 17:
		p, err := decodeErrorParameter(data, present, SSStatusCodec(), opts...)
		if err != nil {
			return EraseCCEntryErrors{}, err
		}
		return EraseCCEntryErrors{SsErrorStatus: p}, nil
	default:
		return EraseCCEntryErrors{}, fmt.Errorf("%w: error code %d is not in eraseCC-Entry ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeEraseCCEntryError(value EraseCCEntryErrors, opts ...ber.EncodeOption) (EncodedError, error) {
	selected := 0
	if value.SystemFailure != nil {
		selected++
	}
	if value.DataMissing != nil {
		selected++
	}
	if value.UnexpectedDataValue != nil {
		selected++
	}
	if value.CallBarred != nil {
		selected++
	}
	if value.IllegalSSOperation != nil {
		selected++
	}
	if value.SsErrorStatus != nil {
		selected++
	}
	if selected != 1 {
		return EncodedError{}, fmt.Errorf("%w: exactly one eraseCC-Entry error arm is required", ber.ErrInvalidBinding)
	}
	if value.SystemFailure != nil {
		return encodeMAPErrorMember(SystemFailure, value.SystemFailure, SystemFailureParamCodec(), opts...)
	}
	if value.DataMissing != nil {
		return encodeMAPErrorMember(DataMissing, value.DataMissing, DataMissingParamCodec(), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	if value.CallBarred != nil {
		return encodeMAPErrorMember(CallBarred, value.CallBarred, CallBarredParamCodec(), opts...)
	}
	if value.IllegalSSOperation != nil {
		return encodeMAPErrorMember(IllegalSSOperation, value.IllegalSSOperation, IllegalSSOperationParamCodec(), opts...)
	}
	if value.SsErrorStatus != nil {
		return encodeMAPErrorMember(SsErrorStatus, value.SsErrorStatus, SSStatusCodec(), opts...)
	}
	return EncodedError{}, fmt.Errorf("%w: no selected eraseCC-Entry error", ber.ErrInvalidBinding)
}

// EraseSSErrors selects exactly the formal ERRORS set of MAP-SupplementaryServiceOperations.eraseSS.
type EraseSSErrors struct {
	SystemFailure               *ErrorValue[SystemFailureParam]
	DataMissing                 *ErrorValue[DataMissingParam]
	UnexpectedDataValue         *ErrorValue[UnexpectedDataParam]
	BearerServiceNotProvisioned *ErrorValue[BearerServNotProvParam]
	TeleserviceNotProvisioned   *ErrorValue[TeleservNotProvParam]
	CallBarred                  *ErrorValue[CallBarredParam]
	IllegalSSOperation          *ErrorValue[IllegalSSOperationParam]
	SsErrorStatus               *ErrorValue[BERValue[SSStatus]]
}

func infoEraseSSOperation() OperationInfo {
	return OperationInfo{Name: "eraseSS", Code: EraseSS, Argument: &TypeRef{ModuleOID: "0.4.0.0.1.3.14.22", ASN1Name: "SS-ForBS-Code", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "SSForBSCode"}, Result: &TypeRef{ModuleOID: "0.4.0.0.1.3.14.22", ASN1Name: "SS-Info", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "SSInfo"}, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: false, Source: sourceInfo1("eraseSS", "17.6.4"), Errors: []ErrorInfo{infoSystemFailureError(), infoDataMissingError(), infoUnexpectedDataValueError(), infoBearerServiceNotProvisionedError(), infoTeleserviceNotProvisionedError(), infoCallBarredError(), infoIllegalSSOperationError(), infoSsErrorStatusError()}, Linked: []MAPOperationCode{}}
}

// EraseSSOperation binds the formal object in TS 29.002 V19.1.0 §17.6.4 (X.880 §§8.2–8.3).
func EraseSSOperation() Operation[SSForBSCode, SSInfo, EraseSSErrors] {
	return Operation[SSForBSCode, SSInfo, EraseSSErrors]{operationBinding[SSForBSCode, SSInfo, EraseSSErrors, OperationInfo, MAPOperationCode, EncodedError]{code: EraseSS, info: infoEraseSSOperation, argument: SSForBSCodeCodec(), result: SSInfoCodec(), decode: decodeEraseSSError, encode: encodeEraseSSError}}
}
func decodeEraseSSError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (EraseSSErrors, error) {
	switch code {
	case 34:
		p, err := decodeErrorParameter(data, present, SystemFailureParamCodec(), opts...)
		if err != nil {
			return EraseSSErrors{}, err
		}
		return EraseSSErrors{SystemFailure: p}, nil
	case 35:
		p, err := decodeErrorParameter(data, present, DataMissingParamCodec(), opts...)
		if err != nil {
			return EraseSSErrors{}, err
		}
		return EraseSSErrors{DataMissing: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return EraseSSErrors{}, err
		}
		return EraseSSErrors{UnexpectedDataValue: p}, nil
	case 10:
		p, err := decodeErrorParameter(data, present, BearerServNotProvParamCodec(), opts...)
		if err != nil {
			return EraseSSErrors{}, err
		}
		return EraseSSErrors{BearerServiceNotProvisioned: p}, nil
	case 11:
		p, err := decodeErrorParameter(data, present, TeleservNotProvParamCodec(), opts...)
		if err != nil {
			return EraseSSErrors{}, err
		}
		return EraseSSErrors{TeleserviceNotProvisioned: p}, nil
	case 13:
		p, err := decodeErrorParameter(data, present, CallBarredParamCodec(), opts...)
		if err != nil {
			return EraseSSErrors{}, err
		}
		return EraseSSErrors{CallBarred: p}, nil
	case 16:
		p, err := decodeErrorParameter(data, present, IllegalSSOperationParamCodec(), opts...)
		if err != nil {
			return EraseSSErrors{}, err
		}
		return EraseSSErrors{IllegalSSOperation: p}, nil
	case 17:
		p, err := decodeErrorParameter(data, present, SSStatusCodec(), opts...)
		if err != nil {
			return EraseSSErrors{}, err
		}
		return EraseSSErrors{SsErrorStatus: p}, nil
	default:
		return EraseSSErrors{}, fmt.Errorf("%w: error code %d is not in eraseSS ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeEraseSSError(value EraseSSErrors, opts ...ber.EncodeOption) (EncodedError, error) {
	selected := 0
	if value.SystemFailure != nil {
		selected++
	}
	if value.DataMissing != nil {
		selected++
	}
	if value.UnexpectedDataValue != nil {
		selected++
	}
	if value.BearerServiceNotProvisioned != nil {
		selected++
	}
	if value.TeleserviceNotProvisioned != nil {
		selected++
	}
	if value.CallBarred != nil {
		selected++
	}
	if value.IllegalSSOperation != nil {
		selected++
	}
	if value.SsErrorStatus != nil {
		selected++
	}
	if selected != 1 {
		return EncodedError{}, fmt.Errorf("%w: exactly one eraseSS error arm is required", ber.ErrInvalidBinding)
	}
	if value.SystemFailure != nil {
		return encodeMAPErrorMember(SystemFailure, value.SystemFailure, SystemFailureParamCodec(), opts...)
	}
	if value.DataMissing != nil {
		return encodeMAPErrorMember(DataMissing, value.DataMissing, DataMissingParamCodec(), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	if value.BearerServiceNotProvisioned != nil {
		return encodeMAPErrorMember(BearerServiceNotProvisioned, value.BearerServiceNotProvisioned, BearerServNotProvParamCodec(), opts...)
	}
	if value.TeleserviceNotProvisioned != nil {
		return encodeMAPErrorMember(TeleserviceNotProvisioned, value.TeleserviceNotProvisioned, TeleservNotProvParamCodec(), opts...)
	}
	if value.CallBarred != nil {
		return encodeMAPErrorMember(CallBarred, value.CallBarred, CallBarredParamCodec(), opts...)
	}
	if value.IllegalSSOperation != nil {
		return encodeMAPErrorMember(IllegalSSOperation, value.IllegalSSOperation, IllegalSSOperationParamCodec(), opts...)
	}
	if value.SsErrorStatus != nil {
		return encodeMAPErrorMember(SsErrorStatus, value.SsErrorStatus, SSStatusCodec(), opts...)
	}
	return EncodedError{}, fmt.Errorf("%w: no selected eraseSS error", ber.ErrInvalidBinding)
}

// FailureReportErrors selects exactly the formal ERRORS set of MAP-MobileServiceOperations.failureReport.
type FailureReportErrors struct {
	SystemFailure       *ErrorValue[SystemFailureParam]
	DataMissing         *ErrorValue[DataMissingParam]
	UnexpectedDataValue *ErrorValue[UnexpectedDataParam]
	UnknownSubscriber   *ErrorValue[UnknownSubscriberParam]
}

func infoFailureReportOperation() OperationInfo {
	return OperationInfo{Name: "failureReport", Code: FailureReport, Argument: &TypeRef{ModuleOID: "0.4.0.0.1.3.11.22", ASN1Name: "FailureReportArg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "FailureReportArg"}, Result: &TypeRef{ModuleOID: "0.4.0.0.1.3.11.22", ASN1Name: "FailureReportRes", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "FailureReportRes"}, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: false, Source: sourceInfo4("failureReport", "17.6.1"), Errors: []ErrorInfo{infoSystemFailureError(), infoDataMissingError(), infoUnexpectedDataValueError(), infoUnknownSubscriberError()}, Linked: []MAPOperationCode{}}
}

// FailureReportOperation binds the formal object in TS 29.002 V19.1.0 §17.6.1 (X.880 §§8.2–8.3).
func FailureReportOperation() Operation[FailureReportArg, FailureReportRes, FailureReportErrors] {
	return Operation[FailureReportArg, FailureReportRes, FailureReportErrors]{operationBinding[FailureReportArg, FailureReportRes, FailureReportErrors, OperationInfo, MAPOperationCode, EncodedError]{code: FailureReport, info: infoFailureReportOperation, argument: FailureReportArgCodec(), result: FailureReportResCodec(), decode: decodeFailureReportError, encode: encodeFailureReportError}}
}
func decodeFailureReportError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (FailureReportErrors, error) {
	switch code {
	case 34:
		p, err := decodeErrorParameter(data, present, SystemFailureParamCodec(), opts...)
		if err != nil {
			return FailureReportErrors{}, err
		}
		return FailureReportErrors{SystemFailure: p}, nil
	case 35:
		p, err := decodeErrorParameter(data, present, DataMissingParamCodec(), opts...)
		if err != nil {
			return FailureReportErrors{}, err
		}
		return FailureReportErrors{DataMissing: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return FailureReportErrors{}, err
		}
		return FailureReportErrors{UnexpectedDataValue: p}, nil
	case 1:
		p, err := decodeErrorParameter(data, present, UnknownSubscriberParamCodec(), opts...)
		if err != nil {
			return FailureReportErrors{}, err
		}
		return FailureReportErrors{UnknownSubscriber: p}, nil
	default:
		return FailureReportErrors{}, fmt.Errorf("%w: error code %d is not in failureReport ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeFailureReportError(value FailureReportErrors, opts ...ber.EncodeOption) (EncodedError, error) {
	selected := 0
	if value.SystemFailure != nil {
		selected++
	}
	if value.DataMissing != nil {
		selected++
	}
	if value.UnexpectedDataValue != nil {
		selected++
	}
	if value.UnknownSubscriber != nil {
		selected++
	}
	if selected != 1 {
		return EncodedError{}, fmt.Errorf("%w: exactly one failureReport error arm is required", ber.ErrInvalidBinding)
	}
	if value.SystemFailure != nil {
		return encodeMAPErrorMember(SystemFailure, value.SystemFailure, SystemFailureParamCodec(), opts...)
	}
	if value.DataMissing != nil {
		return encodeMAPErrorMember(DataMissing, value.DataMissing, DataMissingParamCodec(), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	if value.UnknownSubscriber != nil {
		return encodeMAPErrorMember(UnknownSubscriber, value.UnknownSubscriber, UnknownSubscriberParamCodec(), opts...)
	}
	return EncodedError{}, fmt.Errorf("%w: no selected failureReport error", ber.ErrInvalidBinding)
}

// ForwardAccessSignallingErrors selects exactly the formal ERRORS set of MAP-MobileServiceOperations.forwardAccessSignalling.
type ForwardAccessSignallingErrors struct {
}

func infoForwardAccessSignallingOperation() OperationInfo {
	return OperationInfo{Name: "forwardAccessSignalling", Code: ForwardAccessSignalling, Argument: &TypeRef{ModuleOID: "0.4.0.0.1.3.11.22", ASN1Name: "ForwardAccessSignalling-Arg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "ForwardAccessSignallingArg"}, Result: nil, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: false, Source: sourceInfo4("forwardAccessSignalling", "17.6.1"), Errors: []ErrorInfo{}, Linked: []MAPOperationCode{}}
}

// ForwardAccessSignallingOperation binds the formal object in TS 29.002 V19.1.0 §17.6.1 (X.880 §§8.2–8.3).
func ForwardAccessSignallingOperation() Operation[ForwardAccessSignallingArg, NoParameter, ForwardAccessSignallingErrors] {
	return Operation[ForwardAccessSignallingArg, NoParameter, ForwardAccessSignallingErrors]{operationBinding[ForwardAccessSignallingArg, NoParameter, ForwardAccessSignallingErrors, OperationInfo, MAPOperationCode, EncodedError]{code: ForwardAccessSignalling, info: infoForwardAccessSignallingOperation, argument: ForwardAccessSignallingArgCodec(), result: ValueCodec[NoParameter]{}, decode: decodeForwardAccessSignallingError, encode: encodeForwardAccessSignallingError}}
}
func decodeForwardAccessSignallingError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (ForwardAccessSignallingErrors, error) {
	switch code {
	default:
		return ForwardAccessSignallingErrors{}, fmt.Errorf("%w: error code %d is not in forwardAccessSignalling ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeForwardAccessSignallingError(value ForwardAccessSignallingErrors, opts ...ber.EncodeOption) (EncodedError, error) {
	return EncodedError{}, fmt.Errorf("%w: no selected forwardAccessSignalling error", ber.ErrInvalidBinding)
}

// ForwardCheckSSIndicationErrors selects exactly the formal ERRORS set of MAP-MobileServiceOperations.forwardCheckSS-Indication.
type ForwardCheckSSIndicationErrors struct {
}

func infoForwardCheckSSIndicationOperation() OperationInfo {
	return OperationInfo{Name: "forwardCheckSS-Indication", Code: ForwardCheckSSIndication, Argument: nil, Result: nil, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: false, Source: sourceInfo4("forwardCheckSS-Indication", "17.6.1"), Errors: []ErrorInfo{}, Linked: []MAPOperationCode{}}
}

// ForwardCheckSSIndicationOperation binds the formal object in TS 29.002 V19.1.0 §17.6.1 (X.880 §§8.2–8.3).
func ForwardCheckSSIndicationOperation() Operation[NoParameter, NoParameter, ForwardCheckSSIndicationErrors] {
	return Operation[NoParameter, NoParameter, ForwardCheckSSIndicationErrors]{operationBinding[NoParameter, NoParameter, ForwardCheckSSIndicationErrors, OperationInfo, MAPOperationCode, EncodedError]{code: ForwardCheckSSIndication, info: infoForwardCheckSSIndicationOperation, argument: ValueCodec[NoParameter]{}, result: ValueCodec[NoParameter]{}, decode: decodeForwardCheckSSIndicationError, encode: encodeForwardCheckSSIndicationError}}
}
func decodeForwardCheckSSIndicationError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (ForwardCheckSSIndicationErrors, error) {
	switch code {
	default:
		return ForwardCheckSSIndicationErrors{}, fmt.Errorf("%w: error code %d is not in forwardCheckSS-Indication ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeForwardCheckSSIndicationError(value ForwardCheckSSIndicationErrors, opts ...ber.EncodeOption) (EncodedError, error) {
	return EncodedError{}, fmt.Errorf("%w: no selected forwardCheckSS-Indication error", ber.ErrInvalidBinding)
}

// ForwardGroupCallSignallingErrors selects exactly the formal ERRORS set of MAP-Group-Call-Operations.forwardGroupCallSignalling.
type ForwardGroupCallSignallingErrors struct {
}

func infoForwardGroupCallSignallingOperation() OperationInfo {
	return OperationInfo{Name: "forwardGroupCallSignalling", Code: ForwardGroupCallSignalling, Argument: &TypeRef{ModuleOID: "0.4.0.0.1.3.23.22", ASN1Name: "ForwardGroupCallSignallingArg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "ForwardGroupCallSignallingArg"}, Result: nil, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: false, Source: sourceInfo5("forwardGroupCallSignalling", "17.6.7"), Errors: []ErrorInfo{}, Linked: []MAPOperationCode{}}
}

// ForwardGroupCallSignallingOperation binds the formal object in TS 29.002 V19.1.0 §17.6.7 (X.880 §§8.2–8.3).
func ForwardGroupCallSignallingOperation() Operation[ForwardGroupCallSignallingArg, NoParameter, ForwardGroupCallSignallingErrors] {
	return Operation[ForwardGroupCallSignallingArg, NoParameter, ForwardGroupCallSignallingErrors]{operationBinding[ForwardGroupCallSignallingArg, NoParameter, ForwardGroupCallSignallingErrors, OperationInfo, MAPOperationCode, EncodedError]{code: ForwardGroupCallSignalling, info: infoForwardGroupCallSignallingOperation, argument: ForwardGroupCallSignallingArgCodec(), result: ValueCodec[NoParameter]{}, decode: decodeForwardGroupCallSignallingError, encode: encodeForwardGroupCallSignallingError}}
}
func decodeForwardGroupCallSignallingError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (ForwardGroupCallSignallingErrors, error) {
	switch code {
	default:
		return ForwardGroupCallSignallingErrors{}, fmt.Errorf("%w: error code %d is not in forwardGroupCallSignalling ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeForwardGroupCallSignallingError(value ForwardGroupCallSignallingErrors, opts ...ber.EncodeOption) (EncodedError, error) {
	return EncodedError{}, fmt.Errorf("%w: no selected forwardGroupCallSignalling error", ber.ErrInvalidBinding)
}

// GetPasswordErrors selects exactly the formal ERRORS set of MAP-SupplementaryServiceOperations.getPassword.
type GetPasswordErrors struct {
}

func infoGetPasswordOperation() OperationInfo {
	return OperationInfo{Name: "getPassword", Code: GetPassword, Argument: &TypeRef{ModuleOID: "0.4.0.0.1.3.14.22", ASN1Name: "GuidanceInfo", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "GuidanceInfo"}, Result: &TypeRef{ModuleOID: "0.4.0.0.1.3.14.22", ASN1Name: "Password", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "Password"}, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: false, Source: sourceInfo1("getPassword", "17.6.4"), Errors: []ErrorInfo{}, Linked: []MAPOperationCode{}}
}

// GetPasswordOperation binds the formal object in TS 29.002 V19.1.0 §17.6.4 (X.880 §§8.2–8.3).
func GetPasswordOperation() Operation[BERValue[GuidanceInfo], BERValue[Password], GetPasswordErrors] {
	return Operation[BERValue[GuidanceInfo], BERValue[Password], GetPasswordErrors]{operationBinding[BERValue[GuidanceInfo], BERValue[Password], GetPasswordErrors, OperationInfo, MAPOperationCode, EncodedError]{code: GetPassword, info: infoGetPasswordOperation, argument: GuidanceInfoCodec(), result: PasswordCodec(), decode: decodeGetPasswordError, encode: encodeGetPasswordError}}
}
func decodeGetPasswordError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (GetPasswordErrors, error) {
	switch code {
	default:
		return GetPasswordErrors{}, fmt.Errorf("%w: error code %d is not in getPassword ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeGetPasswordError(value GetPasswordErrors, opts ...ber.EncodeOption) (EncodedError, error) {
	return EncodedError{}, fmt.Errorf("%w: no selected getPassword error", ber.ErrInvalidBinding)
}

// InformServiceCentreErrors selects exactly the formal ERRORS set of MAP-ShortMessageServiceOperations.informServiceCentre.
type InformServiceCentreErrors struct {
}

func infoInformServiceCentreOperation() OperationInfo {
	return OperationInfo{Name: "informServiceCentre", Code: InformServiceCentre, Argument: &TypeRef{ModuleOID: "0.4.0.0.1.3.16.22", ASN1Name: "InformServiceCentreArg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "InformServiceCentreArg"}, Result: nil, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: false, Source: sourceInfo3("informServiceCentre", "17.6.5"), Errors: []ErrorInfo{}, Linked: []MAPOperationCode{}}
}

// InformServiceCentreOperation binds the formal object in TS 29.002 V19.1.0 §17.6.5 (X.880 §§8.2–8.3).
func InformServiceCentreOperation() Operation[InformServiceCentreArg, NoParameter, InformServiceCentreErrors] {
	return Operation[InformServiceCentreArg, NoParameter, InformServiceCentreErrors]{operationBinding[InformServiceCentreArg, NoParameter, InformServiceCentreErrors, OperationInfo, MAPOperationCode, EncodedError]{code: InformServiceCentre, info: infoInformServiceCentreOperation, argument: InformServiceCentreArgCodec(), result: ValueCodec[NoParameter]{}, decode: decodeInformServiceCentreError, encode: encodeInformServiceCentreError}}
}
func decodeInformServiceCentreError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (InformServiceCentreErrors, error) {
	switch code {
	default:
		return InformServiceCentreErrors{}, fmt.Errorf("%w: error code %d is not in informServiceCentre ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeInformServiceCentreError(value InformServiceCentreErrors, opts ...ber.EncodeOption) (EncodedError, error) {
	return EncodedError{}, fmt.Errorf("%w: no selected informServiceCentre error", ber.ErrInvalidBinding)
}

// InsertSubscriberDataErrors selects exactly the formal ERRORS set of MAP-MobileServiceOperations.insertSubscriberData.
type InsertSubscriberDataErrors struct {
	DataMissing            *ErrorValue[DataMissingParam]
	UnexpectedDataValue    *ErrorValue[UnexpectedDataParam]
	UnidentifiedSubscriber *ErrorValue[UnidentifiedSubParam]
}

func infoInsertSubscriberDataOperation() OperationInfo {
	return OperationInfo{Name: "insertSubscriberData", Code: InsertSubscriberData, Argument: &TypeRef{ModuleOID: "0.4.0.0.1.3.11.22", ASN1Name: "InsertSubscriberDataArg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "InsertSubscriberDataArg"}, Result: &TypeRef{ModuleOID: "0.4.0.0.1.3.11.22", ASN1Name: "InsertSubscriberDataRes", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "InsertSubscriberDataRes"}, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: false, Source: sourceInfo4("insertSubscriberData", "17.6.1"), Errors: []ErrorInfo{infoDataMissingError(), infoUnexpectedDataValueError(), infoUnidentifiedSubscriberError()}, Linked: []MAPOperationCode{}}
}

// InsertSubscriberDataOperation binds the formal object in TS 29.002 V19.1.0 §17.6.1 (X.880 §§8.2–8.3).
func InsertSubscriberDataOperation() Operation[InsertSubscriberDataArg, InsertSubscriberDataRes, InsertSubscriberDataErrors] {
	return Operation[InsertSubscriberDataArg, InsertSubscriberDataRes, InsertSubscriberDataErrors]{operationBinding[InsertSubscriberDataArg, InsertSubscriberDataRes, InsertSubscriberDataErrors, OperationInfo, MAPOperationCode, EncodedError]{code: InsertSubscriberData, info: infoInsertSubscriberDataOperation, argument: InsertSubscriberDataArgCodec(), result: InsertSubscriberDataResCodec(), decode: decodeInsertSubscriberDataError, encode: encodeInsertSubscriberDataError}}
}
func decodeInsertSubscriberDataError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (InsertSubscriberDataErrors, error) {
	switch code {
	case 35:
		p, err := decodeErrorParameter(data, present, DataMissingParamCodec(), opts...)
		if err != nil {
			return InsertSubscriberDataErrors{}, err
		}
		return InsertSubscriberDataErrors{DataMissing: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return InsertSubscriberDataErrors{}, err
		}
		return InsertSubscriberDataErrors{UnexpectedDataValue: p}, nil
	case 5:
		p, err := decodeErrorParameter(data, present, UnidentifiedSubParamCodec(), opts...)
		if err != nil {
			return InsertSubscriberDataErrors{}, err
		}
		return InsertSubscriberDataErrors{UnidentifiedSubscriber: p}, nil
	default:
		return InsertSubscriberDataErrors{}, fmt.Errorf("%w: error code %d is not in insertSubscriberData ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeInsertSubscriberDataError(value InsertSubscriberDataErrors, opts ...ber.EncodeOption) (EncodedError, error) {
	selected := 0
	if value.DataMissing != nil {
		selected++
	}
	if value.UnexpectedDataValue != nil {
		selected++
	}
	if value.UnidentifiedSubscriber != nil {
		selected++
	}
	if selected != 1 {
		return EncodedError{}, fmt.Errorf("%w: exactly one insertSubscriberData error arm is required", ber.ErrInvalidBinding)
	}
	if value.DataMissing != nil {
		return encodeMAPErrorMember(DataMissing, value.DataMissing, DataMissingParamCodec(), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	if value.UnidentifiedSubscriber != nil {
		return encodeMAPErrorMember(UnidentifiedSubscriber, value.UnidentifiedSubscriber, UnidentifiedSubParamCodec(), opts...)
	}
	return EncodedError{}, fmt.Errorf("%w: no selected insertSubscriberData error", ber.ErrInvalidBinding)
}

// InterrogateSSErrors selects exactly the formal ERRORS set of MAP-SupplementaryServiceOperations.interrogateSS.
type InterrogateSSErrors struct {
	SystemFailure               *ErrorValue[SystemFailureParam]
	DataMissing                 *ErrorValue[DataMissingParam]
	UnexpectedDataValue         *ErrorValue[UnexpectedDataParam]
	BearerServiceNotProvisioned *ErrorValue[BearerServNotProvParam]
	TeleserviceNotProvisioned   *ErrorValue[TeleservNotProvParam]
	CallBarred                  *ErrorValue[CallBarredParam]
	IllegalSSOperation          *ErrorValue[IllegalSSOperationParam]
	SsNotAvailable              *ErrorValue[SSNotAvailableParam]
}

func infoInterrogateSSOperation() OperationInfo {
	return OperationInfo{Name: "interrogateSS", Code: InterrogateSS, Argument: &TypeRef{ModuleOID: "0.4.0.0.1.3.14.22", ASN1Name: "SS-ForBS-Code", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "SSForBSCode"}, Result: &TypeRef{ModuleOID: "0.4.0.0.1.3.14.22", ASN1Name: "InterrogateSS-Res", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "InterrogateSSRes"}, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: false, Source: sourceInfo1("interrogateSS", "17.6.4"), Errors: []ErrorInfo{infoSystemFailureError(), infoDataMissingError(), infoUnexpectedDataValueError(), infoBearerServiceNotProvisionedError(), infoTeleserviceNotProvisionedError(), infoCallBarredError(), infoIllegalSSOperationError(), infoSsNotAvailableError()}, Linked: []MAPOperationCode{}}
}

// InterrogateSSOperation binds the formal object in TS 29.002 V19.1.0 §17.6.4 (X.880 §§8.2–8.3).
func InterrogateSSOperation() Operation[SSForBSCode, InterrogateSSRes, InterrogateSSErrors] {
	return Operation[SSForBSCode, InterrogateSSRes, InterrogateSSErrors]{operationBinding[SSForBSCode, InterrogateSSRes, InterrogateSSErrors, OperationInfo, MAPOperationCode, EncodedError]{code: InterrogateSS, info: infoInterrogateSSOperation, argument: SSForBSCodeCodec(), result: InterrogateSSResCodec(), decode: decodeInterrogateSSError, encode: encodeInterrogateSSError}}
}
func decodeInterrogateSSError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (InterrogateSSErrors, error) {
	switch code {
	case 34:
		p, err := decodeErrorParameter(data, present, SystemFailureParamCodec(), opts...)
		if err != nil {
			return InterrogateSSErrors{}, err
		}
		return InterrogateSSErrors{SystemFailure: p}, nil
	case 35:
		p, err := decodeErrorParameter(data, present, DataMissingParamCodec(), opts...)
		if err != nil {
			return InterrogateSSErrors{}, err
		}
		return InterrogateSSErrors{DataMissing: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return InterrogateSSErrors{}, err
		}
		return InterrogateSSErrors{UnexpectedDataValue: p}, nil
	case 10:
		p, err := decodeErrorParameter(data, present, BearerServNotProvParamCodec(), opts...)
		if err != nil {
			return InterrogateSSErrors{}, err
		}
		return InterrogateSSErrors{BearerServiceNotProvisioned: p}, nil
	case 11:
		p, err := decodeErrorParameter(data, present, TeleservNotProvParamCodec(), opts...)
		if err != nil {
			return InterrogateSSErrors{}, err
		}
		return InterrogateSSErrors{TeleserviceNotProvisioned: p}, nil
	case 13:
		p, err := decodeErrorParameter(data, present, CallBarredParamCodec(), opts...)
		if err != nil {
			return InterrogateSSErrors{}, err
		}
		return InterrogateSSErrors{CallBarred: p}, nil
	case 16:
		p, err := decodeErrorParameter(data, present, IllegalSSOperationParamCodec(), opts...)
		if err != nil {
			return InterrogateSSErrors{}, err
		}
		return InterrogateSSErrors{IllegalSSOperation: p}, nil
	case 18:
		p, err := decodeErrorParameter(data, present, SSNotAvailableParamCodec(), opts...)
		if err != nil {
			return InterrogateSSErrors{}, err
		}
		return InterrogateSSErrors{SsNotAvailable: p}, nil
	default:
		return InterrogateSSErrors{}, fmt.Errorf("%w: error code %d is not in interrogateSS ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeInterrogateSSError(value InterrogateSSErrors, opts ...ber.EncodeOption) (EncodedError, error) {
	selected := 0
	if value.SystemFailure != nil {
		selected++
	}
	if value.DataMissing != nil {
		selected++
	}
	if value.UnexpectedDataValue != nil {
		selected++
	}
	if value.BearerServiceNotProvisioned != nil {
		selected++
	}
	if value.TeleserviceNotProvisioned != nil {
		selected++
	}
	if value.CallBarred != nil {
		selected++
	}
	if value.IllegalSSOperation != nil {
		selected++
	}
	if value.SsNotAvailable != nil {
		selected++
	}
	if selected != 1 {
		return EncodedError{}, fmt.Errorf("%w: exactly one interrogateSS error arm is required", ber.ErrInvalidBinding)
	}
	if value.SystemFailure != nil {
		return encodeMAPErrorMember(SystemFailure, value.SystemFailure, SystemFailureParamCodec(), opts...)
	}
	if value.DataMissing != nil {
		return encodeMAPErrorMember(DataMissing, value.DataMissing, DataMissingParamCodec(), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	if value.BearerServiceNotProvisioned != nil {
		return encodeMAPErrorMember(BearerServiceNotProvisioned, value.BearerServiceNotProvisioned, BearerServNotProvParamCodec(), opts...)
	}
	if value.TeleserviceNotProvisioned != nil {
		return encodeMAPErrorMember(TeleserviceNotProvisioned, value.TeleserviceNotProvisioned, TeleservNotProvParamCodec(), opts...)
	}
	if value.CallBarred != nil {
		return encodeMAPErrorMember(CallBarred, value.CallBarred, CallBarredParamCodec(), opts...)
	}
	if value.IllegalSSOperation != nil {
		return encodeMAPErrorMember(IllegalSSOperation, value.IllegalSSOperation, IllegalSSOperationParamCodec(), opts...)
	}
	if value.SsNotAvailable != nil {
		return encodeMAPErrorMember(SsNotAvailable, value.SsNotAvailable, SSNotAvailableParamCodec(), opts...)
	}
	return EncodedError{}, fmt.Errorf("%w: no selected interrogateSS error", ber.ErrInvalidBinding)
}

// IstAlertErrors selects exactly the formal ERRORS set of MAP-CallHandlingOperations.ist-Alert.
type IstAlertErrors struct {
	UnexpectedDataValue  *ErrorValue[UnexpectedDataParam]
	ResourceLimitation   *ErrorValue[ResourceLimitationParam]
	UnknownSubscriber    *ErrorValue[UnknownSubscriberParam]
	SystemFailure        *ErrorValue[SystemFailureParam]
	FacilityNotSupported *ErrorValue[FacilityNotSupParam]
}

func infoIstAlertOperation() OperationInfo {
	return OperationInfo{Name: "ist-Alert", Code: IstAlert, Argument: &TypeRef{ModuleOID: "0.4.0.0.1.3.13.22", ASN1Name: "IST-AlertArg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "ISTAlertArg"}, Result: &TypeRef{ModuleOID: "0.4.0.0.1.3.13.22", ASN1Name: "IST-AlertRes", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "ISTAlertRes"}, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: false, Source: sourceInfo6("ist-Alert", "17.6.3"), Errors: []ErrorInfo{infoUnexpectedDataValueError(), infoResourceLimitationError(), infoUnknownSubscriberError(), infoSystemFailureError(), infoFacilityNotSupportedError()}, Linked: []MAPOperationCode{}}
}

// IstAlertOperation binds the formal object in TS 29.002 V19.1.0 §17.6.3 (X.880 §§8.2–8.3).
func IstAlertOperation() Operation[ISTAlertArg, ISTAlertRes, IstAlertErrors] {
	return Operation[ISTAlertArg, ISTAlertRes, IstAlertErrors]{operationBinding[ISTAlertArg, ISTAlertRes, IstAlertErrors, OperationInfo, MAPOperationCode, EncodedError]{code: IstAlert, info: infoIstAlertOperation, argument: ISTAlertArgCodec(), result: ISTAlertResCodec(), decode: decodeIstAlertError, encode: encodeIstAlertError}}
}
func decodeIstAlertError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (IstAlertErrors, error) {
	switch code {
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return IstAlertErrors{}, err
		}
		return IstAlertErrors{UnexpectedDataValue: p}, nil
	case 51:
		p, err := decodeErrorParameter(data, present, ResourceLimitationParamCodec(), opts...)
		if err != nil {
			return IstAlertErrors{}, err
		}
		return IstAlertErrors{ResourceLimitation: p}, nil
	case 1:
		p, err := decodeErrorParameter(data, present, UnknownSubscriberParamCodec(), opts...)
		if err != nil {
			return IstAlertErrors{}, err
		}
		return IstAlertErrors{UnknownSubscriber: p}, nil
	case 34:
		p, err := decodeErrorParameter(data, present, SystemFailureParamCodec(), opts...)
		if err != nil {
			return IstAlertErrors{}, err
		}
		return IstAlertErrors{SystemFailure: p}, nil
	case 21:
		p, err := decodeErrorParameter(data, present, FacilityNotSupParamCodec(), opts...)
		if err != nil {
			return IstAlertErrors{}, err
		}
		return IstAlertErrors{FacilityNotSupported: p}, nil
	default:
		return IstAlertErrors{}, fmt.Errorf("%w: error code %d is not in ist-Alert ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeIstAlertError(value IstAlertErrors, opts ...ber.EncodeOption) (EncodedError, error) {
	selected := 0
	if value.UnexpectedDataValue != nil {
		selected++
	}
	if value.ResourceLimitation != nil {
		selected++
	}
	if value.UnknownSubscriber != nil {
		selected++
	}
	if value.SystemFailure != nil {
		selected++
	}
	if value.FacilityNotSupported != nil {
		selected++
	}
	if selected != 1 {
		return EncodedError{}, fmt.Errorf("%w: exactly one ist-Alert error arm is required", ber.ErrInvalidBinding)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	if value.ResourceLimitation != nil {
		return encodeMAPErrorMember(ResourceLimitation, value.ResourceLimitation, ResourceLimitationParamCodec(), opts...)
	}
	if value.UnknownSubscriber != nil {
		return encodeMAPErrorMember(UnknownSubscriber, value.UnknownSubscriber, UnknownSubscriberParamCodec(), opts...)
	}
	if value.SystemFailure != nil {
		return encodeMAPErrorMember(SystemFailure, value.SystemFailure, SystemFailureParamCodec(), opts...)
	}
	if value.FacilityNotSupported != nil {
		return encodeMAPErrorMember(FacilityNotSupported, value.FacilityNotSupported, FacilityNotSupParamCodec(), opts...)
	}
	return EncodedError{}, fmt.Errorf("%w: no selected ist-Alert error", ber.ErrInvalidBinding)
}

// IstCommandErrors selects exactly the formal ERRORS set of MAP-CallHandlingOperations.ist-Command.
type IstCommandErrors struct {
	UnexpectedDataValue  *ErrorValue[UnexpectedDataParam]
	ResourceLimitation   *ErrorValue[ResourceLimitationParam]
	UnknownSubscriber    *ErrorValue[UnknownSubscriberParam]
	SystemFailure        *ErrorValue[SystemFailureParam]
	FacilityNotSupported *ErrorValue[FacilityNotSupParam]
}

func infoIstCommandOperation() OperationInfo {
	return OperationInfo{Name: "ist-Command", Code: IstCommand, Argument: &TypeRef{ModuleOID: "0.4.0.0.1.3.13.22", ASN1Name: "IST-CommandArg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "ISTCommandArg"}, Result: &TypeRef{ModuleOID: "0.4.0.0.1.3.13.22", ASN1Name: "IST-CommandRes", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "ISTCommandRes"}, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: false, Source: sourceInfo6("ist-Command", "17.6.3"), Errors: []ErrorInfo{infoUnexpectedDataValueError(), infoResourceLimitationError(), infoUnknownSubscriberError(), infoSystemFailureError(), infoFacilityNotSupportedError()}, Linked: []MAPOperationCode{}}
}

// IstCommandOperation binds the formal object in TS 29.002 V19.1.0 §17.6.3 (X.880 §§8.2–8.3).
func IstCommandOperation() Operation[ISTCommandArg, ISTCommandRes, IstCommandErrors] {
	return Operation[ISTCommandArg, ISTCommandRes, IstCommandErrors]{operationBinding[ISTCommandArg, ISTCommandRes, IstCommandErrors, OperationInfo, MAPOperationCode, EncodedError]{code: IstCommand, info: infoIstCommandOperation, argument: ISTCommandArgCodec(), result: ISTCommandResCodec(), decode: decodeIstCommandError, encode: encodeIstCommandError}}
}
func decodeIstCommandError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (IstCommandErrors, error) {
	switch code {
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return IstCommandErrors{}, err
		}
		return IstCommandErrors{UnexpectedDataValue: p}, nil
	case 51:
		p, err := decodeErrorParameter(data, present, ResourceLimitationParamCodec(), opts...)
		if err != nil {
			return IstCommandErrors{}, err
		}
		return IstCommandErrors{ResourceLimitation: p}, nil
	case 1:
		p, err := decodeErrorParameter(data, present, UnknownSubscriberParamCodec(), opts...)
		if err != nil {
			return IstCommandErrors{}, err
		}
		return IstCommandErrors{UnknownSubscriber: p}, nil
	case 34:
		p, err := decodeErrorParameter(data, present, SystemFailureParamCodec(), opts...)
		if err != nil {
			return IstCommandErrors{}, err
		}
		return IstCommandErrors{SystemFailure: p}, nil
	case 21:
		p, err := decodeErrorParameter(data, present, FacilityNotSupParamCodec(), opts...)
		if err != nil {
			return IstCommandErrors{}, err
		}
		return IstCommandErrors{FacilityNotSupported: p}, nil
	default:
		return IstCommandErrors{}, fmt.Errorf("%w: error code %d is not in ist-Command ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeIstCommandError(value IstCommandErrors, opts ...ber.EncodeOption) (EncodedError, error) {
	selected := 0
	if value.UnexpectedDataValue != nil {
		selected++
	}
	if value.ResourceLimitation != nil {
		selected++
	}
	if value.UnknownSubscriber != nil {
		selected++
	}
	if value.SystemFailure != nil {
		selected++
	}
	if value.FacilityNotSupported != nil {
		selected++
	}
	if selected != 1 {
		return EncodedError{}, fmt.Errorf("%w: exactly one ist-Command error arm is required", ber.ErrInvalidBinding)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	if value.ResourceLimitation != nil {
		return encodeMAPErrorMember(ResourceLimitation, value.ResourceLimitation, ResourceLimitationParamCodec(), opts...)
	}
	if value.UnknownSubscriber != nil {
		return encodeMAPErrorMember(UnknownSubscriber, value.UnknownSubscriber, UnknownSubscriberParamCodec(), opts...)
	}
	if value.SystemFailure != nil {
		return encodeMAPErrorMember(SystemFailure, value.SystemFailure, SystemFailureParamCodec(), opts...)
	}
	if value.FacilityNotSupported != nil {
		return encodeMAPErrorMember(FacilityNotSupported, value.FacilityNotSupported, FacilityNotSupParamCodec(), opts...)
	}
	return EncodedError{}, fmt.Errorf("%w: no selected ist-Command error", ber.ErrInvalidBinding)
}

// MoForwardSMErrors selects exactly the formal ERRORS set of MAP-ShortMessageServiceOperations.mo-ForwardSM.
type MoForwardSMErrors struct {
	SystemFailure        *ErrorValue[SystemFailureParam]
	UnexpectedDataValue  *ErrorValue[UnexpectedDataParam]
	FacilityNotSupported *ErrorValue[FacilityNotSupParam]
	SmDeliveryFailure    *ErrorValue[SMDeliveryFailureCause]
}

func infoMoForwardSMOperation() OperationInfo {
	return OperationInfo{Name: "mo-ForwardSM", Code: MoForwardSM, Argument: &TypeRef{ModuleOID: "0.4.0.0.1.3.16.22", ASN1Name: "MO-ForwardSM-Arg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "MOForwardSMArg"}, Result: &TypeRef{ModuleOID: "0.4.0.0.1.3.16.22", ASN1Name: "MO-ForwardSM-Res", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "MOForwardSMRes"}, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: false, Source: sourceInfo3("mo-ForwardSM", "17.6.5"), Errors: []ErrorInfo{infoSystemFailureError(), infoUnexpectedDataValueError(), infoFacilityNotSupportedError(), infoSmDeliveryFailureError()}, Linked: []MAPOperationCode{}}
}

// MoForwardSMOperation binds the formal object in TS 29.002 V19.1.0 §17.6.5 (X.880 §§8.2–8.3).
func MoForwardSMOperation() Operation[MOForwardSMArg, MOForwardSMRes, MoForwardSMErrors] {
	return Operation[MOForwardSMArg, MOForwardSMRes, MoForwardSMErrors]{operationBinding[MOForwardSMArg, MOForwardSMRes, MoForwardSMErrors, OperationInfo, MAPOperationCode, EncodedError]{code: MoForwardSM, info: infoMoForwardSMOperation, argument: MOForwardSMArgCodec(), result: MOForwardSMResCodec(), decode: decodeMoForwardSMError, encode: encodeMoForwardSMError}}
}
func decodeMoForwardSMError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (MoForwardSMErrors, error) {
	switch code {
	case 34:
		p, err := decodeErrorParameter(data, present, SystemFailureParamCodec(), opts...)
		if err != nil {
			return MoForwardSMErrors{}, err
		}
		return MoForwardSMErrors{SystemFailure: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return MoForwardSMErrors{}, err
		}
		return MoForwardSMErrors{UnexpectedDataValue: p}, nil
	case 21:
		p, err := decodeErrorParameter(data, present, FacilityNotSupParamCodec(), opts...)
		if err != nil {
			return MoForwardSMErrors{}, err
		}
		return MoForwardSMErrors{FacilityNotSupported: p}, nil
	case 32:
		p, err := decodeErrorParameter(data, present, SMDeliveryFailureCauseCodec(), opts...)
		if err != nil {
			return MoForwardSMErrors{}, err
		}
		return MoForwardSMErrors{SmDeliveryFailure: p}, nil
	default:
		return MoForwardSMErrors{}, fmt.Errorf("%w: error code %d is not in mo-ForwardSM ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeMoForwardSMError(value MoForwardSMErrors, opts ...ber.EncodeOption) (EncodedError, error) {
	selected := 0
	if value.SystemFailure != nil {
		selected++
	}
	if value.UnexpectedDataValue != nil {
		selected++
	}
	if value.FacilityNotSupported != nil {
		selected++
	}
	if value.SmDeliveryFailure != nil {
		selected++
	}
	if selected != 1 {
		return EncodedError{}, fmt.Errorf("%w: exactly one mo-ForwardSM error arm is required", ber.ErrInvalidBinding)
	}
	if value.SystemFailure != nil {
		return encodeMAPErrorMember(SystemFailure, value.SystemFailure, SystemFailureParamCodec(), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	if value.FacilityNotSupported != nil {
		return encodeMAPErrorMember(FacilityNotSupported, value.FacilityNotSupported, FacilityNotSupParamCodec(), opts...)
	}
	if value.SmDeliveryFailure != nil {
		return encodeMAPErrorMember(SmDeliveryFailure, value.SmDeliveryFailure, SMDeliveryFailureCauseCodec(), opts...)
	}
	return EncodedError{}, fmt.Errorf("%w: no selected mo-ForwardSM error", ber.ErrInvalidBinding)
}

// MtForwardSMErrors selects exactly the formal ERRORS set of MAP-ShortMessageServiceOperations.mt-ForwardSM.
type MtForwardSMErrors struct {
	SystemFailure          *ErrorValue[SystemFailureParam]
	DataMissing            *ErrorValue[DataMissingParam]
	UnexpectedDataValue    *ErrorValue[UnexpectedDataParam]
	FacilityNotSupported   *ErrorValue[FacilityNotSupParam]
	UnidentifiedSubscriber *ErrorValue[UnidentifiedSubParam]
	IllegalSubscriber      *ErrorValue[IllegalSubscriberParam]
	IllegalEquipment       *ErrorValue[IllegalEquipmentParam]
	SubscriberBusyForMTSMS *ErrorValue[SubBusyForMTSMSParam]
	SmDeliveryFailure      *ErrorValue[SMDeliveryFailureCause]
	AbsentSubscriberSM     *ErrorValue[AbsentSubscriberSMParam]
}

func infoMtForwardSMOperation() OperationInfo {
	return OperationInfo{Name: "mt-ForwardSM", Code: MtForwardSM, Argument: &TypeRef{ModuleOID: "0.4.0.0.1.3.16.22", ASN1Name: "MT-ForwardSM-Arg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "MTForwardSMArg"}, Result: &TypeRef{ModuleOID: "0.4.0.0.1.3.16.22", ASN1Name: "MT-ForwardSM-Res", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "MTForwardSMRes"}, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: false, Source: sourceInfo3("mt-ForwardSM", "17.6.5"), Errors: []ErrorInfo{infoSystemFailureError(), infoDataMissingError(), infoUnexpectedDataValueError(), infoFacilityNotSupportedError(), infoUnidentifiedSubscriberError(), infoIllegalSubscriberError(), infoIllegalEquipmentError(), infoSubscriberBusyForMTSMSError(), infoSmDeliveryFailureError(), infoAbsentSubscriberSMError()}, Linked: []MAPOperationCode{}}
}

// MtForwardSMOperation binds the formal object in TS 29.002 V19.1.0 §17.6.5 (X.880 §§8.2–8.3).
func MtForwardSMOperation() Operation[MTForwardSMArg, MTForwardSMRes, MtForwardSMErrors] {
	return Operation[MTForwardSMArg, MTForwardSMRes, MtForwardSMErrors]{operationBinding[MTForwardSMArg, MTForwardSMRes, MtForwardSMErrors, OperationInfo, MAPOperationCode, EncodedError]{code: MtForwardSM, info: infoMtForwardSMOperation, argument: MTForwardSMArgCodec(), result: MTForwardSMResCodec(), decode: decodeMtForwardSMError, encode: encodeMtForwardSMError}}
}
func decodeMtForwardSMError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (MtForwardSMErrors, error) {
	switch code {
	case 34:
		p, err := decodeErrorParameter(data, present, SystemFailureParamCodec(), opts...)
		if err != nil {
			return MtForwardSMErrors{}, err
		}
		return MtForwardSMErrors{SystemFailure: p}, nil
	case 35:
		p, err := decodeErrorParameter(data, present, DataMissingParamCodec(), opts...)
		if err != nil {
			return MtForwardSMErrors{}, err
		}
		return MtForwardSMErrors{DataMissing: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return MtForwardSMErrors{}, err
		}
		return MtForwardSMErrors{UnexpectedDataValue: p}, nil
	case 21:
		p, err := decodeErrorParameter(data, present, FacilityNotSupParamCodec(), opts...)
		if err != nil {
			return MtForwardSMErrors{}, err
		}
		return MtForwardSMErrors{FacilityNotSupported: p}, nil
	case 5:
		p, err := decodeErrorParameter(data, present, UnidentifiedSubParamCodec(), opts...)
		if err != nil {
			return MtForwardSMErrors{}, err
		}
		return MtForwardSMErrors{UnidentifiedSubscriber: p}, nil
	case 9:
		p, err := decodeErrorParameter(data, present, IllegalSubscriberParamCodec(), opts...)
		if err != nil {
			return MtForwardSMErrors{}, err
		}
		return MtForwardSMErrors{IllegalSubscriber: p}, nil
	case 12:
		p, err := decodeErrorParameter(data, present, IllegalEquipmentParamCodec(), opts...)
		if err != nil {
			return MtForwardSMErrors{}, err
		}
		return MtForwardSMErrors{IllegalEquipment: p}, nil
	case 31:
		p, err := decodeErrorParameter(data, present, SubBusyForMTSMSParamCodec(), opts...)
		if err != nil {
			return MtForwardSMErrors{}, err
		}
		return MtForwardSMErrors{SubscriberBusyForMTSMS: p}, nil
	case 32:
		p, err := decodeErrorParameter(data, present, SMDeliveryFailureCauseCodec(), opts...)
		if err != nil {
			return MtForwardSMErrors{}, err
		}
		return MtForwardSMErrors{SmDeliveryFailure: p}, nil
	case 6:
		p, err := decodeErrorParameter(data, present, AbsentSubscriberSMParamCodec(), opts...)
		if err != nil {
			return MtForwardSMErrors{}, err
		}
		return MtForwardSMErrors{AbsentSubscriberSM: p}, nil
	default:
		return MtForwardSMErrors{}, fmt.Errorf("%w: error code %d is not in mt-ForwardSM ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeMtForwardSMError(value MtForwardSMErrors, opts ...ber.EncodeOption) (EncodedError, error) {
	selected := 0
	if value.SystemFailure != nil {
		selected++
	}
	if value.DataMissing != nil {
		selected++
	}
	if value.UnexpectedDataValue != nil {
		selected++
	}
	if value.FacilityNotSupported != nil {
		selected++
	}
	if value.UnidentifiedSubscriber != nil {
		selected++
	}
	if value.IllegalSubscriber != nil {
		selected++
	}
	if value.IllegalEquipment != nil {
		selected++
	}
	if value.SubscriberBusyForMTSMS != nil {
		selected++
	}
	if value.SmDeliveryFailure != nil {
		selected++
	}
	if value.AbsentSubscriberSM != nil {
		selected++
	}
	if selected != 1 {
		return EncodedError{}, fmt.Errorf("%w: exactly one mt-ForwardSM error arm is required", ber.ErrInvalidBinding)
	}
	if value.SystemFailure != nil {
		return encodeMAPErrorMember(SystemFailure, value.SystemFailure, SystemFailureParamCodec(), opts...)
	}
	if value.DataMissing != nil {
		return encodeMAPErrorMember(DataMissing, value.DataMissing, DataMissingParamCodec(), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	if value.FacilityNotSupported != nil {
		return encodeMAPErrorMember(FacilityNotSupported, value.FacilityNotSupported, FacilityNotSupParamCodec(), opts...)
	}
	if value.UnidentifiedSubscriber != nil {
		return encodeMAPErrorMember(UnidentifiedSubscriber, value.UnidentifiedSubscriber, UnidentifiedSubParamCodec(), opts...)
	}
	if value.IllegalSubscriber != nil {
		return encodeMAPErrorMember(IllegalSubscriber, value.IllegalSubscriber, IllegalSubscriberParamCodec(), opts...)
	}
	if value.IllegalEquipment != nil {
		return encodeMAPErrorMember(IllegalEquipment, value.IllegalEquipment, IllegalEquipmentParamCodec(), opts...)
	}
	if value.SubscriberBusyForMTSMS != nil {
		return encodeMAPErrorMember(SubscriberBusyForMTSMS, value.SubscriberBusyForMTSMS, SubBusyForMTSMSParamCodec(), opts...)
	}
	if value.SmDeliveryFailure != nil {
		return encodeMAPErrorMember(SmDeliveryFailure, value.SmDeliveryFailure, SMDeliveryFailureCauseCodec(), opts...)
	}
	if value.AbsentSubscriberSM != nil {
		return encodeMAPErrorMember(AbsentSubscriberSM, value.AbsentSubscriberSM, AbsentSubscriberSMParamCodec(), opts...)
	}
	return EncodedError{}, fmt.Errorf("%w: no selected mt-ForwardSM error", ber.ErrInvalidBinding)
}

// MtForwardSMVGCSErrors selects exactly the formal ERRORS set of MAP-ShortMessageServiceOperations.mt-ForwardSM-VGCS.
type MtForwardSMVGCSErrors struct {
	SystemFailure       *ErrorValue[SystemFailureParam]
	UnexpectedDataValue *ErrorValue[UnexpectedDataParam]
}

func infoMtForwardSMVGCSOperation() OperationInfo {
	return OperationInfo{Name: "mt-ForwardSM-VGCS", Code: MtForwardSMVGCS, Argument: &TypeRef{ModuleOID: "0.4.0.0.1.3.16.22", ASN1Name: "MT-ForwardSM-VGCS-Arg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "MTForwardSMVGCSArg"}, Result: &TypeRef{ModuleOID: "0.4.0.0.1.3.16.22", ASN1Name: "MT-ForwardSM-VGCS-Res", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "MTForwardSMVGCSRes"}, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: false, Source: sourceInfo3("mt-ForwardSM-VGCS", "17.6.5"), Errors: []ErrorInfo{infoSystemFailureError(), infoUnexpectedDataValueError()}, Linked: []MAPOperationCode{}}
}

// MtForwardSMVGCSOperation binds the formal object in TS 29.002 V19.1.0 §17.6.5 (X.880 §§8.2–8.3).
func MtForwardSMVGCSOperation() Operation[MTForwardSMVGCSArg, MTForwardSMVGCSRes, MtForwardSMVGCSErrors] {
	return Operation[MTForwardSMVGCSArg, MTForwardSMVGCSRes, MtForwardSMVGCSErrors]{operationBinding[MTForwardSMVGCSArg, MTForwardSMVGCSRes, MtForwardSMVGCSErrors, OperationInfo, MAPOperationCode, EncodedError]{code: MtForwardSMVGCS, info: infoMtForwardSMVGCSOperation, argument: MTForwardSMVGCSArgCodec(), result: MTForwardSMVGCSResCodec(), decode: decodeMtForwardSMVGCSError, encode: encodeMtForwardSMVGCSError}}
}
func decodeMtForwardSMVGCSError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (MtForwardSMVGCSErrors, error) {
	switch code {
	case 34:
		p, err := decodeErrorParameter(data, present, SystemFailureParamCodec(), opts...)
		if err != nil {
			return MtForwardSMVGCSErrors{}, err
		}
		return MtForwardSMVGCSErrors{SystemFailure: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return MtForwardSMVGCSErrors{}, err
		}
		return MtForwardSMVGCSErrors{UnexpectedDataValue: p}, nil
	default:
		return MtForwardSMVGCSErrors{}, fmt.Errorf("%w: error code %d is not in mt-ForwardSM-VGCS ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeMtForwardSMVGCSError(value MtForwardSMVGCSErrors, opts ...ber.EncodeOption) (EncodedError, error) {
	selected := 0
	if value.SystemFailure != nil {
		selected++
	}
	if value.UnexpectedDataValue != nil {
		selected++
	}
	if selected != 1 {
		return EncodedError{}, fmt.Errorf("%w: exactly one mt-ForwardSM-VGCS error arm is required", ber.ErrInvalidBinding)
	}
	if value.SystemFailure != nil {
		return encodeMAPErrorMember(SystemFailure, value.SystemFailure, SystemFailureParamCodec(), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	return EncodedError{}, fmt.Errorf("%w: no selected mt-ForwardSM-VGCS error", ber.ErrInvalidBinding)
}

// NoteMMEventErrors selects exactly the formal ERRORS set of MAP-MobileServiceOperations.noteMM-Event.
type NoteMMEventErrors struct {
	DataMissing         *ErrorValue[DataMissingParam]
	UnexpectedDataValue *ErrorValue[UnexpectedDataParam]
	UnknownSubscriber   *ErrorValue[UnknownSubscriberParam]
	MmEventNotSupported *ErrorValue[MMEventNotSupportedParam]
}

func infoNoteMMEventOperation() OperationInfo {
	return OperationInfo{Name: "noteMM-Event", Code: NoteMMEvent, Argument: &TypeRef{ModuleOID: "0.4.0.0.1.3.11.22", ASN1Name: "NoteMM-EventArg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "NoteMMEventArg"}, Result: &TypeRef{ModuleOID: "0.4.0.0.1.3.11.22", ASN1Name: "NoteMM-EventRes", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "NoteMMEventRes"}, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: false, Source: sourceInfo4("noteMM-Event", "17.6.1"), Errors: []ErrorInfo{infoDataMissingError(), infoUnexpectedDataValueError(), infoUnknownSubscriberError(), infoMmEventNotSupportedError()}, Linked: []MAPOperationCode{}}
}

// NoteMMEventOperation binds the formal object in TS 29.002 V19.1.0 §17.6.1 (X.880 §§8.2–8.3).
func NoteMMEventOperation() Operation[NoteMMEventArg, NoteMMEventRes, NoteMMEventErrors] {
	return Operation[NoteMMEventArg, NoteMMEventRes, NoteMMEventErrors]{operationBinding[NoteMMEventArg, NoteMMEventRes, NoteMMEventErrors, OperationInfo, MAPOperationCode, EncodedError]{code: NoteMMEvent, info: infoNoteMMEventOperation, argument: NoteMMEventArgCodec(), result: NoteMMEventResCodec(), decode: decodeNoteMMEventError, encode: encodeNoteMMEventError}}
}
func decodeNoteMMEventError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (NoteMMEventErrors, error) {
	switch code {
	case 35:
		p, err := decodeErrorParameter(data, present, DataMissingParamCodec(), opts...)
		if err != nil {
			return NoteMMEventErrors{}, err
		}
		return NoteMMEventErrors{DataMissing: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return NoteMMEventErrors{}, err
		}
		return NoteMMEventErrors{UnexpectedDataValue: p}, nil
	case 1:
		p, err := decodeErrorParameter(data, present, UnknownSubscriberParamCodec(), opts...)
		if err != nil {
			return NoteMMEventErrors{}, err
		}
		return NoteMMEventErrors{UnknownSubscriber: p}, nil
	case 59:
		p, err := decodeErrorParameter(data, present, MMEventNotSupportedParamCodec(), opts...)
		if err != nil {
			return NoteMMEventErrors{}, err
		}
		return NoteMMEventErrors{MmEventNotSupported: p}, nil
	default:
		return NoteMMEventErrors{}, fmt.Errorf("%w: error code %d is not in noteMM-Event ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeNoteMMEventError(value NoteMMEventErrors, opts ...ber.EncodeOption) (EncodedError, error) {
	selected := 0
	if value.DataMissing != nil {
		selected++
	}
	if value.UnexpectedDataValue != nil {
		selected++
	}
	if value.UnknownSubscriber != nil {
		selected++
	}
	if value.MmEventNotSupported != nil {
		selected++
	}
	if selected != 1 {
		return EncodedError{}, fmt.Errorf("%w: exactly one noteMM-Event error arm is required", ber.ErrInvalidBinding)
	}
	if value.DataMissing != nil {
		return encodeMAPErrorMember(DataMissing, value.DataMissing, DataMissingParamCodec(), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	if value.UnknownSubscriber != nil {
		return encodeMAPErrorMember(UnknownSubscriber, value.UnknownSubscriber, UnknownSubscriberParamCodec(), opts...)
	}
	if value.MmEventNotSupported != nil {
		return encodeMAPErrorMember(MmEventNotSupported, value.MmEventNotSupported, MMEventNotSupportedParamCodec(), opts...)
	}
	return EncodedError{}, fmt.Errorf("%w: no selected noteMM-Event error", ber.ErrInvalidBinding)
}

// NoteMsPresentForGprsErrors selects exactly the formal ERRORS set of MAP-MobileServiceOperations.noteMsPresentForGprs.
type NoteMsPresentForGprsErrors struct {
	SystemFailure       *ErrorValue[SystemFailureParam]
	DataMissing         *ErrorValue[DataMissingParam]
	UnexpectedDataValue *ErrorValue[UnexpectedDataParam]
	UnknownSubscriber   *ErrorValue[UnknownSubscriberParam]
}

func infoNoteMsPresentForGprsOperation() OperationInfo {
	return OperationInfo{Name: "noteMsPresentForGprs", Code: NoteMsPresentForGprs, Argument: &TypeRef{ModuleOID: "0.4.0.0.1.3.11.22", ASN1Name: "NoteMsPresentForGprsArg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "NoteMsPresentForGprsArg"}, Result: &TypeRef{ModuleOID: "0.4.0.0.1.3.11.22", ASN1Name: "NoteMsPresentForGprsRes", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "NoteMsPresentForGprsRes"}, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: false, Source: sourceInfo4("noteMsPresentForGprs", "17.6.1"), Errors: []ErrorInfo{infoSystemFailureError(), infoDataMissingError(), infoUnexpectedDataValueError(), infoUnknownSubscriberError()}, Linked: []MAPOperationCode{}}
}

// NoteMsPresentForGprsOperation binds the formal object in TS 29.002 V19.1.0 §17.6.1 (X.880 §§8.2–8.3).
func NoteMsPresentForGprsOperation() Operation[NoteMsPresentForGprsArg, NoteMsPresentForGprsRes, NoteMsPresentForGprsErrors] {
	return Operation[NoteMsPresentForGprsArg, NoteMsPresentForGprsRes, NoteMsPresentForGprsErrors]{operationBinding[NoteMsPresentForGprsArg, NoteMsPresentForGprsRes, NoteMsPresentForGprsErrors, OperationInfo, MAPOperationCode, EncodedError]{code: NoteMsPresentForGprs, info: infoNoteMsPresentForGprsOperation, argument: NoteMsPresentForGprsArgCodec(), result: NoteMsPresentForGprsResCodec(), decode: decodeNoteMsPresentForGprsError, encode: encodeNoteMsPresentForGprsError}}
}
func decodeNoteMsPresentForGprsError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (NoteMsPresentForGprsErrors, error) {
	switch code {
	case 34:
		p, err := decodeErrorParameter(data, present, SystemFailureParamCodec(), opts...)
		if err != nil {
			return NoteMsPresentForGprsErrors{}, err
		}
		return NoteMsPresentForGprsErrors{SystemFailure: p}, nil
	case 35:
		p, err := decodeErrorParameter(data, present, DataMissingParamCodec(), opts...)
		if err != nil {
			return NoteMsPresentForGprsErrors{}, err
		}
		return NoteMsPresentForGprsErrors{DataMissing: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return NoteMsPresentForGprsErrors{}, err
		}
		return NoteMsPresentForGprsErrors{UnexpectedDataValue: p}, nil
	case 1:
		p, err := decodeErrorParameter(data, present, UnknownSubscriberParamCodec(), opts...)
		if err != nil {
			return NoteMsPresentForGprsErrors{}, err
		}
		return NoteMsPresentForGprsErrors{UnknownSubscriber: p}, nil
	default:
		return NoteMsPresentForGprsErrors{}, fmt.Errorf("%w: error code %d is not in noteMsPresentForGprs ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeNoteMsPresentForGprsError(value NoteMsPresentForGprsErrors, opts ...ber.EncodeOption) (EncodedError, error) {
	selected := 0
	if value.SystemFailure != nil {
		selected++
	}
	if value.DataMissing != nil {
		selected++
	}
	if value.UnexpectedDataValue != nil {
		selected++
	}
	if value.UnknownSubscriber != nil {
		selected++
	}
	if selected != 1 {
		return EncodedError{}, fmt.Errorf("%w: exactly one noteMsPresentForGprs error arm is required", ber.ErrInvalidBinding)
	}
	if value.SystemFailure != nil {
		return encodeMAPErrorMember(SystemFailure, value.SystemFailure, SystemFailureParamCodec(), opts...)
	}
	if value.DataMissing != nil {
		return encodeMAPErrorMember(DataMissing, value.DataMissing, DataMissingParamCodec(), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	if value.UnknownSubscriber != nil {
		return encodeMAPErrorMember(UnknownSubscriber, value.UnknownSubscriber, UnknownSubscriberParamCodec(), opts...)
	}
	return EncodedError{}, fmt.Errorf("%w: no selected noteMsPresentForGprs error", ber.ErrInvalidBinding)
}

// NoteSubscriberDataModifiedErrors selects exactly the formal ERRORS set of MAP-MobileServiceOperations.noteSubscriberDataModified.
type NoteSubscriberDataModifiedErrors struct {
	DataMissing         *ErrorValue[DataMissingParam]
	UnexpectedDataValue *ErrorValue[UnexpectedDataParam]
	UnknownSubscriber   *ErrorValue[UnknownSubscriberParam]
}

func infoNoteSubscriberDataModifiedOperation() OperationInfo {
	return OperationInfo{Name: "noteSubscriberDataModified", Code: NoteSubscriberDataModified, Argument: &TypeRef{ModuleOID: "0.4.0.0.1.3.11.22", ASN1Name: "NoteSubscriberDataModifiedArg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "NoteSubscriberDataModifiedArg"}, Result: &TypeRef{ModuleOID: "0.4.0.0.1.3.11.22", ASN1Name: "NoteSubscriberDataModifiedRes", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "NoteSubscriberDataModifiedRes"}, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: false, Source: sourceInfo4("noteSubscriberDataModified", "17.6.1"), Errors: []ErrorInfo{infoDataMissingError(), infoUnexpectedDataValueError(), infoUnknownSubscriberError()}, Linked: []MAPOperationCode{}}
}

// NoteSubscriberDataModifiedOperation binds the formal object in TS 29.002 V19.1.0 §17.6.1 (X.880 §§8.2–8.3).
func NoteSubscriberDataModifiedOperation() Operation[NoteSubscriberDataModifiedArg, NoteSubscriberDataModifiedRes, NoteSubscriberDataModifiedErrors] {
	return Operation[NoteSubscriberDataModifiedArg, NoteSubscriberDataModifiedRes, NoteSubscriberDataModifiedErrors]{operationBinding[NoteSubscriberDataModifiedArg, NoteSubscriberDataModifiedRes, NoteSubscriberDataModifiedErrors, OperationInfo, MAPOperationCode, EncodedError]{code: NoteSubscriberDataModified, info: infoNoteSubscriberDataModifiedOperation, argument: NoteSubscriberDataModifiedArgCodec(), result: NoteSubscriberDataModifiedResCodec(), decode: decodeNoteSubscriberDataModifiedError, encode: encodeNoteSubscriberDataModifiedError}}
}
func decodeNoteSubscriberDataModifiedError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (NoteSubscriberDataModifiedErrors, error) {
	switch code {
	case 35:
		p, err := decodeErrorParameter(data, present, DataMissingParamCodec(), opts...)
		if err != nil {
			return NoteSubscriberDataModifiedErrors{}, err
		}
		return NoteSubscriberDataModifiedErrors{DataMissing: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return NoteSubscriberDataModifiedErrors{}, err
		}
		return NoteSubscriberDataModifiedErrors{UnexpectedDataValue: p}, nil
	case 1:
		p, err := decodeErrorParameter(data, present, UnknownSubscriberParamCodec(), opts...)
		if err != nil {
			return NoteSubscriberDataModifiedErrors{}, err
		}
		return NoteSubscriberDataModifiedErrors{UnknownSubscriber: p}, nil
	default:
		return NoteSubscriberDataModifiedErrors{}, fmt.Errorf("%w: error code %d is not in noteSubscriberDataModified ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeNoteSubscriberDataModifiedError(value NoteSubscriberDataModifiedErrors, opts ...ber.EncodeOption) (EncodedError, error) {
	selected := 0
	if value.DataMissing != nil {
		selected++
	}
	if value.UnexpectedDataValue != nil {
		selected++
	}
	if value.UnknownSubscriber != nil {
		selected++
	}
	if selected != 1 {
		return EncodedError{}, fmt.Errorf("%w: exactly one noteSubscriberDataModified error arm is required", ber.ErrInvalidBinding)
	}
	if value.DataMissing != nil {
		return encodeMAPErrorMember(DataMissing, value.DataMissing, DataMissingParamCodec(), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	if value.UnknownSubscriber != nil {
		return encodeMAPErrorMember(UnknownSubscriber, value.UnknownSubscriber, UnknownSubscriberParamCodec(), opts...)
	}
	return EncodedError{}, fmt.Errorf("%w: no selected noteSubscriberDataModified error", ber.ErrInvalidBinding)
}

// PrepareGroupCallErrors selects exactly the formal ERRORS set of MAP-Group-Call-Operations.prepareGroupCall.
type PrepareGroupCallErrors struct {
	SystemFailure              *ErrorValue[SystemFailureParam]
	NoGroupCallNumberAvailable *ErrorValue[NoGroupCallNbParam]
	UnexpectedDataValue        *ErrorValue[UnexpectedDataParam]
}

func infoPrepareGroupCallOperation() OperationInfo {
	return OperationInfo{Name: "prepareGroupCall", Code: PrepareGroupCall, Argument: &TypeRef{ModuleOID: "0.4.0.0.1.3.23.22", ASN1Name: "PrepareGroupCallArg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "PrepareGroupCallArg"}, Result: &TypeRef{ModuleOID: "0.4.0.0.1.3.23.22", ASN1Name: "PrepareGroupCallRes", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "PrepareGroupCallRes"}, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: false, Source: sourceInfo5("prepareGroupCall", "17.6.7"), Errors: []ErrorInfo{infoSystemFailureError(), infoNoGroupCallNumberAvailableError(), infoUnexpectedDataValueError()}, Linked: []MAPOperationCode{}}
}

// PrepareGroupCallOperation binds the formal object in TS 29.002 V19.1.0 §17.6.7 (X.880 §§8.2–8.3).
func PrepareGroupCallOperation() Operation[PrepareGroupCallArg, PrepareGroupCallRes, PrepareGroupCallErrors] {
	return Operation[PrepareGroupCallArg, PrepareGroupCallRes, PrepareGroupCallErrors]{operationBinding[PrepareGroupCallArg, PrepareGroupCallRes, PrepareGroupCallErrors, OperationInfo, MAPOperationCode, EncodedError]{code: PrepareGroupCall, info: infoPrepareGroupCallOperation, argument: PrepareGroupCallArgCodec(), result: PrepareGroupCallResCodec(), decode: decodePrepareGroupCallError, encode: encodePrepareGroupCallError}}
}
func decodePrepareGroupCallError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (PrepareGroupCallErrors, error) {
	switch code {
	case 34:
		p, err := decodeErrorParameter(data, present, SystemFailureParamCodec(), opts...)
		if err != nil {
			return PrepareGroupCallErrors{}, err
		}
		return PrepareGroupCallErrors{SystemFailure: p}, nil
	case 50:
		p, err := decodeErrorParameter(data, present, NoGroupCallNbParamCodec(), opts...)
		if err != nil {
			return PrepareGroupCallErrors{}, err
		}
		return PrepareGroupCallErrors{NoGroupCallNumberAvailable: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return PrepareGroupCallErrors{}, err
		}
		return PrepareGroupCallErrors{UnexpectedDataValue: p}, nil
	default:
		return PrepareGroupCallErrors{}, fmt.Errorf("%w: error code %d is not in prepareGroupCall ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodePrepareGroupCallError(value PrepareGroupCallErrors, opts ...ber.EncodeOption) (EncodedError, error) {
	selected := 0
	if value.SystemFailure != nil {
		selected++
	}
	if value.NoGroupCallNumberAvailable != nil {
		selected++
	}
	if value.UnexpectedDataValue != nil {
		selected++
	}
	if selected != 1 {
		return EncodedError{}, fmt.Errorf("%w: exactly one prepareGroupCall error arm is required", ber.ErrInvalidBinding)
	}
	if value.SystemFailure != nil {
		return encodeMAPErrorMember(SystemFailure, value.SystemFailure, SystemFailureParamCodec(), opts...)
	}
	if value.NoGroupCallNumberAvailable != nil {
		return encodeMAPErrorMember(NoGroupCallNumberAvailable, value.NoGroupCallNumberAvailable, NoGroupCallNbParamCodec(), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	return EncodedError{}, fmt.Errorf("%w: no selected prepareGroupCall error", ber.ErrInvalidBinding)
}

// PrepareHandoverErrors selects exactly the formal ERRORS set of MAP-MobileServiceOperations.prepareHandover.
type PrepareHandoverErrors struct {
	SystemFailure                  *ErrorValue[SystemFailureParam]
	DataMissing                    *ErrorValue[DataMissingParam]
	UnexpectedDataValue            *ErrorValue[UnexpectedDataParam]
	NoHandoverNumberAvailable      *ErrorValue[NoParameter]
	TargetCellOutsideGroupCallArea *ErrorValue[TargetCellOutsideGCAParam]
}

func infoPrepareHandoverOperation() OperationInfo {
	return OperationInfo{Name: "prepareHandover", Code: PrepareHandover, Argument: &TypeRef{ModuleOID: "0.4.0.0.1.3.11.22", ASN1Name: "PrepareHO-Arg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "PrepareHOArg"}, Result: &TypeRef{ModuleOID: "0.4.0.0.1.3.11.22", ASN1Name: "PrepareHO-Res", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "PrepareHORes"}, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: false, Source: sourceInfo4("prepareHandover", "17.6.1"), Errors: []ErrorInfo{infoSystemFailureError(), infoDataMissingError(), infoUnexpectedDataValueError(), infoNoHandoverNumberAvailableError(), infoTargetCellOutsideGroupCallAreaError()}, Linked: []MAPOperationCode{}}
}

// PrepareHandoverOperation binds the formal object in TS 29.002 V19.1.0 §17.6.1 (X.880 §§8.2–8.3).
func PrepareHandoverOperation() Operation[PrepareHOArg, PrepareHORes, PrepareHandoverErrors] {
	return Operation[PrepareHOArg, PrepareHORes, PrepareHandoverErrors]{operationBinding[PrepareHOArg, PrepareHORes, PrepareHandoverErrors, OperationInfo, MAPOperationCode, EncodedError]{code: PrepareHandover, info: infoPrepareHandoverOperation, argument: PrepareHOArgCodec(), result: PrepareHOResCodec(), decode: decodePrepareHandoverError, encode: encodePrepareHandoverError}}
}
func decodePrepareHandoverError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (PrepareHandoverErrors, error) {
	switch code {
	case 34:
		p, err := decodeErrorParameter(data, present, SystemFailureParamCodec(), opts...)
		if err != nil {
			return PrepareHandoverErrors{}, err
		}
		return PrepareHandoverErrors{SystemFailure: p}, nil
	case 35:
		p, err := decodeErrorParameter(data, present, DataMissingParamCodec(), opts...)
		if err != nil {
			return PrepareHandoverErrors{}, err
		}
		return PrepareHandoverErrors{DataMissing: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return PrepareHandoverErrors{}, err
		}
		return PrepareHandoverErrors{UnexpectedDataValue: p}, nil
	case 25:
		p, err := decodeErrorParameter(data, present, ValueCodec[NoParameter]{}, opts...)
		if err != nil {
			return PrepareHandoverErrors{}, err
		}
		return PrepareHandoverErrors{NoHandoverNumberAvailable: p}, nil
	case 42:
		p, err := decodeErrorParameter(data, present, TargetCellOutsideGCAParamCodec(), opts...)
		if err != nil {
			return PrepareHandoverErrors{}, err
		}
		return PrepareHandoverErrors{TargetCellOutsideGroupCallArea: p}, nil
	default:
		return PrepareHandoverErrors{}, fmt.Errorf("%w: error code %d is not in prepareHandover ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodePrepareHandoverError(value PrepareHandoverErrors, opts ...ber.EncodeOption) (EncodedError, error) {
	selected := 0
	if value.SystemFailure != nil {
		selected++
	}
	if value.DataMissing != nil {
		selected++
	}
	if value.UnexpectedDataValue != nil {
		selected++
	}
	if value.NoHandoverNumberAvailable != nil {
		selected++
	}
	if value.TargetCellOutsideGroupCallArea != nil {
		selected++
	}
	if selected != 1 {
		return EncodedError{}, fmt.Errorf("%w: exactly one prepareHandover error arm is required", ber.ErrInvalidBinding)
	}
	if value.SystemFailure != nil {
		return encodeMAPErrorMember(SystemFailure, value.SystemFailure, SystemFailureParamCodec(), opts...)
	}
	if value.DataMissing != nil {
		return encodeMAPErrorMember(DataMissing, value.DataMissing, DataMissingParamCodec(), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	if value.NoHandoverNumberAvailable != nil {
		return encodeMAPErrorMember(NoHandoverNumberAvailable, value.NoHandoverNumberAvailable, ValueCodec[NoParameter]{}, opts...)
	}
	if value.TargetCellOutsideGroupCallArea != nil {
		return encodeMAPErrorMember(TargetCellOutsideGroupCallArea, value.TargetCellOutsideGroupCallArea, TargetCellOutsideGCAParamCodec(), opts...)
	}
	return EncodedError{}, fmt.Errorf("%w: no selected prepareHandover error", ber.ErrInvalidBinding)
}

// PrepareSubsequentHandoverErrors selects exactly the formal ERRORS set of MAP-MobileServiceOperations.prepareSubsequentHandover.
type PrepareSubsequentHandoverErrors struct {
	UnexpectedDataValue       *ErrorValue[UnexpectedDataParam]
	DataMissing               *ErrorValue[DataMissingParam]
	UnknownMSC                *ErrorValue[NoParameter]
	SubsequentHandoverFailure *ErrorValue[NoParameter]
}

func infoPrepareSubsequentHandoverOperation() OperationInfo {
	return OperationInfo{Name: "prepareSubsequentHandover", Code: PrepareSubsequentHandover, Argument: &TypeRef{ModuleOID: "0.4.0.0.1.3.11.22", ASN1Name: "PrepareSubsequentHO-Arg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "PrepareSubsequentHOArg"}, Result: &TypeRef{ModuleOID: "0.4.0.0.1.3.11.22", ASN1Name: "PrepareSubsequentHO-Res", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "PrepareSubsequentHORes"}, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: false, Source: sourceInfo4("prepareSubsequentHandover", "17.6.1"), Errors: []ErrorInfo{infoUnexpectedDataValueError(), infoDataMissingError(), infoUnknownMSCError(), infoSubsequentHandoverFailureError()}, Linked: []MAPOperationCode{}}
}

// PrepareSubsequentHandoverOperation binds the formal object in TS 29.002 V19.1.0 §17.6.1 (X.880 §§8.2–8.3).
func PrepareSubsequentHandoverOperation() Operation[PrepareSubsequentHOArg, PrepareSubsequentHORes, PrepareSubsequentHandoverErrors] {
	return Operation[PrepareSubsequentHOArg, PrepareSubsequentHORes, PrepareSubsequentHandoverErrors]{operationBinding[PrepareSubsequentHOArg, PrepareSubsequentHORes, PrepareSubsequentHandoverErrors, OperationInfo, MAPOperationCode, EncodedError]{code: PrepareSubsequentHandover, info: infoPrepareSubsequentHandoverOperation, argument: PrepareSubsequentHOArgCodec(), result: PrepareSubsequentHOResCodec(), decode: decodePrepareSubsequentHandoverError, encode: encodePrepareSubsequentHandoverError}}
}
func decodePrepareSubsequentHandoverError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (PrepareSubsequentHandoverErrors, error) {
	switch code {
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return PrepareSubsequentHandoverErrors{}, err
		}
		return PrepareSubsequentHandoverErrors{UnexpectedDataValue: p}, nil
	case 35:
		p, err := decodeErrorParameter(data, present, DataMissingParamCodec(), opts...)
		if err != nil {
			return PrepareSubsequentHandoverErrors{}, err
		}
		return PrepareSubsequentHandoverErrors{DataMissing: p}, nil
	case 3:
		p, err := decodeErrorParameter(data, present, ValueCodec[NoParameter]{}, opts...)
		if err != nil {
			return PrepareSubsequentHandoverErrors{}, err
		}
		return PrepareSubsequentHandoverErrors{UnknownMSC: p}, nil
	case 26:
		p, err := decodeErrorParameter(data, present, ValueCodec[NoParameter]{}, opts...)
		if err != nil {
			return PrepareSubsequentHandoverErrors{}, err
		}
		return PrepareSubsequentHandoverErrors{SubsequentHandoverFailure: p}, nil
	default:
		return PrepareSubsequentHandoverErrors{}, fmt.Errorf("%w: error code %d is not in prepareSubsequentHandover ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodePrepareSubsequentHandoverError(value PrepareSubsequentHandoverErrors, opts ...ber.EncodeOption) (EncodedError, error) {
	selected := 0
	if value.UnexpectedDataValue != nil {
		selected++
	}
	if value.DataMissing != nil {
		selected++
	}
	if value.UnknownMSC != nil {
		selected++
	}
	if value.SubsequentHandoverFailure != nil {
		selected++
	}
	if selected != 1 {
		return EncodedError{}, fmt.Errorf("%w: exactly one prepareSubsequentHandover error arm is required", ber.ErrInvalidBinding)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	if value.DataMissing != nil {
		return encodeMAPErrorMember(DataMissing, value.DataMissing, DataMissingParamCodec(), opts...)
	}
	if value.UnknownMSC != nil {
		return encodeMAPErrorMember(UnknownMSC, value.UnknownMSC, ValueCodec[NoParameter]{}, opts...)
	}
	if value.SubsequentHandoverFailure != nil {
		return encodeMAPErrorMember(SubsequentHandoverFailure, value.SubsequentHandoverFailure, ValueCodec[NoParameter]{}, opts...)
	}
	return EncodedError{}, fmt.Errorf("%w: no selected prepareSubsequentHandover error", ber.ErrInvalidBinding)
}

// ProcessAccessSignallingErrors selects exactly the formal ERRORS set of MAP-MobileServiceOperations.processAccessSignalling.
type ProcessAccessSignallingErrors struct {
}

func infoProcessAccessSignallingOperation() OperationInfo {
	return OperationInfo{Name: "processAccessSignalling", Code: ProcessAccessSignalling, Argument: &TypeRef{ModuleOID: "0.4.0.0.1.3.11.22", ASN1Name: "ProcessAccessSignalling-Arg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "ProcessAccessSignallingArg"}, Result: nil, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: false, Source: sourceInfo4("processAccessSignalling", "17.6.1"), Errors: []ErrorInfo{}, Linked: []MAPOperationCode{}}
}

// ProcessAccessSignallingOperation binds the formal object in TS 29.002 V19.1.0 §17.6.1 (X.880 §§8.2–8.3).
func ProcessAccessSignallingOperation() Operation[ProcessAccessSignallingArg, NoParameter, ProcessAccessSignallingErrors] {
	return Operation[ProcessAccessSignallingArg, NoParameter, ProcessAccessSignallingErrors]{operationBinding[ProcessAccessSignallingArg, NoParameter, ProcessAccessSignallingErrors, OperationInfo, MAPOperationCode, EncodedError]{code: ProcessAccessSignalling, info: infoProcessAccessSignallingOperation, argument: ProcessAccessSignallingArgCodec(), result: ValueCodec[NoParameter]{}, decode: decodeProcessAccessSignallingError, encode: encodeProcessAccessSignallingError}}
}
func decodeProcessAccessSignallingError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (ProcessAccessSignallingErrors, error) {
	switch code {
	default:
		return ProcessAccessSignallingErrors{}, fmt.Errorf("%w: error code %d is not in processAccessSignalling ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeProcessAccessSignallingError(value ProcessAccessSignallingErrors, opts ...ber.EncodeOption) (EncodedError, error) {
	return EncodedError{}, fmt.Errorf("%w: no selected processAccessSignalling error", ber.ErrInvalidBinding)
}

// ProcessGroupCallSignallingErrors selects exactly the formal ERRORS set of MAP-Group-Call-Operations.processGroupCallSignalling.
type ProcessGroupCallSignallingErrors struct {
}

func infoProcessGroupCallSignallingOperation() OperationInfo {
	return OperationInfo{Name: "processGroupCallSignalling", Code: ProcessGroupCallSignalling, Argument: &TypeRef{ModuleOID: "0.4.0.0.1.3.23.22", ASN1Name: "ProcessGroupCallSignallingArg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "ProcessGroupCallSignallingArg"}, Result: nil, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: false, Source: sourceInfo5("processGroupCallSignalling", "17.6.7"), Errors: []ErrorInfo{}, Linked: []MAPOperationCode{}}
}

// ProcessGroupCallSignallingOperation binds the formal object in TS 29.002 V19.1.0 §17.6.7 (X.880 §§8.2–8.3).
func ProcessGroupCallSignallingOperation() Operation[ProcessGroupCallSignallingArg, NoParameter, ProcessGroupCallSignallingErrors] {
	return Operation[ProcessGroupCallSignallingArg, NoParameter, ProcessGroupCallSignallingErrors]{operationBinding[ProcessGroupCallSignallingArg, NoParameter, ProcessGroupCallSignallingErrors, OperationInfo, MAPOperationCode, EncodedError]{code: ProcessGroupCallSignalling, info: infoProcessGroupCallSignallingOperation, argument: ProcessGroupCallSignallingArgCodec(), result: ValueCodec[NoParameter]{}, decode: decodeProcessGroupCallSignallingError, encode: encodeProcessGroupCallSignallingError}}
}
func decodeProcessGroupCallSignallingError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (ProcessGroupCallSignallingErrors, error) {
	switch code {
	default:
		return ProcessGroupCallSignallingErrors{}, fmt.Errorf("%w: error code %d is not in processGroupCallSignalling ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeProcessGroupCallSignallingError(value ProcessGroupCallSignallingErrors, opts ...ber.EncodeOption) (EncodedError, error) {
	return EncodedError{}, fmt.Errorf("%w: no selected processGroupCallSignalling error", ber.ErrInvalidBinding)
}

// ProcessUnstructuredSSRequestErrors selects exactly the formal ERRORS set of MAP-SupplementaryServiceOperations.processUnstructuredSS-Request.
type ProcessUnstructuredSSRequestErrors struct {
	SystemFailure       *ErrorValue[SystemFailureParam]
	DataMissing         *ErrorValue[DataMissingParam]
	UnexpectedDataValue *ErrorValue[UnexpectedDataParam]
	UnknownAlphabet     *ErrorValue[NoParameter]
	CallBarred          *ErrorValue[CallBarredParam]
}

func infoProcessUnstructuredSSRequestOperation() OperationInfo {
	return OperationInfo{Name: "processUnstructuredSS-Request", Code: ProcessUnstructuredSSRequest, Argument: &TypeRef{ModuleOID: "0.4.0.0.1.3.14.22", ASN1Name: "USSD-Arg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "USSDArg"}, Result: &TypeRef{ModuleOID: "0.4.0.0.1.3.14.22", ASN1Name: "USSD-Res", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "USSDRes"}, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: false, Source: sourceInfo1("processUnstructuredSS-Request", "17.6.4"), Errors: []ErrorInfo{infoSystemFailureError(), infoDataMissingError(), infoUnexpectedDataValueError(), infoUnknownAlphabetError(), infoCallBarredError()}, Linked: []MAPOperationCode{}}
}

// ProcessUnstructuredSSRequestOperation binds the formal object in TS 29.002 V19.1.0 §17.6.4 (X.880 §§8.2–8.3).
func ProcessUnstructuredSSRequestOperation() Operation[USSDArg, USSDRes, ProcessUnstructuredSSRequestErrors] {
	return Operation[USSDArg, USSDRes, ProcessUnstructuredSSRequestErrors]{operationBinding[USSDArg, USSDRes, ProcessUnstructuredSSRequestErrors, OperationInfo, MAPOperationCode, EncodedError]{code: ProcessUnstructuredSSRequest, info: infoProcessUnstructuredSSRequestOperation, argument: USSDArgCodec(), result: USSDResCodec(), decode: decodeProcessUnstructuredSSRequestError, encode: encodeProcessUnstructuredSSRequestError}}
}
func decodeProcessUnstructuredSSRequestError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (ProcessUnstructuredSSRequestErrors, error) {
	switch code {
	case 34:
		p, err := decodeErrorParameter(data, present, SystemFailureParamCodec(), opts...)
		if err != nil {
			return ProcessUnstructuredSSRequestErrors{}, err
		}
		return ProcessUnstructuredSSRequestErrors{SystemFailure: p}, nil
	case 35:
		p, err := decodeErrorParameter(data, present, DataMissingParamCodec(), opts...)
		if err != nil {
			return ProcessUnstructuredSSRequestErrors{}, err
		}
		return ProcessUnstructuredSSRequestErrors{DataMissing: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return ProcessUnstructuredSSRequestErrors{}, err
		}
		return ProcessUnstructuredSSRequestErrors{UnexpectedDataValue: p}, nil
	case 71:
		p, err := decodeErrorParameter(data, present, ValueCodec[NoParameter]{}, opts...)
		if err != nil {
			return ProcessUnstructuredSSRequestErrors{}, err
		}
		return ProcessUnstructuredSSRequestErrors{UnknownAlphabet: p}, nil
	case 13:
		p, err := decodeErrorParameter(data, present, CallBarredParamCodec(), opts...)
		if err != nil {
			return ProcessUnstructuredSSRequestErrors{}, err
		}
		return ProcessUnstructuredSSRequestErrors{CallBarred: p}, nil
	default:
		return ProcessUnstructuredSSRequestErrors{}, fmt.Errorf("%w: error code %d is not in processUnstructuredSS-Request ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeProcessUnstructuredSSRequestError(value ProcessUnstructuredSSRequestErrors, opts ...ber.EncodeOption) (EncodedError, error) {
	selected := 0
	if value.SystemFailure != nil {
		selected++
	}
	if value.DataMissing != nil {
		selected++
	}
	if value.UnexpectedDataValue != nil {
		selected++
	}
	if value.UnknownAlphabet != nil {
		selected++
	}
	if value.CallBarred != nil {
		selected++
	}
	if selected != 1 {
		return EncodedError{}, fmt.Errorf("%w: exactly one processUnstructuredSS-Request error arm is required", ber.ErrInvalidBinding)
	}
	if value.SystemFailure != nil {
		return encodeMAPErrorMember(SystemFailure, value.SystemFailure, SystemFailureParamCodec(), opts...)
	}
	if value.DataMissing != nil {
		return encodeMAPErrorMember(DataMissing, value.DataMissing, DataMissingParamCodec(), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	if value.UnknownAlphabet != nil {
		return encodeMAPErrorMember(UnknownAlphabet, value.UnknownAlphabet, ValueCodec[NoParameter]{}, opts...)
	}
	if value.CallBarred != nil {
		return encodeMAPErrorMember(CallBarred, value.CallBarred, CallBarredParamCodec(), opts...)
	}
	return EncodedError{}, fmt.Errorf("%w: no selected processUnstructuredSS-Request error", ber.ErrInvalidBinding)
}

// ProvideRoamingNumberErrors selects exactly the formal ERRORS set of MAP-CallHandlingOperations.provideRoamingNumber.
type ProvideRoamingNumberErrors struct {
	SystemFailure            *ErrorValue[SystemFailureParam]
	DataMissing              *ErrorValue[DataMissingParam]
	UnexpectedDataValue      *ErrorValue[UnexpectedDataParam]
	FacilityNotSupported     *ErrorValue[FacilityNotSupParam]
	OrNotAllowed             *ErrorValue[ORNotAllowedParam]
	AbsentSubscriber         *ErrorValue[AbsentSubscriberParam]
	NoRoamingNumberAvailable *ErrorValue[NoRoamingNbParam]
}

func infoProvideRoamingNumberOperation() OperationInfo {
	return OperationInfo{Name: "provideRoamingNumber", Code: ProvideRoamingNumber, Argument: &TypeRef{ModuleOID: "0.4.0.0.1.3.13.22", ASN1Name: "ProvideRoamingNumberArg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "ProvideRoamingNumberArg"}, Result: &TypeRef{ModuleOID: "0.4.0.0.1.3.13.22", ASN1Name: "ProvideRoamingNumberRes", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "ProvideRoamingNumberRes"}, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: false, Source: sourceInfo6("provideRoamingNumber", "17.6.3"), Errors: []ErrorInfo{infoSystemFailureError(), infoDataMissingError(), infoUnexpectedDataValueError(), infoFacilityNotSupportedError(), infoOrNotAllowedError(), infoAbsentSubscriberError(), infoNoRoamingNumberAvailableError()}, Linked: []MAPOperationCode{}}
}

// ProvideRoamingNumberOperation binds the formal object in TS 29.002 V19.1.0 §17.6.3 (X.880 §§8.2–8.3).
func ProvideRoamingNumberOperation() Operation[ProvideRoamingNumberArg, ProvideRoamingNumberRes, ProvideRoamingNumberErrors] {
	return Operation[ProvideRoamingNumberArg, ProvideRoamingNumberRes, ProvideRoamingNumberErrors]{operationBinding[ProvideRoamingNumberArg, ProvideRoamingNumberRes, ProvideRoamingNumberErrors, OperationInfo, MAPOperationCode, EncodedError]{code: ProvideRoamingNumber, info: infoProvideRoamingNumberOperation, argument: ProvideRoamingNumberArgCodec(), result: ProvideRoamingNumberResCodec(), decode: decodeProvideRoamingNumberError, encode: encodeProvideRoamingNumberError}}
}
func decodeProvideRoamingNumberError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (ProvideRoamingNumberErrors, error) {
	switch code {
	case 34:
		p, err := decodeErrorParameter(data, present, SystemFailureParamCodec(), opts...)
		if err != nil {
			return ProvideRoamingNumberErrors{}, err
		}
		return ProvideRoamingNumberErrors{SystemFailure: p}, nil
	case 35:
		p, err := decodeErrorParameter(data, present, DataMissingParamCodec(), opts...)
		if err != nil {
			return ProvideRoamingNumberErrors{}, err
		}
		return ProvideRoamingNumberErrors{DataMissing: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return ProvideRoamingNumberErrors{}, err
		}
		return ProvideRoamingNumberErrors{UnexpectedDataValue: p}, nil
	case 21:
		p, err := decodeErrorParameter(data, present, FacilityNotSupParamCodec(), opts...)
		if err != nil {
			return ProvideRoamingNumberErrors{}, err
		}
		return ProvideRoamingNumberErrors{FacilityNotSupported: p}, nil
	case 48:
		p, err := decodeErrorParameter(data, present, ORNotAllowedParamCodec(), opts...)
		if err != nil {
			return ProvideRoamingNumberErrors{}, err
		}
		return ProvideRoamingNumberErrors{OrNotAllowed: p}, nil
	case 27:
		p, err := decodeErrorParameter(data, present, AbsentSubscriberParamCodec(), opts...)
		if err != nil {
			return ProvideRoamingNumberErrors{}, err
		}
		return ProvideRoamingNumberErrors{AbsentSubscriber: p}, nil
	case 39:
		p, err := decodeErrorParameter(data, present, NoRoamingNbParamCodec(), opts...)
		if err != nil {
			return ProvideRoamingNumberErrors{}, err
		}
		return ProvideRoamingNumberErrors{NoRoamingNumberAvailable: p}, nil
	default:
		return ProvideRoamingNumberErrors{}, fmt.Errorf("%w: error code %d is not in provideRoamingNumber ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeProvideRoamingNumberError(value ProvideRoamingNumberErrors, opts ...ber.EncodeOption) (EncodedError, error) {
	selected := 0
	if value.SystemFailure != nil {
		selected++
	}
	if value.DataMissing != nil {
		selected++
	}
	if value.UnexpectedDataValue != nil {
		selected++
	}
	if value.FacilityNotSupported != nil {
		selected++
	}
	if value.OrNotAllowed != nil {
		selected++
	}
	if value.AbsentSubscriber != nil {
		selected++
	}
	if value.NoRoamingNumberAvailable != nil {
		selected++
	}
	if selected != 1 {
		return EncodedError{}, fmt.Errorf("%w: exactly one provideRoamingNumber error arm is required", ber.ErrInvalidBinding)
	}
	if value.SystemFailure != nil {
		return encodeMAPErrorMember(SystemFailure, value.SystemFailure, SystemFailureParamCodec(), opts...)
	}
	if value.DataMissing != nil {
		return encodeMAPErrorMember(DataMissing, value.DataMissing, DataMissingParamCodec(), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	if value.FacilityNotSupported != nil {
		return encodeMAPErrorMember(FacilityNotSupported, value.FacilityNotSupported, FacilityNotSupParamCodec(), opts...)
	}
	if value.OrNotAllowed != nil {
		return encodeMAPErrorMember(OrNotAllowed, value.OrNotAllowed, ORNotAllowedParamCodec(), opts...)
	}
	if value.AbsentSubscriber != nil {
		return encodeMAPErrorMember(AbsentSubscriber, value.AbsentSubscriber, AbsentSubscriberParamCodec(), opts...)
	}
	if value.NoRoamingNumberAvailable != nil {
		return encodeMAPErrorMember(NoRoamingNumberAvailable, value.NoRoamingNumberAvailable, NoRoamingNbParamCodec(), opts...)
	}
	return EncodedError{}, fmt.Errorf("%w: no selected provideRoamingNumber error", ber.ErrInvalidBinding)
}

// ProvideSubscriberInfoErrors selects exactly the formal ERRORS set of MAP-MobileServiceOperations.provideSubscriberInfo.
type ProvideSubscriberInfoErrors struct {
	DataMissing         *ErrorValue[DataMissingParam]
	UnexpectedDataValue *ErrorValue[UnexpectedDataParam]
}

func infoProvideSubscriberInfoOperation() OperationInfo {
	return OperationInfo{Name: "provideSubscriberInfo", Code: ProvideSubscriberInfo, Argument: &TypeRef{ModuleOID: "0.4.0.0.1.3.11.22", ASN1Name: "ProvideSubscriberInfoArg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "ProvideSubscriberInfoArg"}, Result: &TypeRef{ModuleOID: "0.4.0.0.1.3.11.22", ASN1Name: "ProvideSubscriberInfoRes", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "ProvideSubscriberInfoRes"}, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: false, Source: sourceInfo4("provideSubscriberInfo", "17.6.1"), Errors: []ErrorInfo{infoDataMissingError(), infoUnexpectedDataValueError()}, Linked: []MAPOperationCode{}}
}

// ProvideSubscriberInfoOperation binds the formal object in TS 29.002 V19.1.0 §17.6.1 (X.880 §§8.2–8.3).
func ProvideSubscriberInfoOperation() Operation[ProvideSubscriberInfoArg, ProvideSubscriberInfoRes, ProvideSubscriberInfoErrors] {
	return Operation[ProvideSubscriberInfoArg, ProvideSubscriberInfoRes, ProvideSubscriberInfoErrors]{operationBinding[ProvideSubscriberInfoArg, ProvideSubscriberInfoRes, ProvideSubscriberInfoErrors, OperationInfo, MAPOperationCode, EncodedError]{code: ProvideSubscriberInfo, info: infoProvideSubscriberInfoOperation, argument: ProvideSubscriberInfoArgCodec(), result: ProvideSubscriberInfoResCodec(), decode: decodeProvideSubscriberInfoError, encode: encodeProvideSubscriberInfoError}}
}
func decodeProvideSubscriberInfoError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (ProvideSubscriberInfoErrors, error) {
	switch code {
	case 35:
		p, err := decodeErrorParameter(data, present, DataMissingParamCodec(), opts...)
		if err != nil {
			return ProvideSubscriberInfoErrors{}, err
		}
		return ProvideSubscriberInfoErrors{DataMissing: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return ProvideSubscriberInfoErrors{}, err
		}
		return ProvideSubscriberInfoErrors{UnexpectedDataValue: p}, nil
	default:
		return ProvideSubscriberInfoErrors{}, fmt.Errorf("%w: error code %d is not in provideSubscriberInfo ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeProvideSubscriberInfoError(value ProvideSubscriberInfoErrors, opts ...ber.EncodeOption) (EncodedError, error) {
	selected := 0
	if value.DataMissing != nil {
		selected++
	}
	if value.UnexpectedDataValue != nil {
		selected++
	}
	if selected != 1 {
		return EncodedError{}, fmt.Errorf("%w: exactly one provideSubscriberInfo error arm is required", ber.ErrInvalidBinding)
	}
	if value.DataMissing != nil {
		return encodeMAPErrorMember(DataMissing, value.DataMissing, DataMissingParamCodec(), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	return EncodedError{}, fmt.Errorf("%w: no selected provideSubscriberInfo error", ber.ErrInvalidBinding)
}

// ProvideSubscriberLocationErrors selects exactly the formal ERRORS set of MAP-LocationServiceOperations.provideSubscriberLocation.
type ProvideSubscriberLocationErrors struct {
	SystemFailure                 *ErrorValue[SystemFailureParam]
	DataMissing                   *ErrorValue[DataMissingParam]
	UnexpectedDataValue           *ErrorValue[UnexpectedDataParam]
	FacilityNotSupported          *ErrorValue[FacilityNotSupParam]
	UnidentifiedSubscriber        *ErrorValue[UnidentifiedSubParam]
	IllegalSubscriber             *ErrorValue[IllegalSubscriberParam]
	IllegalEquipment              *ErrorValue[IllegalEquipmentParam]
	AbsentSubscriber              *ErrorValue[AbsentSubscriberParam]
	UnauthorizedRequestingNetwork *ErrorValue[UnauthorizedRequestingNetworkParam]
	UnauthorizedLCSClient         *ErrorValue[UnauthorizedLCSClientParam]
	PositionMethodFailure         *ErrorValue[PositionMethodFailureParam]
}

func infoProvideSubscriberLocationOperation() OperationInfo {
	return OperationInfo{Name: "provideSubscriberLocation", Code: ProvideSubscriberLocation, Argument: &TypeRef{ModuleOID: "0.4.0.0.1.3.25.22", ASN1Name: "ProvideSubscriberLocation-Arg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "ProvideSubscriberLocationArg"}, Result: &TypeRef{ModuleOID: "0.4.0.0.1.3.25.22", ASN1Name: "ProvideSubscriberLocation-Res", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "ProvideSubscriberLocationRes"}, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: false, Source: sourceInfo7("provideSubscriberLocation", "17.6.8"), Errors: []ErrorInfo{infoSystemFailureError(), infoDataMissingError(), infoUnexpectedDataValueError(), infoFacilityNotSupportedError(), infoUnidentifiedSubscriberError(), infoIllegalSubscriberError(), infoIllegalEquipmentError(), infoAbsentSubscriberError(), infoUnauthorizedRequestingNetworkError(), infoUnauthorizedLCSClientError(), infoPositionMethodFailureError()}, Linked: []MAPOperationCode{}}
}

// ProvideSubscriberLocationOperation binds the formal object in TS 29.002 V19.1.0 §17.6.8 (X.880 §§8.2–8.3).
func ProvideSubscriberLocationOperation() Operation[ProvideSubscriberLocationArg, ProvideSubscriberLocationRes, ProvideSubscriberLocationErrors] {
	return Operation[ProvideSubscriberLocationArg, ProvideSubscriberLocationRes, ProvideSubscriberLocationErrors]{operationBinding[ProvideSubscriberLocationArg, ProvideSubscriberLocationRes, ProvideSubscriberLocationErrors, OperationInfo, MAPOperationCode, EncodedError]{code: ProvideSubscriberLocation, info: infoProvideSubscriberLocationOperation, argument: ProvideSubscriberLocationArgCodec(), result: ProvideSubscriberLocationResCodec(), decode: decodeProvideSubscriberLocationError, encode: encodeProvideSubscriberLocationError}}
}
func decodeProvideSubscriberLocationError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (ProvideSubscriberLocationErrors, error) {
	switch code {
	case 34:
		p, err := decodeErrorParameter(data, present, SystemFailureParamCodec(), opts...)
		if err != nil {
			return ProvideSubscriberLocationErrors{}, err
		}
		return ProvideSubscriberLocationErrors{SystemFailure: p}, nil
	case 35:
		p, err := decodeErrorParameter(data, present, DataMissingParamCodec(), opts...)
		if err != nil {
			return ProvideSubscriberLocationErrors{}, err
		}
		return ProvideSubscriberLocationErrors{DataMissing: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return ProvideSubscriberLocationErrors{}, err
		}
		return ProvideSubscriberLocationErrors{UnexpectedDataValue: p}, nil
	case 21:
		p, err := decodeErrorParameter(data, present, FacilityNotSupParamCodec(), opts...)
		if err != nil {
			return ProvideSubscriberLocationErrors{}, err
		}
		return ProvideSubscriberLocationErrors{FacilityNotSupported: p}, nil
	case 5:
		p, err := decodeErrorParameter(data, present, UnidentifiedSubParamCodec(), opts...)
		if err != nil {
			return ProvideSubscriberLocationErrors{}, err
		}
		return ProvideSubscriberLocationErrors{UnidentifiedSubscriber: p}, nil
	case 9:
		p, err := decodeErrorParameter(data, present, IllegalSubscriberParamCodec(), opts...)
		if err != nil {
			return ProvideSubscriberLocationErrors{}, err
		}
		return ProvideSubscriberLocationErrors{IllegalSubscriber: p}, nil
	case 12:
		p, err := decodeErrorParameter(data, present, IllegalEquipmentParamCodec(), opts...)
		if err != nil {
			return ProvideSubscriberLocationErrors{}, err
		}
		return ProvideSubscriberLocationErrors{IllegalEquipment: p}, nil
	case 27:
		p, err := decodeErrorParameter(data, present, AbsentSubscriberParamCodec(), opts...)
		if err != nil {
			return ProvideSubscriberLocationErrors{}, err
		}
		return ProvideSubscriberLocationErrors{AbsentSubscriber: p}, nil
	case 52:
		p, err := decodeErrorParameter(data, present, UnauthorizedRequestingNetworkParamCodec(), opts...)
		if err != nil {
			return ProvideSubscriberLocationErrors{}, err
		}
		return ProvideSubscriberLocationErrors{UnauthorizedRequestingNetwork: p}, nil
	case 53:
		p, err := decodeErrorParameter(data, present, UnauthorizedLCSClientParamCodec(), opts...)
		if err != nil {
			return ProvideSubscriberLocationErrors{}, err
		}
		return ProvideSubscriberLocationErrors{UnauthorizedLCSClient: p}, nil
	case 54:
		p, err := decodeErrorParameter(data, present, PositionMethodFailureParamCodec(), opts...)
		if err != nil {
			return ProvideSubscriberLocationErrors{}, err
		}
		return ProvideSubscriberLocationErrors{PositionMethodFailure: p}, nil
	default:
		return ProvideSubscriberLocationErrors{}, fmt.Errorf("%w: error code %d is not in provideSubscriberLocation ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeProvideSubscriberLocationError(value ProvideSubscriberLocationErrors, opts ...ber.EncodeOption) (EncodedError, error) {
	selected := 0
	if value.SystemFailure != nil {
		selected++
	}
	if value.DataMissing != nil {
		selected++
	}
	if value.UnexpectedDataValue != nil {
		selected++
	}
	if value.FacilityNotSupported != nil {
		selected++
	}
	if value.UnidentifiedSubscriber != nil {
		selected++
	}
	if value.IllegalSubscriber != nil {
		selected++
	}
	if value.IllegalEquipment != nil {
		selected++
	}
	if value.AbsentSubscriber != nil {
		selected++
	}
	if value.UnauthorizedRequestingNetwork != nil {
		selected++
	}
	if value.UnauthorizedLCSClient != nil {
		selected++
	}
	if value.PositionMethodFailure != nil {
		selected++
	}
	if selected != 1 {
		return EncodedError{}, fmt.Errorf("%w: exactly one provideSubscriberLocation error arm is required", ber.ErrInvalidBinding)
	}
	if value.SystemFailure != nil {
		return encodeMAPErrorMember(SystemFailure, value.SystemFailure, SystemFailureParamCodec(), opts...)
	}
	if value.DataMissing != nil {
		return encodeMAPErrorMember(DataMissing, value.DataMissing, DataMissingParamCodec(), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	if value.FacilityNotSupported != nil {
		return encodeMAPErrorMember(FacilityNotSupported, value.FacilityNotSupported, FacilityNotSupParamCodec(), opts...)
	}
	if value.UnidentifiedSubscriber != nil {
		return encodeMAPErrorMember(UnidentifiedSubscriber, value.UnidentifiedSubscriber, UnidentifiedSubParamCodec(), opts...)
	}
	if value.IllegalSubscriber != nil {
		return encodeMAPErrorMember(IllegalSubscriber, value.IllegalSubscriber, IllegalSubscriberParamCodec(), opts...)
	}
	if value.IllegalEquipment != nil {
		return encodeMAPErrorMember(IllegalEquipment, value.IllegalEquipment, IllegalEquipmentParamCodec(), opts...)
	}
	if value.AbsentSubscriber != nil {
		return encodeMAPErrorMember(AbsentSubscriber, value.AbsentSubscriber, AbsentSubscriberParamCodec(), opts...)
	}
	if value.UnauthorizedRequestingNetwork != nil {
		return encodeMAPErrorMember(UnauthorizedRequestingNetwork, value.UnauthorizedRequestingNetwork, UnauthorizedRequestingNetworkParamCodec(), opts...)
	}
	if value.UnauthorizedLCSClient != nil {
		return encodeMAPErrorMember(UnauthorizedLCSClient, value.UnauthorizedLCSClient, UnauthorizedLCSClientParamCodec(), opts...)
	}
	if value.PositionMethodFailure != nil {
		return encodeMAPErrorMember(PositionMethodFailure, value.PositionMethodFailure, PositionMethodFailureParamCodec(), opts...)
	}
	return EncodedError{}, fmt.Errorf("%w: no selected provideSubscriberLocation error", ber.ErrInvalidBinding)
}

// PurgeMSErrors selects exactly the formal ERRORS set of MAP-MobileServiceOperations.purgeMS.
type PurgeMSErrors struct {
	DataMissing         *ErrorValue[DataMissingParam]
	UnexpectedDataValue *ErrorValue[UnexpectedDataParam]
	UnknownSubscriber   *ErrorValue[UnknownSubscriberParam]
}

func infoPurgeMSOperation() OperationInfo {
	return OperationInfo{Name: "purgeMS", Code: PurgeMS, Argument: &TypeRef{ModuleOID: "0.4.0.0.1.3.11.22", ASN1Name: "PurgeMS-Arg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "PurgeMSArg"}, Result: &TypeRef{ModuleOID: "0.4.0.0.1.3.11.22", ASN1Name: "PurgeMS-Res", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "PurgeMSRes"}, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: false, Source: sourceInfo4("purgeMS", "17.6.1"), Errors: []ErrorInfo{infoDataMissingError(), infoUnexpectedDataValueError(), infoUnknownSubscriberError()}, Linked: []MAPOperationCode{}}
}

// PurgeMSOperation binds the formal object in TS 29.002 V19.1.0 §17.6.1 (X.880 §§8.2–8.3).
func PurgeMSOperation() Operation[PurgeMSArg, PurgeMSRes, PurgeMSErrors] {
	return Operation[PurgeMSArg, PurgeMSRes, PurgeMSErrors]{operationBinding[PurgeMSArg, PurgeMSRes, PurgeMSErrors, OperationInfo, MAPOperationCode, EncodedError]{code: PurgeMS, info: infoPurgeMSOperation, argument: PurgeMSArgCodec(), result: PurgeMSResCodec(), decode: decodePurgeMSError, encode: encodePurgeMSError}}
}
func decodePurgeMSError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (PurgeMSErrors, error) {
	switch code {
	case 35:
		p, err := decodeErrorParameter(data, present, DataMissingParamCodec(), opts...)
		if err != nil {
			return PurgeMSErrors{}, err
		}
		return PurgeMSErrors{DataMissing: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return PurgeMSErrors{}, err
		}
		return PurgeMSErrors{UnexpectedDataValue: p}, nil
	case 1:
		p, err := decodeErrorParameter(data, present, UnknownSubscriberParamCodec(), opts...)
		if err != nil {
			return PurgeMSErrors{}, err
		}
		return PurgeMSErrors{UnknownSubscriber: p}, nil
	default:
		return PurgeMSErrors{}, fmt.Errorf("%w: error code %d is not in purgeMS ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodePurgeMSError(value PurgeMSErrors, opts ...ber.EncodeOption) (EncodedError, error) {
	selected := 0
	if value.DataMissing != nil {
		selected++
	}
	if value.UnexpectedDataValue != nil {
		selected++
	}
	if value.UnknownSubscriber != nil {
		selected++
	}
	if selected != 1 {
		return EncodedError{}, fmt.Errorf("%w: exactly one purgeMS error arm is required", ber.ErrInvalidBinding)
	}
	if value.DataMissing != nil {
		return encodeMAPErrorMember(DataMissing, value.DataMissing, DataMissingParamCodec(), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	if value.UnknownSubscriber != nil {
		return encodeMAPErrorMember(UnknownSubscriber, value.UnknownSubscriber, UnknownSubscriberParamCodec(), opts...)
	}
	return EncodedError{}, fmt.Errorf("%w: no selected purgeMS error", ber.ErrInvalidBinding)
}

// ReadyForSMErrors selects exactly the formal ERRORS set of MAP-ShortMessageServiceOperations.readyForSM.
type ReadyForSMErrors struct {
	DataMissing          *ErrorValue[DataMissingParam]
	UnexpectedDataValue  *ErrorValue[UnexpectedDataParam]
	FacilityNotSupported *ErrorValue[FacilityNotSupParam]
	UnknownSubscriber    *ErrorValue[UnknownSubscriberParam]
}

func infoReadyForSMOperation() OperationInfo {
	return OperationInfo{Name: "readyForSM", Code: ReadyForSM, Argument: &TypeRef{ModuleOID: "0.4.0.0.1.3.16.22", ASN1Name: "ReadyForSM-Arg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "ReadyForSMArg"}, Result: &TypeRef{ModuleOID: "0.4.0.0.1.3.16.22", ASN1Name: "ReadyForSM-Res", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "ReadyForSMRes"}, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: false, Source: sourceInfo3("readyForSM", "17.6.5"), Errors: []ErrorInfo{infoDataMissingError(), infoUnexpectedDataValueError(), infoFacilityNotSupportedError(), infoUnknownSubscriberError()}, Linked: []MAPOperationCode{}}
}

// ReadyForSMOperation binds the formal object in TS 29.002 V19.1.0 §17.6.5 (X.880 §§8.2–8.3).
func ReadyForSMOperation() Operation[ReadyForSMArg, ReadyForSMRes, ReadyForSMErrors] {
	return Operation[ReadyForSMArg, ReadyForSMRes, ReadyForSMErrors]{operationBinding[ReadyForSMArg, ReadyForSMRes, ReadyForSMErrors, OperationInfo, MAPOperationCode, EncodedError]{code: ReadyForSM, info: infoReadyForSMOperation, argument: ReadyForSMArgCodec(), result: ReadyForSMResCodec(), decode: decodeReadyForSMError, encode: encodeReadyForSMError}}
}
func decodeReadyForSMError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (ReadyForSMErrors, error) {
	switch code {
	case 35:
		p, err := decodeErrorParameter(data, present, DataMissingParamCodec(), opts...)
		if err != nil {
			return ReadyForSMErrors{}, err
		}
		return ReadyForSMErrors{DataMissing: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return ReadyForSMErrors{}, err
		}
		return ReadyForSMErrors{UnexpectedDataValue: p}, nil
	case 21:
		p, err := decodeErrorParameter(data, present, FacilityNotSupParamCodec(), opts...)
		if err != nil {
			return ReadyForSMErrors{}, err
		}
		return ReadyForSMErrors{FacilityNotSupported: p}, nil
	case 1:
		p, err := decodeErrorParameter(data, present, UnknownSubscriberParamCodec(), opts...)
		if err != nil {
			return ReadyForSMErrors{}, err
		}
		return ReadyForSMErrors{UnknownSubscriber: p}, nil
	default:
		return ReadyForSMErrors{}, fmt.Errorf("%w: error code %d is not in readyForSM ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeReadyForSMError(value ReadyForSMErrors, opts ...ber.EncodeOption) (EncodedError, error) {
	selected := 0
	if value.DataMissing != nil {
		selected++
	}
	if value.UnexpectedDataValue != nil {
		selected++
	}
	if value.FacilityNotSupported != nil {
		selected++
	}
	if value.UnknownSubscriber != nil {
		selected++
	}
	if selected != 1 {
		return EncodedError{}, fmt.Errorf("%w: exactly one readyForSM error arm is required", ber.ErrInvalidBinding)
	}
	if value.DataMissing != nil {
		return encodeMAPErrorMember(DataMissing, value.DataMissing, DataMissingParamCodec(), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	if value.FacilityNotSupported != nil {
		return encodeMAPErrorMember(FacilityNotSupported, value.FacilityNotSupported, FacilityNotSupParamCodec(), opts...)
	}
	if value.UnknownSubscriber != nil {
		return encodeMAPErrorMember(UnknownSubscriber, value.UnknownSubscriber, UnknownSubscriberParamCodec(), opts...)
	}
	return EncodedError{}, fmt.Errorf("%w: no selected readyForSM error", ber.ErrInvalidBinding)
}

// RegisterCCEntryErrors selects exactly the formal ERRORS set of MAP-SupplementaryServiceOperations.registerCC-Entry.
type RegisterCCEntryErrors struct {
	SystemFailure        *ErrorValue[SystemFailureParam]
	DataMissing          *ErrorValue[DataMissingParam]
	UnexpectedDataValue  *ErrorValue[UnexpectedDataParam]
	CallBarred           *ErrorValue[CallBarredParam]
	IllegalSSOperation   *ErrorValue[IllegalSSOperationParam]
	SsErrorStatus        *ErrorValue[BERValue[SSStatus]]
	SsIncompatibility    *ErrorValue[SSIncompatibilityCause]
	ShortTermDenial      *ErrorValue[ShortTermDenialParam]
	LongTermDenial       *ErrorValue[LongTermDenialParam]
	FacilityNotSupported *ErrorValue[FacilityNotSupParam]
}

func infoRegisterCCEntryOperation() OperationInfo {
	return OperationInfo{Name: "registerCC-Entry", Code: RegisterCCEntry, Argument: &TypeRef{ModuleOID: "0.4.0.0.1.3.14.22", ASN1Name: "RegisterCC-EntryArg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "RegisterCCEntryArg"}, Result: &TypeRef{ModuleOID: "0.4.0.0.1.3.14.22", ASN1Name: "RegisterCC-EntryRes", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "RegisterCCEntryRes"}, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: false, Source: sourceInfo1("registerCC-Entry", "17.6.4"), Errors: []ErrorInfo{infoSystemFailureError(), infoDataMissingError(), infoUnexpectedDataValueError(), infoCallBarredError(), infoIllegalSSOperationError(), infoSsErrorStatusError(), infoSsIncompatibilityError(), infoShortTermDenialError(), infoLongTermDenialError(), infoFacilityNotSupportedError()}, Linked: []MAPOperationCode{}}
}

// RegisterCCEntryOperation binds the formal object in TS 29.002 V19.1.0 §17.6.4 (X.880 §§8.2–8.3).
func RegisterCCEntryOperation() Operation[RegisterCCEntryArg, RegisterCCEntryRes, RegisterCCEntryErrors] {
	return Operation[RegisterCCEntryArg, RegisterCCEntryRes, RegisterCCEntryErrors]{operationBinding[RegisterCCEntryArg, RegisterCCEntryRes, RegisterCCEntryErrors, OperationInfo, MAPOperationCode, EncodedError]{code: RegisterCCEntry, info: infoRegisterCCEntryOperation, argument: RegisterCCEntryArgCodec(), result: RegisterCCEntryResCodec(), decode: decodeRegisterCCEntryError, encode: encodeRegisterCCEntryError}}
}
func decodeRegisterCCEntryError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (RegisterCCEntryErrors, error) {
	switch code {
	case 34:
		p, err := decodeErrorParameter(data, present, SystemFailureParamCodec(), opts...)
		if err != nil {
			return RegisterCCEntryErrors{}, err
		}
		return RegisterCCEntryErrors{SystemFailure: p}, nil
	case 35:
		p, err := decodeErrorParameter(data, present, DataMissingParamCodec(), opts...)
		if err != nil {
			return RegisterCCEntryErrors{}, err
		}
		return RegisterCCEntryErrors{DataMissing: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return RegisterCCEntryErrors{}, err
		}
		return RegisterCCEntryErrors{UnexpectedDataValue: p}, nil
	case 13:
		p, err := decodeErrorParameter(data, present, CallBarredParamCodec(), opts...)
		if err != nil {
			return RegisterCCEntryErrors{}, err
		}
		return RegisterCCEntryErrors{CallBarred: p}, nil
	case 16:
		p, err := decodeErrorParameter(data, present, IllegalSSOperationParamCodec(), opts...)
		if err != nil {
			return RegisterCCEntryErrors{}, err
		}
		return RegisterCCEntryErrors{IllegalSSOperation: p}, nil
	case 17:
		p, err := decodeErrorParameter(data, present, SSStatusCodec(), opts...)
		if err != nil {
			return RegisterCCEntryErrors{}, err
		}
		return RegisterCCEntryErrors{SsErrorStatus: p}, nil
	case 20:
		p, err := decodeErrorParameter(data, present, SSIncompatibilityCauseCodec(), opts...)
		if err != nil {
			return RegisterCCEntryErrors{}, err
		}
		return RegisterCCEntryErrors{SsIncompatibility: p}, nil
	case 29:
		p, err := decodeErrorParameter(data, present, ShortTermDenialParamCodec(), opts...)
		if err != nil {
			return RegisterCCEntryErrors{}, err
		}
		return RegisterCCEntryErrors{ShortTermDenial: p}, nil
	case 30:
		p, err := decodeErrorParameter(data, present, LongTermDenialParamCodec(), opts...)
		if err != nil {
			return RegisterCCEntryErrors{}, err
		}
		return RegisterCCEntryErrors{LongTermDenial: p}, nil
	case 21:
		p, err := decodeErrorParameter(data, present, FacilityNotSupParamCodec(), opts...)
		if err != nil {
			return RegisterCCEntryErrors{}, err
		}
		return RegisterCCEntryErrors{FacilityNotSupported: p}, nil
	default:
		return RegisterCCEntryErrors{}, fmt.Errorf("%w: error code %d is not in registerCC-Entry ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeRegisterCCEntryError(value RegisterCCEntryErrors, opts ...ber.EncodeOption) (EncodedError, error) {
	selected := 0
	if value.SystemFailure != nil {
		selected++
	}
	if value.DataMissing != nil {
		selected++
	}
	if value.UnexpectedDataValue != nil {
		selected++
	}
	if value.CallBarred != nil {
		selected++
	}
	if value.IllegalSSOperation != nil {
		selected++
	}
	if value.SsErrorStatus != nil {
		selected++
	}
	if value.SsIncompatibility != nil {
		selected++
	}
	if value.ShortTermDenial != nil {
		selected++
	}
	if value.LongTermDenial != nil {
		selected++
	}
	if value.FacilityNotSupported != nil {
		selected++
	}
	if selected != 1 {
		return EncodedError{}, fmt.Errorf("%w: exactly one registerCC-Entry error arm is required", ber.ErrInvalidBinding)
	}
	if value.SystemFailure != nil {
		return encodeMAPErrorMember(SystemFailure, value.SystemFailure, SystemFailureParamCodec(), opts...)
	}
	if value.DataMissing != nil {
		return encodeMAPErrorMember(DataMissing, value.DataMissing, DataMissingParamCodec(), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	if value.CallBarred != nil {
		return encodeMAPErrorMember(CallBarred, value.CallBarred, CallBarredParamCodec(), opts...)
	}
	if value.IllegalSSOperation != nil {
		return encodeMAPErrorMember(IllegalSSOperation, value.IllegalSSOperation, IllegalSSOperationParamCodec(), opts...)
	}
	if value.SsErrorStatus != nil {
		return encodeMAPErrorMember(SsErrorStatus, value.SsErrorStatus, SSStatusCodec(), opts...)
	}
	if value.SsIncompatibility != nil {
		return encodeMAPErrorMember(SsIncompatibility, value.SsIncompatibility, SSIncompatibilityCauseCodec(), opts...)
	}
	if value.ShortTermDenial != nil {
		return encodeMAPErrorMember(ShortTermDenial, value.ShortTermDenial, ShortTermDenialParamCodec(), opts...)
	}
	if value.LongTermDenial != nil {
		return encodeMAPErrorMember(LongTermDenial, value.LongTermDenial, LongTermDenialParamCodec(), opts...)
	}
	if value.FacilityNotSupported != nil {
		return encodeMAPErrorMember(FacilityNotSupported, value.FacilityNotSupported, FacilityNotSupParamCodec(), opts...)
	}
	return EncodedError{}, fmt.Errorf("%w: no selected registerCC-Entry error", ber.ErrInvalidBinding)
}

// RegisterPasswordErrors selects exactly the formal ERRORS set of MAP-SupplementaryServiceOperations.registerPassword.
type RegisterPasswordErrors struct {
	SystemFailure               *ErrorValue[SystemFailureParam]
	DataMissing                 *ErrorValue[DataMissingParam]
	UnexpectedDataValue         *ErrorValue[UnexpectedDataParam]
	CallBarred                  *ErrorValue[CallBarredParam]
	SsSubscriptionViolation     *ErrorValue[SSSubscriptionViolationParam]
	PwRegistrationFailure       *ErrorValue[BERValue[PWRegistrationFailureCause]]
	NegativePWCheck             *ErrorValue[NoParameter]
	NumberOfPWAttemptsViolation *ErrorValue[NoParameter]
}

func infoRegisterPasswordOperation() OperationInfo {
	return OperationInfo{Name: "registerPassword", Code: RegisterPassword, Argument: &TypeRef{ModuleOID: "0.4.0.0.1.3.15.22", ASN1Name: "SS-Code", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "SSCode"}, Result: &TypeRef{ModuleOID: "0.4.0.0.1.3.14.22", ASN1Name: "Password", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "Password"}, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: false, Source: sourceInfo1("registerPassword", "17.6.4"), Errors: []ErrorInfo{infoSystemFailureError(), infoDataMissingError(), infoUnexpectedDataValueError(), infoCallBarredError(), infoSsSubscriptionViolationError(), infoPwRegistrationFailureError(), infoNegativePWCheckError(), infoNumberOfPWAttemptsViolationError()}, Linked: []MAPOperationCode{GetPassword}}
}

// RegisterPasswordOperation binds the formal object in TS 29.002 V19.1.0 §17.6.4 (X.880 §§8.2–8.3).
func RegisterPasswordOperation() Operation[BERValue[SSCode], BERValue[Password], RegisterPasswordErrors] {
	return Operation[BERValue[SSCode], BERValue[Password], RegisterPasswordErrors]{operationBinding[BERValue[SSCode], BERValue[Password], RegisterPasswordErrors, OperationInfo, MAPOperationCode, EncodedError]{code: RegisterPassword, info: infoRegisterPasswordOperation, argument: SSCodeCodec(), result: PasswordCodec(), decode: decodeRegisterPasswordError, encode: encodeRegisterPasswordError}}
}
func decodeRegisterPasswordError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (RegisterPasswordErrors, error) {
	switch code {
	case 34:
		p, err := decodeErrorParameter(data, present, SystemFailureParamCodec(), opts...)
		if err != nil {
			return RegisterPasswordErrors{}, err
		}
		return RegisterPasswordErrors{SystemFailure: p}, nil
	case 35:
		p, err := decodeErrorParameter(data, present, DataMissingParamCodec(), opts...)
		if err != nil {
			return RegisterPasswordErrors{}, err
		}
		return RegisterPasswordErrors{DataMissing: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return RegisterPasswordErrors{}, err
		}
		return RegisterPasswordErrors{UnexpectedDataValue: p}, nil
	case 13:
		p, err := decodeErrorParameter(data, present, CallBarredParamCodec(), opts...)
		if err != nil {
			return RegisterPasswordErrors{}, err
		}
		return RegisterPasswordErrors{CallBarred: p}, nil
	case 19:
		p, err := decodeErrorParameter(data, present, SSSubscriptionViolationParamCodec(), opts...)
		if err != nil {
			return RegisterPasswordErrors{}, err
		}
		return RegisterPasswordErrors{SsSubscriptionViolation: p}, nil
	case 37:
		p, err := decodeErrorParameter(data, present, PWRegistrationFailureCauseCodec(), opts...)
		if err != nil {
			return RegisterPasswordErrors{}, err
		}
		return RegisterPasswordErrors{PwRegistrationFailure: p}, nil
	case 38:
		p, err := decodeErrorParameter(data, present, ValueCodec[NoParameter]{}, opts...)
		if err != nil {
			return RegisterPasswordErrors{}, err
		}
		return RegisterPasswordErrors{NegativePWCheck: p}, nil
	case 43:
		p, err := decodeErrorParameter(data, present, ValueCodec[NoParameter]{}, opts...)
		if err != nil {
			return RegisterPasswordErrors{}, err
		}
		return RegisterPasswordErrors{NumberOfPWAttemptsViolation: p}, nil
	default:
		return RegisterPasswordErrors{}, fmt.Errorf("%w: error code %d is not in registerPassword ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeRegisterPasswordError(value RegisterPasswordErrors, opts ...ber.EncodeOption) (EncodedError, error) {
	selected := 0
	if value.SystemFailure != nil {
		selected++
	}
	if value.DataMissing != nil {
		selected++
	}
	if value.UnexpectedDataValue != nil {
		selected++
	}
	if value.CallBarred != nil {
		selected++
	}
	if value.SsSubscriptionViolation != nil {
		selected++
	}
	if value.PwRegistrationFailure != nil {
		selected++
	}
	if value.NegativePWCheck != nil {
		selected++
	}
	if value.NumberOfPWAttemptsViolation != nil {
		selected++
	}
	if selected != 1 {
		return EncodedError{}, fmt.Errorf("%w: exactly one registerPassword error arm is required", ber.ErrInvalidBinding)
	}
	if value.SystemFailure != nil {
		return encodeMAPErrorMember(SystemFailure, value.SystemFailure, SystemFailureParamCodec(), opts...)
	}
	if value.DataMissing != nil {
		return encodeMAPErrorMember(DataMissing, value.DataMissing, DataMissingParamCodec(), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	if value.CallBarred != nil {
		return encodeMAPErrorMember(CallBarred, value.CallBarred, CallBarredParamCodec(), opts...)
	}
	if value.SsSubscriptionViolation != nil {
		return encodeMAPErrorMember(SsSubscriptionViolation, value.SsSubscriptionViolation, SSSubscriptionViolationParamCodec(), opts...)
	}
	if value.PwRegistrationFailure != nil {
		return encodeMAPErrorMember(PwRegistrationFailure, value.PwRegistrationFailure, PWRegistrationFailureCauseCodec(), opts...)
	}
	if value.NegativePWCheck != nil {
		return encodeMAPErrorMember(NegativePWCheck, value.NegativePWCheck, ValueCodec[NoParameter]{}, opts...)
	}
	if value.NumberOfPWAttemptsViolation != nil {
		return encodeMAPErrorMember(NumberOfPWAttemptsViolation, value.NumberOfPWAttemptsViolation, ValueCodec[NoParameter]{}, opts...)
	}
	return EncodedError{}, fmt.Errorf("%w: no selected registerPassword error", ber.ErrInvalidBinding)
}

// RegisterSSErrors selects exactly the formal ERRORS set of MAP-SupplementaryServiceOperations.registerSS.
type RegisterSSErrors struct {
	SystemFailure               *ErrorValue[SystemFailureParam]
	DataMissing                 *ErrorValue[DataMissingParam]
	UnexpectedDataValue         *ErrorValue[UnexpectedDataParam]
	BearerServiceNotProvisioned *ErrorValue[BearerServNotProvParam]
	TeleserviceNotProvisioned   *ErrorValue[TeleservNotProvParam]
	CallBarred                  *ErrorValue[CallBarredParam]
	IllegalSSOperation          *ErrorValue[IllegalSSOperationParam]
	SsErrorStatus               *ErrorValue[BERValue[SSStatus]]
	SsIncompatibility           *ErrorValue[SSIncompatibilityCause]
}

func infoRegisterSSOperation() OperationInfo {
	return OperationInfo{Name: "registerSS", Code: RegisterSS, Argument: &TypeRef{ModuleOID: "0.4.0.0.1.3.14.22", ASN1Name: "RegisterSS-Arg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "RegisterSSArg"}, Result: &TypeRef{ModuleOID: "0.4.0.0.1.3.14.22", ASN1Name: "SS-Info", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "SSInfo"}, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: false, Source: sourceInfo1("registerSS", "17.6.4"), Errors: []ErrorInfo{infoSystemFailureError(), infoDataMissingError(), infoUnexpectedDataValueError(), infoBearerServiceNotProvisionedError(), infoTeleserviceNotProvisionedError(), infoCallBarredError(), infoIllegalSSOperationError(), infoSsErrorStatusError(), infoSsIncompatibilityError()}, Linked: []MAPOperationCode{}}
}

// RegisterSSOperation binds the formal object in TS 29.002 V19.1.0 §17.6.4 (X.880 §§8.2–8.3).
func RegisterSSOperation() Operation[RegisterSSArg, SSInfo, RegisterSSErrors] {
	return Operation[RegisterSSArg, SSInfo, RegisterSSErrors]{operationBinding[RegisterSSArg, SSInfo, RegisterSSErrors, OperationInfo, MAPOperationCode, EncodedError]{code: RegisterSS, info: infoRegisterSSOperation, argument: RegisterSSArgCodec(), result: SSInfoCodec(), decode: decodeRegisterSSError, encode: encodeRegisterSSError}}
}
func decodeRegisterSSError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (RegisterSSErrors, error) {
	switch code {
	case 34:
		p, err := decodeErrorParameter(data, present, SystemFailureParamCodec(), opts...)
		if err != nil {
			return RegisterSSErrors{}, err
		}
		return RegisterSSErrors{SystemFailure: p}, nil
	case 35:
		p, err := decodeErrorParameter(data, present, DataMissingParamCodec(), opts...)
		if err != nil {
			return RegisterSSErrors{}, err
		}
		return RegisterSSErrors{DataMissing: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return RegisterSSErrors{}, err
		}
		return RegisterSSErrors{UnexpectedDataValue: p}, nil
	case 10:
		p, err := decodeErrorParameter(data, present, BearerServNotProvParamCodec(), opts...)
		if err != nil {
			return RegisterSSErrors{}, err
		}
		return RegisterSSErrors{BearerServiceNotProvisioned: p}, nil
	case 11:
		p, err := decodeErrorParameter(data, present, TeleservNotProvParamCodec(), opts...)
		if err != nil {
			return RegisterSSErrors{}, err
		}
		return RegisterSSErrors{TeleserviceNotProvisioned: p}, nil
	case 13:
		p, err := decodeErrorParameter(data, present, CallBarredParamCodec(), opts...)
		if err != nil {
			return RegisterSSErrors{}, err
		}
		return RegisterSSErrors{CallBarred: p}, nil
	case 16:
		p, err := decodeErrorParameter(data, present, IllegalSSOperationParamCodec(), opts...)
		if err != nil {
			return RegisterSSErrors{}, err
		}
		return RegisterSSErrors{IllegalSSOperation: p}, nil
	case 17:
		p, err := decodeErrorParameter(data, present, SSStatusCodec(), opts...)
		if err != nil {
			return RegisterSSErrors{}, err
		}
		return RegisterSSErrors{SsErrorStatus: p}, nil
	case 20:
		p, err := decodeErrorParameter(data, present, SSIncompatibilityCauseCodec(), opts...)
		if err != nil {
			return RegisterSSErrors{}, err
		}
		return RegisterSSErrors{SsIncompatibility: p}, nil
	default:
		return RegisterSSErrors{}, fmt.Errorf("%w: error code %d is not in registerSS ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeRegisterSSError(value RegisterSSErrors, opts ...ber.EncodeOption) (EncodedError, error) {
	selected := 0
	if value.SystemFailure != nil {
		selected++
	}
	if value.DataMissing != nil {
		selected++
	}
	if value.UnexpectedDataValue != nil {
		selected++
	}
	if value.BearerServiceNotProvisioned != nil {
		selected++
	}
	if value.TeleserviceNotProvisioned != nil {
		selected++
	}
	if value.CallBarred != nil {
		selected++
	}
	if value.IllegalSSOperation != nil {
		selected++
	}
	if value.SsErrorStatus != nil {
		selected++
	}
	if value.SsIncompatibility != nil {
		selected++
	}
	if selected != 1 {
		return EncodedError{}, fmt.Errorf("%w: exactly one registerSS error arm is required", ber.ErrInvalidBinding)
	}
	if value.SystemFailure != nil {
		return encodeMAPErrorMember(SystemFailure, value.SystemFailure, SystemFailureParamCodec(), opts...)
	}
	if value.DataMissing != nil {
		return encodeMAPErrorMember(DataMissing, value.DataMissing, DataMissingParamCodec(), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	if value.BearerServiceNotProvisioned != nil {
		return encodeMAPErrorMember(BearerServiceNotProvisioned, value.BearerServiceNotProvisioned, BearerServNotProvParamCodec(), opts...)
	}
	if value.TeleserviceNotProvisioned != nil {
		return encodeMAPErrorMember(TeleserviceNotProvisioned, value.TeleserviceNotProvisioned, TeleservNotProvParamCodec(), opts...)
	}
	if value.CallBarred != nil {
		return encodeMAPErrorMember(CallBarred, value.CallBarred, CallBarredParamCodec(), opts...)
	}
	if value.IllegalSSOperation != nil {
		return encodeMAPErrorMember(IllegalSSOperation, value.IllegalSSOperation, IllegalSSOperationParamCodec(), opts...)
	}
	if value.SsErrorStatus != nil {
		return encodeMAPErrorMember(SsErrorStatus, value.SsErrorStatus, SSStatusCodec(), opts...)
	}
	if value.SsIncompatibility != nil {
		return encodeMAPErrorMember(SsIncompatibility, value.SsIncompatibility, SSIncompatibilityCauseCodec(), opts...)
	}
	return EncodedError{}, fmt.Errorf("%w: no selected registerSS error", ber.ErrInvalidBinding)
}

// ReleaseResourcesErrors selects exactly the formal ERRORS set of MAP-CallHandlingOperations.releaseResources.
type ReleaseResourcesErrors struct {
	UnexpectedDataValue *ErrorValue[UnexpectedDataParam]
	SystemFailure       *ErrorValue[SystemFailureParam]
}

func infoReleaseResourcesOperation() OperationInfo {
	return OperationInfo{Name: "releaseResources", Code: ReleaseResources, Argument: &TypeRef{ModuleOID: "0.4.0.0.1.3.13.22", ASN1Name: "ReleaseResourcesArg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "ReleaseResourcesArg"}, Result: &TypeRef{ModuleOID: "0.4.0.0.1.3.13.22", ASN1Name: "ReleaseResourcesRes", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "ReleaseResourcesRes"}, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: false, Source: sourceInfo6("releaseResources", "17.6.3"), Errors: []ErrorInfo{infoUnexpectedDataValueError(), infoSystemFailureError()}, Linked: []MAPOperationCode{}}
}

// ReleaseResourcesOperation binds the formal object in TS 29.002 V19.1.0 §17.6.3 (X.880 §§8.2–8.3).
func ReleaseResourcesOperation() Operation[ReleaseResourcesArg, ReleaseResourcesRes, ReleaseResourcesErrors] {
	return Operation[ReleaseResourcesArg, ReleaseResourcesRes, ReleaseResourcesErrors]{operationBinding[ReleaseResourcesArg, ReleaseResourcesRes, ReleaseResourcesErrors, OperationInfo, MAPOperationCode, EncodedError]{code: ReleaseResources, info: infoReleaseResourcesOperation, argument: ReleaseResourcesArgCodec(), result: ReleaseResourcesResCodec(), decode: decodeReleaseResourcesError, encode: encodeReleaseResourcesError}}
}
func decodeReleaseResourcesError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (ReleaseResourcesErrors, error) {
	switch code {
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return ReleaseResourcesErrors{}, err
		}
		return ReleaseResourcesErrors{UnexpectedDataValue: p}, nil
	case 34:
		p, err := decodeErrorParameter(data, present, SystemFailureParamCodec(), opts...)
		if err != nil {
			return ReleaseResourcesErrors{}, err
		}
		return ReleaseResourcesErrors{SystemFailure: p}, nil
	default:
		return ReleaseResourcesErrors{}, fmt.Errorf("%w: error code %d is not in releaseResources ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeReleaseResourcesError(value ReleaseResourcesErrors, opts ...ber.EncodeOption) (EncodedError, error) {
	selected := 0
	if value.UnexpectedDataValue != nil {
		selected++
	}
	if value.SystemFailure != nil {
		selected++
	}
	if selected != 1 {
		return EncodedError{}, fmt.Errorf("%w: exactly one releaseResources error arm is required", ber.ErrInvalidBinding)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	if value.SystemFailure != nil {
		return encodeMAPErrorMember(SystemFailure, value.SystemFailure, SystemFailureParamCodec(), opts...)
	}
	return EncodedError{}, fmt.Errorf("%w: no selected releaseResources error", ber.ErrInvalidBinding)
}

// RemoteUserFreeErrors selects exactly the formal ERRORS set of MAP-CallHandlingOperations.remoteUserFree.
type RemoteUserFreeErrors struct {
	UnexpectedDataValue  *ErrorValue[UnexpectedDataParam]
	DataMissing          *ErrorValue[DataMissingParam]
	IncompatibleTerminal *ErrorValue[IncompatibleTerminalParam]
	AbsentSubscriber     *ErrorValue[AbsentSubscriberParam]
	SystemFailure        *ErrorValue[SystemFailureParam]
	BusySubscriber       *ErrorValue[BusySubscriberParam]
}

func infoRemoteUserFreeOperation() OperationInfo {
	return OperationInfo{Name: "remoteUserFree", Code: RemoteUserFree, Argument: &TypeRef{ModuleOID: "0.4.0.0.1.3.13.22", ASN1Name: "RemoteUserFreeArg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "RemoteUserFreeArg"}, Result: &TypeRef{ModuleOID: "0.4.0.0.1.3.13.22", ASN1Name: "RemoteUserFreeRes", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "RemoteUserFreeRes"}, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: false, Source: sourceInfo6("remoteUserFree", "17.6.3"), Errors: []ErrorInfo{infoUnexpectedDataValueError(), infoDataMissingError(), infoIncompatibleTerminalError(), infoAbsentSubscriberError(), infoSystemFailureError(), infoBusySubscriberError()}, Linked: []MAPOperationCode{}}
}

// RemoteUserFreeOperation binds the formal object in TS 29.002 V19.1.0 §17.6.3 (X.880 §§8.2–8.3).
func RemoteUserFreeOperation() Operation[RemoteUserFreeArg, RemoteUserFreeRes, RemoteUserFreeErrors] {
	return Operation[RemoteUserFreeArg, RemoteUserFreeRes, RemoteUserFreeErrors]{operationBinding[RemoteUserFreeArg, RemoteUserFreeRes, RemoteUserFreeErrors, OperationInfo, MAPOperationCode, EncodedError]{code: RemoteUserFree, info: infoRemoteUserFreeOperation, argument: RemoteUserFreeArgCodec(), result: RemoteUserFreeResCodec(), decode: decodeRemoteUserFreeError, encode: encodeRemoteUserFreeError}}
}
func decodeRemoteUserFreeError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (RemoteUserFreeErrors, error) {
	switch code {
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return RemoteUserFreeErrors{}, err
		}
		return RemoteUserFreeErrors{UnexpectedDataValue: p}, nil
	case 35:
		p, err := decodeErrorParameter(data, present, DataMissingParamCodec(), opts...)
		if err != nil {
			return RemoteUserFreeErrors{}, err
		}
		return RemoteUserFreeErrors{DataMissing: p}, nil
	case 28:
		p, err := decodeErrorParameter(data, present, IncompatibleTerminalParamCodec(), opts...)
		if err != nil {
			return RemoteUserFreeErrors{}, err
		}
		return RemoteUserFreeErrors{IncompatibleTerminal: p}, nil
	case 27:
		p, err := decodeErrorParameter(data, present, AbsentSubscriberParamCodec(), opts...)
		if err != nil {
			return RemoteUserFreeErrors{}, err
		}
		return RemoteUserFreeErrors{AbsentSubscriber: p}, nil
	case 34:
		p, err := decodeErrorParameter(data, present, SystemFailureParamCodec(), opts...)
		if err != nil {
			return RemoteUserFreeErrors{}, err
		}
		return RemoteUserFreeErrors{SystemFailure: p}, nil
	case 45:
		p, err := decodeErrorParameter(data, present, BusySubscriberParamCodec(), opts...)
		if err != nil {
			return RemoteUserFreeErrors{}, err
		}
		return RemoteUserFreeErrors{BusySubscriber: p}, nil
	default:
		return RemoteUserFreeErrors{}, fmt.Errorf("%w: error code %d is not in remoteUserFree ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeRemoteUserFreeError(value RemoteUserFreeErrors, opts ...ber.EncodeOption) (EncodedError, error) {
	selected := 0
	if value.UnexpectedDataValue != nil {
		selected++
	}
	if value.DataMissing != nil {
		selected++
	}
	if value.IncompatibleTerminal != nil {
		selected++
	}
	if value.AbsentSubscriber != nil {
		selected++
	}
	if value.SystemFailure != nil {
		selected++
	}
	if value.BusySubscriber != nil {
		selected++
	}
	if selected != 1 {
		return EncodedError{}, fmt.Errorf("%w: exactly one remoteUserFree error arm is required", ber.ErrInvalidBinding)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	if value.DataMissing != nil {
		return encodeMAPErrorMember(DataMissing, value.DataMissing, DataMissingParamCodec(), opts...)
	}
	if value.IncompatibleTerminal != nil {
		return encodeMAPErrorMember(IncompatibleTerminal, value.IncompatibleTerminal, IncompatibleTerminalParamCodec(), opts...)
	}
	if value.AbsentSubscriber != nil {
		return encodeMAPErrorMember(AbsentSubscriber, value.AbsentSubscriber, AbsentSubscriberParamCodec(), opts...)
	}
	if value.SystemFailure != nil {
		return encodeMAPErrorMember(SystemFailure, value.SystemFailure, SystemFailureParamCodec(), opts...)
	}
	if value.BusySubscriber != nil {
		return encodeMAPErrorMember(BusySubscriber, value.BusySubscriber, BusySubscriberParamCodec(), opts...)
	}
	return EncodedError{}, fmt.Errorf("%w: no selected remoteUserFree error", ber.ErrInvalidBinding)
}

// ReportSMDeliveryStatusErrors selects exactly the formal ERRORS set of MAP-ShortMessageServiceOperations.reportSM-DeliveryStatus.
type ReportSMDeliveryStatusErrors struct {
	DataMissing            *ErrorValue[DataMissingParam]
	UnexpectedDataValue    *ErrorValue[UnexpectedDataParam]
	UnknownSubscriber      *ErrorValue[UnknownSubscriberParam]
	MessageWaitingListFull *ErrorValue[MessageWaitListFullParam]
}

func infoReportSMDeliveryStatusOperation() OperationInfo {
	return OperationInfo{Name: "reportSM-DeliveryStatus", Code: ReportSMDeliveryStatus, Argument: &TypeRef{ModuleOID: "0.4.0.0.1.3.16.22", ASN1Name: "ReportSM-DeliveryStatusArg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "ReportSMDeliveryStatusArg"}, Result: &TypeRef{ModuleOID: "0.4.0.0.1.3.16.22", ASN1Name: "ReportSM-DeliveryStatusRes", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "ReportSMDeliveryStatusRes"}, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: false, Source: sourceInfo3("reportSM-DeliveryStatus", "17.6.5"), Errors: []ErrorInfo{infoDataMissingError(), infoUnexpectedDataValueError(), infoUnknownSubscriberError(), infoMessageWaitingListFullError()}, Linked: []MAPOperationCode{}}
}

// ReportSMDeliveryStatusOperation binds the formal object in TS 29.002 V19.1.0 §17.6.5 (X.880 §§8.2–8.3).
func ReportSMDeliveryStatusOperation() Operation[ReportSMDeliveryStatusArg, ReportSMDeliveryStatusRes, ReportSMDeliveryStatusErrors] {
	return Operation[ReportSMDeliveryStatusArg, ReportSMDeliveryStatusRes, ReportSMDeliveryStatusErrors]{operationBinding[ReportSMDeliveryStatusArg, ReportSMDeliveryStatusRes, ReportSMDeliveryStatusErrors, OperationInfo, MAPOperationCode, EncodedError]{code: ReportSMDeliveryStatus, info: infoReportSMDeliveryStatusOperation, argument: ReportSMDeliveryStatusArgCodec(), result: ReportSMDeliveryStatusResCodec(), decode: decodeReportSMDeliveryStatusError, encode: encodeReportSMDeliveryStatusError}}
}
func decodeReportSMDeliveryStatusError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (ReportSMDeliveryStatusErrors, error) {
	switch code {
	case 35:
		p, err := decodeErrorParameter(data, present, DataMissingParamCodec(), opts...)
		if err != nil {
			return ReportSMDeliveryStatusErrors{}, err
		}
		return ReportSMDeliveryStatusErrors{DataMissing: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return ReportSMDeliveryStatusErrors{}, err
		}
		return ReportSMDeliveryStatusErrors{UnexpectedDataValue: p}, nil
	case 1:
		p, err := decodeErrorParameter(data, present, UnknownSubscriberParamCodec(), opts...)
		if err != nil {
			return ReportSMDeliveryStatusErrors{}, err
		}
		return ReportSMDeliveryStatusErrors{UnknownSubscriber: p}, nil
	case 33:
		p, err := decodeErrorParameter(data, present, MessageWaitListFullParamCodec(), opts...)
		if err != nil {
			return ReportSMDeliveryStatusErrors{}, err
		}
		return ReportSMDeliveryStatusErrors{MessageWaitingListFull: p}, nil
	default:
		return ReportSMDeliveryStatusErrors{}, fmt.Errorf("%w: error code %d is not in reportSM-DeliveryStatus ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeReportSMDeliveryStatusError(value ReportSMDeliveryStatusErrors, opts ...ber.EncodeOption) (EncodedError, error) {
	selected := 0
	if value.DataMissing != nil {
		selected++
	}
	if value.UnexpectedDataValue != nil {
		selected++
	}
	if value.UnknownSubscriber != nil {
		selected++
	}
	if value.MessageWaitingListFull != nil {
		selected++
	}
	if selected != 1 {
		return EncodedError{}, fmt.Errorf("%w: exactly one reportSM-DeliveryStatus error arm is required", ber.ErrInvalidBinding)
	}
	if value.DataMissing != nil {
		return encodeMAPErrorMember(DataMissing, value.DataMissing, DataMissingParamCodec(), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	if value.UnknownSubscriber != nil {
		return encodeMAPErrorMember(UnknownSubscriber, value.UnknownSubscriber, UnknownSubscriberParamCodec(), opts...)
	}
	if value.MessageWaitingListFull != nil {
		return encodeMAPErrorMember(MessageWaitingListFull, value.MessageWaitingListFull, MessageWaitListFullParamCodec(), opts...)
	}
	return EncodedError{}, fmt.Errorf("%w: no selected reportSM-DeliveryStatus error", ber.ErrInvalidBinding)
}

// ResetErrors selects exactly the formal ERRORS set of MAP-MobileServiceOperations.reset.
type ResetErrors struct {
}

func infoResetOperation() OperationInfo {
	return OperationInfo{Name: "reset", Code: Reset, Argument: &TypeRef{ModuleOID: "0.4.0.0.1.3.11.22", ASN1Name: "ResetArg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "ResetArg"}, Result: nil, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: false, Source: sourceInfo4("reset", "17.6.1"), Errors: []ErrorInfo{}, Linked: []MAPOperationCode{}}
}

// ResetOperation binds the formal object in TS 29.002 V19.1.0 §17.6.1 (X.880 §§8.2–8.3).
func ResetOperation() Operation[ResetArg, NoParameter, ResetErrors] {
	return Operation[ResetArg, NoParameter, ResetErrors]{operationBinding[ResetArg, NoParameter, ResetErrors, OperationInfo, MAPOperationCode, EncodedError]{code: Reset, info: infoResetOperation, argument: ResetArgCodec(), result: ValueCodec[NoParameter]{}, decode: decodeResetError, encode: encodeResetError}}
}
func decodeResetError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (ResetErrors, error) {
	switch code {
	default:
		return ResetErrors{}, fmt.Errorf("%w: error code %d is not in reset ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeResetError(value ResetErrors, opts ...ber.EncodeOption) (EncodedError, error) {
	return EncodedError{}, fmt.Errorf("%w: no selected reset error", ber.ErrInvalidBinding)
}

// RestoreDataErrors selects exactly the formal ERRORS set of MAP-MobileServiceOperations.restoreData.
type RestoreDataErrors struct {
	SystemFailure       *ErrorValue[SystemFailureParam]
	DataMissing         *ErrorValue[DataMissingParam]
	UnexpectedDataValue *ErrorValue[UnexpectedDataParam]
	UnknownSubscriber   *ErrorValue[UnknownSubscriberParam]
}

func infoRestoreDataOperation() OperationInfo {
	return OperationInfo{Name: "restoreData", Code: RestoreData, Argument: &TypeRef{ModuleOID: "0.4.0.0.1.3.11.22", ASN1Name: "RestoreDataArg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "RestoreDataArg"}, Result: &TypeRef{ModuleOID: "0.4.0.0.1.3.11.22", ASN1Name: "RestoreDataRes", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "RestoreDataRes"}, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: false, Source: sourceInfo4("restoreData", "17.6.1"), Errors: []ErrorInfo{infoSystemFailureError(), infoDataMissingError(), infoUnexpectedDataValueError(), infoUnknownSubscriberError()}, Linked: []MAPOperationCode{}}
}

// RestoreDataOperation binds the formal object in TS 29.002 V19.1.0 §17.6.1 (X.880 §§8.2–8.3).
func RestoreDataOperation() Operation[RestoreDataArg, RestoreDataRes, RestoreDataErrors] {
	return Operation[RestoreDataArg, RestoreDataRes, RestoreDataErrors]{operationBinding[RestoreDataArg, RestoreDataRes, RestoreDataErrors, OperationInfo, MAPOperationCode, EncodedError]{code: RestoreData, info: infoRestoreDataOperation, argument: RestoreDataArgCodec(), result: RestoreDataResCodec(), decode: decodeRestoreDataError, encode: encodeRestoreDataError}}
}
func decodeRestoreDataError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (RestoreDataErrors, error) {
	switch code {
	case 34:
		p, err := decodeErrorParameter(data, present, SystemFailureParamCodec(), opts...)
		if err != nil {
			return RestoreDataErrors{}, err
		}
		return RestoreDataErrors{SystemFailure: p}, nil
	case 35:
		p, err := decodeErrorParameter(data, present, DataMissingParamCodec(), opts...)
		if err != nil {
			return RestoreDataErrors{}, err
		}
		return RestoreDataErrors{DataMissing: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return RestoreDataErrors{}, err
		}
		return RestoreDataErrors{UnexpectedDataValue: p}, nil
	case 1:
		p, err := decodeErrorParameter(data, present, UnknownSubscriberParamCodec(), opts...)
		if err != nil {
			return RestoreDataErrors{}, err
		}
		return RestoreDataErrors{UnknownSubscriber: p}, nil
	default:
		return RestoreDataErrors{}, fmt.Errorf("%w: error code %d is not in restoreData ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeRestoreDataError(value RestoreDataErrors, opts ...ber.EncodeOption) (EncodedError, error) {
	selected := 0
	if value.SystemFailure != nil {
		selected++
	}
	if value.DataMissing != nil {
		selected++
	}
	if value.UnexpectedDataValue != nil {
		selected++
	}
	if value.UnknownSubscriber != nil {
		selected++
	}
	if selected != 1 {
		return EncodedError{}, fmt.Errorf("%w: exactly one restoreData error arm is required", ber.ErrInvalidBinding)
	}
	if value.SystemFailure != nil {
		return encodeMAPErrorMember(SystemFailure, value.SystemFailure, SystemFailureParamCodec(), opts...)
	}
	if value.DataMissing != nil {
		return encodeMAPErrorMember(DataMissing, value.DataMissing, DataMissingParamCodec(), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	if value.UnknownSubscriber != nil {
		return encodeMAPErrorMember(UnknownSubscriber, value.UnknownSubscriber, UnknownSubscriberParamCodec(), opts...)
	}
	return EncodedError{}, fmt.Errorf("%w: no selected restoreData error", ber.ErrInvalidBinding)
}

// ResumeCallHandlingErrors selects exactly the formal ERRORS set of MAP-CallHandlingOperations.resumeCallHandling.
type ResumeCallHandlingErrors struct {
	ForwardingFailed    *ErrorValue[ForwardingFailedParam]
	OrNotAllowed        *ErrorValue[ORNotAllowedParam]
	UnexpectedDataValue *ErrorValue[UnexpectedDataParam]
	DataMissing         *ErrorValue[DataMissingParam]
}

func infoResumeCallHandlingOperation() OperationInfo {
	return OperationInfo{Name: "resumeCallHandling", Code: ResumeCallHandling, Argument: &TypeRef{ModuleOID: "0.4.0.0.1.3.13.22", ASN1Name: "ResumeCallHandlingArg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "ResumeCallHandlingArg"}, Result: &TypeRef{ModuleOID: "0.4.0.0.1.3.13.22", ASN1Name: "ResumeCallHandlingRes", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "ResumeCallHandlingRes"}, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: false, Source: sourceInfo6("resumeCallHandling", "17.6.3"), Errors: []ErrorInfo{infoForwardingFailedError(), infoOrNotAllowedError(), infoUnexpectedDataValueError(), infoDataMissingError()}, Linked: []MAPOperationCode{}}
}

// ResumeCallHandlingOperation binds the formal object in TS 29.002 V19.1.0 §17.6.3 (X.880 §§8.2–8.3).
func ResumeCallHandlingOperation() Operation[ResumeCallHandlingArg, ResumeCallHandlingRes, ResumeCallHandlingErrors] {
	return Operation[ResumeCallHandlingArg, ResumeCallHandlingRes, ResumeCallHandlingErrors]{operationBinding[ResumeCallHandlingArg, ResumeCallHandlingRes, ResumeCallHandlingErrors, OperationInfo, MAPOperationCode, EncodedError]{code: ResumeCallHandling, info: infoResumeCallHandlingOperation, argument: ResumeCallHandlingArgCodec(), result: ResumeCallHandlingResCodec(), decode: decodeResumeCallHandlingError, encode: encodeResumeCallHandlingError}}
}
func decodeResumeCallHandlingError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (ResumeCallHandlingErrors, error) {
	switch code {
	case 47:
		p, err := decodeErrorParameter(data, present, ForwardingFailedParamCodec(), opts...)
		if err != nil {
			return ResumeCallHandlingErrors{}, err
		}
		return ResumeCallHandlingErrors{ForwardingFailed: p}, nil
	case 48:
		p, err := decodeErrorParameter(data, present, ORNotAllowedParamCodec(), opts...)
		if err != nil {
			return ResumeCallHandlingErrors{}, err
		}
		return ResumeCallHandlingErrors{OrNotAllowed: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return ResumeCallHandlingErrors{}, err
		}
		return ResumeCallHandlingErrors{UnexpectedDataValue: p}, nil
	case 35:
		p, err := decodeErrorParameter(data, present, DataMissingParamCodec(), opts...)
		if err != nil {
			return ResumeCallHandlingErrors{}, err
		}
		return ResumeCallHandlingErrors{DataMissing: p}, nil
	default:
		return ResumeCallHandlingErrors{}, fmt.Errorf("%w: error code %d is not in resumeCallHandling ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeResumeCallHandlingError(value ResumeCallHandlingErrors, opts ...ber.EncodeOption) (EncodedError, error) {
	selected := 0
	if value.ForwardingFailed != nil {
		selected++
	}
	if value.OrNotAllowed != nil {
		selected++
	}
	if value.UnexpectedDataValue != nil {
		selected++
	}
	if value.DataMissing != nil {
		selected++
	}
	if selected != 1 {
		return EncodedError{}, fmt.Errorf("%w: exactly one resumeCallHandling error arm is required", ber.ErrInvalidBinding)
	}
	if value.ForwardingFailed != nil {
		return encodeMAPErrorMember(ForwardingFailed, value.ForwardingFailed, ForwardingFailedParamCodec(), opts...)
	}
	if value.OrNotAllowed != nil {
		return encodeMAPErrorMember(OrNotAllowed, value.OrNotAllowed, ORNotAllowedParamCodec(), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	if value.DataMissing != nil {
		return encodeMAPErrorMember(DataMissing, value.DataMissing, DataMissingParamCodec(), opts...)
	}
	return EncodedError{}, fmt.Errorf("%w: no selected resumeCallHandling error", ber.ErrInvalidBinding)
}

// SendAuthenticationInfoErrors selects exactly the formal ERRORS set of MAP-MobileServiceOperations.sendAuthenticationInfo.
type SendAuthenticationInfoErrors struct {
	SystemFailure       *ErrorValue[SystemFailureParam]
	DataMissing         *ErrorValue[DataMissingParam]
	UnexpectedDataValue *ErrorValue[UnexpectedDataParam]
	UnknownSubscriber   *ErrorValue[UnknownSubscriberParam]
}

func infoSendAuthenticationInfoOperation() OperationInfo {
	return OperationInfo{Name: "sendAuthenticationInfo", Code: SendAuthenticationInfo, Argument: &TypeRef{ModuleOID: "0.4.0.0.1.3.11.22", ASN1Name: "SendAuthenticationInfoArg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "SendAuthenticationInfoArg"}, Result: &TypeRef{ModuleOID: "0.4.0.0.1.3.11.22", ASN1Name: "SendAuthenticationInfoRes", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "SendAuthenticationInfoRes"}, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: false, Source: sourceInfo4("sendAuthenticationInfo", "17.6.1"), Errors: []ErrorInfo{infoSystemFailureError(), infoDataMissingError(), infoUnexpectedDataValueError(), infoUnknownSubscriberError()}, Linked: []MAPOperationCode{}}
}

// SendAuthenticationInfoOperation binds the formal object in TS 29.002 V19.1.0 §17.6.1 (X.880 §§8.2–8.3).
func SendAuthenticationInfoOperation() Operation[SendAuthenticationInfoArg, SendAuthenticationInfoRes, SendAuthenticationInfoErrors] {
	return Operation[SendAuthenticationInfoArg, SendAuthenticationInfoRes, SendAuthenticationInfoErrors]{operationBinding[SendAuthenticationInfoArg, SendAuthenticationInfoRes, SendAuthenticationInfoErrors, OperationInfo, MAPOperationCode, EncodedError]{code: SendAuthenticationInfo, info: infoSendAuthenticationInfoOperation, argument: SendAuthenticationInfoArgCodec(), result: SendAuthenticationInfoResCodec(), decode: decodeSendAuthenticationInfoError, encode: encodeSendAuthenticationInfoError}}
}
func decodeSendAuthenticationInfoError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (SendAuthenticationInfoErrors, error) {
	switch code {
	case 34:
		p, err := decodeErrorParameter(data, present, SystemFailureParamCodec(), opts...)
		if err != nil {
			return SendAuthenticationInfoErrors{}, err
		}
		return SendAuthenticationInfoErrors{SystemFailure: p}, nil
	case 35:
		p, err := decodeErrorParameter(data, present, DataMissingParamCodec(), opts...)
		if err != nil {
			return SendAuthenticationInfoErrors{}, err
		}
		return SendAuthenticationInfoErrors{DataMissing: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return SendAuthenticationInfoErrors{}, err
		}
		return SendAuthenticationInfoErrors{UnexpectedDataValue: p}, nil
	case 1:
		p, err := decodeErrorParameter(data, present, UnknownSubscriberParamCodec(), opts...)
		if err != nil {
			return SendAuthenticationInfoErrors{}, err
		}
		return SendAuthenticationInfoErrors{UnknownSubscriber: p}, nil
	default:
		return SendAuthenticationInfoErrors{}, fmt.Errorf("%w: error code %d is not in sendAuthenticationInfo ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeSendAuthenticationInfoError(value SendAuthenticationInfoErrors, opts ...ber.EncodeOption) (EncodedError, error) {
	selected := 0
	if value.SystemFailure != nil {
		selected++
	}
	if value.DataMissing != nil {
		selected++
	}
	if value.UnexpectedDataValue != nil {
		selected++
	}
	if value.UnknownSubscriber != nil {
		selected++
	}
	if selected != 1 {
		return EncodedError{}, fmt.Errorf("%w: exactly one sendAuthenticationInfo error arm is required", ber.ErrInvalidBinding)
	}
	if value.SystemFailure != nil {
		return encodeMAPErrorMember(SystemFailure, value.SystemFailure, SystemFailureParamCodec(), opts...)
	}
	if value.DataMissing != nil {
		return encodeMAPErrorMember(DataMissing, value.DataMissing, DataMissingParamCodec(), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	if value.UnknownSubscriber != nil {
		return encodeMAPErrorMember(UnknownSubscriber, value.UnknownSubscriber, UnknownSubscriberParamCodec(), opts...)
	}
	return EncodedError{}, fmt.Errorf("%w: no selected sendAuthenticationInfo error", ber.ErrInvalidBinding)
}

// SendEndSignalErrors selects exactly the formal ERRORS set of MAP-MobileServiceOperations.sendEndSignal.
type SendEndSignalErrors struct {
}

func infoSendEndSignalOperation() OperationInfo {
	return OperationInfo{Name: "sendEndSignal", Code: SendEndSignal, Argument: &TypeRef{ModuleOID: "0.4.0.0.1.3.11.22", ASN1Name: "SendEndSignal-Arg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "SendEndSignalArg"}, Result: &TypeRef{ModuleOID: "0.4.0.0.1.3.11.22", ASN1Name: "SendEndSignal-Res", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "SendEndSignalRes"}, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: false, Source: sourceInfo4("sendEndSignal", "17.6.1"), Errors: []ErrorInfo{}, Linked: []MAPOperationCode{}}
}

// SendEndSignalOperation binds the formal object in TS 29.002 V19.1.0 §17.6.1 (X.880 §§8.2–8.3).
func SendEndSignalOperation() Operation[SendEndSignalArg, SendEndSignalRes, SendEndSignalErrors] {
	return Operation[SendEndSignalArg, SendEndSignalRes, SendEndSignalErrors]{operationBinding[SendEndSignalArg, SendEndSignalRes, SendEndSignalErrors, OperationInfo, MAPOperationCode, EncodedError]{code: SendEndSignal, info: infoSendEndSignalOperation, argument: SendEndSignalArgCodec(), result: SendEndSignalResCodec(), decode: decodeSendEndSignalError, encode: encodeSendEndSignalError}}
}
func decodeSendEndSignalError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (SendEndSignalErrors, error) {
	switch code {
	default:
		return SendEndSignalErrors{}, fmt.Errorf("%w: error code %d is not in sendEndSignal ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeSendEndSignalError(value SendEndSignalErrors, opts ...ber.EncodeOption) (EncodedError, error) {
	return EncodedError{}, fmt.Errorf("%w: no selected sendEndSignal error", ber.ErrInvalidBinding)
}

// SendGroupCallEndSignalErrors selects exactly the formal ERRORS set of MAP-Group-Call-Operations.sendGroupCallEndSignal.
type SendGroupCallEndSignalErrors struct {
}

func infoSendGroupCallEndSignalOperation() OperationInfo {
	return OperationInfo{Name: "sendGroupCallEndSignal", Code: SendGroupCallEndSignal, Argument: &TypeRef{ModuleOID: "0.4.0.0.1.3.23.22", ASN1Name: "SendGroupCallEndSignalArg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "SendGroupCallEndSignalArg"}, Result: &TypeRef{ModuleOID: "0.4.0.0.1.3.23.22", ASN1Name: "SendGroupCallEndSignalRes", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "SendGroupCallEndSignalRes"}, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: false, Source: sourceInfo5("sendGroupCallEndSignal", "17.6.7"), Errors: []ErrorInfo{}, Linked: []MAPOperationCode{}}
}

// SendGroupCallEndSignalOperation binds the formal object in TS 29.002 V19.1.0 §17.6.7 (X.880 §§8.2–8.3).
func SendGroupCallEndSignalOperation() Operation[SendGroupCallEndSignalArg, SendGroupCallEndSignalRes, SendGroupCallEndSignalErrors] {
	return Operation[SendGroupCallEndSignalArg, SendGroupCallEndSignalRes, SendGroupCallEndSignalErrors]{operationBinding[SendGroupCallEndSignalArg, SendGroupCallEndSignalRes, SendGroupCallEndSignalErrors, OperationInfo, MAPOperationCode, EncodedError]{code: SendGroupCallEndSignal, info: infoSendGroupCallEndSignalOperation, argument: SendGroupCallEndSignalArgCodec(), result: SendGroupCallEndSignalResCodec(), decode: decodeSendGroupCallEndSignalError, encode: encodeSendGroupCallEndSignalError}}
}
func decodeSendGroupCallEndSignalError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (SendGroupCallEndSignalErrors, error) {
	switch code {
	default:
		return SendGroupCallEndSignalErrors{}, fmt.Errorf("%w: error code %d is not in sendGroupCallEndSignal ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeSendGroupCallEndSignalError(value SendGroupCallEndSignalErrors, opts ...ber.EncodeOption) (EncodedError, error) {
	return EncodedError{}, fmt.Errorf("%w: no selected sendGroupCallEndSignal error", ber.ErrInvalidBinding)
}

// SendGroupCallInfoErrors selects exactly the formal ERRORS set of MAP-Group-Call-Operations.sendGroupCallInfo.
type SendGroupCallInfoErrors struct {
	SystemFailure             *ErrorValue[SystemFailureParam]
	OngoingGroupCall          *ErrorValue[OngoingGroupCallParam]
	UnexpectedDataValue       *ErrorValue[UnexpectedDataParam]
	DataMissing               *ErrorValue[DataMissingParam]
	TeleserviceNotProvisioned *ErrorValue[TeleservNotProvParam]
	UnknownSubscriber         *ErrorValue[UnknownSubscriberParam]
}

func infoSendGroupCallInfoOperation() OperationInfo {
	return OperationInfo{Name: "sendGroupCallInfo", Code: SendGroupCallInfo, Argument: &TypeRef{ModuleOID: "0.4.0.0.1.3.23.22", ASN1Name: "SendGroupCallInfoArg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "SendGroupCallInfoArg"}, Result: &TypeRef{ModuleOID: "0.4.0.0.1.3.23.22", ASN1Name: "SendGroupCallInfoRes", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "SendGroupCallInfoRes"}, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: false, Source: sourceInfo5("sendGroupCallInfo", "17.6.7"), Errors: []ErrorInfo{infoSystemFailureError(), infoOngoingGroupCallError(), infoUnexpectedDataValueError(), infoDataMissingError(), infoTeleserviceNotProvisionedError(), infoUnknownSubscriberError()}, Linked: []MAPOperationCode{}}
}

// SendGroupCallInfoOperation binds the formal object in TS 29.002 V19.1.0 §17.6.7 (X.880 §§8.2–8.3).
func SendGroupCallInfoOperation() Operation[SendGroupCallInfoArg, SendGroupCallInfoRes, SendGroupCallInfoErrors] {
	return Operation[SendGroupCallInfoArg, SendGroupCallInfoRes, SendGroupCallInfoErrors]{operationBinding[SendGroupCallInfoArg, SendGroupCallInfoRes, SendGroupCallInfoErrors, OperationInfo, MAPOperationCode, EncodedError]{code: SendGroupCallInfo, info: infoSendGroupCallInfoOperation, argument: SendGroupCallInfoArgCodec(), result: SendGroupCallInfoResCodec(), decode: decodeSendGroupCallInfoError, encode: encodeSendGroupCallInfoError}}
}
func decodeSendGroupCallInfoError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (SendGroupCallInfoErrors, error) {
	switch code {
	case 34:
		p, err := decodeErrorParameter(data, present, SystemFailureParamCodec(), opts...)
		if err != nil {
			return SendGroupCallInfoErrors{}, err
		}
		return SendGroupCallInfoErrors{SystemFailure: p}, nil
	case 22:
		p, err := decodeErrorParameter(data, present, OngoingGroupCallParamCodec(), opts...)
		if err != nil {
			return SendGroupCallInfoErrors{}, err
		}
		return SendGroupCallInfoErrors{OngoingGroupCall: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return SendGroupCallInfoErrors{}, err
		}
		return SendGroupCallInfoErrors{UnexpectedDataValue: p}, nil
	case 35:
		p, err := decodeErrorParameter(data, present, DataMissingParamCodec(), opts...)
		if err != nil {
			return SendGroupCallInfoErrors{}, err
		}
		return SendGroupCallInfoErrors{DataMissing: p}, nil
	case 11:
		p, err := decodeErrorParameter(data, present, TeleservNotProvParamCodec(), opts...)
		if err != nil {
			return SendGroupCallInfoErrors{}, err
		}
		return SendGroupCallInfoErrors{TeleserviceNotProvisioned: p}, nil
	case 1:
		p, err := decodeErrorParameter(data, present, UnknownSubscriberParamCodec(), opts...)
		if err != nil {
			return SendGroupCallInfoErrors{}, err
		}
		return SendGroupCallInfoErrors{UnknownSubscriber: p}, nil
	default:
		return SendGroupCallInfoErrors{}, fmt.Errorf("%w: error code %d is not in sendGroupCallInfo ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeSendGroupCallInfoError(value SendGroupCallInfoErrors, opts ...ber.EncodeOption) (EncodedError, error) {
	selected := 0
	if value.SystemFailure != nil {
		selected++
	}
	if value.OngoingGroupCall != nil {
		selected++
	}
	if value.UnexpectedDataValue != nil {
		selected++
	}
	if value.DataMissing != nil {
		selected++
	}
	if value.TeleserviceNotProvisioned != nil {
		selected++
	}
	if value.UnknownSubscriber != nil {
		selected++
	}
	if selected != 1 {
		return EncodedError{}, fmt.Errorf("%w: exactly one sendGroupCallInfo error arm is required", ber.ErrInvalidBinding)
	}
	if value.SystemFailure != nil {
		return encodeMAPErrorMember(SystemFailure, value.SystemFailure, SystemFailureParamCodec(), opts...)
	}
	if value.OngoingGroupCall != nil {
		return encodeMAPErrorMember(OngoingGroupCall, value.OngoingGroupCall, OngoingGroupCallParamCodec(), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	if value.DataMissing != nil {
		return encodeMAPErrorMember(DataMissing, value.DataMissing, DataMissingParamCodec(), opts...)
	}
	if value.TeleserviceNotProvisioned != nil {
		return encodeMAPErrorMember(TeleserviceNotProvisioned, value.TeleserviceNotProvisioned, TeleservNotProvParamCodec(), opts...)
	}
	if value.UnknownSubscriber != nil {
		return encodeMAPErrorMember(UnknownSubscriber, value.UnknownSubscriber, UnknownSubscriberParamCodec(), opts...)
	}
	return EncodedError{}, fmt.Errorf("%w: no selected sendGroupCallInfo error", ber.ErrInvalidBinding)
}

// SendIMSIErrors selects exactly the formal ERRORS set of MAP-OperationAndMaintenanceOperations.sendIMSI.
type SendIMSIErrors struct {
	DataMissing         *ErrorValue[DataMissingParam]
	UnexpectedDataValue *ErrorValue[UnexpectedDataParam]
	UnknownSubscriber   *ErrorValue[UnknownSubscriberParam]
}

func infoSendIMSIOperation() OperationInfo {
	return OperationInfo{Name: "sendIMSI", Code: SendIMSI, Argument: &TypeRef{ModuleOID: "0.4.0.0.1.3.18.22", ASN1Name: "ISDN-AddressString", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "ISDNAddressString"}, Result: &TypeRef{ModuleOID: "0.4.0.0.1.3.18.22", ASN1Name: "IMSI", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "IMSI"}, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: false, Source: sourceInfo2("sendIMSI", "17.6.2"), Errors: []ErrorInfo{infoDataMissingError(), infoUnexpectedDataValueError(), infoUnknownSubscriberError()}, Linked: []MAPOperationCode{}}
}

// SendIMSIOperation binds the formal object in TS 29.002 V19.1.0 §17.6.2 (X.880 §§8.2–8.3).
func SendIMSIOperation() Operation[BERValue[ISDNAddressString], BERValue[IMSI], SendIMSIErrors] {
	return Operation[BERValue[ISDNAddressString], BERValue[IMSI], SendIMSIErrors]{operationBinding[BERValue[ISDNAddressString], BERValue[IMSI], SendIMSIErrors, OperationInfo, MAPOperationCode, EncodedError]{code: SendIMSI, info: infoSendIMSIOperation, argument: ISDNAddressStringCodec(), result: IMSICodec(), decode: decodeSendIMSIError, encode: encodeSendIMSIError}}
}
func decodeSendIMSIError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (SendIMSIErrors, error) {
	switch code {
	case 35:
		p, err := decodeErrorParameter(data, present, DataMissingParamCodec(), opts...)
		if err != nil {
			return SendIMSIErrors{}, err
		}
		return SendIMSIErrors{DataMissing: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return SendIMSIErrors{}, err
		}
		return SendIMSIErrors{UnexpectedDataValue: p}, nil
	case 1:
		p, err := decodeErrorParameter(data, present, UnknownSubscriberParamCodec(), opts...)
		if err != nil {
			return SendIMSIErrors{}, err
		}
		return SendIMSIErrors{UnknownSubscriber: p}, nil
	default:
		return SendIMSIErrors{}, fmt.Errorf("%w: error code %d is not in sendIMSI ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeSendIMSIError(value SendIMSIErrors, opts ...ber.EncodeOption) (EncodedError, error) {
	selected := 0
	if value.DataMissing != nil {
		selected++
	}
	if value.UnexpectedDataValue != nil {
		selected++
	}
	if value.UnknownSubscriber != nil {
		selected++
	}
	if selected != 1 {
		return EncodedError{}, fmt.Errorf("%w: exactly one sendIMSI error arm is required", ber.ErrInvalidBinding)
	}
	if value.DataMissing != nil {
		return encodeMAPErrorMember(DataMissing, value.DataMissing, DataMissingParamCodec(), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	if value.UnknownSubscriber != nil {
		return encodeMAPErrorMember(UnknownSubscriber, value.UnknownSubscriber, UnknownSubscriberParamCodec(), opts...)
	}
	return EncodedError{}, fmt.Errorf("%w: no selected sendIMSI error", ber.ErrInvalidBinding)
}

// SendIdentificationErrors selects exactly the formal ERRORS set of MAP-MobileServiceOperations.sendIdentification.
type SendIdentificationErrors struct {
	DataMissing            *ErrorValue[DataMissingParam]
	UnidentifiedSubscriber *ErrorValue[UnidentifiedSubParam]
}

func infoSendIdentificationOperation() OperationInfo {
	return OperationInfo{Name: "sendIdentification", Code: SendIdentification, Argument: &TypeRef{ModuleOID: "0.4.0.0.1.3.11.22", ASN1Name: "SendIdentificationArg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "SendIdentificationArg"}, Result: &TypeRef{ModuleOID: "0.4.0.0.1.3.11.22", ASN1Name: "SendIdentificationRes", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "SendIdentificationRes"}, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: false, Source: sourceInfo4("sendIdentification", "17.6.1"), Errors: []ErrorInfo{infoDataMissingError(), infoUnidentifiedSubscriberError()}, Linked: []MAPOperationCode{}}
}

// SendIdentificationOperation binds the formal object in TS 29.002 V19.1.0 §17.6.1 (X.880 §§8.2–8.3).
func SendIdentificationOperation() Operation[SendIdentificationArg, SendIdentificationRes, SendIdentificationErrors] {
	return Operation[SendIdentificationArg, SendIdentificationRes, SendIdentificationErrors]{operationBinding[SendIdentificationArg, SendIdentificationRes, SendIdentificationErrors, OperationInfo, MAPOperationCode, EncodedError]{code: SendIdentification, info: infoSendIdentificationOperation, argument: SendIdentificationArgCodec(), result: SendIdentificationResCodec(), decode: decodeSendIdentificationError, encode: encodeSendIdentificationError}}
}
func decodeSendIdentificationError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (SendIdentificationErrors, error) {
	switch code {
	case 35:
		p, err := decodeErrorParameter(data, present, DataMissingParamCodec(), opts...)
		if err != nil {
			return SendIdentificationErrors{}, err
		}
		return SendIdentificationErrors{DataMissing: p}, nil
	case 5:
		p, err := decodeErrorParameter(data, present, UnidentifiedSubParamCodec(), opts...)
		if err != nil {
			return SendIdentificationErrors{}, err
		}
		return SendIdentificationErrors{UnidentifiedSubscriber: p}, nil
	default:
		return SendIdentificationErrors{}, fmt.Errorf("%w: error code %d is not in sendIdentification ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeSendIdentificationError(value SendIdentificationErrors, opts ...ber.EncodeOption) (EncodedError, error) {
	selected := 0
	if value.DataMissing != nil {
		selected++
	}
	if value.UnidentifiedSubscriber != nil {
		selected++
	}
	if selected != 1 {
		return EncodedError{}, fmt.Errorf("%w: exactly one sendIdentification error arm is required", ber.ErrInvalidBinding)
	}
	if value.DataMissing != nil {
		return encodeMAPErrorMember(DataMissing, value.DataMissing, DataMissingParamCodec(), opts...)
	}
	if value.UnidentifiedSubscriber != nil {
		return encodeMAPErrorMember(UnidentifiedSubscriber, value.UnidentifiedSubscriber, UnidentifiedSubParamCodec(), opts...)
	}
	return EncodedError{}, fmt.Errorf("%w: no selected sendIdentification error", ber.ErrInvalidBinding)
}

// SendRoutingInfoErrors selects exactly the formal ERRORS set of MAP-CallHandlingOperations.sendRoutingInfo.
type SendRoutingInfoErrors struct {
	SystemFailure               *ErrorValue[SystemFailureParam]
	DataMissing                 *ErrorValue[DataMissingParam]
	UnexpectedDataValue         *ErrorValue[UnexpectedDataParam]
	FacilityNotSupported        *ErrorValue[FacilityNotSupParam]
	OrNotAllowed                *ErrorValue[ORNotAllowedParam]
	UnknownSubscriber           *ErrorValue[UnknownSubscriberParam]
	NumberChanged               *ErrorValue[NumberChangedParam]
	BearerServiceNotProvisioned *ErrorValue[BearerServNotProvParam]
	TeleserviceNotProvisioned   *ErrorValue[TeleservNotProvParam]
	AbsentSubscriber            *ErrorValue[AbsentSubscriberParam]
	BusySubscriber              *ErrorValue[BusySubscriberParam]
	NoSubscriberReply           *ErrorValue[NoSubscriberReplyParam]
	CallBarred                  *ErrorValue[CallBarredParam]
	CugReject                   *ErrorValue[CUGRejectParam]
	ForwardingViolation         *ErrorValue[ForwardingViolationParam]
}

func infoSendRoutingInfoOperation() OperationInfo {
	return OperationInfo{Name: "sendRoutingInfo", Code: SendRoutingInfo, Argument: &TypeRef{ModuleOID: "0.4.0.0.1.3.13.22", ASN1Name: "SendRoutingInfoArg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "SendRoutingInfoArg"}, Result: &TypeRef{ModuleOID: "0.4.0.0.1.3.13.22", ASN1Name: "SendRoutingInfoRes", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "SendRoutingInfoRes"}, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: false, Source: sourceInfo6("sendRoutingInfo", "17.6.3"), Errors: []ErrorInfo{infoSystemFailureError(), infoDataMissingError(), infoUnexpectedDataValueError(), infoFacilityNotSupportedError(), infoOrNotAllowedError(), infoUnknownSubscriberError(), infoNumberChangedError(), infoBearerServiceNotProvisionedError(), infoTeleserviceNotProvisionedError(), infoAbsentSubscriberError(), infoBusySubscriberError(), infoNoSubscriberReplyError(), infoCallBarredError(), infoCugRejectError(), infoForwardingViolationError()}, Linked: []MAPOperationCode{}}
}

// SendRoutingInfoOperation binds the formal object in TS 29.002 V19.1.0 §17.6.3 (X.880 §§8.2–8.3).
func SendRoutingInfoOperation() Operation[SendRoutingInfoArg, SendRoutingInfoRes, SendRoutingInfoErrors] {
	return Operation[SendRoutingInfoArg, SendRoutingInfoRes, SendRoutingInfoErrors]{operationBinding[SendRoutingInfoArg, SendRoutingInfoRes, SendRoutingInfoErrors, OperationInfo, MAPOperationCode, EncodedError]{code: SendRoutingInfo, info: infoSendRoutingInfoOperation, argument: SendRoutingInfoArgCodec(), result: SendRoutingInfoResCodec(), decode: decodeSendRoutingInfoError, encode: encodeSendRoutingInfoError}}
}
func decodeSendRoutingInfoError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (SendRoutingInfoErrors, error) {
	switch code {
	case 34:
		p, err := decodeErrorParameter(data, present, SystemFailureParamCodec(), opts...)
		if err != nil {
			return SendRoutingInfoErrors{}, err
		}
		return SendRoutingInfoErrors{SystemFailure: p}, nil
	case 35:
		p, err := decodeErrorParameter(data, present, DataMissingParamCodec(), opts...)
		if err != nil {
			return SendRoutingInfoErrors{}, err
		}
		return SendRoutingInfoErrors{DataMissing: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return SendRoutingInfoErrors{}, err
		}
		return SendRoutingInfoErrors{UnexpectedDataValue: p}, nil
	case 21:
		p, err := decodeErrorParameter(data, present, FacilityNotSupParamCodec(), opts...)
		if err != nil {
			return SendRoutingInfoErrors{}, err
		}
		return SendRoutingInfoErrors{FacilityNotSupported: p}, nil
	case 48:
		p, err := decodeErrorParameter(data, present, ORNotAllowedParamCodec(), opts...)
		if err != nil {
			return SendRoutingInfoErrors{}, err
		}
		return SendRoutingInfoErrors{OrNotAllowed: p}, nil
	case 1:
		p, err := decodeErrorParameter(data, present, UnknownSubscriberParamCodec(), opts...)
		if err != nil {
			return SendRoutingInfoErrors{}, err
		}
		return SendRoutingInfoErrors{UnknownSubscriber: p}, nil
	case 44:
		p, err := decodeErrorParameter(data, present, NumberChangedParamCodec(), opts...)
		if err != nil {
			return SendRoutingInfoErrors{}, err
		}
		return SendRoutingInfoErrors{NumberChanged: p}, nil
	case 10:
		p, err := decodeErrorParameter(data, present, BearerServNotProvParamCodec(), opts...)
		if err != nil {
			return SendRoutingInfoErrors{}, err
		}
		return SendRoutingInfoErrors{BearerServiceNotProvisioned: p}, nil
	case 11:
		p, err := decodeErrorParameter(data, present, TeleservNotProvParamCodec(), opts...)
		if err != nil {
			return SendRoutingInfoErrors{}, err
		}
		return SendRoutingInfoErrors{TeleserviceNotProvisioned: p}, nil
	case 27:
		p, err := decodeErrorParameter(data, present, AbsentSubscriberParamCodec(), opts...)
		if err != nil {
			return SendRoutingInfoErrors{}, err
		}
		return SendRoutingInfoErrors{AbsentSubscriber: p}, nil
	case 45:
		p, err := decodeErrorParameter(data, present, BusySubscriberParamCodec(), opts...)
		if err != nil {
			return SendRoutingInfoErrors{}, err
		}
		return SendRoutingInfoErrors{BusySubscriber: p}, nil
	case 46:
		p, err := decodeErrorParameter(data, present, NoSubscriberReplyParamCodec(), opts...)
		if err != nil {
			return SendRoutingInfoErrors{}, err
		}
		return SendRoutingInfoErrors{NoSubscriberReply: p}, nil
	case 13:
		p, err := decodeErrorParameter(data, present, CallBarredParamCodec(), opts...)
		if err != nil {
			return SendRoutingInfoErrors{}, err
		}
		return SendRoutingInfoErrors{CallBarred: p}, nil
	case 15:
		p, err := decodeErrorParameter(data, present, CUGRejectParamCodec(), opts...)
		if err != nil {
			return SendRoutingInfoErrors{}, err
		}
		return SendRoutingInfoErrors{CugReject: p}, nil
	case 14:
		p, err := decodeErrorParameter(data, present, ForwardingViolationParamCodec(), opts...)
		if err != nil {
			return SendRoutingInfoErrors{}, err
		}
		return SendRoutingInfoErrors{ForwardingViolation: p}, nil
	default:
		return SendRoutingInfoErrors{}, fmt.Errorf("%w: error code %d is not in sendRoutingInfo ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeSendRoutingInfoError(value SendRoutingInfoErrors, opts ...ber.EncodeOption) (EncodedError, error) {
	selected := 0
	if value.SystemFailure != nil {
		selected++
	}
	if value.DataMissing != nil {
		selected++
	}
	if value.UnexpectedDataValue != nil {
		selected++
	}
	if value.FacilityNotSupported != nil {
		selected++
	}
	if value.OrNotAllowed != nil {
		selected++
	}
	if value.UnknownSubscriber != nil {
		selected++
	}
	if value.NumberChanged != nil {
		selected++
	}
	if value.BearerServiceNotProvisioned != nil {
		selected++
	}
	if value.TeleserviceNotProvisioned != nil {
		selected++
	}
	if value.AbsentSubscriber != nil {
		selected++
	}
	if value.BusySubscriber != nil {
		selected++
	}
	if value.NoSubscriberReply != nil {
		selected++
	}
	if value.CallBarred != nil {
		selected++
	}
	if value.CugReject != nil {
		selected++
	}
	if value.ForwardingViolation != nil {
		selected++
	}
	if selected != 1 {
		return EncodedError{}, fmt.Errorf("%w: exactly one sendRoutingInfo error arm is required", ber.ErrInvalidBinding)
	}
	if value.SystemFailure != nil {
		return encodeMAPErrorMember(SystemFailure, value.SystemFailure, SystemFailureParamCodec(), opts...)
	}
	if value.DataMissing != nil {
		return encodeMAPErrorMember(DataMissing, value.DataMissing, DataMissingParamCodec(), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	if value.FacilityNotSupported != nil {
		return encodeMAPErrorMember(FacilityNotSupported, value.FacilityNotSupported, FacilityNotSupParamCodec(), opts...)
	}
	if value.OrNotAllowed != nil {
		return encodeMAPErrorMember(OrNotAllowed, value.OrNotAllowed, ORNotAllowedParamCodec(), opts...)
	}
	if value.UnknownSubscriber != nil {
		return encodeMAPErrorMember(UnknownSubscriber, value.UnknownSubscriber, UnknownSubscriberParamCodec(), opts...)
	}
	if value.NumberChanged != nil {
		return encodeMAPErrorMember(NumberChanged, value.NumberChanged, NumberChangedParamCodec(), opts...)
	}
	if value.BearerServiceNotProvisioned != nil {
		return encodeMAPErrorMember(BearerServiceNotProvisioned, value.BearerServiceNotProvisioned, BearerServNotProvParamCodec(), opts...)
	}
	if value.TeleserviceNotProvisioned != nil {
		return encodeMAPErrorMember(TeleserviceNotProvisioned, value.TeleserviceNotProvisioned, TeleservNotProvParamCodec(), opts...)
	}
	if value.AbsentSubscriber != nil {
		return encodeMAPErrorMember(AbsentSubscriber, value.AbsentSubscriber, AbsentSubscriberParamCodec(), opts...)
	}
	if value.BusySubscriber != nil {
		return encodeMAPErrorMember(BusySubscriber, value.BusySubscriber, BusySubscriberParamCodec(), opts...)
	}
	if value.NoSubscriberReply != nil {
		return encodeMAPErrorMember(NoSubscriberReply, value.NoSubscriberReply, NoSubscriberReplyParamCodec(), opts...)
	}
	if value.CallBarred != nil {
		return encodeMAPErrorMember(CallBarred, value.CallBarred, CallBarredParamCodec(), opts...)
	}
	if value.CugReject != nil {
		return encodeMAPErrorMember(CugReject, value.CugReject, CUGRejectParamCodec(), opts...)
	}
	if value.ForwardingViolation != nil {
		return encodeMAPErrorMember(ForwardingViolation, value.ForwardingViolation, ForwardingViolationParamCodec(), opts...)
	}
	return EncodedError{}, fmt.Errorf("%w: no selected sendRoutingInfo error", ber.ErrInvalidBinding)
}

// SendRoutingInfoForGprsErrors selects exactly the formal ERRORS set of MAP-MobileServiceOperations.sendRoutingInfoForGprs.
type SendRoutingInfoForGprsErrors struct {
	AbsentSubscriber    *ErrorValue[AbsentSubscriberParam]
	SystemFailure       *ErrorValue[SystemFailureParam]
	DataMissing         *ErrorValue[DataMissingParam]
	UnexpectedDataValue *ErrorValue[UnexpectedDataParam]
	UnknownSubscriber   *ErrorValue[UnknownSubscriberParam]
	CallBarred          *ErrorValue[CallBarredParam]
}

func infoSendRoutingInfoForGprsOperation() OperationInfo {
	return OperationInfo{Name: "sendRoutingInfoForGprs", Code: SendRoutingInfoForGprs, Argument: &TypeRef{ModuleOID: "0.4.0.0.1.3.11.22", ASN1Name: "SendRoutingInfoForGprsArg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "SendRoutingInfoForGprsArg"}, Result: &TypeRef{ModuleOID: "0.4.0.0.1.3.11.22", ASN1Name: "SendRoutingInfoForGprsRes", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "SendRoutingInfoForGprsRes"}, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: false, Source: sourceInfo4("sendRoutingInfoForGprs", "17.6.1"), Errors: []ErrorInfo{infoAbsentSubscriberError(), infoSystemFailureError(), infoDataMissingError(), infoUnexpectedDataValueError(), infoUnknownSubscriberError(), infoCallBarredError()}, Linked: []MAPOperationCode{}}
}

// SendRoutingInfoForGprsOperation binds the formal object in TS 29.002 V19.1.0 §17.6.1 (X.880 §§8.2–8.3).
func SendRoutingInfoForGprsOperation() Operation[SendRoutingInfoForGprsArg, SendRoutingInfoForGprsRes, SendRoutingInfoForGprsErrors] {
	return Operation[SendRoutingInfoForGprsArg, SendRoutingInfoForGprsRes, SendRoutingInfoForGprsErrors]{operationBinding[SendRoutingInfoForGprsArg, SendRoutingInfoForGprsRes, SendRoutingInfoForGprsErrors, OperationInfo, MAPOperationCode, EncodedError]{code: SendRoutingInfoForGprs, info: infoSendRoutingInfoForGprsOperation, argument: SendRoutingInfoForGprsArgCodec(), result: SendRoutingInfoForGprsResCodec(), decode: decodeSendRoutingInfoForGprsError, encode: encodeSendRoutingInfoForGprsError}}
}
func decodeSendRoutingInfoForGprsError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (SendRoutingInfoForGprsErrors, error) {
	switch code {
	case 27:
		p, err := decodeErrorParameter(data, present, AbsentSubscriberParamCodec(), opts...)
		if err != nil {
			return SendRoutingInfoForGprsErrors{}, err
		}
		return SendRoutingInfoForGprsErrors{AbsentSubscriber: p}, nil
	case 34:
		p, err := decodeErrorParameter(data, present, SystemFailureParamCodec(), opts...)
		if err != nil {
			return SendRoutingInfoForGprsErrors{}, err
		}
		return SendRoutingInfoForGprsErrors{SystemFailure: p}, nil
	case 35:
		p, err := decodeErrorParameter(data, present, DataMissingParamCodec(), opts...)
		if err != nil {
			return SendRoutingInfoForGprsErrors{}, err
		}
		return SendRoutingInfoForGprsErrors{DataMissing: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return SendRoutingInfoForGprsErrors{}, err
		}
		return SendRoutingInfoForGprsErrors{UnexpectedDataValue: p}, nil
	case 1:
		p, err := decodeErrorParameter(data, present, UnknownSubscriberParamCodec(), opts...)
		if err != nil {
			return SendRoutingInfoForGprsErrors{}, err
		}
		return SendRoutingInfoForGprsErrors{UnknownSubscriber: p}, nil
	case 13:
		p, err := decodeErrorParameter(data, present, CallBarredParamCodec(), opts...)
		if err != nil {
			return SendRoutingInfoForGprsErrors{}, err
		}
		return SendRoutingInfoForGprsErrors{CallBarred: p}, nil
	default:
		return SendRoutingInfoForGprsErrors{}, fmt.Errorf("%w: error code %d is not in sendRoutingInfoForGprs ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeSendRoutingInfoForGprsError(value SendRoutingInfoForGprsErrors, opts ...ber.EncodeOption) (EncodedError, error) {
	selected := 0
	if value.AbsentSubscriber != nil {
		selected++
	}
	if value.SystemFailure != nil {
		selected++
	}
	if value.DataMissing != nil {
		selected++
	}
	if value.UnexpectedDataValue != nil {
		selected++
	}
	if value.UnknownSubscriber != nil {
		selected++
	}
	if value.CallBarred != nil {
		selected++
	}
	if selected != 1 {
		return EncodedError{}, fmt.Errorf("%w: exactly one sendRoutingInfoForGprs error arm is required", ber.ErrInvalidBinding)
	}
	if value.AbsentSubscriber != nil {
		return encodeMAPErrorMember(AbsentSubscriber, value.AbsentSubscriber, AbsentSubscriberParamCodec(), opts...)
	}
	if value.SystemFailure != nil {
		return encodeMAPErrorMember(SystemFailure, value.SystemFailure, SystemFailureParamCodec(), opts...)
	}
	if value.DataMissing != nil {
		return encodeMAPErrorMember(DataMissing, value.DataMissing, DataMissingParamCodec(), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	if value.UnknownSubscriber != nil {
		return encodeMAPErrorMember(UnknownSubscriber, value.UnknownSubscriber, UnknownSubscriberParamCodec(), opts...)
	}
	if value.CallBarred != nil {
		return encodeMAPErrorMember(CallBarred, value.CallBarred, CallBarredParamCodec(), opts...)
	}
	return EncodedError{}, fmt.Errorf("%w: no selected sendRoutingInfoForGprs error", ber.ErrInvalidBinding)
}

// SendRoutingInfoForLCSErrors selects exactly the formal ERRORS set of MAP-LocationServiceOperations.sendRoutingInfoForLCS.
type SendRoutingInfoForLCSErrors struct {
	SystemFailure                 *ErrorValue[SystemFailureParam]
	DataMissing                   *ErrorValue[DataMissingParam]
	UnexpectedDataValue           *ErrorValue[UnexpectedDataParam]
	FacilityNotSupported          *ErrorValue[FacilityNotSupParam]
	UnknownSubscriber             *ErrorValue[UnknownSubscriberParam]
	AbsentSubscriber              *ErrorValue[AbsentSubscriberParam]
	UnauthorizedRequestingNetwork *ErrorValue[UnauthorizedRequestingNetworkParam]
}

func infoSendRoutingInfoForLCSOperation() OperationInfo {
	return OperationInfo{Name: "sendRoutingInfoForLCS", Code: SendRoutingInfoForLCS, Argument: &TypeRef{ModuleOID: "0.4.0.0.1.3.25.22", ASN1Name: "RoutingInfoForLCS-Arg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "RoutingInfoForLCSArg"}, Result: &TypeRef{ModuleOID: "0.4.0.0.1.3.25.22", ASN1Name: "RoutingInfoForLCS-Res", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "RoutingInfoForLCSRes"}, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: false, Source: sourceInfo7("sendRoutingInfoForLCS", "17.6.8"), Errors: []ErrorInfo{infoSystemFailureError(), infoDataMissingError(), infoUnexpectedDataValueError(), infoFacilityNotSupportedError(), infoUnknownSubscriberError(), infoAbsentSubscriberError(), infoUnauthorizedRequestingNetworkError()}, Linked: []MAPOperationCode{}}
}

// SendRoutingInfoForLCSOperation binds the formal object in TS 29.002 V19.1.0 §17.6.8 (X.880 §§8.2–8.3).
func SendRoutingInfoForLCSOperation() Operation[RoutingInfoForLCSArg, RoutingInfoForLCSRes, SendRoutingInfoForLCSErrors] {
	return Operation[RoutingInfoForLCSArg, RoutingInfoForLCSRes, SendRoutingInfoForLCSErrors]{operationBinding[RoutingInfoForLCSArg, RoutingInfoForLCSRes, SendRoutingInfoForLCSErrors, OperationInfo, MAPOperationCode, EncodedError]{code: SendRoutingInfoForLCS, info: infoSendRoutingInfoForLCSOperation, argument: RoutingInfoForLCSArgCodec(), result: RoutingInfoForLCSResCodec(), decode: decodeSendRoutingInfoForLCSError, encode: encodeSendRoutingInfoForLCSError}}
}
func decodeSendRoutingInfoForLCSError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (SendRoutingInfoForLCSErrors, error) {
	switch code {
	case 34:
		p, err := decodeErrorParameter(data, present, SystemFailureParamCodec(), opts...)
		if err != nil {
			return SendRoutingInfoForLCSErrors{}, err
		}
		return SendRoutingInfoForLCSErrors{SystemFailure: p}, nil
	case 35:
		p, err := decodeErrorParameter(data, present, DataMissingParamCodec(), opts...)
		if err != nil {
			return SendRoutingInfoForLCSErrors{}, err
		}
		return SendRoutingInfoForLCSErrors{DataMissing: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return SendRoutingInfoForLCSErrors{}, err
		}
		return SendRoutingInfoForLCSErrors{UnexpectedDataValue: p}, nil
	case 21:
		p, err := decodeErrorParameter(data, present, FacilityNotSupParamCodec(), opts...)
		if err != nil {
			return SendRoutingInfoForLCSErrors{}, err
		}
		return SendRoutingInfoForLCSErrors{FacilityNotSupported: p}, nil
	case 1:
		p, err := decodeErrorParameter(data, present, UnknownSubscriberParamCodec(), opts...)
		if err != nil {
			return SendRoutingInfoForLCSErrors{}, err
		}
		return SendRoutingInfoForLCSErrors{UnknownSubscriber: p}, nil
	case 27:
		p, err := decodeErrorParameter(data, present, AbsentSubscriberParamCodec(), opts...)
		if err != nil {
			return SendRoutingInfoForLCSErrors{}, err
		}
		return SendRoutingInfoForLCSErrors{AbsentSubscriber: p}, nil
	case 52:
		p, err := decodeErrorParameter(data, present, UnauthorizedRequestingNetworkParamCodec(), opts...)
		if err != nil {
			return SendRoutingInfoForLCSErrors{}, err
		}
		return SendRoutingInfoForLCSErrors{UnauthorizedRequestingNetwork: p}, nil
	default:
		return SendRoutingInfoForLCSErrors{}, fmt.Errorf("%w: error code %d is not in sendRoutingInfoForLCS ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeSendRoutingInfoForLCSError(value SendRoutingInfoForLCSErrors, opts ...ber.EncodeOption) (EncodedError, error) {
	selected := 0
	if value.SystemFailure != nil {
		selected++
	}
	if value.DataMissing != nil {
		selected++
	}
	if value.UnexpectedDataValue != nil {
		selected++
	}
	if value.FacilityNotSupported != nil {
		selected++
	}
	if value.UnknownSubscriber != nil {
		selected++
	}
	if value.AbsentSubscriber != nil {
		selected++
	}
	if value.UnauthorizedRequestingNetwork != nil {
		selected++
	}
	if selected != 1 {
		return EncodedError{}, fmt.Errorf("%w: exactly one sendRoutingInfoForLCS error arm is required", ber.ErrInvalidBinding)
	}
	if value.SystemFailure != nil {
		return encodeMAPErrorMember(SystemFailure, value.SystemFailure, SystemFailureParamCodec(), opts...)
	}
	if value.DataMissing != nil {
		return encodeMAPErrorMember(DataMissing, value.DataMissing, DataMissingParamCodec(), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	if value.FacilityNotSupported != nil {
		return encodeMAPErrorMember(FacilityNotSupported, value.FacilityNotSupported, FacilityNotSupParamCodec(), opts...)
	}
	if value.UnknownSubscriber != nil {
		return encodeMAPErrorMember(UnknownSubscriber, value.UnknownSubscriber, UnknownSubscriberParamCodec(), opts...)
	}
	if value.AbsentSubscriber != nil {
		return encodeMAPErrorMember(AbsentSubscriber, value.AbsentSubscriber, AbsentSubscriberParamCodec(), opts...)
	}
	if value.UnauthorizedRequestingNetwork != nil {
		return encodeMAPErrorMember(UnauthorizedRequestingNetwork, value.UnauthorizedRequestingNetwork, UnauthorizedRequestingNetworkParamCodec(), opts...)
	}
	return EncodedError{}, fmt.Errorf("%w: no selected sendRoutingInfoForLCS error", ber.ErrInvalidBinding)
}

// SendRoutingInfoForSMErrors selects exactly the formal ERRORS set of MAP-ShortMessageServiceOperations.sendRoutingInfoForSM.
type SendRoutingInfoForSMErrors struct {
	SystemFailure             *ErrorValue[SystemFailureParam]
	DataMissing               *ErrorValue[DataMissingParam]
	UnexpectedDataValue       *ErrorValue[UnexpectedDataParam]
	FacilityNotSupported      *ErrorValue[FacilityNotSupParam]
	UnknownSubscriber         *ErrorValue[UnknownSubscriberParam]
	TeleserviceNotProvisioned *ErrorValue[TeleservNotProvParam]
	CallBarred                *ErrorValue[CallBarredParam]
	AbsentSubscriberSM        *ErrorValue[AbsentSubscriberSMParam]
}

func infoSendRoutingInfoForSMOperation() OperationInfo {
	return OperationInfo{Name: "sendRoutingInfoForSM", Code: SendRoutingInfoForSM, Argument: &TypeRef{ModuleOID: "0.4.0.0.1.3.16.22", ASN1Name: "RoutingInfoForSM-Arg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "RoutingInfoForSMArg"}, Result: &TypeRef{ModuleOID: "0.4.0.0.1.3.16.22", ASN1Name: "RoutingInfoForSM-Res", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "RoutingInfoForSMRes"}, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: false, Source: sourceInfo3("sendRoutingInfoForSM", "17.6.5"), Errors: []ErrorInfo{infoSystemFailureError(), infoDataMissingError(), infoUnexpectedDataValueError(), infoFacilityNotSupportedError(), infoUnknownSubscriberError(), infoTeleserviceNotProvisionedError(), infoCallBarredError(), infoAbsentSubscriberSMError()}, Linked: []MAPOperationCode{}}
}

// SendRoutingInfoForSMOperation binds the formal object in TS 29.002 V19.1.0 §17.6.5 (X.880 §§8.2–8.3).
func SendRoutingInfoForSMOperation() Operation[RoutingInfoForSMArg, RoutingInfoForSMRes, SendRoutingInfoForSMErrors] {
	return Operation[RoutingInfoForSMArg, RoutingInfoForSMRes, SendRoutingInfoForSMErrors]{operationBinding[RoutingInfoForSMArg, RoutingInfoForSMRes, SendRoutingInfoForSMErrors, OperationInfo, MAPOperationCode, EncodedError]{code: SendRoutingInfoForSM, info: infoSendRoutingInfoForSMOperation, argument: RoutingInfoForSMArgCodec(), result: RoutingInfoForSMResCodec(), decode: decodeSendRoutingInfoForSMError, encode: encodeSendRoutingInfoForSMError}}
}
func decodeSendRoutingInfoForSMError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (SendRoutingInfoForSMErrors, error) {
	switch code {
	case 34:
		p, err := decodeErrorParameter(data, present, SystemFailureParamCodec(), opts...)
		if err != nil {
			return SendRoutingInfoForSMErrors{}, err
		}
		return SendRoutingInfoForSMErrors{SystemFailure: p}, nil
	case 35:
		p, err := decodeErrorParameter(data, present, DataMissingParamCodec(), opts...)
		if err != nil {
			return SendRoutingInfoForSMErrors{}, err
		}
		return SendRoutingInfoForSMErrors{DataMissing: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return SendRoutingInfoForSMErrors{}, err
		}
		return SendRoutingInfoForSMErrors{UnexpectedDataValue: p}, nil
	case 21:
		p, err := decodeErrorParameter(data, present, FacilityNotSupParamCodec(), opts...)
		if err != nil {
			return SendRoutingInfoForSMErrors{}, err
		}
		return SendRoutingInfoForSMErrors{FacilityNotSupported: p}, nil
	case 1:
		p, err := decodeErrorParameter(data, present, UnknownSubscriberParamCodec(), opts...)
		if err != nil {
			return SendRoutingInfoForSMErrors{}, err
		}
		return SendRoutingInfoForSMErrors{UnknownSubscriber: p}, nil
	case 11:
		p, err := decodeErrorParameter(data, present, TeleservNotProvParamCodec(), opts...)
		if err != nil {
			return SendRoutingInfoForSMErrors{}, err
		}
		return SendRoutingInfoForSMErrors{TeleserviceNotProvisioned: p}, nil
	case 13:
		p, err := decodeErrorParameter(data, present, CallBarredParamCodec(), opts...)
		if err != nil {
			return SendRoutingInfoForSMErrors{}, err
		}
		return SendRoutingInfoForSMErrors{CallBarred: p}, nil
	case 6:
		p, err := decodeErrorParameter(data, present, AbsentSubscriberSMParamCodec(), opts...)
		if err != nil {
			return SendRoutingInfoForSMErrors{}, err
		}
		return SendRoutingInfoForSMErrors{AbsentSubscriberSM: p}, nil
	default:
		return SendRoutingInfoForSMErrors{}, fmt.Errorf("%w: error code %d is not in sendRoutingInfoForSM ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeSendRoutingInfoForSMError(value SendRoutingInfoForSMErrors, opts ...ber.EncodeOption) (EncodedError, error) {
	selected := 0
	if value.SystemFailure != nil {
		selected++
	}
	if value.DataMissing != nil {
		selected++
	}
	if value.UnexpectedDataValue != nil {
		selected++
	}
	if value.FacilityNotSupported != nil {
		selected++
	}
	if value.UnknownSubscriber != nil {
		selected++
	}
	if value.TeleserviceNotProvisioned != nil {
		selected++
	}
	if value.CallBarred != nil {
		selected++
	}
	if value.AbsentSubscriberSM != nil {
		selected++
	}
	if selected != 1 {
		return EncodedError{}, fmt.Errorf("%w: exactly one sendRoutingInfoForSM error arm is required", ber.ErrInvalidBinding)
	}
	if value.SystemFailure != nil {
		return encodeMAPErrorMember(SystemFailure, value.SystemFailure, SystemFailureParamCodec(), opts...)
	}
	if value.DataMissing != nil {
		return encodeMAPErrorMember(DataMissing, value.DataMissing, DataMissingParamCodec(), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	if value.FacilityNotSupported != nil {
		return encodeMAPErrorMember(FacilityNotSupported, value.FacilityNotSupported, FacilityNotSupParamCodec(), opts...)
	}
	if value.UnknownSubscriber != nil {
		return encodeMAPErrorMember(UnknownSubscriber, value.UnknownSubscriber, UnknownSubscriberParamCodec(), opts...)
	}
	if value.TeleserviceNotProvisioned != nil {
		return encodeMAPErrorMember(TeleserviceNotProvisioned, value.TeleserviceNotProvisioned, TeleservNotProvParamCodec(), opts...)
	}
	if value.CallBarred != nil {
		return encodeMAPErrorMember(CallBarred, value.CallBarred, CallBarredParamCodec(), opts...)
	}
	if value.AbsentSubscriberSM != nil {
		return encodeMAPErrorMember(AbsentSubscriberSM, value.AbsentSubscriberSM, AbsentSubscriberSMParamCodec(), opts...)
	}
	return EncodedError{}, fmt.Errorf("%w: no selected sendRoutingInfoForSM error", ber.ErrInvalidBinding)
}

// SetReportingStateErrors selects exactly the formal ERRORS set of MAP-CallHandlingOperations.setReportingState.
type SetReportingStateErrors struct {
	SystemFailure          *ErrorValue[SystemFailureParam]
	UnidentifiedSubscriber *ErrorValue[UnidentifiedSubParam]
	UnexpectedDataValue    *ErrorValue[UnexpectedDataParam]
	DataMissing            *ErrorValue[DataMissingParam]
	ResourceLimitation     *ErrorValue[ResourceLimitationParam]
	FacilityNotSupported   *ErrorValue[FacilityNotSupParam]
}

func infoSetReportingStateOperation() OperationInfo {
	return OperationInfo{Name: "setReportingState", Code: SetReportingState, Argument: &TypeRef{ModuleOID: "0.4.0.0.1.3.13.22", ASN1Name: "SetReportingStateArg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "SetReportingStateArg"}, Result: &TypeRef{ModuleOID: "0.4.0.0.1.3.13.22", ASN1Name: "SetReportingStateRes", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "SetReportingStateRes"}, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: false, Source: sourceInfo6("setReportingState", "17.6.3"), Errors: []ErrorInfo{infoSystemFailureError(), infoUnidentifiedSubscriberError(), infoUnexpectedDataValueError(), infoDataMissingError(), infoResourceLimitationError(), infoFacilityNotSupportedError()}, Linked: []MAPOperationCode{}}
}

// SetReportingStateOperation binds the formal object in TS 29.002 V19.1.0 §17.6.3 (X.880 §§8.2–8.3).
func SetReportingStateOperation() Operation[SetReportingStateArg, SetReportingStateRes, SetReportingStateErrors] {
	return Operation[SetReportingStateArg, SetReportingStateRes, SetReportingStateErrors]{operationBinding[SetReportingStateArg, SetReportingStateRes, SetReportingStateErrors, OperationInfo, MAPOperationCode, EncodedError]{code: SetReportingState, info: infoSetReportingStateOperation, argument: SetReportingStateArgCodec(), result: SetReportingStateResCodec(), decode: decodeSetReportingStateError, encode: encodeSetReportingStateError}}
}
func decodeSetReportingStateError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (SetReportingStateErrors, error) {
	switch code {
	case 34:
		p, err := decodeErrorParameter(data, present, SystemFailureParamCodec(), opts...)
		if err != nil {
			return SetReportingStateErrors{}, err
		}
		return SetReportingStateErrors{SystemFailure: p}, nil
	case 5:
		p, err := decodeErrorParameter(data, present, UnidentifiedSubParamCodec(), opts...)
		if err != nil {
			return SetReportingStateErrors{}, err
		}
		return SetReportingStateErrors{UnidentifiedSubscriber: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return SetReportingStateErrors{}, err
		}
		return SetReportingStateErrors{UnexpectedDataValue: p}, nil
	case 35:
		p, err := decodeErrorParameter(data, present, DataMissingParamCodec(), opts...)
		if err != nil {
			return SetReportingStateErrors{}, err
		}
		return SetReportingStateErrors{DataMissing: p}, nil
	case 51:
		p, err := decodeErrorParameter(data, present, ResourceLimitationParamCodec(), opts...)
		if err != nil {
			return SetReportingStateErrors{}, err
		}
		return SetReportingStateErrors{ResourceLimitation: p}, nil
	case 21:
		p, err := decodeErrorParameter(data, present, FacilityNotSupParamCodec(), opts...)
		if err != nil {
			return SetReportingStateErrors{}, err
		}
		return SetReportingStateErrors{FacilityNotSupported: p}, nil
	default:
		return SetReportingStateErrors{}, fmt.Errorf("%w: error code %d is not in setReportingState ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeSetReportingStateError(value SetReportingStateErrors, opts ...ber.EncodeOption) (EncodedError, error) {
	selected := 0
	if value.SystemFailure != nil {
		selected++
	}
	if value.UnidentifiedSubscriber != nil {
		selected++
	}
	if value.UnexpectedDataValue != nil {
		selected++
	}
	if value.DataMissing != nil {
		selected++
	}
	if value.ResourceLimitation != nil {
		selected++
	}
	if value.FacilityNotSupported != nil {
		selected++
	}
	if selected != 1 {
		return EncodedError{}, fmt.Errorf("%w: exactly one setReportingState error arm is required", ber.ErrInvalidBinding)
	}
	if value.SystemFailure != nil {
		return encodeMAPErrorMember(SystemFailure, value.SystemFailure, SystemFailureParamCodec(), opts...)
	}
	if value.UnidentifiedSubscriber != nil {
		return encodeMAPErrorMember(UnidentifiedSubscriber, value.UnidentifiedSubscriber, UnidentifiedSubParamCodec(), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	if value.DataMissing != nil {
		return encodeMAPErrorMember(DataMissing, value.DataMissing, DataMissingParamCodec(), opts...)
	}
	if value.ResourceLimitation != nil {
		return encodeMAPErrorMember(ResourceLimitation, value.ResourceLimitation, ResourceLimitationParamCodec(), opts...)
	}
	if value.FacilityNotSupported != nil {
		return encodeMAPErrorMember(FacilityNotSupported, value.FacilityNotSupported, FacilityNotSupParamCodec(), opts...)
	}
	return EncodedError{}, fmt.Errorf("%w: no selected setReportingState error", ber.ErrInvalidBinding)
}

// SsInvocationNotificationErrors selects exactly the formal ERRORS set of MAP-SupplementaryServiceOperations.ss-InvocationNotification.
type SsInvocationNotificationErrors struct {
	DataMissing         *ErrorValue[DataMissingParam]
	UnexpectedDataValue *ErrorValue[UnexpectedDataParam]
	UnknownSubscriber   *ErrorValue[UnknownSubscriberParam]
}

func infoSsInvocationNotificationOperation() OperationInfo {
	return OperationInfo{Name: "ss-InvocationNotification", Code: SsInvocationNotification, Argument: &TypeRef{ModuleOID: "0.4.0.0.1.3.14.22", ASN1Name: "SS-InvocationNotificationArg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "SSInvocationNotificationArg"}, Result: &TypeRef{ModuleOID: "0.4.0.0.1.3.14.22", ASN1Name: "SS-InvocationNotificationRes", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "SSInvocationNotificationRes"}, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: false, Source: sourceInfo1("ss-InvocationNotification", "17.6.4"), Errors: []ErrorInfo{infoDataMissingError(), infoUnexpectedDataValueError(), infoUnknownSubscriberError()}, Linked: []MAPOperationCode{}}
}

// SsInvocationNotificationOperation binds the formal object in TS 29.002 V19.1.0 §17.6.4 (X.880 §§8.2–8.3).
func SsInvocationNotificationOperation() Operation[SSInvocationNotificationArg, SSInvocationNotificationRes, SsInvocationNotificationErrors] {
	return Operation[SSInvocationNotificationArg, SSInvocationNotificationRes, SsInvocationNotificationErrors]{operationBinding[SSInvocationNotificationArg, SSInvocationNotificationRes, SsInvocationNotificationErrors, OperationInfo, MAPOperationCode, EncodedError]{code: SsInvocationNotification, info: infoSsInvocationNotificationOperation, argument: SSInvocationNotificationArgCodec(), result: SSInvocationNotificationResCodec(), decode: decodeSsInvocationNotificationError, encode: encodeSsInvocationNotificationError}}
}
func decodeSsInvocationNotificationError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (SsInvocationNotificationErrors, error) {
	switch code {
	case 35:
		p, err := decodeErrorParameter(data, present, DataMissingParamCodec(), opts...)
		if err != nil {
			return SsInvocationNotificationErrors{}, err
		}
		return SsInvocationNotificationErrors{DataMissing: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return SsInvocationNotificationErrors{}, err
		}
		return SsInvocationNotificationErrors{UnexpectedDataValue: p}, nil
	case 1:
		p, err := decodeErrorParameter(data, present, UnknownSubscriberParamCodec(), opts...)
		if err != nil {
			return SsInvocationNotificationErrors{}, err
		}
		return SsInvocationNotificationErrors{UnknownSubscriber: p}, nil
	default:
		return SsInvocationNotificationErrors{}, fmt.Errorf("%w: error code %d is not in ss-InvocationNotification ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeSsInvocationNotificationError(value SsInvocationNotificationErrors, opts ...ber.EncodeOption) (EncodedError, error) {
	selected := 0
	if value.DataMissing != nil {
		selected++
	}
	if value.UnexpectedDataValue != nil {
		selected++
	}
	if value.UnknownSubscriber != nil {
		selected++
	}
	if selected != 1 {
		return EncodedError{}, fmt.Errorf("%w: exactly one ss-InvocationNotification error arm is required", ber.ErrInvalidBinding)
	}
	if value.DataMissing != nil {
		return encodeMAPErrorMember(DataMissing, value.DataMissing, DataMissingParamCodec(), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	if value.UnknownSubscriber != nil {
		return encodeMAPErrorMember(UnknownSubscriber, value.UnknownSubscriber, UnknownSubscriberParamCodec(), opts...)
	}
	return EncodedError{}, fmt.Errorf("%w: no selected ss-InvocationNotification error", ber.ErrInvalidBinding)
}

// StatusReportErrors selects exactly the formal ERRORS set of MAP-CallHandlingOperations.statusReport.
type StatusReportErrors struct {
	UnknownSubscriber   *ErrorValue[UnknownSubscriberParam]
	SystemFailure       *ErrorValue[SystemFailureParam]
	UnexpectedDataValue *ErrorValue[UnexpectedDataParam]
	DataMissing         *ErrorValue[DataMissingParam]
}

func infoStatusReportOperation() OperationInfo {
	return OperationInfo{Name: "statusReport", Code: StatusReport, Argument: &TypeRef{ModuleOID: "0.4.0.0.1.3.13.22", ASN1Name: "StatusReportArg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "StatusReportArg"}, Result: &TypeRef{ModuleOID: "0.4.0.0.1.3.13.22", ASN1Name: "StatusReportRes", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "StatusReportRes"}, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: false, Source: sourceInfo6("statusReport", "17.6.3"), Errors: []ErrorInfo{infoUnknownSubscriberError(), infoSystemFailureError(), infoUnexpectedDataValueError(), infoDataMissingError()}, Linked: []MAPOperationCode{}}
}

// StatusReportOperation binds the formal object in TS 29.002 V19.1.0 §17.6.3 (X.880 §§8.2–8.3).
func StatusReportOperation() Operation[StatusReportArg, StatusReportRes, StatusReportErrors] {
	return Operation[StatusReportArg, StatusReportRes, StatusReportErrors]{operationBinding[StatusReportArg, StatusReportRes, StatusReportErrors, OperationInfo, MAPOperationCode, EncodedError]{code: StatusReport, info: infoStatusReportOperation, argument: StatusReportArgCodec(), result: StatusReportResCodec(), decode: decodeStatusReportError, encode: encodeStatusReportError}}
}
func decodeStatusReportError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (StatusReportErrors, error) {
	switch code {
	case 1:
		p, err := decodeErrorParameter(data, present, UnknownSubscriberParamCodec(), opts...)
		if err != nil {
			return StatusReportErrors{}, err
		}
		return StatusReportErrors{UnknownSubscriber: p}, nil
	case 34:
		p, err := decodeErrorParameter(data, present, SystemFailureParamCodec(), opts...)
		if err != nil {
			return StatusReportErrors{}, err
		}
		return StatusReportErrors{SystemFailure: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return StatusReportErrors{}, err
		}
		return StatusReportErrors{UnexpectedDataValue: p}, nil
	case 35:
		p, err := decodeErrorParameter(data, present, DataMissingParamCodec(), opts...)
		if err != nil {
			return StatusReportErrors{}, err
		}
		return StatusReportErrors{DataMissing: p}, nil
	default:
		return StatusReportErrors{}, fmt.Errorf("%w: error code %d is not in statusReport ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeStatusReportError(value StatusReportErrors, opts ...ber.EncodeOption) (EncodedError, error) {
	selected := 0
	if value.UnknownSubscriber != nil {
		selected++
	}
	if value.SystemFailure != nil {
		selected++
	}
	if value.UnexpectedDataValue != nil {
		selected++
	}
	if value.DataMissing != nil {
		selected++
	}
	if selected != 1 {
		return EncodedError{}, fmt.Errorf("%w: exactly one statusReport error arm is required", ber.ErrInvalidBinding)
	}
	if value.UnknownSubscriber != nil {
		return encodeMAPErrorMember(UnknownSubscriber, value.UnknownSubscriber, UnknownSubscriberParamCodec(), opts...)
	}
	if value.SystemFailure != nil {
		return encodeMAPErrorMember(SystemFailure, value.SystemFailure, SystemFailureParamCodec(), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	if value.DataMissing != nil {
		return encodeMAPErrorMember(DataMissing, value.DataMissing, DataMissingParamCodec(), opts...)
	}
	return EncodedError{}, fmt.Errorf("%w: no selected statusReport error", ber.ErrInvalidBinding)
}

// SubscriberLocationReportErrors selects exactly the formal ERRORS set of MAP-LocationServiceOperations.subscriberLocationReport.
type SubscriberLocationReportErrors struct {
	SystemFailure                 *ErrorValue[SystemFailureParam]
	DataMissing                   *ErrorValue[DataMissingParam]
	ResourceLimitation            *ErrorValue[ResourceLimitationParam]
	UnexpectedDataValue           *ErrorValue[UnexpectedDataParam]
	UnknownSubscriber             *ErrorValue[UnknownSubscriberParam]
	UnauthorizedRequestingNetwork *ErrorValue[UnauthorizedRequestingNetworkParam]
	UnknownOrUnreachableLCSClient *ErrorValue[UnknownOrUnreachableLCSClientParam]
}

func infoSubscriberLocationReportOperation() OperationInfo {
	return OperationInfo{Name: "subscriberLocationReport", Code: SubscriberLocationReport, Argument: &TypeRef{ModuleOID: "0.4.0.0.1.3.25.22", ASN1Name: "SubscriberLocationReport-Arg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "SubscriberLocationReportArg"}, Result: &TypeRef{ModuleOID: "0.4.0.0.1.3.25.22", ASN1Name: "SubscriberLocationReport-Res", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "SubscriberLocationReportRes"}, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: false, Source: sourceInfo7("subscriberLocationReport", "17.6.8"), Errors: []ErrorInfo{infoSystemFailureError(), infoDataMissingError(), infoResourceLimitationError(), infoUnexpectedDataValueError(), infoUnknownSubscriberError(), infoUnauthorizedRequestingNetworkError(), infoUnknownOrUnreachableLCSClientError()}, Linked: []MAPOperationCode{}}
}

// SubscriberLocationReportOperation binds the formal object in TS 29.002 V19.1.0 §17.6.8 (X.880 §§8.2–8.3).
func SubscriberLocationReportOperation() Operation[SubscriberLocationReportArg, SubscriberLocationReportRes, SubscriberLocationReportErrors] {
	return Operation[SubscriberLocationReportArg, SubscriberLocationReportRes, SubscriberLocationReportErrors]{operationBinding[SubscriberLocationReportArg, SubscriberLocationReportRes, SubscriberLocationReportErrors, OperationInfo, MAPOperationCode, EncodedError]{code: SubscriberLocationReport, info: infoSubscriberLocationReportOperation, argument: SubscriberLocationReportArgCodec(), result: SubscriberLocationReportResCodec(), decode: decodeSubscriberLocationReportError, encode: encodeSubscriberLocationReportError}}
}
func decodeSubscriberLocationReportError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (SubscriberLocationReportErrors, error) {
	switch code {
	case 34:
		p, err := decodeErrorParameter(data, present, SystemFailureParamCodec(), opts...)
		if err != nil {
			return SubscriberLocationReportErrors{}, err
		}
		return SubscriberLocationReportErrors{SystemFailure: p}, nil
	case 35:
		p, err := decodeErrorParameter(data, present, DataMissingParamCodec(), opts...)
		if err != nil {
			return SubscriberLocationReportErrors{}, err
		}
		return SubscriberLocationReportErrors{DataMissing: p}, nil
	case 51:
		p, err := decodeErrorParameter(data, present, ResourceLimitationParamCodec(), opts...)
		if err != nil {
			return SubscriberLocationReportErrors{}, err
		}
		return SubscriberLocationReportErrors{ResourceLimitation: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return SubscriberLocationReportErrors{}, err
		}
		return SubscriberLocationReportErrors{UnexpectedDataValue: p}, nil
	case 1:
		p, err := decodeErrorParameter(data, present, UnknownSubscriberParamCodec(), opts...)
		if err != nil {
			return SubscriberLocationReportErrors{}, err
		}
		return SubscriberLocationReportErrors{UnknownSubscriber: p}, nil
	case 52:
		p, err := decodeErrorParameter(data, present, UnauthorizedRequestingNetworkParamCodec(), opts...)
		if err != nil {
			return SubscriberLocationReportErrors{}, err
		}
		return SubscriberLocationReportErrors{UnauthorizedRequestingNetwork: p}, nil
	case 58:
		p, err := decodeErrorParameter(data, present, UnknownOrUnreachableLCSClientParamCodec(), opts...)
		if err != nil {
			return SubscriberLocationReportErrors{}, err
		}
		return SubscriberLocationReportErrors{UnknownOrUnreachableLCSClient: p}, nil
	default:
		return SubscriberLocationReportErrors{}, fmt.Errorf("%w: error code %d is not in subscriberLocationReport ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeSubscriberLocationReportError(value SubscriberLocationReportErrors, opts ...ber.EncodeOption) (EncodedError, error) {
	selected := 0
	if value.SystemFailure != nil {
		selected++
	}
	if value.DataMissing != nil {
		selected++
	}
	if value.ResourceLimitation != nil {
		selected++
	}
	if value.UnexpectedDataValue != nil {
		selected++
	}
	if value.UnknownSubscriber != nil {
		selected++
	}
	if value.UnauthorizedRequestingNetwork != nil {
		selected++
	}
	if value.UnknownOrUnreachableLCSClient != nil {
		selected++
	}
	if selected != 1 {
		return EncodedError{}, fmt.Errorf("%w: exactly one subscriberLocationReport error arm is required", ber.ErrInvalidBinding)
	}
	if value.SystemFailure != nil {
		return encodeMAPErrorMember(SystemFailure, value.SystemFailure, SystemFailureParamCodec(), opts...)
	}
	if value.DataMissing != nil {
		return encodeMAPErrorMember(DataMissing, value.DataMissing, DataMissingParamCodec(), opts...)
	}
	if value.ResourceLimitation != nil {
		return encodeMAPErrorMember(ResourceLimitation, value.ResourceLimitation, ResourceLimitationParamCodec(), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	if value.UnknownSubscriber != nil {
		return encodeMAPErrorMember(UnknownSubscriber, value.UnknownSubscriber, UnknownSubscriberParamCodec(), opts...)
	}
	if value.UnauthorizedRequestingNetwork != nil {
		return encodeMAPErrorMember(UnauthorizedRequestingNetwork, value.UnauthorizedRequestingNetwork, UnauthorizedRequestingNetworkParamCodec(), opts...)
	}
	if value.UnknownOrUnreachableLCSClient != nil {
		return encodeMAPErrorMember(UnknownOrUnreachableLCSClient, value.UnknownOrUnreachableLCSClient, UnknownOrUnreachableLCSClientParamCodec(), opts...)
	}
	return EncodedError{}, fmt.Errorf("%w: no selected subscriberLocationReport error", ber.ErrInvalidBinding)
}

// UnstructuredSSNotifyErrors selects exactly the formal ERRORS set of MAP-SupplementaryServiceOperations.unstructuredSS-Notify.
type UnstructuredSSNotifyErrors struct {
	SystemFailure       *ErrorValue[SystemFailureParam]
	DataMissing         *ErrorValue[DataMissingParam]
	UnexpectedDataValue *ErrorValue[UnexpectedDataParam]
	AbsentSubscriber    *ErrorValue[AbsentSubscriberParam]
	IllegalSubscriber   *ErrorValue[IllegalSubscriberParam]
	IllegalEquipment    *ErrorValue[IllegalEquipmentParam]
	UnknownAlphabet     *ErrorValue[NoParameter]
	UssdBusy            *ErrorValue[NoParameter]
}

func infoUnstructuredSSNotifyOperation() OperationInfo {
	return OperationInfo{Name: "unstructuredSS-Notify", Code: UnstructuredSSNotify, Argument: &TypeRef{ModuleOID: "0.4.0.0.1.3.14.22", ASN1Name: "USSD-Arg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "USSDArg"}, Result: nil, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: true, Source: sourceInfo1("unstructuredSS-Notify", "17.6.4"), Errors: []ErrorInfo{infoSystemFailureError(), infoDataMissingError(), infoUnexpectedDataValueError(), infoAbsentSubscriberError(), infoIllegalSubscriberError(), infoIllegalEquipmentError(), infoUnknownAlphabetError(), infoUssdBusyError()}, Linked: []MAPOperationCode{}}
}

// UnstructuredSSNotifyOperation binds the formal object in TS 29.002 V19.1.0 §17.6.4 (X.880 §§8.2–8.3).
func UnstructuredSSNotifyOperation() Operation[USSDArg, NoParameter, UnstructuredSSNotifyErrors] {
	return Operation[USSDArg, NoParameter, UnstructuredSSNotifyErrors]{operationBinding[USSDArg, NoParameter, UnstructuredSSNotifyErrors, OperationInfo, MAPOperationCode, EncodedError]{code: UnstructuredSSNotify, info: infoUnstructuredSSNotifyOperation, argument: USSDArgCodec(), result: ValueCodec[NoParameter]{}, decode: decodeUnstructuredSSNotifyError, encode: encodeUnstructuredSSNotifyError}}
}
func decodeUnstructuredSSNotifyError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (UnstructuredSSNotifyErrors, error) {
	switch code {
	case 34:
		p, err := decodeErrorParameter(data, present, SystemFailureParamCodec(), opts...)
		if err != nil {
			return UnstructuredSSNotifyErrors{}, err
		}
		return UnstructuredSSNotifyErrors{SystemFailure: p}, nil
	case 35:
		p, err := decodeErrorParameter(data, present, DataMissingParamCodec(), opts...)
		if err != nil {
			return UnstructuredSSNotifyErrors{}, err
		}
		return UnstructuredSSNotifyErrors{DataMissing: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return UnstructuredSSNotifyErrors{}, err
		}
		return UnstructuredSSNotifyErrors{UnexpectedDataValue: p}, nil
	case 27:
		p, err := decodeErrorParameter(data, present, AbsentSubscriberParamCodec(), opts...)
		if err != nil {
			return UnstructuredSSNotifyErrors{}, err
		}
		return UnstructuredSSNotifyErrors{AbsentSubscriber: p}, nil
	case 9:
		p, err := decodeErrorParameter(data, present, IllegalSubscriberParamCodec(), opts...)
		if err != nil {
			return UnstructuredSSNotifyErrors{}, err
		}
		return UnstructuredSSNotifyErrors{IllegalSubscriber: p}, nil
	case 12:
		p, err := decodeErrorParameter(data, present, IllegalEquipmentParamCodec(), opts...)
		if err != nil {
			return UnstructuredSSNotifyErrors{}, err
		}
		return UnstructuredSSNotifyErrors{IllegalEquipment: p}, nil
	case 71:
		p, err := decodeErrorParameter(data, present, ValueCodec[NoParameter]{}, opts...)
		if err != nil {
			return UnstructuredSSNotifyErrors{}, err
		}
		return UnstructuredSSNotifyErrors{UnknownAlphabet: p}, nil
	case 72:
		p, err := decodeErrorParameter(data, present, ValueCodec[NoParameter]{}, opts...)
		if err != nil {
			return UnstructuredSSNotifyErrors{}, err
		}
		return UnstructuredSSNotifyErrors{UssdBusy: p}, nil
	default:
		return UnstructuredSSNotifyErrors{}, fmt.Errorf("%w: error code %d is not in unstructuredSS-Notify ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeUnstructuredSSNotifyError(value UnstructuredSSNotifyErrors, opts ...ber.EncodeOption) (EncodedError, error) {
	selected := 0
	if value.SystemFailure != nil {
		selected++
	}
	if value.DataMissing != nil {
		selected++
	}
	if value.UnexpectedDataValue != nil {
		selected++
	}
	if value.AbsentSubscriber != nil {
		selected++
	}
	if value.IllegalSubscriber != nil {
		selected++
	}
	if value.IllegalEquipment != nil {
		selected++
	}
	if value.UnknownAlphabet != nil {
		selected++
	}
	if value.UssdBusy != nil {
		selected++
	}
	if selected != 1 {
		return EncodedError{}, fmt.Errorf("%w: exactly one unstructuredSS-Notify error arm is required", ber.ErrInvalidBinding)
	}
	if value.SystemFailure != nil {
		return encodeMAPErrorMember(SystemFailure, value.SystemFailure, SystemFailureParamCodec(), opts...)
	}
	if value.DataMissing != nil {
		return encodeMAPErrorMember(DataMissing, value.DataMissing, DataMissingParamCodec(), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	if value.AbsentSubscriber != nil {
		return encodeMAPErrorMember(AbsentSubscriber, value.AbsentSubscriber, AbsentSubscriberParamCodec(), opts...)
	}
	if value.IllegalSubscriber != nil {
		return encodeMAPErrorMember(IllegalSubscriber, value.IllegalSubscriber, IllegalSubscriberParamCodec(), opts...)
	}
	if value.IllegalEquipment != nil {
		return encodeMAPErrorMember(IllegalEquipment, value.IllegalEquipment, IllegalEquipmentParamCodec(), opts...)
	}
	if value.UnknownAlphabet != nil {
		return encodeMAPErrorMember(UnknownAlphabet, value.UnknownAlphabet, ValueCodec[NoParameter]{}, opts...)
	}
	if value.UssdBusy != nil {
		return encodeMAPErrorMember(UssdBusy, value.UssdBusy, ValueCodec[NoParameter]{}, opts...)
	}
	return EncodedError{}, fmt.Errorf("%w: no selected unstructuredSS-Notify error", ber.ErrInvalidBinding)
}

// UnstructuredSSRequestErrors selects exactly the formal ERRORS set of MAP-SupplementaryServiceOperations.unstructuredSS-Request.
type UnstructuredSSRequestErrors struct {
	SystemFailure       *ErrorValue[SystemFailureParam]
	DataMissing         *ErrorValue[DataMissingParam]
	UnexpectedDataValue *ErrorValue[UnexpectedDataParam]
	AbsentSubscriber    *ErrorValue[AbsentSubscriberParam]
	IllegalSubscriber   *ErrorValue[IllegalSubscriberParam]
	IllegalEquipment    *ErrorValue[IllegalEquipmentParam]
	UnknownAlphabet     *ErrorValue[NoParameter]
	UssdBusy            *ErrorValue[NoParameter]
}

func infoUnstructuredSSRequestOperation() OperationInfo {
	return OperationInfo{Name: "unstructuredSS-Request", Code: UnstructuredSSRequest, Argument: &TypeRef{ModuleOID: "0.4.0.0.1.3.14.22", ASN1Name: "USSD-Arg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "USSDArg"}, Result: &TypeRef{ModuleOID: "0.4.0.0.1.3.14.22", ASN1Name: "USSD-Res", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "USSDRes"}, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: false, Source: sourceInfo1("unstructuredSS-Request", "17.6.4"), Errors: []ErrorInfo{infoSystemFailureError(), infoDataMissingError(), infoUnexpectedDataValueError(), infoAbsentSubscriberError(), infoIllegalSubscriberError(), infoIllegalEquipmentError(), infoUnknownAlphabetError(), infoUssdBusyError()}, Linked: []MAPOperationCode{}}
}

// UnstructuredSSRequestOperation binds the formal object in TS 29.002 V19.1.0 §17.6.4 (X.880 §§8.2–8.3).
func UnstructuredSSRequestOperation() Operation[USSDArg, USSDRes, UnstructuredSSRequestErrors] {
	return Operation[USSDArg, USSDRes, UnstructuredSSRequestErrors]{operationBinding[USSDArg, USSDRes, UnstructuredSSRequestErrors, OperationInfo, MAPOperationCode, EncodedError]{code: UnstructuredSSRequest, info: infoUnstructuredSSRequestOperation, argument: USSDArgCodec(), result: USSDResCodec(), decode: decodeUnstructuredSSRequestError, encode: encodeUnstructuredSSRequestError}}
}
func decodeUnstructuredSSRequestError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (UnstructuredSSRequestErrors, error) {
	switch code {
	case 34:
		p, err := decodeErrorParameter(data, present, SystemFailureParamCodec(), opts...)
		if err != nil {
			return UnstructuredSSRequestErrors{}, err
		}
		return UnstructuredSSRequestErrors{SystemFailure: p}, nil
	case 35:
		p, err := decodeErrorParameter(data, present, DataMissingParamCodec(), opts...)
		if err != nil {
			return UnstructuredSSRequestErrors{}, err
		}
		return UnstructuredSSRequestErrors{DataMissing: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return UnstructuredSSRequestErrors{}, err
		}
		return UnstructuredSSRequestErrors{UnexpectedDataValue: p}, nil
	case 27:
		p, err := decodeErrorParameter(data, present, AbsentSubscriberParamCodec(), opts...)
		if err != nil {
			return UnstructuredSSRequestErrors{}, err
		}
		return UnstructuredSSRequestErrors{AbsentSubscriber: p}, nil
	case 9:
		p, err := decodeErrorParameter(data, present, IllegalSubscriberParamCodec(), opts...)
		if err != nil {
			return UnstructuredSSRequestErrors{}, err
		}
		return UnstructuredSSRequestErrors{IllegalSubscriber: p}, nil
	case 12:
		p, err := decodeErrorParameter(data, present, IllegalEquipmentParamCodec(), opts...)
		if err != nil {
			return UnstructuredSSRequestErrors{}, err
		}
		return UnstructuredSSRequestErrors{IllegalEquipment: p}, nil
	case 71:
		p, err := decodeErrorParameter(data, present, ValueCodec[NoParameter]{}, opts...)
		if err != nil {
			return UnstructuredSSRequestErrors{}, err
		}
		return UnstructuredSSRequestErrors{UnknownAlphabet: p}, nil
	case 72:
		p, err := decodeErrorParameter(data, present, ValueCodec[NoParameter]{}, opts...)
		if err != nil {
			return UnstructuredSSRequestErrors{}, err
		}
		return UnstructuredSSRequestErrors{UssdBusy: p}, nil
	default:
		return UnstructuredSSRequestErrors{}, fmt.Errorf("%w: error code %d is not in unstructuredSS-Request ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeUnstructuredSSRequestError(value UnstructuredSSRequestErrors, opts ...ber.EncodeOption) (EncodedError, error) {
	selected := 0
	if value.SystemFailure != nil {
		selected++
	}
	if value.DataMissing != nil {
		selected++
	}
	if value.UnexpectedDataValue != nil {
		selected++
	}
	if value.AbsentSubscriber != nil {
		selected++
	}
	if value.IllegalSubscriber != nil {
		selected++
	}
	if value.IllegalEquipment != nil {
		selected++
	}
	if value.UnknownAlphabet != nil {
		selected++
	}
	if value.UssdBusy != nil {
		selected++
	}
	if selected != 1 {
		return EncodedError{}, fmt.Errorf("%w: exactly one unstructuredSS-Request error arm is required", ber.ErrInvalidBinding)
	}
	if value.SystemFailure != nil {
		return encodeMAPErrorMember(SystemFailure, value.SystemFailure, SystemFailureParamCodec(), opts...)
	}
	if value.DataMissing != nil {
		return encodeMAPErrorMember(DataMissing, value.DataMissing, DataMissingParamCodec(), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	if value.AbsentSubscriber != nil {
		return encodeMAPErrorMember(AbsentSubscriber, value.AbsentSubscriber, AbsentSubscriberParamCodec(), opts...)
	}
	if value.IllegalSubscriber != nil {
		return encodeMAPErrorMember(IllegalSubscriber, value.IllegalSubscriber, IllegalSubscriberParamCodec(), opts...)
	}
	if value.IllegalEquipment != nil {
		return encodeMAPErrorMember(IllegalEquipment, value.IllegalEquipment, IllegalEquipmentParamCodec(), opts...)
	}
	if value.UnknownAlphabet != nil {
		return encodeMAPErrorMember(UnknownAlphabet, value.UnknownAlphabet, ValueCodec[NoParameter]{}, opts...)
	}
	if value.UssdBusy != nil {
		return encodeMAPErrorMember(UssdBusy, value.UssdBusy, ValueCodec[NoParameter]{}, opts...)
	}
	return EncodedError{}, fmt.Errorf("%w: no selected unstructuredSS-Request error", ber.ErrInvalidBinding)
}

// UpdateGprsLocationErrors selects exactly the formal ERRORS set of MAP-MobileServiceOperations.updateGprsLocation.
type UpdateGprsLocationErrors struct {
	SystemFailure       *ErrorValue[SystemFailureParam]
	UnexpectedDataValue *ErrorValue[UnexpectedDataParam]
	UnknownSubscriber   *ErrorValue[UnknownSubscriberParam]
	RoamingNotAllowed   *ErrorValue[RoamingNotAllowedParam]
}

func infoUpdateGprsLocationOperation() OperationInfo {
	return OperationInfo{Name: "updateGprsLocation", Code: UpdateGprsLocation, Argument: &TypeRef{ModuleOID: "0.4.0.0.1.3.11.22", ASN1Name: "UpdateGprsLocationArg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "UpdateGprsLocationArg"}, Result: &TypeRef{ModuleOID: "0.4.0.0.1.3.11.22", ASN1Name: "UpdateGprsLocationRes", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "UpdateGprsLocationRes"}, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: false, Source: sourceInfo4("updateGprsLocation", "17.6.1"), Errors: []ErrorInfo{infoSystemFailureError(), infoUnexpectedDataValueError(), infoUnknownSubscriberError(), infoRoamingNotAllowedError()}, Linked: []MAPOperationCode{}}
}

// UpdateGprsLocationOperation binds the formal object in TS 29.002 V19.1.0 §17.6.1 (X.880 §§8.2–8.3).
func UpdateGprsLocationOperation() Operation[UpdateGprsLocationArg, UpdateGprsLocationRes, UpdateGprsLocationErrors] {
	return Operation[UpdateGprsLocationArg, UpdateGprsLocationRes, UpdateGprsLocationErrors]{operationBinding[UpdateGprsLocationArg, UpdateGprsLocationRes, UpdateGprsLocationErrors, OperationInfo, MAPOperationCode, EncodedError]{code: UpdateGprsLocation, info: infoUpdateGprsLocationOperation, argument: UpdateGprsLocationArgCodec(), result: UpdateGprsLocationResCodec(), decode: decodeUpdateGprsLocationError, encode: encodeUpdateGprsLocationError}}
}
func decodeUpdateGprsLocationError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (UpdateGprsLocationErrors, error) {
	switch code {
	case 34:
		p, err := decodeErrorParameter(data, present, SystemFailureParamCodec(), opts...)
		if err != nil {
			return UpdateGprsLocationErrors{}, err
		}
		return UpdateGprsLocationErrors{SystemFailure: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return UpdateGprsLocationErrors{}, err
		}
		return UpdateGprsLocationErrors{UnexpectedDataValue: p}, nil
	case 1:
		p, err := decodeErrorParameter(data, present, UnknownSubscriberParamCodec(), opts...)
		if err != nil {
			return UpdateGprsLocationErrors{}, err
		}
		return UpdateGprsLocationErrors{UnknownSubscriber: p}, nil
	case 8:
		p, err := decodeErrorParameter(data, present, RoamingNotAllowedParamCodec(), opts...)
		if err != nil {
			return UpdateGprsLocationErrors{}, err
		}
		return UpdateGprsLocationErrors{RoamingNotAllowed: p}, nil
	default:
		return UpdateGprsLocationErrors{}, fmt.Errorf("%w: error code %d is not in updateGprsLocation ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeUpdateGprsLocationError(value UpdateGprsLocationErrors, opts ...ber.EncodeOption) (EncodedError, error) {
	selected := 0
	if value.SystemFailure != nil {
		selected++
	}
	if value.UnexpectedDataValue != nil {
		selected++
	}
	if value.UnknownSubscriber != nil {
		selected++
	}
	if value.RoamingNotAllowed != nil {
		selected++
	}
	if selected != 1 {
		return EncodedError{}, fmt.Errorf("%w: exactly one updateGprsLocation error arm is required", ber.ErrInvalidBinding)
	}
	if value.SystemFailure != nil {
		return encodeMAPErrorMember(SystemFailure, value.SystemFailure, SystemFailureParamCodec(), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	if value.UnknownSubscriber != nil {
		return encodeMAPErrorMember(UnknownSubscriber, value.UnknownSubscriber, UnknownSubscriberParamCodec(), opts...)
	}
	if value.RoamingNotAllowed != nil {
		return encodeMAPErrorMember(RoamingNotAllowed, value.RoamingNotAllowed, RoamingNotAllowedParamCodec(), opts...)
	}
	return EncodedError{}, fmt.Errorf("%w: no selected updateGprsLocation error", ber.ErrInvalidBinding)
}

// UpdateLocationErrors selects exactly the formal ERRORS set of MAP-MobileServiceOperations.updateLocation.
type UpdateLocationErrors struct {
	SystemFailure       *ErrorValue[SystemFailureParam]
	DataMissing         *ErrorValue[DataMissingParam]
	UnexpectedDataValue *ErrorValue[UnexpectedDataParam]
	UnknownSubscriber   *ErrorValue[UnknownSubscriberParam]
	RoamingNotAllowed   *ErrorValue[RoamingNotAllowedParam]
}

func infoUpdateLocationOperation() OperationInfo {
	return OperationInfo{Name: "updateLocation", Code: UpdateLocation, Argument: &TypeRef{ModuleOID: "0.4.0.0.1.3.11.22", ASN1Name: "UpdateLocationArg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "UpdateLocationArg"}, Result: &TypeRef{ModuleOID: "0.4.0.0.1.3.11.22", ASN1Name: "UpdateLocationRes", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "UpdateLocationRes"}, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: false, Source: sourceInfo4("updateLocation", "17.6.1"), Errors: []ErrorInfo{infoSystemFailureError(), infoDataMissingError(), infoUnexpectedDataValueError(), infoUnknownSubscriberError(), infoRoamingNotAllowedError()}, Linked: []MAPOperationCode{}}
}

// UpdateLocationOperation binds the formal object in TS 29.002 V19.1.0 §17.6.1 (X.880 §§8.2–8.3).
func UpdateLocationOperation() Operation[UpdateLocationArg, UpdateLocationRes, UpdateLocationErrors] {
	return Operation[UpdateLocationArg, UpdateLocationRes, UpdateLocationErrors]{operationBinding[UpdateLocationArg, UpdateLocationRes, UpdateLocationErrors, OperationInfo, MAPOperationCode, EncodedError]{code: UpdateLocation, info: infoUpdateLocationOperation, argument: UpdateLocationArgCodec(), result: UpdateLocationResCodec(), decode: decodeUpdateLocationError, encode: encodeUpdateLocationError}}
}
func decodeUpdateLocationError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (UpdateLocationErrors, error) {
	switch code {
	case 34:
		p, err := decodeErrorParameter(data, present, SystemFailureParamCodec(), opts...)
		if err != nil {
			return UpdateLocationErrors{}, err
		}
		return UpdateLocationErrors{SystemFailure: p}, nil
	case 35:
		p, err := decodeErrorParameter(data, present, DataMissingParamCodec(), opts...)
		if err != nil {
			return UpdateLocationErrors{}, err
		}
		return UpdateLocationErrors{DataMissing: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return UpdateLocationErrors{}, err
		}
		return UpdateLocationErrors{UnexpectedDataValue: p}, nil
	case 1:
		p, err := decodeErrorParameter(data, present, UnknownSubscriberParamCodec(), opts...)
		if err != nil {
			return UpdateLocationErrors{}, err
		}
		return UpdateLocationErrors{UnknownSubscriber: p}, nil
	case 8:
		p, err := decodeErrorParameter(data, present, RoamingNotAllowedParamCodec(), opts...)
		if err != nil {
			return UpdateLocationErrors{}, err
		}
		return UpdateLocationErrors{RoamingNotAllowed: p}, nil
	default:
		return UpdateLocationErrors{}, fmt.Errorf("%w: error code %d is not in updateLocation ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeUpdateLocationError(value UpdateLocationErrors, opts ...ber.EncodeOption) (EncodedError, error) {
	selected := 0
	if value.SystemFailure != nil {
		selected++
	}
	if value.DataMissing != nil {
		selected++
	}
	if value.UnexpectedDataValue != nil {
		selected++
	}
	if value.UnknownSubscriber != nil {
		selected++
	}
	if value.RoamingNotAllowed != nil {
		selected++
	}
	if selected != 1 {
		return EncodedError{}, fmt.Errorf("%w: exactly one updateLocation error arm is required", ber.ErrInvalidBinding)
	}
	if value.SystemFailure != nil {
		return encodeMAPErrorMember(SystemFailure, value.SystemFailure, SystemFailureParamCodec(), opts...)
	}
	if value.DataMissing != nil {
		return encodeMAPErrorMember(DataMissing, value.DataMissing, DataMissingParamCodec(), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	if value.UnknownSubscriber != nil {
		return encodeMAPErrorMember(UnknownSubscriber, value.UnknownSubscriber, UnknownSubscriberParamCodec(), opts...)
	}
	if value.RoamingNotAllowed != nil {
		return encodeMAPErrorMember(RoamingNotAllowed, value.RoamingNotAllowed, RoamingNotAllowedParamCodec(), opts...)
	}
	return EncodedError{}, fmt.Errorf("%w: no selected updateLocation error", ber.ErrInvalidBinding)
}

// UpdateVcsgLocationErrors selects exactly the formal ERRORS set of MAP-MobileServiceOperations.updateVcsgLocation.
type UpdateVcsgLocationErrors struct {
	SystemFailure       *ErrorValue[SystemFailureParam]
	UnexpectedDataValue *ErrorValue[UnexpectedDataParam]
	UnknownSubscriber   *ErrorValue[UnknownSubscriberParam]
}

func infoUpdateVcsgLocationOperation() OperationInfo {
	return OperationInfo{Name: "updateVcsgLocation", Code: UpdateVcsgLocation, Argument: &TypeRef{ModuleOID: "0.4.0.0.1.3.11.22", ASN1Name: "UpdateVcsgLocationArg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "UpdateVcsgLocationArg"}, Result: &TypeRef{ModuleOID: "0.4.0.0.1.3.11.22", ASN1Name: "UpdateVcsgLocationRes", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "UpdateVcsgLocationRes"}, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: false, Source: sourceInfo4("updateVcsgLocation", "17.6.1"), Errors: []ErrorInfo{infoSystemFailureError(), infoUnexpectedDataValueError(), infoUnknownSubscriberError()}, Linked: []MAPOperationCode{}}
}

// UpdateVcsgLocationOperation binds the formal object in TS 29.002 V19.1.0 §17.6.1 (X.880 §§8.2–8.3).
func UpdateVcsgLocationOperation() Operation[UpdateVcsgLocationArg, UpdateVcsgLocationRes, UpdateVcsgLocationErrors] {
	return Operation[UpdateVcsgLocationArg, UpdateVcsgLocationRes, UpdateVcsgLocationErrors]{operationBinding[UpdateVcsgLocationArg, UpdateVcsgLocationRes, UpdateVcsgLocationErrors, OperationInfo, MAPOperationCode, EncodedError]{code: UpdateVcsgLocation, info: infoUpdateVcsgLocationOperation, argument: UpdateVcsgLocationArgCodec(), result: UpdateVcsgLocationResCodec(), decode: decodeUpdateVcsgLocationError, encode: encodeUpdateVcsgLocationError}}
}
func decodeUpdateVcsgLocationError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (UpdateVcsgLocationErrors, error) {
	switch code {
	case 34:
		p, err := decodeErrorParameter(data, present, SystemFailureParamCodec(), opts...)
		if err != nil {
			return UpdateVcsgLocationErrors{}, err
		}
		return UpdateVcsgLocationErrors{SystemFailure: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return UpdateVcsgLocationErrors{}, err
		}
		return UpdateVcsgLocationErrors{UnexpectedDataValue: p}, nil
	case 1:
		p, err := decodeErrorParameter(data, present, UnknownSubscriberParamCodec(), opts...)
		if err != nil {
			return UpdateVcsgLocationErrors{}, err
		}
		return UpdateVcsgLocationErrors{UnknownSubscriber: p}, nil
	default:
		return UpdateVcsgLocationErrors{}, fmt.Errorf("%w: error code %d is not in updateVcsgLocation ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeUpdateVcsgLocationError(value UpdateVcsgLocationErrors, opts ...ber.EncodeOption) (EncodedError, error) {
	selected := 0
	if value.SystemFailure != nil {
		selected++
	}
	if value.UnexpectedDataValue != nil {
		selected++
	}
	if value.UnknownSubscriber != nil {
		selected++
	}
	if selected != 1 {
		return EncodedError{}, fmt.Errorf("%w: exactly one updateVcsgLocation error arm is required", ber.ErrInvalidBinding)
	}
	if value.SystemFailure != nil {
		return encodeMAPErrorMember(SystemFailure, value.SystemFailure, SystemFailureParamCodec(), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	if value.UnknownSubscriber != nil {
		return encodeMAPErrorMember(UnknownSubscriber, value.UnknownSubscriber, UnknownSubscriberParamCodec(), opts...)
	}
	return EncodedError{}, fmt.Errorf("%w: no selected updateVcsgLocation error", ber.ErrInvalidBinding)
}
func Operations() []OperationInfo {
	return []OperationInfo{infoActivateSSOperation(), infoActivateTraceModeOperation(), infoAlertServiceCentreOperation(), infoAnyTimeInterrogationOperation(), infoAnyTimeModificationOperation(), infoAnyTimeSubscriptionInterrogationOperation(), infoAuthenticationFailureReportOperation(), infoCancelLocationOperation(), infoCancelVcsgLocationOperation(), infoCheckIMEIOperation(), infoDeactivateSSOperation(), infoDeactivateTraceModeOperation(), infoDeleteSubscriberDataOperation(), infoEraseCCEntryOperation(), infoEraseSSOperation(), infoFailureReportOperation(), infoForwardAccessSignallingOperation(), infoForwardCheckSSIndicationOperation(), infoForwardGroupCallSignallingOperation(), infoGetPasswordOperation(), infoInformServiceCentreOperation(), infoInsertSubscriberDataOperation(), infoInterrogateSSOperation(), infoIstAlertOperation(), infoIstCommandOperation(), infoMoForwardSMOperation(), infoMtForwardSMOperation(), infoMtForwardSMVGCSOperation(), infoNoteMMEventOperation(), infoNoteMsPresentForGprsOperation(), infoNoteSubscriberDataModifiedOperation(), infoPrepareGroupCallOperation(), infoPrepareHandoverOperation(), infoPrepareSubsequentHandoverOperation(), infoProcessAccessSignallingOperation(), infoProcessGroupCallSignallingOperation(), infoProcessUnstructuredSSRequestOperation(), infoProvideRoamingNumberOperation(), infoProvideSubscriberInfoOperation(), infoProvideSubscriberLocationOperation(), infoPurgeMSOperation(), infoReadyForSMOperation(), infoRegisterCCEntryOperation(), infoRegisterPasswordOperation(), infoRegisterSSOperation(), infoReleaseResourcesOperation(), infoRemoteUserFreeOperation(), infoReportSMDeliveryStatusOperation(), infoResetOperation(), infoRestoreDataOperation(), infoResumeCallHandlingOperation(), infoSendAuthenticationInfoOperation(), infoSendEndSignalOperation(), infoSendGroupCallEndSignalOperation(), infoSendGroupCallInfoOperation(), infoSendIMSIOperation(), infoSendIdentificationOperation(), infoSendRoutingInfoOperation(), infoSendRoutingInfoForGprsOperation(), infoSendRoutingInfoForLCSOperation(), infoSendRoutingInfoForSMOperation(), infoSetReportingStateOperation(), infoSsInvocationNotificationOperation(), infoStatusReportOperation(), infoSubscriberLocationReportOperation(), infoUnstructuredSSNotifyOperation(), infoUnstructuredSSRequestOperation(), infoUpdateGprsLocationOperation(), infoUpdateLocationOperation(), infoUpdateVcsgLocationOperation()}
}
func LookupOperation(code MAPOperationCode) (OperationInfo, bool) {
	switch code {
	case ActivateSS:
		return infoActivateSSOperation(), true
	case ActivateTraceMode:
		return infoActivateTraceModeOperation(), true
	case AlertServiceCentre:
		return infoAlertServiceCentreOperation(), true
	case AnyTimeInterrogation:
		return infoAnyTimeInterrogationOperation(), true
	case AnyTimeModification:
		return infoAnyTimeModificationOperation(), true
	case AnyTimeSubscriptionInterrogation:
		return infoAnyTimeSubscriptionInterrogationOperation(), true
	case AuthenticationFailureReport:
		return infoAuthenticationFailureReportOperation(), true
	case CancelLocation:
		return infoCancelLocationOperation(), true
	case CancelVcsgLocation:
		return infoCancelVcsgLocationOperation(), true
	case CheckIMEI:
		return infoCheckIMEIOperation(), true
	case DeactivateSS:
		return infoDeactivateSSOperation(), true
	case DeactivateTraceMode:
		return infoDeactivateTraceModeOperation(), true
	case DeleteSubscriberData:
		return infoDeleteSubscriberDataOperation(), true
	case EraseCCEntry:
		return infoEraseCCEntryOperation(), true
	case EraseSS:
		return infoEraseSSOperation(), true
	case FailureReport:
		return infoFailureReportOperation(), true
	case ForwardAccessSignalling:
		return infoForwardAccessSignallingOperation(), true
	case ForwardCheckSSIndication:
		return infoForwardCheckSSIndicationOperation(), true
	case ForwardGroupCallSignalling:
		return infoForwardGroupCallSignallingOperation(), true
	case GetPassword:
		return infoGetPasswordOperation(), true
	case InformServiceCentre:
		return infoInformServiceCentreOperation(), true
	case InsertSubscriberData:
		return infoInsertSubscriberDataOperation(), true
	case InterrogateSS:
		return infoInterrogateSSOperation(), true
	case IstAlert:
		return infoIstAlertOperation(), true
	case IstCommand:
		return infoIstCommandOperation(), true
	case MoForwardSM:
		return infoMoForwardSMOperation(), true
	case MtForwardSM:
		return infoMtForwardSMOperation(), true
	case MtForwardSMVGCS:
		return infoMtForwardSMVGCSOperation(), true
	case NoteMMEvent:
		return infoNoteMMEventOperation(), true
	case NoteMsPresentForGprs:
		return infoNoteMsPresentForGprsOperation(), true
	case NoteSubscriberDataModified:
		return infoNoteSubscriberDataModifiedOperation(), true
	case PrepareGroupCall:
		return infoPrepareGroupCallOperation(), true
	case PrepareHandover:
		return infoPrepareHandoverOperation(), true
	case PrepareSubsequentHandover:
		return infoPrepareSubsequentHandoverOperation(), true
	case ProcessAccessSignalling:
		return infoProcessAccessSignallingOperation(), true
	case ProcessGroupCallSignalling:
		return infoProcessGroupCallSignallingOperation(), true
	case ProcessUnstructuredSSRequest:
		return infoProcessUnstructuredSSRequestOperation(), true
	case ProvideRoamingNumber:
		return infoProvideRoamingNumberOperation(), true
	case ProvideSubscriberInfo:
		return infoProvideSubscriberInfoOperation(), true
	case ProvideSubscriberLocation:
		return infoProvideSubscriberLocationOperation(), true
	case PurgeMS:
		return infoPurgeMSOperation(), true
	case ReadyForSM:
		return infoReadyForSMOperation(), true
	case RegisterCCEntry:
		return infoRegisterCCEntryOperation(), true
	case RegisterPassword:
		return infoRegisterPasswordOperation(), true
	case RegisterSS:
		return infoRegisterSSOperation(), true
	case ReleaseResources:
		return infoReleaseResourcesOperation(), true
	case RemoteUserFree:
		return infoRemoteUserFreeOperation(), true
	case ReportSMDeliveryStatus:
		return infoReportSMDeliveryStatusOperation(), true
	case Reset:
		return infoResetOperation(), true
	case RestoreData:
		return infoRestoreDataOperation(), true
	case ResumeCallHandling:
		return infoResumeCallHandlingOperation(), true
	case SendAuthenticationInfo:
		return infoSendAuthenticationInfoOperation(), true
	case SendEndSignal:
		return infoSendEndSignalOperation(), true
	case SendGroupCallEndSignal:
		return infoSendGroupCallEndSignalOperation(), true
	case SendGroupCallInfo:
		return infoSendGroupCallInfoOperation(), true
	case SendIMSI:
		return infoSendIMSIOperation(), true
	case SendIdentification:
		return infoSendIdentificationOperation(), true
	case SendRoutingInfo:
		return infoSendRoutingInfoOperation(), true
	case SendRoutingInfoForGprs:
		return infoSendRoutingInfoForGprsOperation(), true
	case SendRoutingInfoForLCS:
		return infoSendRoutingInfoForLCSOperation(), true
	case SendRoutingInfoForSM:
		return infoSendRoutingInfoForSMOperation(), true
	case SetReportingState:
		return infoSetReportingStateOperation(), true
	case SsInvocationNotification:
		return infoSsInvocationNotificationOperation(), true
	case StatusReport:
		return infoStatusReportOperation(), true
	case SubscriberLocationReport:
		return infoSubscriberLocationReportOperation(), true
	case UnstructuredSSNotify:
		return infoUnstructuredSSNotifyOperation(), true
	case UnstructuredSSRequest:
		return infoUnstructuredSSRequestOperation(), true
	case UpdateGprsLocation:
		return infoUpdateGprsLocationOperation(), true
	case UpdateLocation:
		return infoUpdateLocationOperation(), true
	case UpdateVcsgLocation:
		return infoUpdateVcsgLocationOperation(), true
	default:
		return OperationInfo{}, false
	}
}

type SSErrorInfo struct {
	Name              string
	Code              SSErrorCode
	Parameter         *TypeRef
	ParameterOptional *bool
	Source            SourceRef
}
type SSErrorDescriptor[P any] struct {
	errorBinding[P, SSErrorInfo, SSErrorCode]
}

// SSDeflectionToServedSubscriberErrorDescriptor binds the formal ERROR object SS-Errors.deflectionToServedSubscriber (X.880 §8.3).
func SSDeflectionToServedSubscriberErrorDescriptor() SSErrorDescriptor[NoParameter] {
	return SSErrorDescriptor[NoParameter]{errorBinding[NoParameter, SSErrorInfo, SSErrorCode]{code: SSDeflectionToServedSubscriber, info: infoSSDeflectionToServedSubscriberError, parameter: ValueCodec[NoParameter]{}}}
}
func infoSSDeflectionToServedSubscriberError() SSErrorInfo {
	return SSErrorInfo{Name: "deflectionToServedSubscriber", Code: SSDeflectionToServedSubscriber, Parameter: nil, ParameterOptional: nil, Source: sourceInfo8("deflectionToServedSubscriber", "4.3")}
}

// SSInvalidDeflectedToNumberErrorDescriptor binds the formal ERROR object SS-Errors.invalidDeflectedToNumber (X.880 §8.3).
func SSInvalidDeflectedToNumberErrorDescriptor() SSErrorDescriptor[NoParameter] {
	return SSErrorDescriptor[NoParameter]{errorBinding[NoParameter, SSErrorInfo, SSErrorCode]{code: SSInvalidDeflectedToNumber, info: infoSSInvalidDeflectedToNumberError, parameter: ValueCodec[NoParameter]{}}}
}
func infoSSInvalidDeflectedToNumberError() SSErrorInfo {
	return SSErrorInfo{Name: "invalidDeflectedToNumber", Code: SSInvalidDeflectedToNumber, Parameter: nil, ParameterOptional: nil, Source: sourceInfo8("invalidDeflectedToNumber", "4.3")}
}

// SSLcsInvalidPruErrorDescriptor binds the formal ERROR object SS-Errors.lcs-invalidPru (X.880 §8.3).
func SSLcsInvalidPruErrorDescriptor() SSErrorDescriptor[NoParameter] {
	return SSErrorDescriptor[NoParameter]{errorBinding[NoParameter, SSErrorInfo, SSErrorCode]{code: SSLcsInvalidPru, info: infoSSLcsInvalidPruError, parameter: ValueCodec[NoParameter]{}}}
}
func infoSSLcsInvalidPruError() SSErrorInfo {
	return SSErrorInfo{Name: "lcs-invalidPru", Code: SSLcsInvalidPru, Parameter: nil, ParameterOptional: nil, Source: sourceInfo8("lcs-invalidPru", "4.3")}
}

// SSLcsPruAssociationRejErrorDescriptor binds the formal ERROR object SS-Errors.lcs-PruAssociationRej (X.880 §8.3).
func SSLcsPruAssociationRejErrorDescriptor() SSErrorDescriptor[PruAssociationRejParam] {
	return SSErrorDescriptor[PruAssociationRejParam]{errorBinding[PruAssociationRejParam, SSErrorInfo, SSErrorCode]{code: SSLcsPruAssociationRej, info: infoSSLcsPruAssociationRejError, parameter: PruAssociationRejParamCodec()}}
}
func infoSSLcsPruAssociationRejError() SSErrorInfo {
	return SSErrorInfo{Name: "lcs-PruAssociationRej", Code: SSLcsPruAssociationRej, Parameter: &TypeRef{ModuleOID: "0.4.0.0.2.3.1.18", ASN1Name: "PruAssociationRejParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "PruAssociationRejParam"}, ParameterOptional: nil, Source: sourceInfo8("lcs-PruAssociationRej", "4.3")}
}

// SSMaxNumberOfMPTYParticipantsExceededErrorDescriptor binds the formal ERROR object SS-Errors.maxNumberOfMPTY-ParticipantsExceeded (X.880 §8.3).
func SSMaxNumberOfMPTYParticipantsExceededErrorDescriptor() SSErrorDescriptor[NoParameter] {
	return SSErrorDescriptor[NoParameter]{errorBinding[NoParameter, SSErrorInfo, SSErrorCode]{code: SSMaxNumberOfMPTYParticipantsExceeded, info: infoSSMaxNumberOfMPTYParticipantsExceededError, parameter: ValueCodec[NoParameter]{}}}
}
func infoSSMaxNumberOfMPTYParticipantsExceededError() SSErrorInfo {
	return SSErrorInfo{Name: "maxNumberOfMPTY-ParticipantsExceeded", Code: SSMaxNumberOfMPTYParticipantsExceeded, Parameter: nil, ParameterOptional: nil, Source: sourceInfo8("maxNumberOfMPTY-ParticipantsExceeded", "4.3")}
}

// SSRejectedByNetworkErrorDescriptor binds the formal ERROR object SS-Errors.rejectedByNetwork (X.880 §8.3).
func SSRejectedByNetworkErrorDescriptor() SSErrorDescriptor[NoParameter] {
	return SSErrorDescriptor[NoParameter]{errorBinding[NoParameter, SSErrorInfo, SSErrorCode]{code: SSRejectedByNetwork, info: infoSSRejectedByNetworkError, parameter: ValueCodec[NoParameter]{}}}
}
func infoSSRejectedByNetworkError() SSErrorInfo {
	return SSErrorInfo{Name: "rejectedByNetwork", Code: SSRejectedByNetwork, Parameter: nil, ParameterOptional: nil, Source: sourceInfo8("rejectedByNetwork", "4.3")}
}

// SSRejectedByUserErrorDescriptor binds the formal ERROR object SS-Errors.rejectedByUser (X.880 §8.3).
func SSRejectedByUserErrorDescriptor() SSErrorDescriptor[NoParameter] {
	return SSErrorDescriptor[NoParameter]{errorBinding[NoParameter, SSErrorInfo, SSErrorCode]{code: SSRejectedByUser, info: infoSSRejectedByUserError, parameter: ValueCodec[NoParameter]{}}}
}
func infoSSRejectedByUserError() SSErrorInfo {
	return SSErrorInfo{Name: "rejectedByUser", Code: SSRejectedByUser, Parameter: nil, ParameterOptional: nil, Source: sourceInfo8("rejectedByUser", "4.3")}
}

// SSResourcesNotAvailableErrorDescriptor binds the formal ERROR object SS-Errors.resourcesNotAvailable (X.880 §8.3).
func SSResourcesNotAvailableErrorDescriptor() SSErrorDescriptor[NoParameter] {
	return SSErrorDescriptor[NoParameter]{errorBinding[NoParameter, SSErrorInfo, SSErrorCode]{code: SSResourcesNotAvailable, info: infoSSResourcesNotAvailableError, parameter: ValueCodec[NoParameter]{}}}
}
func infoSSResourcesNotAvailableError() SSErrorInfo {
	return SSErrorInfo{Name: "resourcesNotAvailable", Code: SSResourcesNotAvailable, Parameter: nil, ParameterOptional: nil, Source: sourceInfo8("resourcesNotAvailable", "4.3")}
}

// SSSpecialServiceCodeErrorDescriptor binds the formal ERROR object SS-Errors.specialServiceCode (X.880 §8.3).
func SSSpecialServiceCodeErrorDescriptor() SSErrorDescriptor[NoParameter] {
	return SSErrorDescriptor[NoParameter]{errorBinding[NoParameter, SSErrorInfo, SSErrorCode]{code: SSSpecialServiceCode, info: infoSSSpecialServiceCodeError, parameter: ValueCodec[NoParameter]{}}}
}
func infoSSSpecialServiceCodeError() SSErrorInfo {
	return SSErrorInfo{Name: "specialServiceCode", Code: SSSpecialServiceCode, Parameter: nil, ParameterOptional: nil, Source: sourceInfo8("specialServiceCode", "4.3")}
}
func SSErrors() []SSErrorInfo {
	return []SSErrorInfo{infoSSDeflectionToServedSubscriberError(), infoSSInvalidDeflectedToNumberError(), infoSSLcsInvalidPruError(), infoSSLcsPruAssociationRejError(), infoSSMaxNumberOfMPTYParticipantsExceededError(), infoSSRejectedByNetworkError(), infoSSRejectedByUserError(), infoSSResourcesNotAvailableError(), infoSSSpecialServiceCodeError()}
}
func LookupSSError(code SSErrorCode) (SSErrorInfo, bool) {
	switch code {
	case SSDeflectionToServedSubscriber:
		return infoSSDeflectionToServedSubscriberError(), true
	case SSInvalidDeflectedToNumber:
		return infoSSInvalidDeflectedToNumberError(), true
	case SSLcsInvalidPru:
		return infoSSLcsInvalidPruError(), true
	case SSLcsPruAssociationRej:
		return infoSSLcsPruAssociationRejError(), true
	case SSMaxNumberOfMPTYParticipantsExceeded:
		return infoSSMaxNumberOfMPTYParticipantsExceededError(), true
	case SSRejectedByNetwork:
		return infoSSRejectedByNetworkError(), true
	case SSRejectedByUser:
		return infoSSRejectedByUserError(), true
	case SSResourcesNotAvailable:
		return infoSSResourcesNotAvailableError(), true
	case SSSpecialServiceCode:
		return infoSSSpecialServiceCodeError(), true
	default:
		return SSErrorInfo{}, false
	}
}

type SSErrorMemberInfo struct {
	Name, DeclaringModuleOID string
	LocalCode                int64
	Parameter                *TypeRef
	Source                   SourceRef
}
type SSErrorEncoding struct {
	LocalCode    int64
	Parameter    []byte
	HasParameter bool
	Source       SourceRef
}

func encodeSSErrorMember[P any](code int64, source SourceRef, value *ErrorValue[P], codec ValueCodec[P], opts ...ber.EncodeOption) (SSErrorEncoding, error) {
	data, present, err := encodeErrorParameter(value, codec, opts...)
	if err != nil {
		return SSErrorEncoding{}, err
	}
	return SSErrorEncoding{LocalCode: code, Source: source, Parameter: data, HasParameter: present}, nil
}

type SSOperationInfo struct {
	Name                               string
	Code                               SSOperationCode
	Argument, Result                   *TypeRef
	ArgumentOptional, ResultOptional   *bool
	ReturnResult, ReturnResultExplicit bool
	Errors                             []SSErrorMemberInfo
	Source                             SourceRef
}
type SSOperation[A, R, E any] struct {
	operationBinding[A, R, E, SSOperationInfo, SSOperationCode, SSErrorEncoding]
}

func (d SSOperation[A, R, E]) DecodeError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (E, error) {
	return d.decodeError(int64(code), data, present, opts...)
}
func (d SSOperation[A, R, E]) EncodeError(v E, opts ...ber.EncodeOption) (SSErrorEncoding, error) {
	return d.encodeError(v, opts...)
}
func (d SSOperation[A, R, E]) Errors() []SSErrorMemberInfo { return d.Info().Errors }

// SSAccessRegisterCCEntryErrors selects exactly the formal ERRORS set of SS-Operations.accessRegisterCCEntry.
type SSAccessRegisterCCEntryErrors struct {
	SystemFailure        *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam]
	DataMissing          *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERDataMissingParam]
	UnexpectedDataValue  *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParam]
	CallBarred           *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERCallBarredParam]
	IllegalSSOperation   *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERIllegalSSOperationParam]
	SsErrorStatus        *ErrorValue[v21_map_ss_datatypes.BERValue[v21_map_ss_datatypes.SSSSStatus]]
	SsIncompatibility    *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERSSIncompatibilityCause]
	ShortTermDenial      *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERShortTermDenialParam]
	LongTermDenial       *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERLongTermDenialParam]
	FacilityNotSupported *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParam]
}

func infoSSAccessRegisterCCEntryOperation() SSOperationInfo {
	return SSOperationInfo{Name: "accessRegisterCCEntry", Code: SSAccessRegisterCCEntry, Argument: &TypeRef{ModuleOID: "0.4.0.0.2.3.2.18", ASN1Name: "AccessRegisterCCEntryArg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "AccessRegisterCCEntryArg"}, Result: &TypeRef{ModuleOID: "0.4.0.0.1.3.14.21", ASN1Name: "RegisterCC-EntryRes", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_ss_datatypes", GoName: "SSRegisterCCEntryRes"}, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: false, Source: sourceInfo9("accessRegisterCCEntry", "4.2"), Errors: []SSErrorMemberInfo{SSErrorMemberInfo{Name: "systemFailure", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 34, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "SystemFailureParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERSystemFailureParam"}, Source: sourceInfo10("systemFailure", "17.6.6")}, SSErrorMemberInfo{Name: "dataMissing", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 35, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "DataMissingParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERDataMissingParam"}, Source: sourceInfo10("dataMissing", "17.6.6")}, SSErrorMemberInfo{Name: "unexpectedDataValue", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 36, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "UnexpectedDataParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERUnexpectedDataParam"}, Source: sourceInfo10("unexpectedDataValue", "17.6.6")}, SSErrorMemberInfo{Name: "callBarred", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 13, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "CallBarredParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERCallBarredParam"}, Source: sourceInfo10("callBarred", "17.6.6")}, SSErrorMemberInfo{Name: "illegalSS-Operation", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 16, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "IllegalSS-OperationParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERIllegalSSOperationParam"}, Source: sourceInfo10("illegalSS-Operation", "17.6.6")}, SSErrorMemberInfo{Name: "ss-ErrorStatus", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 17, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.14.21", ASN1Name: "SS-Status", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_ss_datatypes", GoName: "SSSSStatus"}, Source: sourceInfo10("ss-ErrorStatus", "17.6.6")}, SSErrorMemberInfo{Name: "ss-Incompatibility", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 20, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "SS-IncompatibilityCause", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERSSIncompatibilityCause"}, Source: sourceInfo10("ss-Incompatibility", "17.6.6")}, SSErrorMemberInfo{Name: "shortTermDenial", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 29, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "ShortTermDenialParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERShortTermDenialParam"}, Source: sourceInfo10("shortTermDenial", "17.6.6")}, SSErrorMemberInfo{Name: "longTermDenial", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 30, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "LongTermDenialParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERLongTermDenialParam"}, Source: sourceInfo10("longTermDenial", "17.6.6")}, SSErrorMemberInfo{Name: "facilityNotSupported", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 21, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "FacilityNotSupParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERFacilityNotSupParam"}, Source: sourceInfo10("facilityNotSupported", "17.6.6")}}}
}

// SSAccessRegisterCCEntryOperation binds the formal object in TS 24.080 V19.4.0 §4.2 (X.880 §§8.2–8.3).
func SSAccessRegisterCCEntryOperation() SSOperation[AccessRegisterCCEntryArg, v21_map_ss_datatypes.SSRegisterCCEntryRes, SSAccessRegisterCCEntryErrors] {
	return SSOperation[AccessRegisterCCEntryArg, v21_map_ss_datatypes.SSRegisterCCEntryRes, SSAccessRegisterCCEntryErrors]{operationBinding[AccessRegisterCCEntryArg, v21_map_ss_datatypes.SSRegisterCCEntryRes, SSAccessRegisterCCEntryErrors, SSOperationInfo, SSOperationCode, SSErrorEncoding]{code: SSAccessRegisterCCEntry, info: infoSSAccessRegisterCCEntryOperation, argument: AccessRegisterCCEntryArgCodec(), result: adaptValueCodec[v21_map_ss_datatypes.SSRegisterCCEntryRes](v21_map_ss_datatypes.SSRegisterCCEntryResCodec()), decode: decodeSSAccessRegisterCCEntryError, encode: encodeSSAccessRegisterCCEntryError}}
}
func decodeSSAccessRegisterCCEntryError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (SSAccessRegisterCCEntryErrors, error) {
	switch code {
	case 34:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam](__asn1pkg_v21_map_er_datatypes.ERSystemFailureParamCodec()), opts...)
		if err != nil {
			return SSAccessRegisterCCEntryErrors{}, err
		}
		return SSAccessRegisterCCEntryErrors{SystemFailure: p}, nil
	case 35:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERDataMissingParam](__asn1pkg_v21_map_er_datatypes.ERDataMissingParamCodec()), opts...)
		if err != nil {
			return SSAccessRegisterCCEntryErrors{}, err
		}
		return SSAccessRegisterCCEntryErrors{DataMissing: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParam](__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParamCodec()), opts...)
		if err != nil {
			return SSAccessRegisterCCEntryErrors{}, err
		}
		return SSAccessRegisterCCEntryErrors{UnexpectedDataValue: p}, nil
	case 13:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERCallBarredParam](__asn1pkg_v21_map_er_datatypes.ERCallBarredParamCodec()), opts...)
		if err != nil {
			return SSAccessRegisterCCEntryErrors{}, err
		}
		return SSAccessRegisterCCEntryErrors{CallBarred: p}, nil
	case 16:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERIllegalSSOperationParam](__asn1pkg_v21_map_er_datatypes.ERIllegalSSOperationParamCodec()), opts...)
		if err != nil {
			return SSAccessRegisterCCEntryErrors{}, err
		}
		return SSAccessRegisterCCEntryErrors{IllegalSSOperation: p}, nil
	case 17:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[v21_map_ss_datatypes.BERValue[v21_map_ss_datatypes.SSSSStatus]](v21_map_ss_datatypes.SSSSStatusCodec()), opts...)
		if err != nil {
			return SSAccessRegisterCCEntryErrors{}, err
		}
		return SSAccessRegisterCCEntryErrors{SsErrorStatus: p}, nil
	case 20:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSSIncompatibilityCause](__asn1pkg_v21_map_er_datatypes.ERSSIncompatibilityCauseCodec()), opts...)
		if err != nil {
			return SSAccessRegisterCCEntryErrors{}, err
		}
		return SSAccessRegisterCCEntryErrors{SsIncompatibility: p}, nil
	case 29:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERShortTermDenialParam](__asn1pkg_v21_map_er_datatypes.ERShortTermDenialParamCodec()), opts...)
		if err != nil {
			return SSAccessRegisterCCEntryErrors{}, err
		}
		return SSAccessRegisterCCEntryErrors{ShortTermDenial: p}, nil
	case 30:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERLongTermDenialParam](__asn1pkg_v21_map_er_datatypes.ERLongTermDenialParamCodec()), opts...)
		if err != nil {
			return SSAccessRegisterCCEntryErrors{}, err
		}
		return SSAccessRegisterCCEntryErrors{LongTermDenial: p}, nil
	case 21:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParam](__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParamCodec()), opts...)
		if err != nil {
			return SSAccessRegisterCCEntryErrors{}, err
		}
		return SSAccessRegisterCCEntryErrors{FacilityNotSupported: p}, nil
	default:
		return SSAccessRegisterCCEntryErrors{}, fmt.Errorf("%w: error code %d is not in accessRegisterCCEntry ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeSSAccessRegisterCCEntryError(value SSAccessRegisterCCEntryErrors, opts ...ber.EncodeOption) (SSErrorEncoding, error) {
	selected := 0
	if value.SystemFailure != nil {
		selected++
	}
	if value.DataMissing != nil {
		selected++
	}
	if value.UnexpectedDataValue != nil {
		selected++
	}
	if value.CallBarred != nil {
		selected++
	}
	if value.IllegalSSOperation != nil {
		selected++
	}
	if value.SsErrorStatus != nil {
		selected++
	}
	if value.SsIncompatibility != nil {
		selected++
	}
	if value.ShortTermDenial != nil {
		selected++
	}
	if value.LongTermDenial != nil {
		selected++
	}
	if value.FacilityNotSupported != nil {
		selected++
	}
	if selected != 1 {
		return SSErrorEncoding{}, fmt.Errorf("%w: exactly one accessRegisterCCEntry error arm is required", ber.ErrInvalidBinding)
	}
	if value.SystemFailure != nil {
		return encodeSSErrorMember(34, sourceInfo10("systemFailure", "17.6.6"), value.SystemFailure, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam](__asn1pkg_v21_map_er_datatypes.ERSystemFailureParamCodec()), opts...)
	}
	if value.DataMissing != nil {
		return encodeSSErrorMember(35, sourceInfo10("dataMissing", "17.6.6"), value.DataMissing, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERDataMissingParam](__asn1pkg_v21_map_er_datatypes.ERDataMissingParamCodec()), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeSSErrorMember(36, sourceInfo10("unexpectedDataValue", "17.6.6"), value.UnexpectedDataValue, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParam](__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParamCodec()), opts...)
	}
	if value.CallBarred != nil {
		return encodeSSErrorMember(13, sourceInfo10("callBarred", "17.6.6"), value.CallBarred, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERCallBarredParam](__asn1pkg_v21_map_er_datatypes.ERCallBarredParamCodec()), opts...)
	}
	if value.IllegalSSOperation != nil {
		return encodeSSErrorMember(16, sourceInfo10("illegalSS-Operation", "17.6.6"), value.IllegalSSOperation, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERIllegalSSOperationParam](__asn1pkg_v21_map_er_datatypes.ERIllegalSSOperationParamCodec()), opts...)
	}
	if value.SsErrorStatus != nil {
		return encodeSSErrorMember(17, sourceInfo10("ss-ErrorStatus", "17.6.6"), value.SsErrorStatus, adaptValueCodec[v21_map_ss_datatypes.BERValue[v21_map_ss_datatypes.SSSSStatus]](v21_map_ss_datatypes.SSSSStatusCodec()), opts...)
	}
	if value.SsIncompatibility != nil {
		return encodeSSErrorMember(20, sourceInfo10("ss-Incompatibility", "17.6.6"), value.SsIncompatibility, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSSIncompatibilityCause](__asn1pkg_v21_map_er_datatypes.ERSSIncompatibilityCauseCodec()), opts...)
	}
	if value.ShortTermDenial != nil {
		return encodeSSErrorMember(29, sourceInfo10("shortTermDenial", "17.6.6"), value.ShortTermDenial, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERShortTermDenialParam](__asn1pkg_v21_map_er_datatypes.ERShortTermDenialParamCodec()), opts...)
	}
	if value.LongTermDenial != nil {
		return encodeSSErrorMember(30, sourceInfo10("longTermDenial", "17.6.6"), value.LongTermDenial, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERLongTermDenialParam](__asn1pkg_v21_map_er_datatypes.ERLongTermDenialParamCodec()), opts...)
	}
	if value.FacilityNotSupported != nil {
		return encodeSSErrorMember(21, sourceInfo10("facilityNotSupported", "17.6.6"), value.FacilityNotSupported, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParam](__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParamCodec()), opts...)
	}
	return SSErrorEncoding{}, fmt.Errorf("%w: no selected accessRegisterCCEntry error", ber.ErrInvalidBinding)
}

// SSBuildMPTYErrors selects exactly the formal ERRORS set of SS-Operations.buildMPTY.
type SSBuildMPTYErrors struct {
	IllegalSSOperation                  *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERIllegalSSOperationParam]
	SsErrorStatus                       *ErrorValue[v21_map_ss_datatypes.BERValue[v21_map_ss_datatypes.SSSSStatus]]
	SsNotAvailable                      *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERSSNotAvailableParam]
	SsIncompatibility                   *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERSSIncompatibilityCause]
	SystemFailure                       *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam]
	ResourcesNotAvailable               *ErrorValue[NoParameter]
	MaxNumberOfMPTYParticipantsExceeded *ErrorValue[NoParameter]
}

func infoSSBuildMPTYOperation() SSOperationInfo {
	return SSOperationInfo{Name: "buildMPTY", Code: SSBuildMPTY, Argument: nil, Result: nil, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: true, Source: sourceInfo9("buildMPTY", "4.2"), Errors: []SSErrorMemberInfo{SSErrorMemberInfo{Name: "illegalSS-Operation", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 16, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "IllegalSS-OperationParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERIllegalSSOperationParam"}, Source: sourceInfo10("illegalSS-Operation", "17.6.6")}, SSErrorMemberInfo{Name: "ss-ErrorStatus", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 17, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.14.21", ASN1Name: "SS-Status", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_ss_datatypes", GoName: "SSSSStatus"}, Source: sourceInfo10("ss-ErrorStatus", "17.6.6")}, SSErrorMemberInfo{Name: "ss-NotAvailable", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 18, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "SS-NotAvailableParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERSSNotAvailableParam"}, Source: sourceInfo10("ss-NotAvailable", "17.6.6")}, SSErrorMemberInfo{Name: "ss-Incompatibility", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 20, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "SS-IncompatibilityCause", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERSSIncompatibilityCause"}, Source: sourceInfo10("ss-Incompatibility", "17.6.6")}, SSErrorMemberInfo{Name: "systemFailure", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 34, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "SystemFailureParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERSystemFailureParam"}, Source: sourceInfo10("systemFailure", "17.6.6")}, SSErrorMemberInfo{Name: "resourcesNotAvailable", DeclaringModuleOID: "{#0/#4/#0/#0/#2/#3/#1/#18}", LocalCode: 127, Parameter: nil, Source: sourceInfo8("resourcesNotAvailable", "4.3")}, SSErrorMemberInfo{Name: "maxNumberOfMPTY-ParticipantsExceeded", DeclaringModuleOID: "{#0/#4/#0/#0/#2/#3/#1/#18}", LocalCode: 126, Parameter: nil, Source: sourceInfo8("maxNumberOfMPTY-ParticipantsExceeded", "4.3")}}}
}

// SSBuildMPTYOperation binds the formal object in TS 24.080 V19.4.0 §4.2 (X.880 §§8.2–8.3).
func SSBuildMPTYOperation() SSOperation[NoParameter, NoParameter, SSBuildMPTYErrors] {
	return SSOperation[NoParameter, NoParameter, SSBuildMPTYErrors]{operationBinding[NoParameter, NoParameter, SSBuildMPTYErrors, SSOperationInfo, SSOperationCode, SSErrorEncoding]{code: SSBuildMPTY, info: infoSSBuildMPTYOperation, argument: ValueCodec[NoParameter]{}, result: ValueCodec[NoParameter]{}, decode: decodeSSBuildMPTYError, encode: encodeSSBuildMPTYError}}
}
func decodeSSBuildMPTYError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (SSBuildMPTYErrors, error) {
	switch code {
	case 16:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERIllegalSSOperationParam](__asn1pkg_v21_map_er_datatypes.ERIllegalSSOperationParamCodec()), opts...)
		if err != nil {
			return SSBuildMPTYErrors{}, err
		}
		return SSBuildMPTYErrors{IllegalSSOperation: p}, nil
	case 17:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[v21_map_ss_datatypes.BERValue[v21_map_ss_datatypes.SSSSStatus]](v21_map_ss_datatypes.SSSSStatusCodec()), opts...)
		if err != nil {
			return SSBuildMPTYErrors{}, err
		}
		return SSBuildMPTYErrors{SsErrorStatus: p}, nil
	case 18:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSSNotAvailableParam](__asn1pkg_v21_map_er_datatypes.ERSSNotAvailableParamCodec()), opts...)
		if err != nil {
			return SSBuildMPTYErrors{}, err
		}
		return SSBuildMPTYErrors{SsNotAvailable: p}, nil
	case 20:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSSIncompatibilityCause](__asn1pkg_v21_map_er_datatypes.ERSSIncompatibilityCauseCodec()), opts...)
		if err != nil {
			return SSBuildMPTYErrors{}, err
		}
		return SSBuildMPTYErrors{SsIncompatibility: p}, nil
	case 34:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam](__asn1pkg_v21_map_er_datatypes.ERSystemFailureParamCodec()), opts...)
		if err != nil {
			return SSBuildMPTYErrors{}, err
		}
		return SSBuildMPTYErrors{SystemFailure: p}, nil
	case 127:
		p, err := decodeErrorParameter(data, present, ValueCodec[NoParameter]{}, opts...)
		if err != nil {
			return SSBuildMPTYErrors{}, err
		}
		return SSBuildMPTYErrors{ResourcesNotAvailable: p}, nil
	case 126:
		p, err := decodeErrorParameter(data, present, ValueCodec[NoParameter]{}, opts...)
		if err != nil {
			return SSBuildMPTYErrors{}, err
		}
		return SSBuildMPTYErrors{MaxNumberOfMPTYParticipantsExceeded: p}, nil
	default:
		return SSBuildMPTYErrors{}, fmt.Errorf("%w: error code %d is not in buildMPTY ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeSSBuildMPTYError(value SSBuildMPTYErrors, opts ...ber.EncodeOption) (SSErrorEncoding, error) {
	selected := 0
	if value.IllegalSSOperation != nil {
		selected++
	}
	if value.SsErrorStatus != nil {
		selected++
	}
	if value.SsNotAvailable != nil {
		selected++
	}
	if value.SsIncompatibility != nil {
		selected++
	}
	if value.SystemFailure != nil {
		selected++
	}
	if value.ResourcesNotAvailable != nil {
		selected++
	}
	if value.MaxNumberOfMPTYParticipantsExceeded != nil {
		selected++
	}
	if selected != 1 {
		return SSErrorEncoding{}, fmt.Errorf("%w: exactly one buildMPTY error arm is required", ber.ErrInvalidBinding)
	}
	if value.IllegalSSOperation != nil {
		return encodeSSErrorMember(16, sourceInfo10("illegalSS-Operation", "17.6.6"), value.IllegalSSOperation, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERIllegalSSOperationParam](__asn1pkg_v21_map_er_datatypes.ERIllegalSSOperationParamCodec()), opts...)
	}
	if value.SsErrorStatus != nil {
		return encodeSSErrorMember(17, sourceInfo10("ss-ErrorStatus", "17.6.6"), value.SsErrorStatus, adaptValueCodec[v21_map_ss_datatypes.BERValue[v21_map_ss_datatypes.SSSSStatus]](v21_map_ss_datatypes.SSSSStatusCodec()), opts...)
	}
	if value.SsNotAvailable != nil {
		return encodeSSErrorMember(18, sourceInfo10("ss-NotAvailable", "17.6.6"), value.SsNotAvailable, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSSNotAvailableParam](__asn1pkg_v21_map_er_datatypes.ERSSNotAvailableParamCodec()), opts...)
	}
	if value.SsIncompatibility != nil {
		return encodeSSErrorMember(20, sourceInfo10("ss-Incompatibility", "17.6.6"), value.SsIncompatibility, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSSIncompatibilityCause](__asn1pkg_v21_map_er_datatypes.ERSSIncompatibilityCauseCodec()), opts...)
	}
	if value.SystemFailure != nil {
		return encodeSSErrorMember(34, sourceInfo10("systemFailure", "17.6.6"), value.SystemFailure, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam](__asn1pkg_v21_map_er_datatypes.ERSystemFailureParamCodec()), opts...)
	}
	if value.ResourcesNotAvailable != nil {
		return encodeSSErrorMember(127, sourceInfo8("resourcesNotAvailable", "4.3"), value.ResourcesNotAvailable, ValueCodec[NoParameter]{}, opts...)
	}
	if value.MaxNumberOfMPTYParticipantsExceeded != nil {
		return encodeSSErrorMember(126, sourceInfo8("maxNumberOfMPTY-ParticipantsExceeded", "4.3"), value.MaxNumberOfMPTYParticipantsExceeded, ValueCodec[NoParameter]{}, opts...)
	}
	return SSErrorEncoding{}, fmt.Errorf("%w: no selected buildMPTY error", ber.ErrInvalidBinding)
}

// SSCallDeflectionErrors selects exactly the formal ERRORS set of SS-Operations.callDeflection.
type SSCallDeflectionErrors struct {
	IllegalSSOperation           *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERIllegalSSOperationParam]
	SsErrorStatus                *ErrorValue[v21_map_ss_datatypes.BERValue[v21_map_ss_datatypes.SSSSStatus]]
	SsNotAvailable               *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERSSNotAvailableParam]
	SsIncompatibility            *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERSSIncompatibilityCause]
	FacilityNotSupported         *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParam]
	SystemFailure                *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam]
	ResourcesNotAvailable        *ErrorValue[NoParameter]
	ForwardingViolation          *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERForwardingViolationParam]
	CallBarred                   *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERCallBarredParam]
	DeflectionToServedSubscriber *ErrorValue[NoParameter]
	InvalidDeflectedToNumber     *ErrorValue[NoParameter]
	SpecialServiceCode           *ErrorValue[NoParameter]
	ForwardingFailed             *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERForwardingFailedParam]
}

func infoSSCallDeflectionOperation() SSOperationInfo {
	return SSOperationInfo{Name: "callDeflection", Code: SSCallDeflection, Argument: &TypeRef{ModuleOID: "0.4.0.0.2.3.2.18", ASN1Name: "CallDeflectionArg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "CallDeflectionArg"}, Result: nil, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: true, Source: sourceInfo9("callDeflection", "4.2"), Errors: []SSErrorMemberInfo{SSErrorMemberInfo{Name: "illegalSS-Operation", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 16, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "IllegalSS-OperationParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERIllegalSSOperationParam"}, Source: sourceInfo10("illegalSS-Operation", "17.6.6")}, SSErrorMemberInfo{Name: "ss-ErrorStatus", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 17, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.14.21", ASN1Name: "SS-Status", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_ss_datatypes", GoName: "SSSSStatus"}, Source: sourceInfo10("ss-ErrorStatus", "17.6.6")}, SSErrorMemberInfo{Name: "ss-NotAvailable", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 18, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "SS-NotAvailableParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERSSNotAvailableParam"}, Source: sourceInfo10("ss-NotAvailable", "17.6.6")}, SSErrorMemberInfo{Name: "ss-Incompatibility", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 20, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "SS-IncompatibilityCause", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERSSIncompatibilityCause"}, Source: sourceInfo10("ss-Incompatibility", "17.6.6")}, SSErrorMemberInfo{Name: "facilityNotSupported", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 21, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "FacilityNotSupParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERFacilityNotSupParam"}, Source: sourceInfo10("facilityNotSupported", "17.6.6")}, SSErrorMemberInfo{Name: "systemFailure", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 34, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "SystemFailureParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERSystemFailureParam"}, Source: sourceInfo10("systemFailure", "17.6.6")}, SSErrorMemberInfo{Name: "resourcesNotAvailable", DeclaringModuleOID: "{#0/#4/#0/#0/#2/#3/#1/#18}", LocalCode: 127, Parameter: nil, Source: sourceInfo8("resourcesNotAvailable", "4.3")}, SSErrorMemberInfo{Name: "forwardingViolation", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 14, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "ForwardingViolationParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERForwardingViolationParam"}, Source: sourceInfo10("forwardingViolation", "17.6.6")}, SSErrorMemberInfo{Name: "callBarred", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 13, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "CallBarredParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERCallBarredParam"}, Source: sourceInfo10("callBarred", "17.6.6")}, SSErrorMemberInfo{Name: "deflectionToServedSubscriber", DeclaringModuleOID: "{#0/#4/#0/#0/#2/#3/#1/#18}", LocalCode: 123, Parameter: nil, Source: sourceInfo8("deflectionToServedSubscriber", "4.3")}, SSErrorMemberInfo{Name: "invalidDeflectedToNumber", DeclaringModuleOID: "{#0/#4/#0/#0/#2/#3/#1/#18}", LocalCode: 125, Parameter: nil, Source: sourceInfo8("invalidDeflectedToNumber", "4.3")}, SSErrorMemberInfo{Name: "specialServiceCode", DeclaringModuleOID: "{#0/#4/#0/#0/#2/#3/#1/#18}", LocalCode: 124, Parameter: nil, Source: sourceInfo8("specialServiceCode", "4.3")}, SSErrorMemberInfo{Name: "forwardingFailed", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 47, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "ForwardingFailedParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERForwardingFailedParam"}, Source: sourceInfo10("forwardingFailed", "17.6.6")}}}
}

// SSCallDeflectionOperation binds the formal object in TS 24.080 V19.4.0 §4.2 (X.880 §§8.2–8.3).
func SSCallDeflectionOperation() SSOperation[CallDeflectionArg, NoParameter, SSCallDeflectionErrors] {
	return SSOperation[CallDeflectionArg, NoParameter, SSCallDeflectionErrors]{operationBinding[CallDeflectionArg, NoParameter, SSCallDeflectionErrors, SSOperationInfo, SSOperationCode, SSErrorEncoding]{code: SSCallDeflection, info: infoSSCallDeflectionOperation, argument: CallDeflectionArgCodec(), result: ValueCodec[NoParameter]{}, decode: decodeSSCallDeflectionError, encode: encodeSSCallDeflectionError}}
}
func decodeSSCallDeflectionError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (SSCallDeflectionErrors, error) {
	switch code {
	case 16:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERIllegalSSOperationParam](__asn1pkg_v21_map_er_datatypes.ERIllegalSSOperationParamCodec()), opts...)
		if err != nil {
			return SSCallDeflectionErrors{}, err
		}
		return SSCallDeflectionErrors{IllegalSSOperation: p}, nil
	case 17:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[v21_map_ss_datatypes.BERValue[v21_map_ss_datatypes.SSSSStatus]](v21_map_ss_datatypes.SSSSStatusCodec()), opts...)
		if err != nil {
			return SSCallDeflectionErrors{}, err
		}
		return SSCallDeflectionErrors{SsErrorStatus: p}, nil
	case 18:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSSNotAvailableParam](__asn1pkg_v21_map_er_datatypes.ERSSNotAvailableParamCodec()), opts...)
		if err != nil {
			return SSCallDeflectionErrors{}, err
		}
		return SSCallDeflectionErrors{SsNotAvailable: p}, nil
	case 20:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSSIncompatibilityCause](__asn1pkg_v21_map_er_datatypes.ERSSIncompatibilityCauseCodec()), opts...)
		if err != nil {
			return SSCallDeflectionErrors{}, err
		}
		return SSCallDeflectionErrors{SsIncompatibility: p}, nil
	case 21:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParam](__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParamCodec()), opts...)
		if err != nil {
			return SSCallDeflectionErrors{}, err
		}
		return SSCallDeflectionErrors{FacilityNotSupported: p}, nil
	case 34:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam](__asn1pkg_v21_map_er_datatypes.ERSystemFailureParamCodec()), opts...)
		if err != nil {
			return SSCallDeflectionErrors{}, err
		}
		return SSCallDeflectionErrors{SystemFailure: p}, nil
	case 127:
		p, err := decodeErrorParameter(data, present, ValueCodec[NoParameter]{}, opts...)
		if err != nil {
			return SSCallDeflectionErrors{}, err
		}
		return SSCallDeflectionErrors{ResourcesNotAvailable: p}, nil
	case 14:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERForwardingViolationParam](__asn1pkg_v21_map_er_datatypes.ERForwardingViolationParamCodec()), opts...)
		if err != nil {
			return SSCallDeflectionErrors{}, err
		}
		return SSCallDeflectionErrors{ForwardingViolation: p}, nil
	case 13:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERCallBarredParam](__asn1pkg_v21_map_er_datatypes.ERCallBarredParamCodec()), opts...)
		if err != nil {
			return SSCallDeflectionErrors{}, err
		}
		return SSCallDeflectionErrors{CallBarred: p}, nil
	case 123:
		p, err := decodeErrorParameter(data, present, ValueCodec[NoParameter]{}, opts...)
		if err != nil {
			return SSCallDeflectionErrors{}, err
		}
		return SSCallDeflectionErrors{DeflectionToServedSubscriber: p}, nil
	case 125:
		p, err := decodeErrorParameter(data, present, ValueCodec[NoParameter]{}, opts...)
		if err != nil {
			return SSCallDeflectionErrors{}, err
		}
		return SSCallDeflectionErrors{InvalidDeflectedToNumber: p}, nil
	case 124:
		p, err := decodeErrorParameter(data, present, ValueCodec[NoParameter]{}, opts...)
		if err != nil {
			return SSCallDeflectionErrors{}, err
		}
		return SSCallDeflectionErrors{SpecialServiceCode: p}, nil
	case 47:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERForwardingFailedParam](__asn1pkg_v21_map_er_datatypes.ERForwardingFailedParamCodec()), opts...)
		if err != nil {
			return SSCallDeflectionErrors{}, err
		}
		return SSCallDeflectionErrors{ForwardingFailed: p}, nil
	default:
		return SSCallDeflectionErrors{}, fmt.Errorf("%w: error code %d is not in callDeflection ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeSSCallDeflectionError(value SSCallDeflectionErrors, opts ...ber.EncodeOption) (SSErrorEncoding, error) {
	selected := 0
	if value.IllegalSSOperation != nil {
		selected++
	}
	if value.SsErrorStatus != nil {
		selected++
	}
	if value.SsNotAvailable != nil {
		selected++
	}
	if value.SsIncompatibility != nil {
		selected++
	}
	if value.FacilityNotSupported != nil {
		selected++
	}
	if value.SystemFailure != nil {
		selected++
	}
	if value.ResourcesNotAvailable != nil {
		selected++
	}
	if value.ForwardingViolation != nil {
		selected++
	}
	if value.CallBarred != nil {
		selected++
	}
	if value.DeflectionToServedSubscriber != nil {
		selected++
	}
	if value.InvalidDeflectedToNumber != nil {
		selected++
	}
	if value.SpecialServiceCode != nil {
		selected++
	}
	if value.ForwardingFailed != nil {
		selected++
	}
	if selected != 1 {
		return SSErrorEncoding{}, fmt.Errorf("%w: exactly one callDeflection error arm is required", ber.ErrInvalidBinding)
	}
	if value.IllegalSSOperation != nil {
		return encodeSSErrorMember(16, sourceInfo10("illegalSS-Operation", "17.6.6"), value.IllegalSSOperation, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERIllegalSSOperationParam](__asn1pkg_v21_map_er_datatypes.ERIllegalSSOperationParamCodec()), opts...)
	}
	if value.SsErrorStatus != nil {
		return encodeSSErrorMember(17, sourceInfo10("ss-ErrorStatus", "17.6.6"), value.SsErrorStatus, adaptValueCodec[v21_map_ss_datatypes.BERValue[v21_map_ss_datatypes.SSSSStatus]](v21_map_ss_datatypes.SSSSStatusCodec()), opts...)
	}
	if value.SsNotAvailable != nil {
		return encodeSSErrorMember(18, sourceInfo10("ss-NotAvailable", "17.6.6"), value.SsNotAvailable, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSSNotAvailableParam](__asn1pkg_v21_map_er_datatypes.ERSSNotAvailableParamCodec()), opts...)
	}
	if value.SsIncompatibility != nil {
		return encodeSSErrorMember(20, sourceInfo10("ss-Incompatibility", "17.6.6"), value.SsIncompatibility, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSSIncompatibilityCause](__asn1pkg_v21_map_er_datatypes.ERSSIncompatibilityCauseCodec()), opts...)
	}
	if value.FacilityNotSupported != nil {
		return encodeSSErrorMember(21, sourceInfo10("facilityNotSupported", "17.6.6"), value.FacilityNotSupported, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParam](__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParamCodec()), opts...)
	}
	if value.SystemFailure != nil {
		return encodeSSErrorMember(34, sourceInfo10("systemFailure", "17.6.6"), value.SystemFailure, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam](__asn1pkg_v21_map_er_datatypes.ERSystemFailureParamCodec()), opts...)
	}
	if value.ResourcesNotAvailable != nil {
		return encodeSSErrorMember(127, sourceInfo8("resourcesNotAvailable", "4.3"), value.ResourcesNotAvailable, ValueCodec[NoParameter]{}, opts...)
	}
	if value.ForwardingViolation != nil {
		return encodeSSErrorMember(14, sourceInfo10("forwardingViolation", "17.6.6"), value.ForwardingViolation, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERForwardingViolationParam](__asn1pkg_v21_map_er_datatypes.ERForwardingViolationParamCodec()), opts...)
	}
	if value.CallBarred != nil {
		return encodeSSErrorMember(13, sourceInfo10("callBarred", "17.6.6"), value.CallBarred, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERCallBarredParam](__asn1pkg_v21_map_er_datatypes.ERCallBarredParamCodec()), opts...)
	}
	if value.DeflectionToServedSubscriber != nil {
		return encodeSSErrorMember(123, sourceInfo8("deflectionToServedSubscriber", "4.3"), value.DeflectionToServedSubscriber, ValueCodec[NoParameter]{}, opts...)
	}
	if value.InvalidDeflectedToNumber != nil {
		return encodeSSErrorMember(125, sourceInfo8("invalidDeflectedToNumber", "4.3"), value.InvalidDeflectedToNumber, ValueCodec[NoParameter]{}, opts...)
	}
	if value.SpecialServiceCode != nil {
		return encodeSSErrorMember(124, sourceInfo8("specialServiceCode", "4.3"), value.SpecialServiceCode, ValueCodec[NoParameter]{}, opts...)
	}
	if value.ForwardingFailed != nil {
		return encodeSSErrorMember(47, sourceInfo10("forwardingFailed", "17.6.6"), value.ForwardingFailed, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERForwardingFailedParam](__asn1pkg_v21_map_er_datatypes.ERForwardingFailedParamCodec()), opts...)
	}
	return SSErrorEncoding{}, fmt.Errorf("%w: no selected callDeflection error", ber.ErrInvalidBinding)
}

// SSExplicitCTErrors selects exactly the formal ERRORS set of SS-Operations.explicitCT.
type SSExplicitCTErrors struct {
	IllegalSSOperation    *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERIllegalSSOperationParam]
	SsErrorStatus         *ErrorValue[v21_map_ss_datatypes.BERValue[v21_map_ss_datatypes.SSSSStatus]]
	SsNotAvailable        *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERSSNotAvailableParam]
	SsIncompatibility     *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERSSIncompatibilityCause]
	FacilityNotSupported  *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParam]
	SystemFailure         *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam]
	ResourcesNotAvailable *ErrorValue[NoParameter]
	CallBarred            *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERCallBarredParam]
}

func infoSSExplicitCTOperation() SSOperationInfo {
	return SSOperationInfo{Name: "explicitCT", Code: SSExplicitCT, Argument: nil, Result: nil, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: true, Source: sourceInfo9("explicitCT", "4.2"), Errors: []SSErrorMemberInfo{SSErrorMemberInfo{Name: "illegalSS-Operation", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 16, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "IllegalSS-OperationParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERIllegalSSOperationParam"}, Source: sourceInfo10("illegalSS-Operation", "17.6.6")}, SSErrorMemberInfo{Name: "ss-ErrorStatus", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 17, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.14.21", ASN1Name: "SS-Status", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_ss_datatypes", GoName: "SSSSStatus"}, Source: sourceInfo10("ss-ErrorStatus", "17.6.6")}, SSErrorMemberInfo{Name: "ss-NotAvailable", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 18, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "SS-NotAvailableParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERSSNotAvailableParam"}, Source: sourceInfo10("ss-NotAvailable", "17.6.6")}, SSErrorMemberInfo{Name: "ss-Incompatibility", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 20, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "SS-IncompatibilityCause", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERSSIncompatibilityCause"}, Source: sourceInfo10("ss-Incompatibility", "17.6.6")}, SSErrorMemberInfo{Name: "facilityNotSupported", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 21, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "FacilityNotSupParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERFacilityNotSupParam"}, Source: sourceInfo10("facilityNotSupported", "17.6.6")}, SSErrorMemberInfo{Name: "systemFailure", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 34, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "SystemFailureParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERSystemFailureParam"}, Source: sourceInfo10("systemFailure", "17.6.6")}, SSErrorMemberInfo{Name: "resourcesNotAvailable", DeclaringModuleOID: "{#0/#4/#0/#0/#2/#3/#1/#18}", LocalCode: 127, Parameter: nil, Source: sourceInfo8("resourcesNotAvailable", "4.3")}, SSErrorMemberInfo{Name: "callBarred", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 13, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "CallBarredParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERCallBarredParam"}, Source: sourceInfo10("callBarred", "17.6.6")}}}
}

// SSExplicitCTOperation binds the formal object in TS 24.080 V19.4.0 §4.2 (X.880 §§8.2–8.3).
func SSExplicitCTOperation() SSOperation[NoParameter, NoParameter, SSExplicitCTErrors] {
	return SSOperation[NoParameter, NoParameter, SSExplicitCTErrors]{operationBinding[NoParameter, NoParameter, SSExplicitCTErrors, SSOperationInfo, SSOperationCode, SSErrorEncoding]{code: SSExplicitCT, info: infoSSExplicitCTOperation, argument: ValueCodec[NoParameter]{}, result: ValueCodec[NoParameter]{}, decode: decodeSSExplicitCTError, encode: encodeSSExplicitCTError}}
}
func decodeSSExplicitCTError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (SSExplicitCTErrors, error) {
	switch code {
	case 16:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERIllegalSSOperationParam](__asn1pkg_v21_map_er_datatypes.ERIllegalSSOperationParamCodec()), opts...)
		if err != nil {
			return SSExplicitCTErrors{}, err
		}
		return SSExplicitCTErrors{IllegalSSOperation: p}, nil
	case 17:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[v21_map_ss_datatypes.BERValue[v21_map_ss_datatypes.SSSSStatus]](v21_map_ss_datatypes.SSSSStatusCodec()), opts...)
		if err != nil {
			return SSExplicitCTErrors{}, err
		}
		return SSExplicitCTErrors{SsErrorStatus: p}, nil
	case 18:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSSNotAvailableParam](__asn1pkg_v21_map_er_datatypes.ERSSNotAvailableParamCodec()), opts...)
		if err != nil {
			return SSExplicitCTErrors{}, err
		}
		return SSExplicitCTErrors{SsNotAvailable: p}, nil
	case 20:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSSIncompatibilityCause](__asn1pkg_v21_map_er_datatypes.ERSSIncompatibilityCauseCodec()), opts...)
		if err != nil {
			return SSExplicitCTErrors{}, err
		}
		return SSExplicitCTErrors{SsIncompatibility: p}, nil
	case 21:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParam](__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParamCodec()), opts...)
		if err != nil {
			return SSExplicitCTErrors{}, err
		}
		return SSExplicitCTErrors{FacilityNotSupported: p}, nil
	case 34:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam](__asn1pkg_v21_map_er_datatypes.ERSystemFailureParamCodec()), opts...)
		if err != nil {
			return SSExplicitCTErrors{}, err
		}
		return SSExplicitCTErrors{SystemFailure: p}, nil
	case 127:
		p, err := decodeErrorParameter(data, present, ValueCodec[NoParameter]{}, opts...)
		if err != nil {
			return SSExplicitCTErrors{}, err
		}
		return SSExplicitCTErrors{ResourcesNotAvailable: p}, nil
	case 13:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERCallBarredParam](__asn1pkg_v21_map_er_datatypes.ERCallBarredParamCodec()), opts...)
		if err != nil {
			return SSExplicitCTErrors{}, err
		}
		return SSExplicitCTErrors{CallBarred: p}, nil
	default:
		return SSExplicitCTErrors{}, fmt.Errorf("%w: error code %d is not in explicitCT ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeSSExplicitCTError(value SSExplicitCTErrors, opts ...ber.EncodeOption) (SSErrorEncoding, error) {
	selected := 0
	if value.IllegalSSOperation != nil {
		selected++
	}
	if value.SsErrorStatus != nil {
		selected++
	}
	if value.SsNotAvailable != nil {
		selected++
	}
	if value.SsIncompatibility != nil {
		selected++
	}
	if value.FacilityNotSupported != nil {
		selected++
	}
	if value.SystemFailure != nil {
		selected++
	}
	if value.ResourcesNotAvailable != nil {
		selected++
	}
	if value.CallBarred != nil {
		selected++
	}
	if selected != 1 {
		return SSErrorEncoding{}, fmt.Errorf("%w: exactly one explicitCT error arm is required", ber.ErrInvalidBinding)
	}
	if value.IllegalSSOperation != nil {
		return encodeSSErrorMember(16, sourceInfo10("illegalSS-Operation", "17.6.6"), value.IllegalSSOperation, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERIllegalSSOperationParam](__asn1pkg_v21_map_er_datatypes.ERIllegalSSOperationParamCodec()), opts...)
	}
	if value.SsErrorStatus != nil {
		return encodeSSErrorMember(17, sourceInfo10("ss-ErrorStatus", "17.6.6"), value.SsErrorStatus, adaptValueCodec[v21_map_ss_datatypes.BERValue[v21_map_ss_datatypes.SSSSStatus]](v21_map_ss_datatypes.SSSSStatusCodec()), opts...)
	}
	if value.SsNotAvailable != nil {
		return encodeSSErrorMember(18, sourceInfo10("ss-NotAvailable", "17.6.6"), value.SsNotAvailable, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSSNotAvailableParam](__asn1pkg_v21_map_er_datatypes.ERSSNotAvailableParamCodec()), opts...)
	}
	if value.SsIncompatibility != nil {
		return encodeSSErrorMember(20, sourceInfo10("ss-Incompatibility", "17.6.6"), value.SsIncompatibility, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSSIncompatibilityCause](__asn1pkg_v21_map_er_datatypes.ERSSIncompatibilityCauseCodec()), opts...)
	}
	if value.FacilityNotSupported != nil {
		return encodeSSErrorMember(21, sourceInfo10("facilityNotSupported", "17.6.6"), value.FacilityNotSupported, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParam](__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParamCodec()), opts...)
	}
	if value.SystemFailure != nil {
		return encodeSSErrorMember(34, sourceInfo10("systemFailure", "17.6.6"), value.SystemFailure, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam](__asn1pkg_v21_map_er_datatypes.ERSystemFailureParamCodec()), opts...)
	}
	if value.ResourcesNotAvailable != nil {
		return encodeSSErrorMember(127, sourceInfo8("resourcesNotAvailable", "4.3"), value.ResourcesNotAvailable, ValueCodec[NoParameter]{}, opts...)
	}
	if value.CallBarred != nil {
		return encodeSSErrorMember(13, sourceInfo10("callBarred", "17.6.6"), value.CallBarred, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERCallBarredParam](__asn1pkg_v21_map_er_datatypes.ERCallBarredParamCodec()), opts...)
	}
	return SSErrorEncoding{}, fmt.Errorf("%w: no selected explicitCT error", ber.ErrInvalidBinding)
}

// SSForwardCUGInfoErrors selects exactly the formal ERRORS set of SS-Operations.forwardCUG-Info.
type SSForwardCUGInfoErrors struct {
}

func infoSSForwardCUGInfoOperation() SSOperationInfo {
	return SSOperationInfo{Name: "forwardCUG-Info", Code: SSForwardCUGInfo, Argument: &TypeRef{ModuleOID: "0.4.0.0.2.3.2.18", ASN1Name: "ForwardCUG-InfoArg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "ForwardCUGInfoArg"}, Result: nil, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: false, Source: sourceInfo9("forwardCUG-Info", "4.2"), Errors: []SSErrorMemberInfo{}}
}

// SSForwardCUGInfoOperation binds the formal object in TS 24.080 V19.4.0 §4.2 (X.880 §§8.2–8.3).
func SSForwardCUGInfoOperation() SSOperation[ForwardCUGInfoArg, NoParameter, SSForwardCUGInfoErrors] {
	return SSOperation[ForwardCUGInfoArg, NoParameter, SSForwardCUGInfoErrors]{operationBinding[ForwardCUGInfoArg, NoParameter, SSForwardCUGInfoErrors, SSOperationInfo, SSOperationCode, SSErrorEncoding]{code: SSForwardCUGInfo, info: infoSSForwardCUGInfoOperation, argument: ForwardCUGInfoArgCodec(), result: ValueCodec[NoParameter]{}, decode: decodeSSForwardCUGInfoError, encode: encodeSSForwardCUGInfoError}}
}
func decodeSSForwardCUGInfoError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (SSForwardCUGInfoErrors, error) {
	switch code {
	default:
		return SSForwardCUGInfoErrors{}, fmt.Errorf("%w: error code %d is not in forwardCUG-Info ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeSSForwardCUGInfoError(value SSForwardCUGInfoErrors, opts ...ber.EncodeOption) (SSErrorEncoding, error) {
	return SSErrorEncoding{}, fmt.Errorf("%w: no selected forwardCUG-Info error", ber.ErrInvalidBinding)
}

// SSForwardChargeAdviceErrors selects exactly the formal ERRORS set of SS-Operations.forwardChargeAdvice.
type SSForwardChargeAdviceErrors struct {
}

func infoSSForwardChargeAdviceOperation() SSOperationInfo {
	return SSOperationInfo{Name: "forwardChargeAdvice", Code: SSForwardChargeAdvice, Argument: &TypeRef{ModuleOID: "0.4.0.0.2.3.2.18", ASN1Name: "ForwardChargeAdviceArg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "ForwardChargeAdviceArg"}, Result: nil, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: true, Source: sourceInfo9("forwardChargeAdvice", "4.2"), Errors: []SSErrorMemberInfo{}}
}

// SSForwardChargeAdviceOperation binds the formal object in TS 24.080 V19.4.0 §4.2 (X.880 §§8.2–8.3).
func SSForwardChargeAdviceOperation() SSOperation[ForwardChargeAdviceArg, NoParameter, SSForwardChargeAdviceErrors] {
	return SSOperation[ForwardChargeAdviceArg, NoParameter, SSForwardChargeAdviceErrors]{operationBinding[ForwardChargeAdviceArg, NoParameter, SSForwardChargeAdviceErrors, SSOperationInfo, SSOperationCode, SSErrorEncoding]{code: SSForwardChargeAdvice, info: infoSSForwardChargeAdviceOperation, argument: ForwardChargeAdviceArgCodec(), result: ValueCodec[NoParameter]{}, decode: decodeSSForwardChargeAdviceError, encode: encodeSSForwardChargeAdviceError}}
}
func decodeSSForwardChargeAdviceError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (SSForwardChargeAdviceErrors, error) {
	switch code {
	default:
		return SSForwardChargeAdviceErrors{}, fmt.Errorf("%w: error code %d is not in forwardChargeAdvice ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeSSForwardChargeAdviceError(value SSForwardChargeAdviceErrors, opts ...ber.EncodeOption) (SSErrorEncoding, error) {
	return SSErrorEncoding{}, fmt.Errorf("%w: no selected forwardChargeAdvice error", ber.ErrInvalidBinding)
}

// SSHoldMPTYErrors selects exactly the formal ERRORS set of SS-Operations.holdMPTY.
type SSHoldMPTYErrors struct {
	IllegalSSOperation   *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERIllegalSSOperationParam]
	SsErrorStatus        *ErrorValue[v21_map_ss_datatypes.BERValue[v21_map_ss_datatypes.SSSSStatus]]
	SsIncompatibility    *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERSSIncompatibilityCause]
	FacilityNotSupported *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParam]
	SystemFailure        *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam]
}

func infoSSHoldMPTYOperation() SSOperationInfo {
	return SSOperationInfo{Name: "holdMPTY", Code: SSHoldMPTY, Argument: nil, Result: nil, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: true, Source: sourceInfo9("holdMPTY", "4.2"), Errors: []SSErrorMemberInfo{SSErrorMemberInfo{Name: "illegalSS-Operation", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 16, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "IllegalSS-OperationParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERIllegalSSOperationParam"}, Source: sourceInfo10("illegalSS-Operation", "17.6.6")}, SSErrorMemberInfo{Name: "ss-ErrorStatus", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 17, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.14.21", ASN1Name: "SS-Status", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_ss_datatypes", GoName: "SSSSStatus"}, Source: sourceInfo10("ss-ErrorStatus", "17.6.6")}, SSErrorMemberInfo{Name: "ss-Incompatibility", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 20, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "SS-IncompatibilityCause", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERSSIncompatibilityCause"}, Source: sourceInfo10("ss-Incompatibility", "17.6.6")}, SSErrorMemberInfo{Name: "facilityNotSupported", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 21, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "FacilityNotSupParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERFacilityNotSupParam"}, Source: sourceInfo10("facilityNotSupported", "17.6.6")}, SSErrorMemberInfo{Name: "systemFailure", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 34, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "SystemFailureParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERSystemFailureParam"}, Source: sourceInfo10("systemFailure", "17.6.6")}}}
}

// SSHoldMPTYOperation binds the formal object in TS 24.080 V19.4.0 §4.2 (X.880 §§8.2–8.3).
func SSHoldMPTYOperation() SSOperation[NoParameter, NoParameter, SSHoldMPTYErrors] {
	return SSOperation[NoParameter, NoParameter, SSHoldMPTYErrors]{operationBinding[NoParameter, NoParameter, SSHoldMPTYErrors, SSOperationInfo, SSOperationCode, SSErrorEncoding]{code: SSHoldMPTY, info: infoSSHoldMPTYOperation, argument: ValueCodec[NoParameter]{}, result: ValueCodec[NoParameter]{}, decode: decodeSSHoldMPTYError, encode: encodeSSHoldMPTYError}}
}
func decodeSSHoldMPTYError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (SSHoldMPTYErrors, error) {
	switch code {
	case 16:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERIllegalSSOperationParam](__asn1pkg_v21_map_er_datatypes.ERIllegalSSOperationParamCodec()), opts...)
		if err != nil {
			return SSHoldMPTYErrors{}, err
		}
		return SSHoldMPTYErrors{IllegalSSOperation: p}, nil
	case 17:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[v21_map_ss_datatypes.BERValue[v21_map_ss_datatypes.SSSSStatus]](v21_map_ss_datatypes.SSSSStatusCodec()), opts...)
		if err != nil {
			return SSHoldMPTYErrors{}, err
		}
		return SSHoldMPTYErrors{SsErrorStatus: p}, nil
	case 20:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSSIncompatibilityCause](__asn1pkg_v21_map_er_datatypes.ERSSIncompatibilityCauseCodec()), opts...)
		if err != nil {
			return SSHoldMPTYErrors{}, err
		}
		return SSHoldMPTYErrors{SsIncompatibility: p}, nil
	case 21:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParam](__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParamCodec()), opts...)
		if err != nil {
			return SSHoldMPTYErrors{}, err
		}
		return SSHoldMPTYErrors{FacilityNotSupported: p}, nil
	case 34:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam](__asn1pkg_v21_map_er_datatypes.ERSystemFailureParamCodec()), opts...)
		if err != nil {
			return SSHoldMPTYErrors{}, err
		}
		return SSHoldMPTYErrors{SystemFailure: p}, nil
	default:
		return SSHoldMPTYErrors{}, fmt.Errorf("%w: error code %d is not in holdMPTY ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeSSHoldMPTYError(value SSHoldMPTYErrors, opts ...ber.EncodeOption) (SSErrorEncoding, error) {
	selected := 0
	if value.IllegalSSOperation != nil {
		selected++
	}
	if value.SsErrorStatus != nil {
		selected++
	}
	if value.SsIncompatibility != nil {
		selected++
	}
	if value.FacilityNotSupported != nil {
		selected++
	}
	if value.SystemFailure != nil {
		selected++
	}
	if selected != 1 {
		return SSErrorEncoding{}, fmt.Errorf("%w: exactly one holdMPTY error arm is required", ber.ErrInvalidBinding)
	}
	if value.IllegalSSOperation != nil {
		return encodeSSErrorMember(16, sourceInfo10("illegalSS-Operation", "17.6.6"), value.IllegalSSOperation, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERIllegalSSOperationParam](__asn1pkg_v21_map_er_datatypes.ERIllegalSSOperationParamCodec()), opts...)
	}
	if value.SsErrorStatus != nil {
		return encodeSSErrorMember(17, sourceInfo10("ss-ErrorStatus", "17.6.6"), value.SsErrorStatus, adaptValueCodec[v21_map_ss_datatypes.BERValue[v21_map_ss_datatypes.SSSSStatus]](v21_map_ss_datatypes.SSSSStatusCodec()), opts...)
	}
	if value.SsIncompatibility != nil {
		return encodeSSErrorMember(20, sourceInfo10("ss-Incompatibility", "17.6.6"), value.SsIncompatibility, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSSIncompatibilityCause](__asn1pkg_v21_map_er_datatypes.ERSSIncompatibilityCauseCodec()), opts...)
	}
	if value.FacilityNotSupported != nil {
		return encodeSSErrorMember(21, sourceInfo10("facilityNotSupported", "17.6.6"), value.FacilityNotSupported, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParam](__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParamCodec()), opts...)
	}
	if value.SystemFailure != nil {
		return encodeSSErrorMember(34, sourceInfo10("systemFailure", "17.6.6"), value.SystemFailure, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam](__asn1pkg_v21_map_er_datatypes.ERSystemFailureParamCodec()), opts...)
	}
	return SSErrorEncoding{}, fmt.Errorf("%w: no selected holdMPTY error", ber.ErrInvalidBinding)
}

// SSLcsAreaEventCancellationErrors selects exactly the formal ERRORS set of SS-Operations.lcs-AreaEventCancellation.
type SSLcsAreaEventCancellationErrors struct {
	SystemFailure        *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam]
	FacilityNotSupported *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParam]
	UnexpectedDataValue  *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParam]
}

func infoSSLcsAreaEventCancellationOperation() SSOperationInfo {
	return SSOperationInfo{Name: "lcs-AreaEventCancellation", Code: SSLcsAreaEventCancellation, Argument: &TypeRef{ModuleOID: "0.4.0.0.2.3.2.18", ASN1Name: "LCS-AreaEventCancellationArg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "LCSAreaEventCancellationArg"}, Result: nil, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: true, Source: sourceInfo9("lcs-AreaEventCancellation", "4.2"), Errors: []SSErrorMemberInfo{SSErrorMemberInfo{Name: "systemFailure", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 34, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "SystemFailureParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERSystemFailureParam"}, Source: sourceInfo10("systemFailure", "17.6.6")}, SSErrorMemberInfo{Name: "facilityNotSupported", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 21, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "FacilityNotSupParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERFacilityNotSupParam"}, Source: sourceInfo10("facilityNotSupported", "17.6.6")}, SSErrorMemberInfo{Name: "unexpectedDataValue", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 36, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "UnexpectedDataParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERUnexpectedDataParam"}, Source: sourceInfo10("unexpectedDataValue", "17.6.6")}}}
}

// SSLcsAreaEventCancellationOperation binds the formal object in TS 24.080 V19.4.0 §4.2 (X.880 §§8.2–8.3).
func SSLcsAreaEventCancellationOperation() SSOperation[LCSAreaEventCancellationArg, NoParameter, SSLcsAreaEventCancellationErrors] {
	return SSOperation[LCSAreaEventCancellationArg, NoParameter, SSLcsAreaEventCancellationErrors]{operationBinding[LCSAreaEventCancellationArg, NoParameter, SSLcsAreaEventCancellationErrors, SSOperationInfo, SSOperationCode, SSErrorEncoding]{code: SSLcsAreaEventCancellation, info: infoSSLcsAreaEventCancellationOperation, argument: LCSAreaEventCancellationArgCodec(), result: ValueCodec[NoParameter]{}, decode: decodeSSLcsAreaEventCancellationError, encode: encodeSSLcsAreaEventCancellationError}}
}
func decodeSSLcsAreaEventCancellationError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (SSLcsAreaEventCancellationErrors, error) {
	switch code {
	case 34:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam](__asn1pkg_v21_map_er_datatypes.ERSystemFailureParamCodec()), opts...)
		if err != nil {
			return SSLcsAreaEventCancellationErrors{}, err
		}
		return SSLcsAreaEventCancellationErrors{SystemFailure: p}, nil
	case 21:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParam](__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParamCodec()), opts...)
		if err != nil {
			return SSLcsAreaEventCancellationErrors{}, err
		}
		return SSLcsAreaEventCancellationErrors{FacilityNotSupported: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParam](__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParamCodec()), opts...)
		if err != nil {
			return SSLcsAreaEventCancellationErrors{}, err
		}
		return SSLcsAreaEventCancellationErrors{UnexpectedDataValue: p}, nil
	default:
		return SSLcsAreaEventCancellationErrors{}, fmt.Errorf("%w: error code %d is not in lcs-AreaEventCancellation ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeSSLcsAreaEventCancellationError(value SSLcsAreaEventCancellationErrors, opts ...ber.EncodeOption) (SSErrorEncoding, error) {
	selected := 0
	if value.SystemFailure != nil {
		selected++
	}
	if value.FacilityNotSupported != nil {
		selected++
	}
	if value.UnexpectedDataValue != nil {
		selected++
	}
	if selected != 1 {
		return SSErrorEncoding{}, fmt.Errorf("%w: exactly one lcs-AreaEventCancellation error arm is required", ber.ErrInvalidBinding)
	}
	if value.SystemFailure != nil {
		return encodeSSErrorMember(34, sourceInfo10("systemFailure", "17.6.6"), value.SystemFailure, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam](__asn1pkg_v21_map_er_datatypes.ERSystemFailureParamCodec()), opts...)
	}
	if value.FacilityNotSupported != nil {
		return encodeSSErrorMember(21, sourceInfo10("facilityNotSupported", "17.6.6"), value.FacilityNotSupported, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParam](__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParamCodec()), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeSSErrorMember(36, sourceInfo10("unexpectedDataValue", "17.6.6"), value.UnexpectedDataValue, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParam](__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParamCodec()), opts...)
	}
	return SSErrorEncoding{}, fmt.Errorf("%w: no selected lcs-AreaEventCancellation error", ber.ErrInvalidBinding)
}

// SSLcsAreaEventReportErrors selects exactly the formal ERRORS set of SS-Operations.lcs-AreaEventReport.
type SSLcsAreaEventReportErrors struct {
	SystemFailure        *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam]
	UnexpectedDataValue  *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParam]
	FacilityNotSupported *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParam]
}

func infoSSLcsAreaEventReportOperation() SSOperationInfo {
	return SSOperationInfo{Name: "lcs-AreaEventReport", Code: SSLcsAreaEventReport, Argument: &TypeRef{ModuleOID: "0.4.0.0.2.3.2.18", ASN1Name: "LCS-AreaEventReportArg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "LCSAreaEventReportArg"}, Result: nil, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: true, Source: sourceInfo9("lcs-AreaEventReport", "4.2"), Errors: []SSErrorMemberInfo{SSErrorMemberInfo{Name: "systemFailure", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 34, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "SystemFailureParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERSystemFailureParam"}, Source: sourceInfo10("systemFailure", "17.6.6")}, SSErrorMemberInfo{Name: "unexpectedDataValue", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 36, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "UnexpectedDataParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERUnexpectedDataParam"}, Source: sourceInfo10("unexpectedDataValue", "17.6.6")}, SSErrorMemberInfo{Name: "facilityNotSupported", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 21, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "FacilityNotSupParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERFacilityNotSupParam"}, Source: sourceInfo10("facilityNotSupported", "17.6.6")}}}
}

// SSLcsAreaEventReportOperation binds the formal object in TS 24.080 V19.4.0 §4.2 (X.880 §§8.2–8.3).
func SSLcsAreaEventReportOperation() SSOperation[LCSAreaEventReportArg, NoParameter, SSLcsAreaEventReportErrors] {
	return SSOperation[LCSAreaEventReportArg, NoParameter, SSLcsAreaEventReportErrors]{operationBinding[LCSAreaEventReportArg, NoParameter, SSLcsAreaEventReportErrors, SSOperationInfo, SSOperationCode, SSErrorEncoding]{code: SSLcsAreaEventReport, info: infoSSLcsAreaEventReportOperation, argument: LCSAreaEventReportArgCodec(), result: ValueCodec[NoParameter]{}, decode: decodeSSLcsAreaEventReportError, encode: encodeSSLcsAreaEventReportError}}
}
func decodeSSLcsAreaEventReportError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (SSLcsAreaEventReportErrors, error) {
	switch code {
	case 34:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam](__asn1pkg_v21_map_er_datatypes.ERSystemFailureParamCodec()), opts...)
		if err != nil {
			return SSLcsAreaEventReportErrors{}, err
		}
		return SSLcsAreaEventReportErrors{SystemFailure: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParam](__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParamCodec()), opts...)
		if err != nil {
			return SSLcsAreaEventReportErrors{}, err
		}
		return SSLcsAreaEventReportErrors{UnexpectedDataValue: p}, nil
	case 21:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParam](__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParamCodec()), opts...)
		if err != nil {
			return SSLcsAreaEventReportErrors{}, err
		}
		return SSLcsAreaEventReportErrors{FacilityNotSupported: p}, nil
	default:
		return SSLcsAreaEventReportErrors{}, fmt.Errorf("%w: error code %d is not in lcs-AreaEventReport ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeSSLcsAreaEventReportError(value SSLcsAreaEventReportErrors, opts ...ber.EncodeOption) (SSErrorEncoding, error) {
	selected := 0
	if value.SystemFailure != nil {
		selected++
	}
	if value.UnexpectedDataValue != nil {
		selected++
	}
	if value.FacilityNotSupported != nil {
		selected++
	}
	if selected != 1 {
		return SSErrorEncoding{}, fmt.Errorf("%w: exactly one lcs-AreaEventReport error arm is required", ber.ErrInvalidBinding)
	}
	if value.SystemFailure != nil {
		return encodeSSErrorMember(34, sourceInfo10("systemFailure", "17.6.6"), value.SystemFailure, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam](__asn1pkg_v21_map_er_datatypes.ERSystemFailureParamCodec()), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeSSErrorMember(36, sourceInfo10("unexpectedDataValue", "17.6.6"), value.UnexpectedDataValue, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParam](__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParamCodec()), opts...)
	}
	if value.FacilityNotSupported != nil {
		return encodeSSErrorMember(21, sourceInfo10("facilityNotSupported", "17.6.6"), value.FacilityNotSupported, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParam](__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParamCodec()), opts...)
	}
	return SSErrorEncoding{}, fmt.Errorf("%w: no selected lcs-AreaEventReport error", ber.ErrInvalidBinding)
}

// SSLcsAreaEventRequestErrors selects exactly the formal ERRORS set of SS-Operations.lcs-AreaEventRequest.
type SSLcsAreaEventRequestErrors struct {
	SystemFailure        *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam]
	FacilityNotSupported *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParam]
	UnexpectedDataValue  *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParam]
}

func infoSSLcsAreaEventRequestOperation() SSOperationInfo {
	return SSOperationInfo{Name: "lcs-AreaEventRequest", Code: SSLcsAreaEventRequest, Argument: &TypeRef{ModuleOID: "0.4.0.0.2.3.2.18", ASN1Name: "LCS-AreaEventRequestArg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "LCSAreaEventRequestArg"}, Result: nil, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: true, Source: sourceInfo9("lcs-AreaEventRequest", "4.2"), Errors: []SSErrorMemberInfo{SSErrorMemberInfo{Name: "systemFailure", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 34, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "SystemFailureParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERSystemFailureParam"}, Source: sourceInfo10("systemFailure", "17.6.6")}, SSErrorMemberInfo{Name: "facilityNotSupported", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 21, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "FacilityNotSupParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERFacilityNotSupParam"}, Source: sourceInfo10("facilityNotSupported", "17.6.6")}, SSErrorMemberInfo{Name: "unexpectedDataValue", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 36, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "UnexpectedDataParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERUnexpectedDataParam"}, Source: sourceInfo10("unexpectedDataValue", "17.6.6")}}}
}

// SSLcsAreaEventRequestOperation binds the formal object in TS 24.080 V19.4.0 §4.2 (X.880 §§8.2–8.3).
func SSLcsAreaEventRequestOperation() SSOperation[LCSAreaEventRequestArg, NoParameter, SSLcsAreaEventRequestErrors] {
	return SSOperation[LCSAreaEventRequestArg, NoParameter, SSLcsAreaEventRequestErrors]{operationBinding[LCSAreaEventRequestArg, NoParameter, SSLcsAreaEventRequestErrors, SSOperationInfo, SSOperationCode, SSErrorEncoding]{code: SSLcsAreaEventRequest, info: infoSSLcsAreaEventRequestOperation, argument: LCSAreaEventRequestArgCodec(), result: ValueCodec[NoParameter]{}, decode: decodeSSLcsAreaEventRequestError, encode: encodeSSLcsAreaEventRequestError}}
}
func decodeSSLcsAreaEventRequestError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (SSLcsAreaEventRequestErrors, error) {
	switch code {
	case 34:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam](__asn1pkg_v21_map_er_datatypes.ERSystemFailureParamCodec()), opts...)
		if err != nil {
			return SSLcsAreaEventRequestErrors{}, err
		}
		return SSLcsAreaEventRequestErrors{SystemFailure: p}, nil
	case 21:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParam](__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParamCodec()), opts...)
		if err != nil {
			return SSLcsAreaEventRequestErrors{}, err
		}
		return SSLcsAreaEventRequestErrors{FacilityNotSupported: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParam](__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParamCodec()), opts...)
		if err != nil {
			return SSLcsAreaEventRequestErrors{}, err
		}
		return SSLcsAreaEventRequestErrors{UnexpectedDataValue: p}, nil
	default:
		return SSLcsAreaEventRequestErrors{}, fmt.Errorf("%w: error code %d is not in lcs-AreaEventRequest ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeSSLcsAreaEventRequestError(value SSLcsAreaEventRequestErrors, opts ...ber.EncodeOption) (SSErrorEncoding, error) {
	selected := 0
	if value.SystemFailure != nil {
		selected++
	}
	if value.FacilityNotSupported != nil {
		selected++
	}
	if value.UnexpectedDataValue != nil {
		selected++
	}
	if selected != 1 {
		return SSErrorEncoding{}, fmt.Errorf("%w: exactly one lcs-AreaEventRequest error arm is required", ber.ErrInvalidBinding)
	}
	if value.SystemFailure != nil {
		return encodeSSErrorMember(34, sourceInfo10("systemFailure", "17.6.6"), value.SystemFailure, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam](__asn1pkg_v21_map_er_datatypes.ERSystemFailureParamCodec()), opts...)
	}
	if value.FacilityNotSupported != nil {
		return encodeSSErrorMember(21, sourceInfo10("facilityNotSupported", "17.6.6"), value.FacilityNotSupported, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParam](__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParamCodec()), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeSSErrorMember(36, sourceInfo10("unexpectedDataValue", "17.6.6"), value.UnexpectedDataValue, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParam](__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParamCodec()), opts...)
	}
	return SSErrorEncoding{}, fmt.Errorf("%w: no selected lcs-AreaEventRequest error", ber.ErrInvalidBinding)
}

// SSLcsCancelDeferredLocationErrors selects exactly the formal ERRORS set of SS-Operations.lcs-CancelDeferredLocation.
type SSLcsCancelDeferredLocationErrors struct {
	SystemFailure       *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam]
	UnexpectedDataValue *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParam]
}

func infoSSLcsCancelDeferredLocationOperation() SSOperationInfo {
	return SSOperationInfo{Name: "lcs-CancelDeferredLocation", Code: SSLcsCancelDeferredLocation, Argument: &TypeRef{ModuleOID: "0.4.0.0.2.3.2.18", ASN1Name: "LCS-CancelDeferredLocationArg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "LCSCancelDeferredLocationArg"}, Result: nil, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: true, Source: sourceInfo9("lcs-CancelDeferredLocation", "4.2"), Errors: []SSErrorMemberInfo{SSErrorMemberInfo{Name: "systemFailure", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 34, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "SystemFailureParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERSystemFailureParam"}, Source: sourceInfo10("systemFailure", "17.6.6")}, SSErrorMemberInfo{Name: "unexpectedDataValue", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 36, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "UnexpectedDataParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERUnexpectedDataParam"}, Source: sourceInfo10("unexpectedDataValue", "17.6.6")}}}
}

// SSLcsCancelDeferredLocationOperation binds the formal object in TS 24.080 V19.4.0 §4.2 (X.880 §§8.2–8.3).
func SSLcsCancelDeferredLocationOperation() SSOperation[LCSCancelDeferredLocationArg, NoParameter, SSLcsCancelDeferredLocationErrors] {
	return SSOperation[LCSCancelDeferredLocationArg, NoParameter, SSLcsCancelDeferredLocationErrors]{operationBinding[LCSCancelDeferredLocationArg, NoParameter, SSLcsCancelDeferredLocationErrors, SSOperationInfo, SSOperationCode, SSErrorEncoding]{code: SSLcsCancelDeferredLocation, info: infoSSLcsCancelDeferredLocationOperation, argument: LCSCancelDeferredLocationArgCodec(), result: ValueCodec[NoParameter]{}, decode: decodeSSLcsCancelDeferredLocationError, encode: encodeSSLcsCancelDeferredLocationError}}
}
func decodeSSLcsCancelDeferredLocationError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (SSLcsCancelDeferredLocationErrors, error) {
	switch code {
	case 34:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam](__asn1pkg_v21_map_er_datatypes.ERSystemFailureParamCodec()), opts...)
		if err != nil {
			return SSLcsCancelDeferredLocationErrors{}, err
		}
		return SSLcsCancelDeferredLocationErrors{SystemFailure: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParam](__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParamCodec()), opts...)
		if err != nil {
			return SSLcsCancelDeferredLocationErrors{}, err
		}
		return SSLcsCancelDeferredLocationErrors{UnexpectedDataValue: p}, nil
	default:
		return SSLcsCancelDeferredLocationErrors{}, fmt.Errorf("%w: error code %d is not in lcs-CancelDeferredLocation ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeSSLcsCancelDeferredLocationError(value SSLcsCancelDeferredLocationErrors, opts ...ber.EncodeOption) (SSErrorEncoding, error) {
	selected := 0
	if value.SystemFailure != nil {
		selected++
	}
	if value.UnexpectedDataValue != nil {
		selected++
	}
	if selected != 1 {
		return SSErrorEncoding{}, fmt.Errorf("%w: exactly one lcs-CancelDeferredLocation error arm is required", ber.ErrInvalidBinding)
	}
	if value.SystemFailure != nil {
		return encodeSSErrorMember(34, sourceInfo10("systemFailure", "17.6.6"), value.SystemFailure, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam](__asn1pkg_v21_map_er_datatypes.ERSystemFailureParamCodec()), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeSSErrorMember(36, sourceInfo10("unexpectedDataValue", "17.6.6"), value.UnexpectedDataValue, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParam](__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParamCodec()), opts...)
	}
	return SSErrorEncoding{}, fmt.Errorf("%w: no selected lcs-CancelDeferredLocation error", ber.ErrInvalidBinding)
}

// SSLcsDLRSPPTransportErrors selects exactly the formal ERRORS set of SS-Operations.lcs-DLRSPPTransport.
type SSLcsDLRSPPTransportErrors struct {
	SystemFailure        *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam]
	FacilityNotSupported *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParam]
}

func infoSSLcsDLRSPPTransportOperation() SSOperationInfo {
	return SSOperationInfo{Name: "lcs-DLRSPPTransport", Code: SSLcsDLRSPPTransport, Argument: &TypeRef{ModuleOID: "0.4.0.0.2.3.2.18", ASN1Name: "LCS-DLRSPPTransportArg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "LCSDLRSPPTransportArg"}, Result: &TypeRef{ModuleOID: "0.4.0.0.2.3.2.18", ASN1Name: "LCS-DLRSPPTransportRes", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "LCSDLRSPPTransportRes"}, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: false, Source: sourceInfo9("lcs-DLRSPPTransport", "4.2"), Errors: []SSErrorMemberInfo{SSErrorMemberInfo{Name: "systemFailure", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 34, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "SystemFailureParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERSystemFailureParam"}, Source: sourceInfo10("systemFailure", "17.6.6")}, SSErrorMemberInfo{Name: "facilityNotSupported", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 21, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "FacilityNotSupParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERFacilityNotSupParam"}, Source: sourceInfo10("facilityNotSupported", "17.6.6")}}}
}

// SSLcsDLRSPPTransportOperation binds the formal object in TS 24.080 V19.4.0 §4.2 (X.880 §§8.2–8.3).
func SSLcsDLRSPPTransportOperation() SSOperation[LCSDLRSPPTransportArg, LCSDLRSPPTransportRes, SSLcsDLRSPPTransportErrors] {
	return SSOperation[LCSDLRSPPTransportArg, LCSDLRSPPTransportRes, SSLcsDLRSPPTransportErrors]{operationBinding[LCSDLRSPPTransportArg, LCSDLRSPPTransportRes, SSLcsDLRSPPTransportErrors, SSOperationInfo, SSOperationCode, SSErrorEncoding]{code: SSLcsDLRSPPTransport, info: infoSSLcsDLRSPPTransportOperation, argument: LCSDLRSPPTransportArgCodec(), result: LCSDLRSPPTransportResCodec(), decode: decodeSSLcsDLRSPPTransportError, encode: encodeSSLcsDLRSPPTransportError}}
}
func decodeSSLcsDLRSPPTransportError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (SSLcsDLRSPPTransportErrors, error) {
	switch code {
	case 34:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam](__asn1pkg_v21_map_er_datatypes.ERSystemFailureParamCodec()), opts...)
		if err != nil {
			return SSLcsDLRSPPTransportErrors{}, err
		}
		return SSLcsDLRSPPTransportErrors{SystemFailure: p}, nil
	case 21:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParam](__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParamCodec()), opts...)
		if err != nil {
			return SSLcsDLRSPPTransportErrors{}, err
		}
		return SSLcsDLRSPPTransportErrors{FacilityNotSupported: p}, nil
	default:
		return SSLcsDLRSPPTransportErrors{}, fmt.Errorf("%w: error code %d is not in lcs-DLRSPPTransport ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeSSLcsDLRSPPTransportError(value SSLcsDLRSPPTransportErrors, opts ...ber.EncodeOption) (SSErrorEncoding, error) {
	selected := 0
	if value.SystemFailure != nil {
		selected++
	}
	if value.FacilityNotSupported != nil {
		selected++
	}
	if selected != 1 {
		return SSErrorEncoding{}, fmt.Errorf("%w: exactly one lcs-DLRSPPTransport error arm is required", ber.ErrInvalidBinding)
	}
	if value.SystemFailure != nil {
		return encodeSSErrorMember(34, sourceInfo10("systemFailure", "17.6.6"), value.SystemFailure, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam](__asn1pkg_v21_map_er_datatypes.ERSystemFailureParamCodec()), opts...)
	}
	if value.FacilityNotSupported != nil {
		return encodeSSErrorMember(21, sourceInfo10("facilityNotSupported", "17.6.6"), value.FacilityNotSupported, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParam](__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParamCodec()), opts...)
	}
	return SSErrorEncoding{}, fmt.Errorf("%w: no selected lcs-DLRSPPTransport error", ber.ErrInvalidBinding)
}

// SSLcsEventReportErrors selects exactly the formal ERRORS set of SS-Operations.lcs-EventReport.
type SSLcsEventReportErrors struct {
	SystemFailure           *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam]
	FacilityNotSupported    *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParam]
	SsSubscriptionViolation *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERSSSubscriptionViolationParam]
	UnexpectedDataValue     *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParam]
	DataMissing             *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERDataMissingParam]
	ResourceLimitation      *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERResourceLimitationParam]
}

func infoSSLcsEventReportOperation() SSOperationInfo {
	return SSOperationInfo{Name: "lcs-EventReport", Code: SSLcsEventReport, Argument: &TypeRef{ModuleOID: "0.4.0.0.2.3.2.18", ASN1Name: "LCS-EventReportArg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "LCSEventReportArg"}, Result: &TypeRef{ModuleOID: "0.4.0.0.2.3.2.18", ASN1Name: "LCS-EventReportRes", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "LCSEventReportRes"}, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: false, Source: sourceInfo9("lcs-EventReport", "4.2"), Errors: []SSErrorMemberInfo{SSErrorMemberInfo{Name: "systemFailure", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 34, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "SystemFailureParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERSystemFailureParam"}, Source: sourceInfo10("systemFailure", "17.6.6")}, SSErrorMemberInfo{Name: "facilityNotSupported", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 21, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "FacilityNotSupParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERFacilityNotSupParam"}, Source: sourceInfo10("facilityNotSupported", "17.6.6")}, SSErrorMemberInfo{Name: "ss-SubscriptionViolation", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 19, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "SS-SubscriptionViolationParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERSSSubscriptionViolationParam"}, Source: sourceInfo10("ss-SubscriptionViolation", "17.6.6")}, SSErrorMemberInfo{Name: "unexpectedDataValue", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 36, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "UnexpectedDataParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERUnexpectedDataParam"}, Source: sourceInfo10("unexpectedDataValue", "17.6.6")}, SSErrorMemberInfo{Name: "dataMissing", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 35, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "DataMissingParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERDataMissingParam"}, Source: sourceInfo10("dataMissing", "17.6.6")}, SSErrorMemberInfo{Name: "resourceLimitation", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 51, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "ResourceLimitationParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERResourceLimitationParam"}, Source: sourceInfo10("resourceLimitation", "17.6.6")}}}
}

// SSLcsEventReportOperation binds the formal object in TS 24.080 V19.4.0 §4.2 (X.880 §§8.2–8.3).
func SSLcsEventReportOperation() SSOperation[LCSEventReportArg, LCSEventReportRes, SSLcsEventReportErrors] {
	return SSOperation[LCSEventReportArg, LCSEventReportRes, SSLcsEventReportErrors]{operationBinding[LCSEventReportArg, LCSEventReportRes, SSLcsEventReportErrors, SSOperationInfo, SSOperationCode, SSErrorEncoding]{code: SSLcsEventReport, info: infoSSLcsEventReportOperation, argument: LCSEventReportArgCodec(), result: LCSEventReportResCodec(), decode: decodeSSLcsEventReportError, encode: encodeSSLcsEventReportError}}
}
func decodeSSLcsEventReportError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (SSLcsEventReportErrors, error) {
	switch code {
	case 34:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam](__asn1pkg_v21_map_er_datatypes.ERSystemFailureParamCodec()), opts...)
		if err != nil {
			return SSLcsEventReportErrors{}, err
		}
		return SSLcsEventReportErrors{SystemFailure: p}, nil
	case 21:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParam](__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParamCodec()), opts...)
		if err != nil {
			return SSLcsEventReportErrors{}, err
		}
		return SSLcsEventReportErrors{FacilityNotSupported: p}, nil
	case 19:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSSSubscriptionViolationParam](__asn1pkg_v21_map_er_datatypes.ERSSSubscriptionViolationParamCodec()), opts...)
		if err != nil {
			return SSLcsEventReportErrors{}, err
		}
		return SSLcsEventReportErrors{SsSubscriptionViolation: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParam](__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParamCodec()), opts...)
		if err != nil {
			return SSLcsEventReportErrors{}, err
		}
		return SSLcsEventReportErrors{UnexpectedDataValue: p}, nil
	case 35:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERDataMissingParam](__asn1pkg_v21_map_er_datatypes.ERDataMissingParamCodec()), opts...)
		if err != nil {
			return SSLcsEventReportErrors{}, err
		}
		return SSLcsEventReportErrors{DataMissing: p}, nil
	case 51:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERResourceLimitationParam](__asn1pkg_v21_map_er_datatypes.ERResourceLimitationParamCodec()), opts...)
		if err != nil {
			return SSLcsEventReportErrors{}, err
		}
		return SSLcsEventReportErrors{ResourceLimitation: p}, nil
	default:
		return SSLcsEventReportErrors{}, fmt.Errorf("%w: error code %d is not in lcs-EventReport ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeSSLcsEventReportError(value SSLcsEventReportErrors, opts ...ber.EncodeOption) (SSErrorEncoding, error) {
	selected := 0
	if value.SystemFailure != nil {
		selected++
	}
	if value.FacilityNotSupported != nil {
		selected++
	}
	if value.SsSubscriptionViolation != nil {
		selected++
	}
	if value.UnexpectedDataValue != nil {
		selected++
	}
	if value.DataMissing != nil {
		selected++
	}
	if value.ResourceLimitation != nil {
		selected++
	}
	if selected != 1 {
		return SSErrorEncoding{}, fmt.Errorf("%w: exactly one lcs-EventReport error arm is required", ber.ErrInvalidBinding)
	}
	if value.SystemFailure != nil {
		return encodeSSErrorMember(34, sourceInfo10("systemFailure", "17.6.6"), value.SystemFailure, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam](__asn1pkg_v21_map_er_datatypes.ERSystemFailureParamCodec()), opts...)
	}
	if value.FacilityNotSupported != nil {
		return encodeSSErrorMember(21, sourceInfo10("facilityNotSupported", "17.6.6"), value.FacilityNotSupported, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParam](__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParamCodec()), opts...)
	}
	if value.SsSubscriptionViolation != nil {
		return encodeSSErrorMember(19, sourceInfo10("ss-SubscriptionViolation", "17.6.6"), value.SsSubscriptionViolation, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSSSubscriptionViolationParam](__asn1pkg_v21_map_er_datatypes.ERSSSubscriptionViolationParamCodec()), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeSSErrorMember(36, sourceInfo10("unexpectedDataValue", "17.6.6"), value.UnexpectedDataValue, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParam](__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParamCodec()), opts...)
	}
	if value.DataMissing != nil {
		return encodeSSErrorMember(35, sourceInfo10("dataMissing", "17.6.6"), value.DataMissing, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERDataMissingParam](__asn1pkg_v21_map_er_datatypes.ERDataMissingParamCodec()), opts...)
	}
	if value.ResourceLimitation != nil {
		return encodeSSErrorMember(51, sourceInfo10("resourceLimitation", "17.6.6"), value.ResourceLimitation, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERResourceLimitationParam](__asn1pkg_v21_map_er_datatypes.ERResourceLimitationParamCodec()), opts...)
	}
	return SSErrorEncoding{}, fmt.Errorf("%w: no selected lcs-EventReport error", ber.ErrInvalidBinding)
}

// SSLcsLocationNotificationErrors selects exactly the formal ERRORS set of SS-Operations.lcs-LocationNotification.
type SSLcsLocationNotificationErrors struct {
	SystemFailure       *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam]
	UnexpectedDataValue *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParam]
}

func infoSSLcsLocationNotificationOperation() SSOperationInfo {
	return SSOperationInfo{Name: "lcs-LocationNotification", Code: SSLcsLocationNotification, Argument: &TypeRef{ModuleOID: "0.4.0.0.2.3.2.18", ASN1Name: "LocationNotificationArg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "LocationNotificationArg"}, Result: &TypeRef{ModuleOID: "0.4.0.0.2.3.2.18", ASN1Name: "LocationNotificationRes", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "LocationNotificationRes"}, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: false, Source: sourceInfo9("lcs-LocationNotification", "4.2"), Errors: []SSErrorMemberInfo{SSErrorMemberInfo{Name: "systemFailure", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 34, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "SystemFailureParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERSystemFailureParam"}, Source: sourceInfo10("systemFailure", "17.6.6")}, SSErrorMemberInfo{Name: "unexpectedDataValue", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 36, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "UnexpectedDataParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERUnexpectedDataParam"}, Source: sourceInfo10("unexpectedDataValue", "17.6.6")}}}
}

// SSLcsLocationNotificationOperation binds the formal object in TS 24.080 V19.4.0 §4.2 (X.880 §§8.2–8.3).
func SSLcsLocationNotificationOperation() SSOperation[LocationNotificationArg, LocationNotificationRes, SSLcsLocationNotificationErrors] {
	return SSOperation[LocationNotificationArg, LocationNotificationRes, SSLcsLocationNotificationErrors]{operationBinding[LocationNotificationArg, LocationNotificationRes, SSLcsLocationNotificationErrors, SSOperationInfo, SSOperationCode, SSErrorEncoding]{code: SSLcsLocationNotification, info: infoSSLcsLocationNotificationOperation, argument: LocationNotificationArgCodec(), result: LocationNotificationResCodec(), decode: decodeSSLcsLocationNotificationError, encode: encodeSSLcsLocationNotificationError}}
}
func decodeSSLcsLocationNotificationError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (SSLcsLocationNotificationErrors, error) {
	switch code {
	case 34:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam](__asn1pkg_v21_map_er_datatypes.ERSystemFailureParamCodec()), opts...)
		if err != nil {
			return SSLcsLocationNotificationErrors{}, err
		}
		return SSLcsLocationNotificationErrors{SystemFailure: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParam](__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParamCodec()), opts...)
		if err != nil {
			return SSLcsLocationNotificationErrors{}, err
		}
		return SSLcsLocationNotificationErrors{UnexpectedDataValue: p}, nil
	default:
		return SSLcsLocationNotificationErrors{}, fmt.Errorf("%w: error code %d is not in lcs-LocationNotification ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeSSLcsLocationNotificationError(value SSLcsLocationNotificationErrors, opts ...ber.EncodeOption) (SSErrorEncoding, error) {
	selected := 0
	if value.SystemFailure != nil {
		selected++
	}
	if value.UnexpectedDataValue != nil {
		selected++
	}
	if selected != 1 {
		return SSErrorEncoding{}, fmt.Errorf("%w: exactly one lcs-LocationNotification error arm is required", ber.ErrInvalidBinding)
	}
	if value.SystemFailure != nil {
		return encodeSSErrorMember(34, sourceInfo10("systemFailure", "17.6.6"), value.SystemFailure, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam](__asn1pkg_v21_map_er_datatypes.ERSystemFailureParamCodec()), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeSSErrorMember(36, sourceInfo10("unexpectedDataValue", "17.6.6"), value.UnexpectedDataValue, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParam](__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParamCodec()), opts...)
	}
	return SSErrorEncoding{}, fmt.Errorf("%w: no selected lcs-LocationNotification error", ber.ErrInvalidBinding)
}

// SSLcsLocationPrivacySettingErrors selects exactly the formal ERRORS set of SS-Operations.lcs-LocationPrivacySetting.
type SSLcsLocationPrivacySettingErrors struct {
	SystemFailure       *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam]
	UnexpectedDataValue *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParam]
}

func infoSSLcsLocationPrivacySettingOperation() SSOperationInfo {
	return SSOperationInfo{Name: "lcs-LocationPrivacySetting", Code: SSLcsLocationPrivacySetting, Argument: &TypeRef{ModuleOID: "0.4.0.0.2.3.2.18", ASN1Name: "LCS-LocationPrivacySettingArg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "LCSLocationPrivacySettingArg"}, Result: nil, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: true, Source: sourceInfo9("lcs-LocationPrivacySetting", "4.2"), Errors: []SSErrorMemberInfo{SSErrorMemberInfo{Name: "systemFailure", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 34, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "SystemFailureParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERSystemFailureParam"}, Source: sourceInfo10("systemFailure", "17.6.6")}, SSErrorMemberInfo{Name: "unexpectedDataValue", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 36, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "UnexpectedDataParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERUnexpectedDataParam"}, Source: sourceInfo10("unexpectedDataValue", "17.6.6")}}}
}

// SSLcsLocationPrivacySettingOperation binds the formal object in TS 24.080 V19.4.0 §4.2 (X.880 §§8.2–8.3).
func SSLcsLocationPrivacySettingOperation() SSOperation[LCSLocationPrivacySettingArg, NoParameter, SSLcsLocationPrivacySettingErrors] {
	return SSOperation[LCSLocationPrivacySettingArg, NoParameter, SSLcsLocationPrivacySettingErrors]{operationBinding[LCSLocationPrivacySettingArg, NoParameter, SSLcsLocationPrivacySettingErrors, SSOperationInfo, SSOperationCode, SSErrorEncoding]{code: SSLcsLocationPrivacySetting, info: infoSSLcsLocationPrivacySettingOperation, argument: LCSLocationPrivacySettingArgCodec(), result: ValueCodec[NoParameter]{}, decode: decodeSSLcsLocationPrivacySettingError, encode: encodeSSLcsLocationPrivacySettingError}}
}
func decodeSSLcsLocationPrivacySettingError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (SSLcsLocationPrivacySettingErrors, error) {
	switch code {
	case 34:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam](__asn1pkg_v21_map_er_datatypes.ERSystemFailureParamCodec()), opts...)
		if err != nil {
			return SSLcsLocationPrivacySettingErrors{}, err
		}
		return SSLcsLocationPrivacySettingErrors{SystemFailure: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParam](__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParamCodec()), opts...)
		if err != nil {
			return SSLcsLocationPrivacySettingErrors{}, err
		}
		return SSLcsLocationPrivacySettingErrors{UnexpectedDataValue: p}, nil
	default:
		return SSLcsLocationPrivacySettingErrors{}, fmt.Errorf("%w: error code %d is not in lcs-LocationPrivacySetting ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeSSLcsLocationPrivacySettingError(value SSLcsLocationPrivacySettingErrors, opts ...ber.EncodeOption) (SSErrorEncoding, error) {
	selected := 0
	if value.SystemFailure != nil {
		selected++
	}
	if value.UnexpectedDataValue != nil {
		selected++
	}
	if selected != 1 {
		return SSErrorEncoding{}, fmt.Errorf("%w: exactly one lcs-LocationPrivacySetting error arm is required", ber.ErrInvalidBinding)
	}
	if value.SystemFailure != nil {
		return encodeSSErrorMember(34, sourceInfo10("systemFailure", "17.6.6"), value.SystemFailure, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam](__asn1pkg_v21_map_er_datatypes.ERSystemFailureParamCodec()), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeSSErrorMember(36, sourceInfo10("unexpectedDataValue", "17.6.6"), value.UnexpectedDataValue, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParam](__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParamCodec()), opts...)
	}
	return SSErrorEncoding{}, fmt.Errorf("%w: no selected lcs-LocationPrivacySetting error", ber.ErrInvalidBinding)
}

// SSLcsLocationUpdateErrors selects exactly the formal ERRORS set of SS-Operations.lcs-LocationUpdate.
type SSLcsLocationUpdateErrors struct {
	SystemFailure       *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam]
	UnexpectedDataValue *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParam]
}

func infoSSLcsLocationUpdateOperation() SSOperationInfo {
	return SSOperationInfo{Name: "lcs-LocationUpdate", Code: SSLcsLocationUpdate, Argument: &TypeRef{ModuleOID: "0.4.0.0.2.3.2.18", ASN1Name: "LCS-LocationUpdateArg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "LCSLocationUpdateArg"}, Result: &TypeRef{ModuleOID: "0.4.0.0.2.3.2.18", ASN1Name: "LCS-LocationUpdateRes", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "LCSLocationUpdateRes"}, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: false, Source: sourceInfo9("lcs-LocationUpdate", "4.2"), Errors: []SSErrorMemberInfo{SSErrorMemberInfo{Name: "systemFailure", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 34, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "SystemFailureParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERSystemFailureParam"}, Source: sourceInfo10("systemFailure", "17.6.6")}, SSErrorMemberInfo{Name: "unexpectedDataValue", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 36, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "UnexpectedDataParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERUnexpectedDataParam"}, Source: sourceInfo10("unexpectedDataValue", "17.6.6")}}}
}

// SSLcsLocationUpdateOperation binds the formal object in TS 24.080 V19.4.0 §4.2 (X.880 §§8.2–8.3).
func SSLcsLocationUpdateOperation() SSOperation[LCSLocationUpdateArg, LCSLocationUpdateRes, SSLcsLocationUpdateErrors] {
	return SSOperation[LCSLocationUpdateArg, LCSLocationUpdateRes, SSLcsLocationUpdateErrors]{operationBinding[LCSLocationUpdateArg, LCSLocationUpdateRes, SSLcsLocationUpdateErrors, SSOperationInfo, SSOperationCode, SSErrorEncoding]{code: SSLcsLocationUpdate, info: infoSSLcsLocationUpdateOperation, argument: LCSLocationUpdateArgCodec(), result: LCSLocationUpdateResCodec(), decode: decodeSSLcsLocationUpdateError, encode: encodeSSLcsLocationUpdateError}}
}
func decodeSSLcsLocationUpdateError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (SSLcsLocationUpdateErrors, error) {
	switch code {
	case 34:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam](__asn1pkg_v21_map_er_datatypes.ERSystemFailureParamCodec()), opts...)
		if err != nil {
			return SSLcsLocationUpdateErrors{}, err
		}
		return SSLcsLocationUpdateErrors{SystemFailure: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParam](__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParamCodec()), opts...)
		if err != nil {
			return SSLcsLocationUpdateErrors{}, err
		}
		return SSLcsLocationUpdateErrors{UnexpectedDataValue: p}, nil
	default:
		return SSLcsLocationUpdateErrors{}, fmt.Errorf("%w: error code %d is not in lcs-LocationUpdate ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeSSLcsLocationUpdateError(value SSLcsLocationUpdateErrors, opts ...ber.EncodeOption) (SSErrorEncoding, error) {
	selected := 0
	if value.SystemFailure != nil {
		selected++
	}
	if value.UnexpectedDataValue != nil {
		selected++
	}
	if selected != 1 {
		return SSErrorEncoding{}, fmt.Errorf("%w: exactly one lcs-LocationUpdate error arm is required", ber.ErrInvalidBinding)
	}
	if value.SystemFailure != nil {
		return encodeSSErrorMember(34, sourceInfo10("systemFailure", "17.6.6"), value.SystemFailure, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam](__asn1pkg_v21_map_er_datatypes.ERSystemFailureParamCodec()), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeSSErrorMember(36, sourceInfo10("unexpectedDataValue", "17.6.6"), value.UnexpectedDataValue, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParam](__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParamCodec()), opts...)
	}
	return SSErrorEncoding{}, fmt.Errorf("%w: no selected lcs-LocationUpdate error", ber.ErrInvalidBinding)
}

// SSLcsMOLRErrors selects exactly the formal ERRORS set of SS-Operations.lcs-MOLR.
type SSLcsMOLRErrors struct {
	SystemFailure           *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam]
	UnexpectedDataValue     *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParam]
	DataMissing             *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERDataMissingParam]
	FacilityNotSupported    *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParam]
	SsSubscriptionViolation *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERSSSubscriptionViolationParam]
	PositionMethodFailure   *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERPositionMethodFailureParam]
}

func infoSSLcsMOLROperation() SSOperationInfo {
	return SSOperationInfo{Name: "lcs-MOLR", Code: SSLcsMOLR, Argument: &TypeRef{ModuleOID: "0.4.0.0.2.3.2.18", ASN1Name: "LCS-MOLRArg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "LCSMOLRArg"}, Result: &TypeRef{ModuleOID: "0.4.0.0.2.3.2.18", ASN1Name: "LCS-MOLRRes", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "LCSMOLRRes"}, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: false, Source: sourceInfo9("lcs-MOLR", "4.2"), Errors: []SSErrorMemberInfo{SSErrorMemberInfo{Name: "systemFailure", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 34, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "SystemFailureParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERSystemFailureParam"}, Source: sourceInfo10("systemFailure", "17.6.6")}, SSErrorMemberInfo{Name: "unexpectedDataValue", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 36, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "UnexpectedDataParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERUnexpectedDataParam"}, Source: sourceInfo10("unexpectedDataValue", "17.6.6")}, SSErrorMemberInfo{Name: "dataMissing", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 35, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "DataMissingParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERDataMissingParam"}, Source: sourceInfo10("dataMissing", "17.6.6")}, SSErrorMemberInfo{Name: "facilityNotSupported", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 21, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "FacilityNotSupParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERFacilityNotSupParam"}, Source: sourceInfo10("facilityNotSupported", "17.6.6")}, SSErrorMemberInfo{Name: "ss-SubscriptionViolation", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 19, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "SS-SubscriptionViolationParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERSSSubscriptionViolationParam"}, Source: sourceInfo10("ss-SubscriptionViolation", "17.6.6")}, SSErrorMemberInfo{Name: "positionMethodFailure", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 54, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "PositionMethodFailure-Param", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERPositionMethodFailureParam"}, Source: sourceInfo10("positionMethodFailure", "17.6.6")}}}
}

// SSLcsMOLROperation binds the formal object in TS 24.080 V19.4.0 §4.2 (X.880 §§8.2–8.3).
func SSLcsMOLROperation() SSOperation[LCSMOLRArg, LCSMOLRRes, SSLcsMOLRErrors] {
	return SSOperation[LCSMOLRArg, LCSMOLRRes, SSLcsMOLRErrors]{operationBinding[LCSMOLRArg, LCSMOLRRes, SSLcsMOLRErrors, SSOperationInfo, SSOperationCode, SSErrorEncoding]{code: SSLcsMOLR, info: infoSSLcsMOLROperation, argument: LCSMOLRArgCodec(), result: LCSMOLRResCodec(), decode: decodeSSLcsMOLRError, encode: encodeSSLcsMOLRError}}
}
func decodeSSLcsMOLRError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (SSLcsMOLRErrors, error) {
	switch code {
	case 34:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam](__asn1pkg_v21_map_er_datatypes.ERSystemFailureParamCodec()), opts...)
		if err != nil {
			return SSLcsMOLRErrors{}, err
		}
		return SSLcsMOLRErrors{SystemFailure: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParam](__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParamCodec()), opts...)
		if err != nil {
			return SSLcsMOLRErrors{}, err
		}
		return SSLcsMOLRErrors{UnexpectedDataValue: p}, nil
	case 35:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERDataMissingParam](__asn1pkg_v21_map_er_datatypes.ERDataMissingParamCodec()), opts...)
		if err != nil {
			return SSLcsMOLRErrors{}, err
		}
		return SSLcsMOLRErrors{DataMissing: p}, nil
	case 21:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParam](__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParamCodec()), opts...)
		if err != nil {
			return SSLcsMOLRErrors{}, err
		}
		return SSLcsMOLRErrors{FacilityNotSupported: p}, nil
	case 19:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSSSubscriptionViolationParam](__asn1pkg_v21_map_er_datatypes.ERSSSubscriptionViolationParamCodec()), opts...)
		if err != nil {
			return SSLcsMOLRErrors{}, err
		}
		return SSLcsMOLRErrors{SsSubscriptionViolation: p}, nil
	case 54:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERPositionMethodFailureParam](__asn1pkg_v21_map_er_datatypes.ERPositionMethodFailureParamCodec()), opts...)
		if err != nil {
			return SSLcsMOLRErrors{}, err
		}
		return SSLcsMOLRErrors{PositionMethodFailure: p}, nil
	default:
		return SSLcsMOLRErrors{}, fmt.Errorf("%w: error code %d is not in lcs-MOLR ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeSSLcsMOLRError(value SSLcsMOLRErrors, opts ...ber.EncodeOption) (SSErrorEncoding, error) {
	selected := 0
	if value.SystemFailure != nil {
		selected++
	}
	if value.UnexpectedDataValue != nil {
		selected++
	}
	if value.DataMissing != nil {
		selected++
	}
	if value.FacilityNotSupported != nil {
		selected++
	}
	if value.SsSubscriptionViolation != nil {
		selected++
	}
	if value.PositionMethodFailure != nil {
		selected++
	}
	if selected != 1 {
		return SSErrorEncoding{}, fmt.Errorf("%w: exactly one lcs-MOLR error arm is required", ber.ErrInvalidBinding)
	}
	if value.SystemFailure != nil {
		return encodeSSErrorMember(34, sourceInfo10("systemFailure", "17.6.6"), value.SystemFailure, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam](__asn1pkg_v21_map_er_datatypes.ERSystemFailureParamCodec()), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeSSErrorMember(36, sourceInfo10("unexpectedDataValue", "17.6.6"), value.UnexpectedDataValue, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParam](__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParamCodec()), opts...)
	}
	if value.DataMissing != nil {
		return encodeSSErrorMember(35, sourceInfo10("dataMissing", "17.6.6"), value.DataMissing, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERDataMissingParam](__asn1pkg_v21_map_er_datatypes.ERDataMissingParamCodec()), opts...)
	}
	if value.FacilityNotSupported != nil {
		return encodeSSErrorMember(21, sourceInfo10("facilityNotSupported", "17.6.6"), value.FacilityNotSupported, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParam](__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParamCodec()), opts...)
	}
	if value.SsSubscriptionViolation != nil {
		return encodeSSErrorMember(19, sourceInfo10("ss-SubscriptionViolation", "17.6.6"), value.SsSubscriptionViolation, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSSSubscriptionViolationParam](__asn1pkg_v21_map_er_datatypes.ERSSSubscriptionViolationParamCodec()), opts...)
	}
	if value.PositionMethodFailure != nil {
		return encodeSSErrorMember(54, sourceInfo10("positionMethodFailure", "17.6.6"), value.PositionMethodFailure, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERPositionMethodFailureParam](__asn1pkg_v21_map_er_datatypes.ERPositionMethodFailureParamCodec()), opts...)
	}
	return SSErrorEncoding{}, fmt.Errorf("%w: no selected lcs-MOLR error", ber.ErrInvalidBinding)
}

// SSLcsMSCancelDeferredLocationErrors selects exactly the formal ERRORS set of SS-Operations.lcs-MSCancelDeferredLocation.
type SSLcsMSCancelDeferredLocationErrors struct {
	SystemFailure       *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam]
	UnexpectedDataValue *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParam]
}

func infoSSLcsMSCancelDeferredLocationOperation() SSOperationInfo {
	return SSOperationInfo{Name: "lcs-MSCancelDeferredLocation", Code: SSLcsMSCancelDeferredLocation, Argument: &TypeRef{ModuleOID: "0.4.0.0.2.3.2.18", ASN1Name: "LCS-CancelDeferredLocationArg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "LCSCancelDeferredLocationArg"}, Result: nil, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: true, Source: sourceInfo9("lcs-MSCancelDeferredLocation", "4.2"), Errors: []SSErrorMemberInfo{SSErrorMemberInfo{Name: "systemFailure", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 34, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "SystemFailureParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERSystemFailureParam"}, Source: sourceInfo10("systemFailure", "17.6.6")}, SSErrorMemberInfo{Name: "unexpectedDataValue", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 36, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "UnexpectedDataParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERUnexpectedDataParam"}, Source: sourceInfo10("unexpectedDataValue", "17.6.6")}}}
}

// SSLcsMSCancelDeferredLocationOperation binds the formal object in TS 24.080 V19.4.0 §4.2 (X.880 §§8.2–8.3).
func SSLcsMSCancelDeferredLocationOperation() SSOperation[LCSCancelDeferredLocationArg, NoParameter, SSLcsMSCancelDeferredLocationErrors] {
	return SSOperation[LCSCancelDeferredLocationArg, NoParameter, SSLcsMSCancelDeferredLocationErrors]{operationBinding[LCSCancelDeferredLocationArg, NoParameter, SSLcsMSCancelDeferredLocationErrors, SSOperationInfo, SSOperationCode, SSErrorEncoding]{code: SSLcsMSCancelDeferredLocation, info: infoSSLcsMSCancelDeferredLocationOperation, argument: LCSCancelDeferredLocationArgCodec(), result: ValueCodec[NoParameter]{}, decode: decodeSSLcsMSCancelDeferredLocationError, encode: encodeSSLcsMSCancelDeferredLocationError}}
}
func decodeSSLcsMSCancelDeferredLocationError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (SSLcsMSCancelDeferredLocationErrors, error) {
	switch code {
	case 34:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam](__asn1pkg_v21_map_er_datatypes.ERSystemFailureParamCodec()), opts...)
		if err != nil {
			return SSLcsMSCancelDeferredLocationErrors{}, err
		}
		return SSLcsMSCancelDeferredLocationErrors{SystemFailure: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParam](__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParamCodec()), opts...)
		if err != nil {
			return SSLcsMSCancelDeferredLocationErrors{}, err
		}
		return SSLcsMSCancelDeferredLocationErrors{UnexpectedDataValue: p}, nil
	default:
		return SSLcsMSCancelDeferredLocationErrors{}, fmt.Errorf("%w: error code %d is not in lcs-MSCancelDeferredLocation ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeSSLcsMSCancelDeferredLocationError(value SSLcsMSCancelDeferredLocationErrors, opts ...ber.EncodeOption) (SSErrorEncoding, error) {
	selected := 0
	if value.SystemFailure != nil {
		selected++
	}
	if value.UnexpectedDataValue != nil {
		selected++
	}
	if selected != 1 {
		return SSErrorEncoding{}, fmt.Errorf("%w: exactly one lcs-MSCancelDeferredLocation error arm is required", ber.ErrInvalidBinding)
	}
	if value.SystemFailure != nil {
		return encodeSSErrorMember(34, sourceInfo10("systemFailure", "17.6.6"), value.SystemFailure, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam](__asn1pkg_v21_map_er_datatypes.ERSystemFailureParamCodec()), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeSSErrorMember(36, sourceInfo10("unexpectedDataValue", "17.6.6"), value.UnexpectedDataValue, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParam](__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParamCodec()), opts...)
	}
	return SSErrorEncoding{}, fmt.Errorf("%w: no selected lcs-MSCancelDeferredLocation error", ber.ErrInvalidBinding)
}

// SSLcsPeriodicLocationCancellationErrors selects exactly the formal ERRORS set of SS-Operations.lcs-PeriodicLocationCancellation.
type SSLcsPeriodicLocationCancellationErrors struct {
	SystemFailure       *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam]
	UnexpectedDataValue *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParam]
}

func infoSSLcsPeriodicLocationCancellationOperation() SSOperationInfo {
	return SSOperationInfo{Name: "lcs-PeriodicLocationCancellation", Code: SSLcsPeriodicLocationCancellation, Argument: &TypeRef{ModuleOID: "0.4.0.0.2.3.2.18", ASN1Name: "LCS-PeriodicLocationCancellationArg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "LCSPeriodicLocationCancellationArg"}, Result: nil, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: true, Source: sourceInfo9("lcs-PeriodicLocationCancellation", "4.2"), Errors: []SSErrorMemberInfo{SSErrorMemberInfo{Name: "systemFailure", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 34, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "SystemFailureParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERSystemFailureParam"}, Source: sourceInfo10("systemFailure", "17.6.6")}, SSErrorMemberInfo{Name: "unexpectedDataValue", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 36, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "UnexpectedDataParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERUnexpectedDataParam"}, Source: sourceInfo10("unexpectedDataValue", "17.6.6")}}}
}

// SSLcsPeriodicLocationCancellationOperation binds the formal object in TS 24.080 V19.4.0 §4.2 (X.880 §§8.2–8.3).
func SSLcsPeriodicLocationCancellationOperation() SSOperation[LCSPeriodicLocationCancellationArg, NoParameter, SSLcsPeriodicLocationCancellationErrors] {
	return SSOperation[LCSPeriodicLocationCancellationArg, NoParameter, SSLcsPeriodicLocationCancellationErrors]{operationBinding[LCSPeriodicLocationCancellationArg, NoParameter, SSLcsPeriodicLocationCancellationErrors, SSOperationInfo, SSOperationCode, SSErrorEncoding]{code: SSLcsPeriodicLocationCancellation, info: infoSSLcsPeriodicLocationCancellationOperation, argument: LCSPeriodicLocationCancellationArgCodec(), result: ValueCodec[NoParameter]{}, decode: decodeSSLcsPeriodicLocationCancellationError, encode: encodeSSLcsPeriodicLocationCancellationError}}
}
func decodeSSLcsPeriodicLocationCancellationError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (SSLcsPeriodicLocationCancellationErrors, error) {
	switch code {
	case 34:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam](__asn1pkg_v21_map_er_datatypes.ERSystemFailureParamCodec()), opts...)
		if err != nil {
			return SSLcsPeriodicLocationCancellationErrors{}, err
		}
		return SSLcsPeriodicLocationCancellationErrors{SystemFailure: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParam](__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParamCodec()), opts...)
		if err != nil {
			return SSLcsPeriodicLocationCancellationErrors{}, err
		}
		return SSLcsPeriodicLocationCancellationErrors{UnexpectedDataValue: p}, nil
	default:
		return SSLcsPeriodicLocationCancellationErrors{}, fmt.Errorf("%w: error code %d is not in lcs-PeriodicLocationCancellation ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeSSLcsPeriodicLocationCancellationError(value SSLcsPeriodicLocationCancellationErrors, opts ...ber.EncodeOption) (SSErrorEncoding, error) {
	selected := 0
	if value.SystemFailure != nil {
		selected++
	}
	if value.UnexpectedDataValue != nil {
		selected++
	}
	if selected != 1 {
		return SSErrorEncoding{}, fmt.Errorf("%w: exactly one lcs-PeriodicLocationCancellation error arm is required", ber.ErrInvalidBinding)
	}
	if value.SystemFailure != nil {
		return encodeSSErrorMember(34, sourceInfo10("systemFailure", "17.6.6"), value.SystemFailure, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam](__asn1pkg_v21_map_er_datatypes.ERSystemFailureParamCodec()), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeSSErrorMember(36, sourceInfo10("unexpectedDataValue", "17.6.6"), value.UnexpectedDataValue, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParam](__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParamCodec()), opts...)
	}
	return SSErrorEncoding{}, fmt.Errorf("%w: no selected lcs-PeriodicLocationCancellation error", ber.ErrInvalidBinding)
}

// SSLcsPeriodicLocationRequestErrors selects exactly the formal ERRORS set of SS-Operations.lcs-PeriodicLocationRequest.
type SSLcsPeriodicLocationRequestErrors struct {
	SystemFailure        *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam]
	FacilityNotSupported *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParam]
	UnexpectedDataValue  *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParam]
	DataMissing          *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERDataMissingParam]
}

func infoSSLcsPeriodicLocationRequestOperation() SSOperationInfo {
	return SSOperationInfo{Name: "lcs-PeriodicLocationRequest", Code: SSLcsPeriodicLocationRequest, Argument: &TypeRef{ModuleOID: "0.4.0.0.2.3.2.18", ASN1Name: "LCS-PeriodicLocationRequestArg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "LCSPeriodicLocationRequestArg"}, Result: &TypeRef{ModuleOID: "0.4.0.0.2.3.2.18", ASN1Name: "LCS-PeriodicLocationRequestRes", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "LCSPeriodicLocationRequestRes"}, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: false, Source: sourceInfo9("lcs-PeriodicLocationRequest", "4.2"), Errors: []SSErrorMemberInfo{SSErrorMemberInfo{Name: "systemFailure", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 34, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "SystemFailureParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERSystemFailureParam"}, Source: sourceInfo10("systemFailure", "17.6.6")}, SSErrorMemberInfo{Name: "facilityNotSupported", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 21, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "FacilityNotSupParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERFacilityNotSupParam"}, Source: sourceInfo10("facilityNotSupported", "17.6.6")}, SSErrorMemberInfo{Name: "unexpectedDataValue", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 36, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "UnexpectedDataParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERUnexpectedDataParam"}, Source: sourceInfo10("unexpectedDataValue", "17.6.6")}, SSErrorMemberInfo{Name: "dataMissing", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 35, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "DataMissingParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERDataMissingParam"}, Source: sourceInfo10("dataMissing", "17.6.6")}}}
}

// SSLcsPeriodicLocationRequestOperation binds the formal object in TS 24.080 V19.4.0 §4.2 (X.880 §§8.2–8.3).
func SSLcsPeriodicLocationRequestOperation() SSOperation[LCSPeriodicLocationRequestArg, LCSPeriodicLocationRequestRes, SSLcsPeriodicLocationRequestErrors] {
	return SSOperation[LCSPeriodicLocationRequestArg, LCSPeriodicLocationRequestRes, SSLcsPeriodicLocationRequestErrors]{operationBinding[LCSPeriodicLocationRequestArg, LCSPeriodicLocationRequestRes, SSLcsPeriodicLocationRequestErrors, SSOperationInfo, SSOperationCode, SSErrorEncoding]{code: SSLcsPeriodicLocationRequest, info: infoSSLcsPeriodicLocationRequestOperation, argument: LCSPeriodicLocationRequestArgCodec(), result: LCSPeriodicLocationRequestResCodec(), decode: decodeSSLcsPeriodicLocationRequestError, encode: encodeSSLcsPeriodicLocationRequestError}}
}
func decodeSSLcsPeriodicLocationRequestError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (SSLcsPeriodicLocationRequestErrors, error) {
	switch code {
	case 34:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam](__asn1pkg_v21_map_er_datatypes.ERSystemFailureParamCodec()), opts...)
		if err != nil {
			return SSLcsPeriodicLocationRequestErrors{}, err
		}
		return SSLcsPeriodicLocationRequestErrors{SystemFailure: p}, nil
	case 21:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParam](__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParamCodec()), opts...)
		if err != nil {
			return SSLcsPeriodicLocationRequestErrors{}, err
		}
		return SSLcsPeriodicLocationRequestErrors{FacilityNotSupported: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParam](__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParamCodec()), opts...)
		if err != nil {
			return SSLcsPeriodicLocationRequestErrors{}, err
		}
		return SSLcsPeriodicLocationRequestErrors{UnexpectedDataValue: p}, nil
	case 35:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERDataMissingParam](__asn1pkg_v21_map_er_datatypes.ERDataMissingParamCodec()), opts...)
		if err != nil {
			return SSLcsPeriodicLocationRequestErrors{}, err
		}
		return SSLcsPeriodicLocationRequestErrors{DataMissing: p}, nil
	default:
		return SSLcsPeriodicLocationRequestErrors{}, fmt.Errorf("%w: error code %d is not in lcs-PeriodicLocationRequest ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeSSLcsPeriodicLocationRequestError(value SSLcsPeriodicLocationRequestErrors, opts ...ber.EncodeOption) (SSErrorEncoding, error) {
	selected := 0
	if value.SystemFailure != nil {
		selected++
	}
	if value.FacilityNotSupported != nil {
		selected++
	}
	if value.UnexpectedDataValue != nil {
		selected++
	}
	if value.DataMissing != nil {
		selected++
	}
	if selected != 1 {
		return SSErrorEncoding{}, fmt.Errorf("%w: exactly one lcs-PeriodicLocationRequest error arm is required", ber.ErrInvalidBinding)
	}
	if value.SystemFailure != nil {
		return encodeSSErrorMember(34, sourceInfo10("systemFailure", "17.6.6"), value.SystemFailure, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam](__asn1pkg_v21_map_er_datatypes.ERSystemFailureParamCodec()), opts...)
	}
	if value.FacilityNotSupported != nil {
		return encodeSSErrorMember(21, sourceInfo10("facilityNotSupported", "17.6.6"), value.FacilityNotSupported, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParam](__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParamCodec()), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeSSErrorMember(36, sourceInfo10("unexpectedDataValue", "17.6.6"), value.UnexpectedDataValue, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParam](__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParamCodec()), opts...)
	}
	if value.DataMissing != nil {
		return encodeSSErrorMember(35, sourceInfo10("dataMissing", "17.6.6"), value.DataMissing, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERDataMissingParam](__asn1pkg_v21_map_er_datatypes.ERDataMissingParamCodec()), opts...)
	}
	return SSErrorEncoding{}, fmt.Errorf("%w: no selected lcs-PeriodicLocationRequest error", ber.ErrInvalidBinding)
}

// SSLcsPeriodicTriggeredInvokeErrors selects exactly the formal ERRORS set of SS-Operations.lcs-PeriodicTriggeredInvoke.
type SSLcsPeriodicTriggeredInvokeErrors struct {
	SystemFailure        *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam]
	FacilityNotSupported *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParam]
	UnexpectedDataValue  *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParam]
	DataMissing          *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERDataMissingParam]
	ResourceLimitation   *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERResourceLimitationParam]
}

func infoSSLcsPeriodicTriggeredInvokeOperation() SSOperationInfo {
	return SSOperationInfo{Name: "lcs-PeriodicTriggeredInvoke", Code: SSLcsPeriodicTriggeredInvoke, Argument: &TypeRef{ModuleOID: "0.4.0.0.2.3.2.18", ASN1Name: "LCS-PeriodicTriggeredInvokeArg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "LCSPeriodicTriggeredInvokeArg"}, Result: &TypeRef{ModuleOID: "0.4.0.0.2.3.2.18", ASN1Name: "LCS-PeriodicTriggeredInvokeRes", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "LCSPeriodicTriggeredInvokeRes"}, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: false, Source: sourceInfo9("lcs-PeriodicTriggeredInvoke", "4.2"), Errors: []SSErrorMemberInfo{SSErrorMemberInfo{Name: "systemFailure", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 34, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "SystemFailureParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERSystemFailureParam"}, Source: sourceInfo10("systemFailure", "17.6.6")}, SSErrorMemberInfo{Name: "facilityNotSupported", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 21, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "FacilityNotSupParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERFacilityNotSupParam"}, Source: sourceInfo10("facilityNotSupported", "17.6.6")}, SSErrorMemberInfo{Name: "unexpectedDataValue", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 36, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "UnexpectedDataParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERUnexpectedDataParam"}, Source: sourceInfo10("unexpectedDataValue", "17.6.6")}, SSErrorMemberInfo{Name: "dataMissing", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 35, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "DataMissingParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERDataMissingParam"}, Source: sourceInfo10("dataMissing", "17.6.6")}, SSErrorMemberInfo{Name: "resourceLimitation", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 51, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "ResourceLimitationParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERResourceLimitationParam"}, Source: sourceInfo10("resourceLimitation", "17.6.6")}}}
}

// SSLcsPeriodicTriggeredInvokeOperation binds the formal object in TS 24.080 V19.4.0 §4.2 (X.880 §§8.2–8.3).
func SSLcsPeriodicTriggeredInvokeOperation() SSOperation[LCSPeriodicTriggeredInvokeArg, LCSPeriodicTriggeredInvokeRes, SSLcsPeriodicTriggeredInvokeErrors] {
	return SSOperation[LCSPeriodicTriggeredInvokeArg, LCSPeriodicTriggeredInvokeRes, SSLcsPeriodicTriggeredInvokeErrors]{operationBinding[LCSPeriodicTriggeredInvokeArg, LCSPeriodicTriggeredInvokeRes, SSLcsPeriodicTriggeredInvokeErrors, SSOperationInfo, SSOperationCode, SSErrorEncoding]{code: SSLcsPeriodicTriggeredInvoke, info: infoSSLcsPeriodicTriggeredInvokeOperation, argument: LCSPeriodicTriggeredInvokeArgCodec(), result: LCSPeriodicTriggeredInvokeResCodec(), decode: decodeSSLcsPeriodicTriggeredInvokeError, encode: encodeSSLcsPeriodicTriggeredInvokeError}}
}
func decodeSSLcsPeriodicTriggeredInvokeError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (SSLcsPeriodicTriggeredInvokeErrors, error) {
	switch code {
	case 34:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam](__asn1pkg_v21_map_er_datatypes.ERSystemFailureParamCodec()), opts...)
		if err != nil {
			return SSLcsPeriodicTriggeredInvokeErrors{}, err
		}
		return SSLcsPeriodicTriggeredInvokeErrors{SystemFailure: p}, nil
	case 21:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParam](__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParamCodec()), opts...)
		if err != nil {
			return SSLcsPeriodicTriggeredInvokeErrors{}, err
		}
		return SSLcsPeriodicTriggeredInvokeErrors{FacilityNotSupported: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParam](__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParamCodec()), opts...)
		if err != nil {
			return SSLcsPeriodicTriggeredInvokeErrors{}, err
		}
		return SSLcsPeriodicTriggeredInvokeErrors{UnexpectedDataValue: p}, nil
	case 35:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERDataMissingParam](__asn1pkg_v21_map_er_datatypes.ERDataMissingParamCodec()), opts...)
		if err != nil {
			return SSLcsPeriodicTriggeredInvokeErrors{}, err
		}
		return SSLcsPeriodicTriggeredInvokeErrors{DataMissing: p}, nil
	case 51:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERResourceLimitationParam](__asn1pkg_v21_map_er_datatypes.ERResourceLimitationParamCodec()), opts...)
		if err != nil {
			return SSLcsPeriodicTriggeredInvokeErrors{}, err
		}
		return SSLcsPeriodicTriggeredInvokeErrors{ResourceLimitation: p}, nil
	default:
		return SSLcsPeriodicTriggeredInvokeErrors{}, fmt.Errorf("%w: error code %d is not in lcs-PeriodicTriggeredInvoke ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeSSLcsPeriodicTriggeredInvokeError(value SSLcsPeriodicTriggeredInvokeErrors, opts ...ber.EncodeOption) (SSErrorEncoding, error) {
	selected := 0
	if value.SystemFailure != nil {
		selected++
	}
	if value.FacilityNotSupported != nil {
		selected++
	}
	if value.UnexpectedDataValue != nil {
		selected++
	}
	if value.DataMissing != nil {
		selected++
	}
	if value.ResourceLimitation != nil {
		selected++
	}
	if selected != 1 {
		return SSErrorEncoding{}, fmt.Errorf("%w: exactly one lcs-PeriodicTriggeredInvoke error arm is required", ber.ErrInvalidBinding)
	}
	if value.SystemFailure != nil {
		return encodeSSErrorMember(34, sourceInfo10("systemFailure", "17.6.6"), value.SystemFailure, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam](__asn1pkg_v21_map_er_datatypes.ERSystemFailureParamCodec()), opts...)
	}
	if value.FacilityNotSupported != nil {
		return encodeSSErrorMember(21, sourceInfo10("facilityNotSupported", "17.6.6"), value.FacilityNotSupported, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParam](__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParamCodec()), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeSSErrorMember(36, sourceInfo10("unexpectedDataValue", "17.6.6"), value.UnexpectedDataValue, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParam](__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParamCodec()), opts...)
	}
	if value.DataMissing != nil {
		return encodeSSErrorMember(35, sourceInfo10("dataMissing", "17.6.6"), value.DataMissing, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERDataMissingParam](__asn1pkg_v21_map_er_datatypes.ERDataMissingParamCodec()), opts...)
	}
	if value.ResourceLimitation != nil {
		return encodeSSErrorMember(51, sourceInfo10("resourceLimitation", "17.6.6"), value.ResourceLimitation, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERResourceLimitationParam](__asn1pkg_v21_map_er_datatypes.ERResourceLimitationParamCodec()), opts...)
	}
	return SSErrorEncoding{}, fmt.Errorf("%w: no selected lcs-PeriodicTriggeredInvoke error", ber.ErrInvalidBinding)
}

// SSLcsPruAssociationErrors selects exactly the formal ERRORS set of SS-Operations.lcs-PruAssociation.
type SSLcsPruAssociationErrors struct {
	LcsInvalidPru        *ErrorValue[NoParameter]
	LcsPruAssociationRej *ErrorValue[PruAssociationRejParam]
	SystemFailure        *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam]
	UnexpectedDataValue  *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParam]
}

func infoSSLcsPruAssociationOperation() SSOperationInfo {
	return SSOperationInfo{Name: "lcs-PruAssociation", Code: SSLcsPruAssociation, Argument: &TypeRef{ModuleOID: "0.4.0.0.2.3.2.18", ASN1Name: "LCS-PruAssociationArg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "LCSPruAssociationArg"}, Result: &TypeRef{ModuleOID: "0.4.0.0.2.3.2.18", ASN1Name: "LCS-PruAssociationRes", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "LCSPruAssociationRes"}, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: false, Source: sourceInfo9("lcs-PruAssociation", "4.2"), Errors: []SSErrorMemberInfo{SSErrorMemberInfo{Name: "lcs-invalidPru", DeclaringModuleOID: "{#0/#4/#0/#0/#2/#3/#1/#18}", LocalCode: 120, Parameter: nil, Source: sourceInfo8("lcs-invalidPru", "4.3")}, SSErrorMemberInfo{Name: "lcs-PruAssociationRej", DeclaringModuleOID: "{#0/#4/#0/#0/#2/#3/#1/#18}", LocalCode: 119, Parameter: &TypeRef{ModuleOID: "0.4.0.0.2.3.1.18", ASN1Name: "PruAssociationRejParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "PruAssociationRejParam"}, Source: sourceInfo8("lcs-PruAssociationRej", "4.3")}, SSErrorMemberInfo{Name: "systemFailure", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 34, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "SystemFailureParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERSystemFailureParam"}, Source: sourceInfo10("systemFailure", "17.6.6")}, SSErrorMemberInfo{Name: "unexpectedDataValue", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 36, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "UnexpectedDataParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERUnexpectedDataParam"}, Source: sourceInfo10("unexpectedDataValue", "17.6.6")}}}
}

// SSLcsPruAssociationOperation binds the formal object in TS 24.080 V19.4.0 §4.2 (X.880 §§8.2–8.3).
func SSLcsPruAssociationOperation() SSOperation[LCSPruAssociationArg, LCSPruAssociationRes, SSLcsPruAssociationErrors] {
	return SSOperation[LCSPruAssociationArg, LCSPruAssociationRes, SSLcsPruAssociationErrors]{operationBinding[LCSPruAssociationArg, LCSPruAssociationRes, SSLcsPruAssociationErrors, SSOperationInfo, SSOperationCode, SSErrorEncoding]{code: SSLcsPruAssociation, info: infoSSLcsPruAssociationOperation, argument: LCSPruAssociationArgCodec(), result: LCSPruAssociationResCodec(), decode: decodeSSLcsPruAssociationError, encode: encodeSSLcsPruAssociationError}}
}
func decodeSSLcsPruAssociationError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (SSLcsPruAssociationErrors, error) {
	switch code {
	case 120:
		p, err := decodeErrorParameter(data, present, ValueCodec[NoParameter]{}, opts...)
		if err != nil {
			return SSLcsPruAssociationErrors{}, err
		}
		return SSLcsPruAssociationErrors{LcsInvalidPru: p}, nil
	case 119:
		p, err := decodeErrorParameter(data, present, PruAssociationRejParamCodec(), opts...)
		if err != nil {
			return SSLcsPruAssociationErrors{}, err
		}
		return SSLcsPruAssociationErrors{LcsPruAssociationRej: p}, nil
	case 34:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam](__asn1pkg_v21_map_er_datatypes.ERSystemFailureParamCodec()), opts...)
		if err != nil {
			return SSLcsPruAssociationErrors{}, err
		}
		return SSLcsPruAssociationErrors{SystemFailure: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParam](__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParamCodec()), opts...)
		if err != nil {
			return SSLcsPruAssociationErrors{}, err
		}
		return SSLcsPruAssociationErrors{UnexpectedDataValue: p}, nil
	default:
		return SSLcsPruAssociationErrors{}, fmt.Errorf("%w: error code %d is not in lcs-PruAssociation ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeSSLcsPruAssociationError(value SSLcsPruAssociationErrors, opts ...ber.EncodeOption) (SSErrorEncoding, error) {
	selected := 0
	if value.LcsInvalidPru != nil {
		selected++
	}
	if value.LcsPruAssociationRej != nil {
		selected++
	}
	if value.SystemFailure != nil {
		selected++
	}
	if value.UnexpectedDataValue != nil {
		selected++
	}
	if selected != 1 {
		return SSErrorEncoding{}, fmt.Errorf("%w: exactly one lcs-PruAssociation error arm is required", ber.ErrInvalidBinding)
	}
	if value.LcsInvalidPru != nil {
		return encodeSSErrorMember(120, sourceInfo8("lcs-invalidPru", "4.3"), value.LcsInvalidPru, ValueCodec[NoParameter]{}, opts...)
	}
	if value.LcsPruAssociationRej != nil {
		return encodeSSErrorMember(119, sourceInfo8("lcs-PruAssociationRej", "4.3"), value.LcsPruAssociationRej, PruAssociationRejParamCodec(), opts...)
	}
	if value.SystemFailure != nil {
		return encodeSSErrorMember(34, sourceInfo10("systemFailure", "17.6.6"), value.SystemFailure, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam](__asn1pkg_v21_map_er_datatypes.ERSystemFailureParamCodec()), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeSSErrorMember(36, sourceInfo10("unexpectedDataValue", "17.6.6"), value.UnexpectedDataValue, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParam](__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParamCodec()), opts...)
	}
	return SSErrorEncoding{}, fmt.Errorf("%w: no selected lcs-PruAssociation error", ber.ErrInvalidBinding)
}

// SSLcsPruDisassociationErrors selects exactly the formal ERRORS set of SS-Operations.lcs-PruDisassociation.
type SSLcsPruDisassociationErrors struct {
	SystemFailure       *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam]
	UnexpectedDataValue *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParam]
}

func infoSSLcsPruDisassociationOperation() SSOperationInfo {
	return SSOperationInfo{Name: "lcs-PruDisassociation", Code: SSLcsPruDisassociation, Argument: &TypeRef{ModuleOID: "0.4.0.0.2.3.2.18", ASN1Name: "LCS-PruDisassociationArg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "LCSPruDisassociationArg"}, Result: nil, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: true, Source: sourceInfo9("lcs-PruDisassociation", "4.2"), Errors: []SSErrorMemberInfo{SSErrorMemberInfo{Name: "systemFailure", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 34, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "SystemFailureParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERSystemFailureParam"}, Source: sourceInfo10("systemFailure", "17.6.6")}, SSErrorMemberInfo{Name: "unexpectedDataValue", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 36, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "UnexpectedDataParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERUnexpectedDataParam"}, Source: sourceInfo10("unexpectedDataValue", "17.6.6")}}}
}

// SSLcsPruDisassociationOperation binds the formal object in TS 24.080 V19.4.0 §4.2 (X.880 §§8.2–8.3).
func SSLcsPruDisassociationOperation() SSOperation[LCSPruDisassociationArg, NoParameter, SSLcsPruDisassociationErrors] {
	return SSOperation[LCSPruDisassociationArg, NoParameter, SSLcsPruDisassociationErrors]{operationBinding[LCSPruDisassociationArg, NoParameter, SSLcsPruDisassociationErrors, SSOperationInfo, SSOperationCode, SSErrorEncoding]{code: SSLcsPruDisassociation, info: infoSSLcsPruDisassociationOperation, argument: LCSPruDisassociationArgCodec(), result: ValueCodec[NoParameter]{}, decode: decodeSSLcsPruDisassociationError, encode: encodeSSLcsPruDisassociationError}}
}
func decodeSSLcsPruDisassociationError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (SSLcsPruDisassociationErrors, error) {
	switch code {
	case 34:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam](__asn1pkg_v21_map_er_datatypes.ERSystemFailureParamCodec()), opts...)
		if err != nil {
			return SSLcsPruDisassociationErrors{}, err
		}
		return SSLcsPruDisassociationErrors{SystemFailure: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParam](__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParamCodec()), opts...)
		if err != nil {
			return SSLcsPruDisassociationErrors{}, err
		}
		return SSLcsPruDisassociationErrors{UnexpectedDataValue: p}, nil
	default:
		return SSLcsPruDisassociationErrors{}, fmt.Errorf("%w: error code %d is not in lcs-PruDisassociation ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeSSLcsPruDisassociationError(value SSLcsPruDisassociationErrors, opts ...ber.EncodeOption) (SSErrorEncoding, error) {
	selected := 0
	if value.SystemFailure != nil {
		selected++
	}
	if value.UnexpectedDataValue != nil {
		selected++
	}
	if selected != 1 {
		return SSErrorEncoding{}, fmt.Errorf("%w: exactly one lcs-PruDisassociation error arm is required", ber.ErrInvalidBinding)
	}
	if value.SystemFailure != nil {
		return encodeSSErrorMember(34, sourceInfo10("systemFailure", "17.6.6"), value.SystemFailure, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam](__asn1pkg_v21_map_er_datatypes.ERSystemFailureParamCodec()), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeSSErrorMember(36, sourceInfo10("unexpectedDataValue", "17.6.6"), value.UnexpectedDataValue, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParam](__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParamCodec()), opts...)
	}
	return SSErrorEncoding{}, fmt.Errorf("%w: no selected lcs-PruDisassociation error", ber.ErrInvalidBinding)
}

// SSLcsSLMOLRErrors selects exactly the formal ERRORS set of SS-Operations.lcs-SLMOLR.
type SSLcsSLMOLRErrors struct {
	SystemFailure           *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam]
	UnexpectedDataValue     *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParam]
	DataMissing             *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERDataMissingParam]
	FacilityNotSupported    *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParam]
	SsSubscriptionViolation *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERSSSubscriptionViolationParam]
	PositionMethodFailure   *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERPositionMethodFailureParam]
}

func infoSSLcsSLMOLROperation() SSOperationInfo {
	return SSOperationInfo{Name: "lcs-SLMOLR", Code: SSLcsSLMOLR, Argument: &TypeRef{ModuleOID: "0.4.0.0.2.3.2.18", ASN1Name: "LCS-SLMOLRArg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "LCSSLMOLRArg"}, Result: &TypeRef{ModuleOID: "0.4.0.0.2.3.2.18", ASN1Name: "LCS-SLMOLRRes", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "LCSSLMOLRRes"}, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: false, Source: sourceInfo9("lcs-SLMOLR", "4.2"), Errors: []SSErrorMemberInfo{SSErrorMemberInfo{Name: "systemFailure", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 34, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "SystemFailureParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERSystemFailureParam"}, Source: sourceInfo10("systemFailure", "17.6.6")}, SSErrorMemberInfo{Name: "unexpectedDataValue", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 36, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "UnexpectedDataParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERUnexpectedDataParam"}, Source: sourceInfo10("unexpectedDataValue", "17.6.6")}, SSErrorMemberInfo{Name: "dataMissing", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 35, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "DataMissingParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERDataMissingParam"}, Source: sourceInfo10("dataMissing", "17.6.6")}, SSErrorMemberInfo{Name: "facilityNotSupported", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 21, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "FacilityNotSupParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERFacilityNotSupParam"}, Source: sourceInfo10("facilityNotSupported", "17.6.6")}, SSErrorMemberInfo{Name: "ss-SubscriptionViolation", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 19, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "SS-SubscriptionViolationParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERSSSubscriptionViolationParam"}, Source: sourceInfo10("ss-SubscriptionViolation", "17.6.6")}, SSErrorMemberInfo{Name: "positionMethodFailure", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 54, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "PositionMethodFailure-Param", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERPositionMethodFailureParam"}, Source: sourceInfo10("positionMethodFailure", "17.6.6")}}}
}

// SSLcsSLMOLROperation binds the formal object in TS 24.080 V19.4.0 §4.2 (X.880 §§8.2–8.3).
func SSLcsSLMOLROperation() SSOperation[LCSSLMOLRArg, LCSSLMOLRRes, SSLcsSLMOLRErrors] {
	return SSOperation[LCSSLMOLRArg, LCSSLMOLRRes, SSLcsSLMOLRErrors]{operationBinding[LCSSLMOLRArg, LCSSLMOLRRes, SSLcsSLMOLRErrors, SSOperationInfo, SSOperationCode, SSErrorEncoding]{code: SSLcsSLMOLR, info: infoSSLcsSLMOLROperation, argument: LCSSLMOLRArgCodec(), result: LCSSLMOLRResCodec(), decode: decodeSSLcsSLMOLRError, encode: encodeSSLcsSLMOLRError}}
}
func decodeSSLcsSLMOLRError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (SSLcsSLMOLRErrors, error) {
	switch code {
	case 34:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam](__asn1pkg_v21_map_er_datatypes.ERSystemFailureParamCodec()), opts...)
		if err != nil {
			return SSLcsSLMOLRErrors{}, err
		}
		return SSLcsSLMOLRErrors{SystemFailure: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParam](__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParamCodec()), opts...)
		if err != nil {
			return SSLcsSLMOLRErrors{}, err
		}
		return SSLcsSLMOLRErrors{UnexpectedDataValue: p}, nil
	case 35:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERDataMissingParam](__asn1pkg_v21_map_er_datatypes.ERDataMissingParamCodec()), opts...)
		if err != nil {
			return SSLcsSLMOLRErrors{}, err
		}
		return SSLcsSLMOLRErrors{DataMissing: p}, nil
	case 21:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParam](__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParamCodec()), opts...)
		if err != nil {
			return SSLcsSLMOLRErrors{}, err
		}
		return SSLcsSLMOLRErrors{FacilityNotSupported: p}, nil
	case 19:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSSSubscriptionViolationParam](__asn1pkg_v21_map_er_datatypes.ERSSSubscriptionViolationParamCodec()), opts...)
		if err != nil {
			return SSLcsSLMOLRErrors{}, err
		}
		return SSLcsSLMOLRErrors{SsSubscriptionViolation: p}, nil
	case 54:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERPositionMethodFailureParam](__asn1pkg_v21_map_er_datatypes.ERPositionMethodFailureParamCodec()), opts...)
		if err != nil {
			return SSLcsSLMOLRErrors{}, err
		}
		return SSLcsSLMOLRErrors{PositionMethodFailure: p}, nil
	default:
		return SSLcsSLMOLRErrors{}, fmt.Errorf("%w: error code %d is not in lcs-SLMOLR ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeSSLcsSLMOLRError(value SSLcsSLMOLRErrors, opts ...ber.EncodeOption) (SSErrorEncoding, error) {
	selected := 0
	if value.SystemFailure != nil {
		selected++
	}
	if value.UnexpectedDataValue != nil {
		selected++
	}
	if value.DataMissing != nil {
		selected++
	}
	if value.FacilityNotSupported != nil {
		selected++
	}
	if value.SsSubscriptionViolation != nil {
		selected++
	}
	if value.PositionMethodFailure != nil {
		selected++
	}
	if selected != 1 {
		return SSErrorEncoding{}, fmt.Errorf("%w: exactly one lcs-SLMOLR error arm is required", ber.ErrInvalidBinding)
	}
	if value.SystemFailure != nil {
		return encodeSSErrorMember(34, sourceInfo10("systemFailure", "17.6.6"), value.SystemFailure, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam](__asn1pkg_v21_map_er_datatypes.ERSystemFailureParamCodec()), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeSSErrorMember(36, sourceInfo10("unexpectedDataValue", "17.6.6"), value.UnexpectedDataValue, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParam](__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParamCodec()), opts...)
	}
	if value.DataMissing != nil {
		return encodeSSErrorMember(35, sourceInfo10("dataMissing", "17.6.6"), value.DataMissing, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERDataMissingParam](__asn1pkg_v21_map_er_datatypes.ERDataMissingParamCodec()), opts...)
	}
	if value.FacilityNotSupported != nil {
		return encodeSSErrorMember(21, sourceInfo10("facilityNotSupported", "17.6.6"), value.FacilityNotSupported, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParam](__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParamCodec()), opts...)
	}
	if value.SsSubscriptionViolation != nil {
		return encodeSSErrorMember(19, sourceInfo10("ss-SubscriptionViolation", "17.6.6"), value.SsSubscriptionViolation, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSSSubscriptionViolationParam](__asn1pkg_v21_map_er_datatypes.ERSSSubscriptionViolationParamCodec()), opts...)
	}
	if value.PositionMethodFailure != nil {
		return encodeSSErrorMember(54, sourceInfo10("positionMethodFailure", "17.6.6"), value.PositionMethodFailure, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERPositionMethodFailureParam](__asn1pkg_v21_map_er_datatypes.ERPositionMethodFailureParamCodec()), opts...)
	}
	return SSErrorEncoding{}, fmt.Errorf("%w: no selected lcs-SLMOLR error", ber.ErrInvalidBinding)
}

// SSLcsSLMTLRErrors selects exactly the formal ERRORS set of SS-Operations.lcs-SLMTLR.
type SSLcsSLMTLRErrors struct {
	SystemFailure        *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam]
	UnexpectedDataValue  *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParam]
	DataMissing          *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERDataMissingParam]
	FacilityNotSupported *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParam]
}

func infoSSLcsSLMTLROperation() SSOperationInfo {
	return SSOperationInfo{Name: "lcs-SLMTLR", Code: SSLcsSLMTLR, Argument: &TypeRef{ModuleOID: "0.4.0.0.2.3.2.18", ASN1Name: "LCS-SLMTLRArg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "LCSSLMTLRArg"}, Result: &TypeRef{ModuleOID: "0.4.0.0.2.3.2.18", ASN1Name: "LCS-SLMTLRRes", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "LCSSLMTLRRes"}, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: false, Source: sourceInfo9("lcs-SLMTLR", "4.2"), Errors: []SSErrorMemberInfo{SSErrorMemberInfo{Name: "systemFailure", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 34, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "SystemFailureParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERSystemFailureParam"}, Source: sourceInfo10("systemFailure", "17.6.6")}, SSErrorMemberInfo{Name: "unexpectedDataValue", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 36, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "UnexpectedDataParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERUnexpectedDataParam"}, Source: sourceInfo10("unexpectedDataValue", "17.6.6")}, SSErrorMemberInfo{Name: "dataMissing", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 35, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "DataMissingParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERDataMissingParam"}, Source: sourceInfo10("dataMissing", "17.6.6")}, SSErrorMemberInfo{Name: "facilityNotSupported", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 21, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "FacilityNotSupParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERFacilityNotSupParam"}, Source: sourceInfo10("facilityNotSupported", "17.6.6")}}}
}

// SSLcsSLMTLROperation binds the formal object in TS 24.080 V19.4.0 §4.2 (X.880 §§8.2–8.3).
func SSLcsSLMTLROperation() SSOperation[LCSSLMTLRArg, LCSSLMTLRRes, SSLcsSLMTLRErrors] {
	return SSOperation[LCSSLMTLRArg, LCSSLMTLRRes, SSLcsSLMTLRErrors]{operationBinding[LCSSLMTLRArg, LCSSLMTLRRes, SSLcsSLMTLRErrors, SSOperationInfo, SSOperationCode, SSErrorEncoding]{code: SSLcsSLMTLR, info: infoSSLcsSLMTLROperation, argument: LCSSLMTLRArgCodec(), result: LCSSLMTLRResCodec(), decode: decodeSSLcsSLMTLRError, encode: encodeSSLcsSLMTLRError}}
}
func decodeSSLcsSLMTLRError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (SSLcsSLMTLRErrors, error) {
	switch code {
	case 34:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam](__asn1pkg_v21_map_er_datatypes.ERSystemFailureParamCodec()), opts...)
		if err != nil {
			return SSLcsSLMTLRErrors{}, err
		}
		return SSLcsSLMTLRErrors{SystemFailure: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParam](__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParamCodec()), opts...)
		if err != nil {
			return SSLcsSLMTLRErrors{}, err
		}
		return SSLcsSLMTLRErrors{UnexpectedDataValue: p}, nil
	case 35:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERDataMissingParam](__asn1pkg_v21_map_er_datatypes.ERDataMissingParamCodec()), opts...)
		if err != nil {
			return SSLcsSLMTLRErrors{}, err
		}
		return SSLcsSLMTLRErrors{DataMissing: p}, nil
	case 21:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParam](__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParamCodec()), opts...)
		if err != nil {
			return SSLcsSLMTLRErrors{}, err
		}
		return SSLcsSLMTLRErrors{FacilityNotSupported: p}, nil
	default:
		return SSLcsSLMTLRErrors{}, fmt.Errorf("%w: error code %d is not in lcs-SLMTLR ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeSSLcsSLMTLRError(value SSLcsSLMTLRErrors, opts ...ber.EncodeOption) (SSErrorEncoding, error) {
	selected := 0
	if value.SystemFailure != nil {
		selected++
	}
	if value.UnexpectedDataValue != nil {
		selected++
	}
	if value.DataMissing != nil {
		selected++
	}
	if value.FacilityNotSupported != nil {
		selected++
	}
	if selected != 1 {
		return SSErrorEncoding{}, fmt.Errorf("%w: exactly one lcs-SLMTLR error arm is required", ber.ErrInvalidBinding)
	}
	if value.SystemFailure != nil {
		return encodeSSErrorMember(34, sourceInfo10("systemFailure", "17.6.6"), value.SystemFailure, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam](__asn1pkg_v21_map_er_datatypes.ERSystemFailureParamCodec()), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeSSErrorMember(36, sourceInfo10("unexpectedDataValue", "17.6.6"), value.UnexpectedDataValue, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParam](__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParamCodec()), opts...)
	}
	if value.DataMissing != nil {
		return encodeSSErrorMember(35, sourceInfo10("dataMissing", "17.6.6"), value.DataMissing, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERDataMissingParam](__asn1pkg_v21_map_er_datatypes.ERDataMissingParamCodec()), opts...)
	}
	if value.FacilityNotSupported != nil {
		return encodeSSErrorMember(21, sourceInfo10("facilityNotSupported", "17.6.6"), value.FacilityNotSupported, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParam](__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParamCodec()), opts...)
	}
	return SSErrorEncoding{}, fmt.Errorf("%w: no selected lcs-SLMTLR error", ber.ErrInvalidBinding)
}

// SSLcsULRSPPTransportErrors selects exactly the formal ERRORS set of SS-Operations.lcs-ULRSPPTransport.
type SSLcsULRSPPTransportErrors struct {
	SystemFailure        *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam]
	FacilityNotSupported *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParam]
}

func infoSSLcsULRSPPTransportOperation() SSOperationInfo {
	return SSOperationInfo{Name: "lcs-ULRSPPTransport", Code: SSLcsULRSPPTransport, Argument: &TypeRef{ModuleOID: "0.4.0.0.2.3.2.18", ASN1Name: "LCS-ULRSPPTransportArg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "LCSULRSPPTransportArg"}, Result: &TypeRef{ModuleOID: "0.4.0.0.2.3.2.18", ASN1Name: "LCS-ULRSPPTransportRes", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "LCSULRSPPTransportRes"}, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: false, Source: sourceInfo9("lcs-ULRSPPTransport", "4.2"), Errors: []SSErrorMemberInfo{SSErrorMemberInfo{Name: "systemFailure", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 34, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "SystemFailureParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERSystemFailureParam"}, Source: sourceInfo10("systemFailure", "17.6.6")}, SSErrorMemberInfo{Name: "facilityNotSupported", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 21, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "FacilityNotSupParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERFacilityNotSupParam"}, Source: sourceInfo10("facilityNotSupported", "17.6.6")}}}
}

// SSLcsULRSPPTransportOperation binds the formal object in TS 24.080 V19.4.0 §4.2 (X.880 §§8.2–8.3).
func SSLcsULRSPPTransportOperation() SSOperation[LCSULRSPPTransportArg, LCSULRSPPTransportRes, SSLcsULRSPPTransportErrors] {
	return SSOperation[LCSULRSPPTransportArg, LCSULRSPPTransportRes, SSLcsULRSPPTransportErrors]{operationBinding[LCSULRSPPTransportArg, LCSULRSPPTransportRes, SSLcsULRSPPTransportErrors, SSOperationInfo, SSOperationCode, SSErrorEncoding]{code: SSLcsULRSPPTransport, info: infoSSLcsULRSPPTransportOperation, argument: LCSULRSPPTransportArgCodec(), result: LCSULRSPPTransportResCodec(), decode: decodeSSLcsULRSPPTransportError, encode: encodeSSLcsULRSPPTransportError}}
}
func decodeSSLcsULRSPPTransportError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (SSLcsULRSPPTransportErrors, error) {
	switch code {
	case 34:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam](__asn1pkg_v21_map_er_datatypes.ERSystemFailureParamCodec()), opts...)
		if err != nil {
			return SSLcsULRSPPTransportErrors{}, err
		}
		return SSLcsULRSPPTransportErrors{SystemFailure: p}, nil
	case 21:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParam](__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParamCodec()), opts...)
		if err != nil {
			return SSLcsULRSPPTransportErrors{}, err
		}
		return SSLcsULRSPPTransportErrors{FacilityNotSupported: p}, nil
	default:
		return SSLcsULRSPPTransportErrors{}, fmt.Errorf("%w: error code %d is not in lcs-ULRSPPTransport ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeSSLcsULRSPPTransportError(value SSLcsULRSPPTransportErrors, opts ...ber.EncodeOption) (SSErrorEncoding, error) {
	selected := 0
	if value.SystemFailure != nil {
		selected++
	}
	if value.FacilityNotSupported != nil {
		selected++
	}
	if selected != 1 {
		return SSErrorEncoding{}, fmt.Errorf("%w: exactly one lcs-ULRSPPTransport error arm is required", ber.ErrInvalidBinding)
	}
	if value.SystemFailure != nil {
		return encodeSSErrorMember(34, sourceInfo10("systemFailure", "17.6.6"), value.SystemFailure, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam](__asn1pkg_v21_map_er_datatypes.ERSystemFailureParamCodec()), opts...)
	}
	if value.FacilityNotSupported != nil {
		return encodeSSErrorMember(21, sourceInfo10("facilityNotSupported", "17.6.6"), value.FacilityNotSupported, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParam](__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParamCodec()), opts...)
	}
	return SSErrorEncoding{}, fmt.Errorf("%w: no selected lcs-ULRSPPTransport error", ber.ErrInvalidBinding)
}

// SSNotifySSErrors selects exactly the formal ERRORS set of SS-Operations.notifySS.
type SSNotifySSErrors struct {
}

func infoSSNotifySSOperation() SSOperationInfo {
	return SSOperationInfo{Name: "notifySS", Code: SSNotifySS, Argument: &TypeRef{ModuleOID: "0.4.0.0.2.3.2.18", ASN1Name: "NotifySS-Arg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "NotifySSArg"}, Result: nil, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: false, Source: sourceInfo9("notifySS", "4.2"), Errors: []SSErrorMemberInfo{}}
}

// SSNotifySSOperation binds the formal object in TS 24.080 V19.4.0 §4.2 (X.880 §§8.2–8.3).
func SSNotifySSOperation() SSOperation[NotifySSArg, NoParameter, SSNotifySSErrors] {
	return SSOperation[NotifySSArg, NoParameter, SSNotifySSErrors]{operationBinding[NotifySSArg, NoParameter, SSNotifySSErrors, SSOperationInfo, SSOperationCode, SSErrorEncoding]{code: SSNotifySS, info: infoSSNotifySSOperation, argument: NotifySSArgCodec(), result: ValueCodec[NoParameter]{}, decode: decodeSSNotifySSError, encode: encodeSSNotifySSError}}
}
func decodeSSNotifySSError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (SSNotifySSErrors, error) {
	switch code {
	default:
		return SSNotifySSErrors{}, fmt.Errorf("%w: error code %d is not in notifySS ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeSSNotifySSError(value SSNotifySSErrors, opts ...ber.EncodeOption) (SSErrorEncoding, error) {
	return SSErrorEncoding{}, fmt.Errorf("%w: no selected notifySS error", ber.ErrInvalidBinding)
}

// SSProcessUnstructuredSSDataErrors selects exactly the formal ERRORS set of SS-Operations.processUnstructuredSS-Data.
type SSProcessUnstructuredSSDataErrors struct {
	SystemFailure       *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam]
	UnexpectedDataValue *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParam]
}

func infoSSProcessUnstructuredSSDataOperation() SSOperationInfo {
	return SSOperationInfo{Name: "processUnstructuredSS-Data", Code: SSProcessUnstructuredSSData, Argument: &TypeRef{ModuleOID: "0.4.0.0.2.3.2.18", ASN1Name: "SS-UserData", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "SSUserData"}, Result: &TypeRef{ModuleOID: "0.4.0.0.2.3.2.18", ASN1Name: "SS-UserData", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "SSUserData"}, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: false, Source: sourceInfo9("processUnstructuredSS-Data", "4.2"), Errors: []SSErrorMemberInfo{SSErrorMemberInfo{Name: "systemFailure", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 34, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "SystemFailureParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERSystemFailureParam"}, Source: sourceInfo10("systemFailure", "17.6.6")}, SSErrorMemberInfo{Name: "unexpectedDataValue", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 36, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "UnexpectedDataParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERUnexpectedDataParam"}, Source: sourceInfo10("unexpectedDataValue", "17.6.6")}}}
}

// SSProcessUnstructuredSSDataOperation binds the formal object in TS 24.080 V19.4.0 §4.2 (X.880 §§8.2–8.3).
func SSProcessUnstructuredSSDataOperation() SSOperation[BERValue[SSUserData], BERValue[SSUserData], SSProcessUnstructuredSSDataErrors] {
	return SSOperation[BERValue[SSUserData], BERValue[SSUserData], SSProcessUnstructuredSSDataErrors]{operationBinding[BERValue[SSUserData], BERValue[SSUserData], SSProcessUnstructuredSSDataErrors, SSOperationInfo, SSOperationCode, SSErrorEncoding]{code: SSProcessUnstructuredSSData, info: infoSSProcessUnstructuredSSDataOperation, argument: SSUserDataCodec(), result: SSUserDataCodec(), decode: decodeSSProcessUnstructuredSSDataError, encode: encodeSSProcessUnstructuredSSDataError}}
}
func decodeSSProcessUnstructuredSSDataError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (SSProcessUnstructuredSSDataErrors, error) {
	switch code {
	case 34:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam](__asn1pkg_v21_map_er_datatypes.ERSystemFailureParamCodec()), opts...)
		if err != nil {
			return SSProcessUnstructuredSSDataErrors{}, err
		}
		return SSProcessUnstructuredSSDataErrors{SystemFailure: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParam](__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParamCodec()), opts...)
		if err != nil {
			return SSProcessUnstructuredSSDataErrors{}, err
		}
		return SSProcessUnstructuredSSDataErrors{UnexpectedDataValue: p}, nil
	default:
		return SSProcessUnstructuredSSDataErrors{}, fmt.Errorf("%w: error code %d is not in processUnstructuredSS-Data ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeSSProcessUnstructuredSSDataError(value SSProcessUnstructuredSSDataErrors, opts ...ber.EncodeOption) (SSErrorEncoding, error) {
	selected := 0
	if value.SystemFailure != nil {
		selected++
	}
	if value.UnexpectedDataValue != nil {
		selected++
	}
	if selected != 1 {
		return SSErrorEncoding{}, fmt.Errorf("%w: exactly one processUnstructuredSS-Data error arm is required", ber.ErrInvalidBinding)
	}
	if value.SystemFailure != nil {
		return encodeSSErrorMember(34, sourceInfo10("systemFailure", "17.6.6"), value.SystemFailure, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam](__asn1pkg_v21_map_er_datatypes.ERSystemFailureParamCodec()), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeSSErrorMember(36, sourceInfo10("unexpectedDataValue", "17.6.6"), value.UnexpectedDataValue, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParam](__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParamCodec()), opts...)
	}
	return SSErrorEncoding{}, fmt.Errorf("%w: no selected processUnstructuredSS-Data error", ber.ErrInvalidBinding)
}

// SSRetrieveMPTYErrors selects exactly the formal ERRORS set of SS-Operations.retrieveMPTY.
type SSRetrieveMPTYErrors struct {
	IllegalSSOperation   *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERIllegalSSOperationParam]
	SsErrorStatus        *ErrorValue[v21_map_ss_datatypes.BERValue[v21_map_ss_datatypes.SSSSStatus]]
	SsIncompatibility    *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERSSIncompatibilityCause]
	FacilityNotSupported *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParam]
	SystemFailure        *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam]
}

func infoSSRetrieveMPTYOperation() SSOperationInfo {
	return SSOperationInfo{Name: "retrieveMPTY", Code: SSRetrieveMPTY, Argument: nil, Result: nil, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: true, Source: sourceInfo9("retrieveMPTY", "4.2"), Errors: []SSErrorMemberInfo{SSErrorMemberInfo{Name: "illegalSS-Operation", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 16, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "IllegalSS-OperationParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERIllegalSSOperationParam"}, Source: sourceInfo10("illegalSS-Operation", "17.6.6")}, SSErrorMemberInfo{Name: "ss-ErrorStatus", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 17, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.14.21", ASN1Name: "SS-Status", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_ss_datatypes", GoName: "SSSSStatus"}, Source: sourceInfo10("ss-ErrorStatus", "17.6.6")}, SSErrorMemberInfo{Name: "ss-Incompatibility", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 20, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "SS-IncompatibilityCause", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERSSIncompatibilityCause"}, Source: sourceInfo10("ss-Incompatibility", "17.6.6")}, SSErrorMemberInfo{Name: "facilityNotSupported", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 21, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "FacilityNotSupParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERFacilityNotSupParam"}, Source: sourceInfo10("facilityNotSupported", "17.6.6")}, SSErrorMemberInfo{Name: "systemFailure", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 34, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "SystemFailureParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERSystemFailureParam"}, Source: sourceInfo10("systemFailure", "17.6.6")}}}
}

// SSRetrieveMPTYOperation binds the formal object in TS 24.080 V19.4.0 §4.2 (X.880 §§8.2–8.3).
func SSRetrieveMPTYOperation() SSOperation[NoParameter, NoParameter, SSRetrieveMPTYErrors] {
	return SSOperation[NoParameter, NoParameter, SSRetrieveMPTYErrors]{operationBinding[NoParameter, NoParameter, SSRetrieveMPTYErrors, SSOperationInfo, SSOperationCode, SSErrorEncoding]{code: SSRetrieveMPTY, info: infoSSRetrieveMPTYOperation, argument: ValueCodec[NoParameter]{}, result: ValueCodec[NoParameter]{}, decode: decodeSSRetrieveMPTYError, encode: encodeSSRetrieveMPTYError}}
}
func decodeSSRetrieveMPTYError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (SSRetrieveMPTYErrors, error) {
	switch code {
	case 16:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERIllegalSSOperationParam](__asn1pkg_v21_map_er_datatypes.ERIllegalSSOperationParamCodec()), opts...)
		if err != nil {
			return SSRetrieveMPTYErrors{}, err
		}
		return SSRetrieveMPTYErrors{IllegalSSOperation: p}, nil
	case 17:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[v21_map_ss_datatypes.BERValue[v21_map_ss_datatypes.SSSSStatus]](v21_map_ss_datatypes.SSSSStatusCodec()), opts...)
		if err != nil {
			return SSRetrieveMPTYErrors{}, err
		}
		return SSRetrieveMPTYErrors{SsErrorStatus: p}, nil
	case 20:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSSIncompatibilityCause](__asn1pkg_v21_map_er_datatypes.ERSSIncompatibilityCauseCodec()), opts...)
		if err != nil {
			return SSRetrieveMPTYErrors{}, err
		}
		return SSRetrieveMPTYErrors{SsIncompatibility: p}, nil
	case 21:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParam](__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParamCodec()), opts...)
		if err != nil {
			return SSRetrieveMPTYErrors{}, err
		}
		return SSRetrieveMPTYErrors{FacilityNotSupported: p}, nil
	case 34:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam](__asn1pkg_v21_map_er_datatypes.ERSystemFailureParamCodec()), opts...)
		if err != nil {
			return SSRetrieveMPTYErrors{}, err
		}
		return SSRetrieveMPTYErrors{SystemFailure: p}, nil
	default:
		return SSRetrieveMPTYErrors{}, fmt.Errorf("%w: error code %d is not in retrieveMPTY ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeSSRetrieveMPTYError(value SSRetrieveMPTYErrors, opts ...ber.EncodeOption) (SSErrorEncoding, error) {
	selected := 0
	if value.IllegalSSOperation != nil {
		selected++
	}
	if value.SsErrorStatus != nil {
		selected++
	}
	if value.SsIncompatibility != nil {
		selected++
	}
	if value.FacilityNotSupported != nil {
		selected++
	}
	if value.SystemFailure != nil {
		selected++
	}
	if selected != 1 {
		return SSErrorEncoding{}, fmt.Errorf("%w: exactly one retrieveMPTY error arm is required", ber.ErrInvalidBinding)
	}
	if value.IllegalSSOperation != nil {
		return encodeSSErrorMember(16, sourceInfo10("illegalSS-Operation", "17.6.6"), value.IllegalSSOperation, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERIllegalSSOperationParam](__asn1pkg_v21_map_er_datatypes.ERIllegalSSOperationParamCodec()), opts...)
	}
	if value.SsErrorStatus != nil {
		return encodeSSErrorMember(17, sourceInfo10("ss-ErrorStatus", "17.6.6"), value.SsErrorStatus, adaptValueCodec[v21_map_ss_datatypes.BERValue[v21_map_ss_datatypes.SSSSStatus]](v21_map_ss_datatypes.SSSSStatusCodec()), opts...)
	}
	if value.SsIncompatibility != nil {
		return encodeSSErrorMember(20, sourceInfo10("ss-Incompatibility", "17.6.6"), value.SsIncompatibility, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSSIncompatibilityCause](__asn1pkg_v21_map_er_datatypes.ERSSIncompatibilityCauseCodec()), opts...)
	}
	if value.FacilityNotSupported != nil {
		return encodeSSErrorMember(21, sourceInfo10("facilityNotSupported", "17.6.6"), value.FacilityNotSupported, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParam](__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParamCodec()), opts...)
	}
	if value.SystemFailure != nil {
		return encodeSSErrorMember(34, sourceInfo10("systemFailure", "17.6.6"), value.SystemFailure, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam](__asn1pkg_v21_map_er_datatypes.ERSystemFailureParamCodec()), opts...)
	}
	return SSErrorEncoding{}, fmt.Errorf("%w: no selected retrieveMPTY error", ber.ErrInvalidBinding)
}

// SSSplitMPTYErrors selects exactly the formal ERRORS set of SS-Operations.splitMPTY.
type SSSplitMPTYErrors struct {
	IllegalSSOperation   *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERIllegalSSOperationParam]
	SsErrorStatus        *ErrorValue[v21_map_ss_datatypes.BERValue[v21_map_ss_datatypes.SSSSStatus]]
	SsIncompatibility    *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERSSIncompatibilityCause]
	FacilityNotSupported *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParam]
	SystemFailure        *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam]
}

func infoSSSplitMPTYOperation() SSOperationInfo {
	return SSOperationInfo{Name: "splitMPTY", Code: SSSplitMPTY, Argument: nil, Result: nil, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: true, Source: sourceInfo9("splitMPTY", "4.2"), Errors: []SSErrorMemberInfo{SSErrorMemberInfo{Name: "illegalSS-Operation", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 16, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "IllegalSS-OperationParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERIllegalSSOperationParam"}, Source: sourceInfo10("illegalSS-Operation", "17.6.6")}, SSErrorMemberInfo{Name: "ss-ErrorStatus", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 17, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.14.21", ASN1Name: "SS-Status", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_ss_datatypes", GoName: "SSSSStatus"}, Source: sourceInfo10("ss-ErrorStatus", "17.6.6")}, SSErrorMemberInfo{Name: "ss-Incompatibility", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 20, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "SS-IncompatibilityCause", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERSSIncompatibilityCause"}, Source: sourceInfo10("ss-Incompatibility", "17.6.6")}, SSErrorMemberInfo{Name: "facilityNotSupported", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 21, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "FacilityNotSupParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERFacilityNotSupParam"}, Source: sourceInfo10("facilityNotSupported", "17.6.6")}, SSErrorMemberInfo{Name: "systemFailure", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 34, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "SystemFailureParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERSystemFailureParam"}, Source: sourceInfo10("systemFailure", "17.6.6")}}}
}

// SSSplitMPTYOperation binds the formal object in TS 24.080 V19.4.0 §4.2 (X.880 §§8.2–8.3).
func SSSplitMPTYOperation() SSOperation[NoParameter, NoParameter, SSSplitMPTYErrors] {
	return SSOperation[NoParameter, NoParameter, SSSplitMPTYErrors]{operationBinding[NoParameter, NoParameter, SSSplitMPTYErrors, SSOperationInfo, SSOperationCode, SSErrorEncoding]{code: SSSplitMPTY, info: infoSSSplitMPTYOperation, argument: ValueCodec[NoParameter]{}, result: ValueCodec[NoParameter]{}, decode: decodeSSSplitMPTYError, encode: encodeSSSplitMPTYError}}
}
func decodeSSSplitMPTYError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (SSSplitMPTYErrors, error) {
	switch code {
	case 16:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERIllegalSSOperationParam](__asn1pkg_v21_map_er_datatypes.ERIllegalSSOperationParamCodec()), opts...)
		if err != nil {
			return SSSplitMPTYErrors{}, err
		}
		return SSSplitMPTYErrors{IllegalSSOperation: p}, nil
	case 17:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[v21_map_ss_datatypes.BERValue[v21_map_ss_datatypes.SSSSStatus]](v21_map_ss_datatypes.SSSSStatusCodec()), opts...)
		if err != nil {
			return SSSplitMPTYErrors{}, err
		}
		return SSSplitMPTYErrors{SsErrorStatus: p}, nil
	case 20:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSSIncompatibilityCause](__asn1pkg_v21_map_er_datatypes.ERSSIncompatibilityCauseCodec()), opts...)
		if err != nil {
			return SSSplitMPTYErrors{}, err
		}
		return SSSplitMPTYErrors{SsIncompatibility: p}, nil
	case 21:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParam](__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParamCodec()), opts...)
		if err != nil {
			return SSSplitMPTYErrors{}, err
		}
		return SSSplitMPTYErrors{FacilityNotSupported: p}, nil
	case 34:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam](__asn1pkg_v21_map_er_datatypes.ERSystemFailureParamCodec()), opts...)
		if err != nil {
			return SSSplitMPTYErrors{}, err
		}
		return SSSplitMPTYErrors{SystemFailure: p}, nil
	default:
		return SSSplitMPTYErrors{}, fmt.Errorf("%w: error code %d is not in splitMPTY ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeSSSplitMPTYError(value SSSplitMPTYErrors, opts ...ber.EncodeOption) (SSErrorEncoding, error) {
	selected := 0
	if value.IllegalSSOperation != nil {
		selected++
	}
	if value.SsErrorStatus != nil {
		selected++
	}
	if value.SsIncompatibility != nil {
		selected++
	}
	if value.FacilityNotSupported != nil {
		selected++
	}
	if value.SystemFailure != nil {
		selected++
	}
	if selected != 1 {
		return SSErrorEncoding{}, fmt.Errorf("%w: exactly one splitMPTY error arm is required", ber.ErrInvalidBinding)
	}
	if value.IllegalSSOperation != nil {
		return encodeSSErrorMember(16, sourceInfo10("illegalSS-Operation", "17.6.6"), value.IllegalSSOperation, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERIllegalSSOperationParam](__asn1pkg_v21_map_er_datatypes.ERIllegalSSOperationParamCodec()), opts...)
	}
	if value.SsErrorStatus != nil {
		return encodeSSErrorMember(17, sourceInfo10("ss-ErrorStatus", "17.6.6"), value.SsErrorStatus, adaptValueCodec[v21_map_ss_datatypes.BERValue[v21_map_ss_datatypes.SSSSStatus]](v21_map_ss_datatypes.SSSSStatusCodec()), opts...)
	}
	if value.SsIncompatibility != nil {
		return encodeSSErrorMember(20, sourceInfo10("ss-Incompatibility", "17.6.6"), value.SsIncompatibility, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSSIncompatibilityCause](__asn1pkg_v21_map_er_datatypes.ERSSIncompatibilityCauseCodec()), opts...)
	}
	if value.FacilityNotSupported != nil {
		return encodeSSErrorMember(21, sourceInfo10("facilityNotSupported", "17.6.6"), value.FacilityNotSupported, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParam](__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParamCodec()), opts...)
	}
	if value.SystemFailure != nil {
		return encodeSSErrorMember(34, sourceInfo10("systemFailure", "17.6.6"), value.SystemFailure, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam](__asn1pkg_v21_map_er_datatypes.ERSystemFailureParamCodec()), opts...)
	}
	return SSErrorEncoding{}, fmt.Errorf("%w: no selected splitMPTY error", ber.ErrInvalidBinding)
}

// SSUserUserServiceErrors selects exactly the formal ERRORS set of SS-Operations.userUserService.
type SSUserUserServiceErrors struct {
	IllegalSSOperation    *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERIllegalSSOperationParam]
	SsErrorStatus         *ErrorValue[v21_map_ss_datatypes.BERValue[v21_map_ss_datatypes.SSSSStatus]]
	SsNotAvailable        *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERSSNotAvailableParam]
	SsIncompatibility     *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERSSIncompatibilityCause]
	FacilityNotSupported  *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParam]
	SystemFailure         *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam]
	ResourcesNotAvailable *ErrorValue[NoParameter]
	RejectedByNetwork     *ErrorValue[NoParameter]
	RejectedByUser        *ErrorValue[NoParameter]
}

func infoSSUserUserServiceOperation() SSOperationInfo {
	return SSOperationInfo{Name: "userUserService", Code: SSUserUserService, Argument: &TypeRef{ModuleOID: "0.4.0.0.2.3.2.18", ASN1Name: "UserUserServiceArg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "UserUserServiceArg"}, Result: nil, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: true, Source: sourceInfo9("userUserService", "4.2"), Errors: []SSErrorMemberInfo{SSErrorMemberInfo{Name: "illegalSS-Operation", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 16, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "IllegalSS-OperationParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERIllegalSSOperationParam"}, Source: sourceInfo10("illegalSS-Operation", "17.6.6")}, SSErrorMemberInfo{Name: "ss-ErrorStatus", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 17, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.14.21", ASN1Name: "SS-Status", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_ss_datatypes", GoName: "SSSSStatus"}, Source: sourceInfo10("ss-ErrorStatus", "17.6.6")}, SSErrorMemberInfo{Name: "ss-NotAvailable", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 18, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "SS-NotAvailableParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERSSNotAvailableParam"}, Source: sourceInfo10("ss-NotAvailable", "17.6.6")}, SSErrorMemberInfo{Name: "ss-Incompatibility", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 20, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "SS-IncompatibilityCause", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERSSIncompatibilityCause"}, Source: sourceInfo10("ss-Incompatibility", "17.6.6")}, SSErrorMemberInfo{Name: "facilityNotSupported", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 21, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "FacilityNotSupParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERFacilityNotSupParam"}, Source: sourceInfo10("facilityNotSupported", "17.6.6")}, SSErrorMemberInfo{Name: "systemFailure", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 34, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "SystemFailureParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERSystemFailureParam"}, Source: sourceInfo10("systemFailure", "17.6.6")}, SSErrorMemberInfo{Name: "resourcesNotAvailable", DeclaringModuleOID: "{#0/#4/#0/#0/#2/#3/#1/#18}", LocalCode: 127, Parameter: nil, Source: sourceInfo8("resourcesNotAvailable", "4.3")}, SSErrorMemberInfo{Name: "rejectedByNetwork", DeclaringModuleOID: "{#0/#4/#0/#0/#2/#3/#1/#18}", LocalCode: 122, Parameter: nil, Source: sourceInfo8("rejectedByNetwork", "4.3")}, SSErrorMemberInfo{Name: "rejectedByUser", DeclaringModuleOID: "{#0/#4/#0/#0/#2/#3/#1/#18}", LocalCode: 121, Parameter: nil, Source: sourceInfo8("rejectedByUser", "4.3")}}}
}

// SSUserUserServiceOperation binds the formal object in TS 24.080 V19.4.0 §4.2 (X.880 §§8.2–8.3).
func SSUserUserServiceOperation() SSOperation[UserUserServiceArg, NoParameter, SSUserUserServiceErrors] {
	return SSOperation[UserUserServiceArg, NoParameter, SSUserUserServiceErrors]{operationBinding[UserUserServiceArg, NoParameter, SSUserUserServiceErrors, SSOperationInfo, SSOperationCode, SSErrorEncoding]{code: SSUserUserService, info: infoSSUserUserServiceOperation, argument: UserUserServiceArgCodec(), result: ValueCodec[NoParameter]{}, decode: decodeSSUserUserServiceError, encode: encodeSSUserUserServiceError}}
}
func decodeSSUserUserServiceError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (SSUserUserServiceErrors, error) {
	switch code {
	case 16:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERIllegalSSOperationParam](__asn1pkg_v21_map_er_datatypes.ERIllegalSSOperationParamCodec()), opts...)
		if err != nil {
			return SSUserUserServiceErrors{}, err
		}
		return SSUserUserServiceErrors{IllegalSSOperation: p}, nil
	case 17:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[v21_map_ss_datatypes.BERValue[v21_map_ss_datatypes.SSSSStatus]](v21_map_ss_datatypes.SSSSStatusCodec()), opts...)
		if err != nil {
			return SSUserUserServiceErrors{}, err
		}
		return SSUserUserServiceErrors{SsErrorStatus: p}, nil
	case 18:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSSNotAvailableParam](__asn1pkg_v21_map_er_datatypes.ERSSNotAvailableParamCodec()), opts...)
		if err != nil {
			return SSUserUserServiceErrors{}, err
		}
		return SSUserUserServiceErrors{SsNotAvailable: p}, nil
	case 20:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSSIncompatibilityCause](__asn1pkg_v21_map_er_datatypes.ERSSIncompatibilityCauseCodec()), opts...)
		if err != nil {
			return SSUserUserServiceErrors{}, err
		}
		return SSUserUserServiceErrors{SsIncompatibility: p}, nil
	case 21:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParam](__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParamCodec()), opts...)
		if err != nil {
			return SSUserUserServiceErrors{}, err
		}
		return SSUserUserServiceErrors{FacilityNotSupported: p}, nil
	case 34:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam](__asn1pkg_v21_map_er_datatypes.ERSystemFailureParamCodec()), opts...)
		if err != nil {
			return SSUserUserServiceErrors{}, err
		}
		return SSUserUserServiceErrors{SystemFailure: p}, nil
	case 127:
		p, err := decodeErrorParameter(data, present, ValueCodec[NoParameter]{}, opts...)
		if err != nil {
			return SSUserUserServiceErrors{}, err
		}
		return SSUserUserServiceErrors{ResourcesNotAvailable: p}, nil
	case 122:
		p, err := decodeErrorParameter(data, present, ValueCodec[NoParameter]{}, opts...)
		if err != nil {
			return SSUserUserServiceErrors{}, err
		}
		return SSUserUserServiceErrors{RejectedByNetwork: p}, nil
	case 121:
		p, err := decodeErrorParameter(data, present, ValueCodec[NoParameter]{}, opts...)
		if err != nil {
			return SSUserUserServiceErrors{}, err
		}
		return SSUserUserServiceErrors{RejectedByUser: p}, nil
	default:
		return SSUserUserServiceErrors{}, fmt.Errorf("%w: error code %d is not in userUserService ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeSSUserUserServiceError(value SSUserUserServiceErrors, opts ...ber.EncodeOption) (SSErrorEncoding, error) {
	selected := 0
	if value.IllegalSSOperation != nil {
		selected++
	}
	if value.SsErrorStatus != nil {
		selected++
	}
	if value.SsNotAvailable != nil {
		selected++
	}
	if value.SsIncompatibility != nil {
		selected++
	}
	if value.FacilityNotSupported != nil {
		selected++
	}
	if value.SystemFailure != nil {
		selected++
	}
	if value.ResourcesNotAvailable != nil {
		selected++
	}
	if value.RejectedByNetwork != nil {
		selected++
	}
	if value.RejectedByUser != nil {
		selected++
	}
	if selected != 1 {
		return SSErrorEncoding{}, fmt.Errorf("%w: exactly one userUserService error arm is required", ber.ErrInvalidBinding)
	}
	if value.IllegalSSOperation != nil {
		return encodeSSErrorMember(16, sourceInfo10("illegalSS-Operation", "17.6.6"), value.IllegalSSOperation, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERIllegalSSOperationParam](__asn1pkg_v21_map_er_datatypes.ERIllegalSSOperationParamCodec()), opts...)
	}
	if value.SsErrorStatus != nil {
		return encodeSSErrorMember(17, sourceInfo10("ss-ErrorStatus", "17.6.6"), value.SsErrorStatus, adaptValueCodec[v21_map_ss_datatypes.BERValue[v21_map_ss_datatypes.SSSSStatus]](v21_map_ss_datatypes.SSSSStatusCodec()), opts...)
	}
	if value.SsNotAvailable != nil {
		return encodeSSErrorMember(18, sourceInfo10("ss-NotAvailable", "17.6.6"), value.SsNotAvailable, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSSNotAvailableParam](__asn1pkg_v21_map_er_datatypes.ERSSNotAvailableParamCodec()), opts...)
	}
	if value.SsIncompatibility != nil {
		return encodeSSErrorMember(20, sourceInfo10("ss-Incompatibility", "17.6.6"), value.SsIncompatibility, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSSIncompatibilityCause](__asn1pkg_v21_map_er_datatypes.ERSSIncompatibilityCauseCodec()), opts...)
	}
	if value.FacilityNotSupported != nil {
		return encodeSSErrorMember(21, sourceInfo10("facilityNotSupported", "17.6.6"), value.FacilityNotSupported, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParam](__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParamCodec()), opts...)
	}
	if value.SystemFailure != nil {
		return encodeSSErrorMember(34, sourceInfo10("systemFailure", "17.6.6"), value.SystemFailure, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam](__asn1pkg_v21_map_er_datatypes.ERSystemFailureParamCodec()), opts...)
	}
	if value.ResourcesNotAvailable != nil {
		return encodeSSErrorMember(127, sourceInfo8("resourcesNotAvailable", "4.3"), value.ResourcesNotAvailable, ValueCodec[NoParameter]{}, opts...)
	}
	if value.RejectedByNetwork != nil {
		return encodeSSErrorMember(122, sourceInfo8("rejectedByNetwork", "4.3"), value.RejectedByNetwork, ValueCodec[NoParameter]{}, opts...)
	}
	if value.RejectedByUser != nil {
		return encodeSSErrorMember(121, sourceInfo8("rejectedByUser", "4.3"), value.RejectedByUser, ValueCodec[NoParameter]{}, opts...)
	}
	return SSErrorEncoding{}, fmt.Errorf("%w: no selected userUserService error", ber.ErrInvalidBinding)
}
func SSOperations() []SSOperationInfo {
	return []SSOperationInfo{infoSSAccessRegisterCCEntryOperation(), infoSSBuildMPTYOperation(), infoSSCallDeflectionOperation(), infoSSExplicitCTOperation(), infoSSForwardCUGInfoOperation(), infoSSForwardChargeAdviceOperation(), infoSSHoldMPTYOperation(), infoSSLcsAreaEventCancellationOperation(), infoSSLcsAreaEventReportOperation(), infoSSLcsAreaEventRequestOperation(), infoSSLcsCancelDeferredLocationOperation(), infoSSLcsDLRSPPTransportOperation(), infoSSLcsEventReportOperation(), infoSSLcsLocationNotificationOperation(), infoSSLcsLocationPrivacySettingOperation(), infoSSLcsLocationUpdateOperation(), infoSSLcsMOLROperation(), infoSSLcsMSCancelDeferredLocationOperation(), infoSSLcsPeriodicLocationCancellationOperation(), infoSSLcsPeriodicLocationRequestOperation(), infoSSLcsPeriodicTriggeredInvokeOperation(), infoSSLcsPruAssociationOperation(), infoSSLcsPruDisassociationOperation(), infoSSLcsSLMOLROperation(), infoSSLcsSLMTLROperation(), infoSSLcsULRSPPTransportOperation(), infoSSNotifySSOperation(), infoSSProcessUnstructuredSSDataOperation(), infoSSRetrieveMPTYOperation(), infoSSSplitMPTYOperation(), infoSSUserUserServiceOperation()}
}
func LookupSSOperation(code SSOperationCode) (SSOperationInfo, bool) {
	switch code {
	case SSAccessRegisterCCEntry:
		return infoSSAccessRegisterCCEntryOperation(), true
	case SSBuildMPTY:
		return infoSSBuildMPTYOperation(), true
	case SSCallDeflection:
		return infoSSCallDeflectionOperation(), true
	case SSExplicitCT:
		return infoSSExplicitCTOperation(), true
	case SSForwardCUGInfo:
		return infoSSForwardCUGInfoOperation(), true
	case SSForwardChargeAdvice:
		return infoSSForwardChargeAdviceOperation(), true
	case SSHoldMPTY:
		return infoSSHoldMPTYOperation(), true
	case SSLcsAreaEventCancellation:
		return infoSSLcsAreaEventCancellationOperation(), true
	case SSLcsAreaEventReport:
		return infoSSLcsAreaEventReportOperation(), true
	case SSLcsAreaEventRequest:
		return infoSSLcsAreaEventRequestOperation(), true
	case SSLcsCancelDeferredLocation:
		return infoSSLcsCancelDeferredLocationOperation(), true
	case SSLcsDLRSPPTransport:
		return infoSSLcsDLRSPPTransportOperation(), true
	case SSLcsEventReport:
		return infoSSLcsEventReportOperation(), true
	case SSLcsLocationNotification:
		return infoSSLcsLocationNotificationOperation(), true
	case SSLcsLocationPrivacySetting:
		return infoSSLcsLocationPrivacySettingOperation(), true
	case SSLcsLocationUpdate:
		return infoSSLcsLocationUpdateOperation(), true
	case SSLcsMOLR:
		return infoSSLcsMOLROperation(), true
	case SSLcsMSCancelDeferredLocation:
		return infoSSLcsMSCancelDeferredLocationOperation(), true
	case SSLcsPeriodicLocationCancellation:
		return infoSSLcsPeriodicLocationCancellationOperation(), true
	case SSLcsPeriodicLocationRequest:
		return infoSSLcsPeriodicLocationRequestOperation(), true
	case SSLcsPeriodicTriggeredInvoke:
		return infoSSLcsPeriodicTriggeredInvokeOperation(), true
	case SSLcsPruAssociation:
		return infoSSLcsPruAssociationOperation(), true
	case SSLcsPruDisassociation:
		return infoSSLcsPruDisassociationOperation(), true
	case SSLcsSLMOLR:
		return infoSSLcsSLMOLROperation(), true
	case SSLcsSLMTLR:
		return infoSSLcsSLMTLROperation(), true
	case SSLcsULRSPPTransport:
		return infoSSLcsULRSPPTransportOperation(), true
	case SSNotifySS:
		return infoSSNotifySSOperation(), true
	case SSProcessUnstructuredSSData:
		return infoSSProcessUnstructuredSSDataOperation(), true
	case SSRetrieveMPTY:
		return infoSSRetrieveMPTYOperation(), true
	case SSSplitMPTY:
		return infoSSSplitMPTYOperation(), true
	case SSUserUserService:
		return infoSSUserUserServiceOperation(), true
	default:
		return SSOperationInfo{}, false
	}
}

type ApplicationContext struct {
	Name    string
	OID     runtime.ObjectIdentifier
	Version int
	Source  SourceRef
}

func ApplicationContexts() []ApplicationContext {
	return []ApplicationContext{
		{Name: "networkLocUpContext-v3", OID: NetworkLocUpContextV3(), Version: 3, Source: sourceInfo11("networkLocUpContext-v3", "17.3.3")},
		{Name: "locationCancellationContext-v3", OID: LocationCancellationContextV3(), Version: 3, Source: sourceInfo11("locationCancellationContext-v3", "17.3.3")},
		{Name: "roamingNumberEnquiryContext-v3", OID: RoamingNumberEnquiryContextV3(), Version: 3, Source: sourceInfo11("roamingNumberEnquiryContext-v3", "17.3.3")},
		{Name: "authenticationFailureReportContext-v3", OID: AuthenticationFailureReportContextV3(), Version: 3, Source: sourceInfo11("authenticationFailureReportContext-v3", "17.3.3")},
		{Name: "locationInfoRetrievalContext-v3", OID: LocationInfoRetrievalContextV3(), Version: 3, Source: sourceInfo11("locationInfoRetrievalContext-v3", "17.3.3")},
		{Name: "resetContext-v3", OID: ResetContextV3(), Version: 3, Source: sourceInfo11("resetContext-v3", "17.3.3")},
		{Name: "handoverControlContext-v3", OID: HandoverControlContextV3(), Version: 3, Source: sourceInfo11("handoverControlContext-v3", "17.3.3")},
		{Name: "equipmentMngtContext-v3", OID: EquipmentMngtContextV3(), Version: 3, Source: sourceInfo11("equipmentMngtContext-v3", "17.3.3")},
		{Name: "infoRetrievalContext-v3", OID: InfoRetrievalContextV3(), Version: 3, Source: sourceInfo11("infoRetrievalContext-v3", "17.3.3")},
		{Name: "interVlrInfoRetrievalContext-v3", OID: InterVlrInfoRetrievalContextV3(), Version: 3, Source: sourceInfo11("interVlrInfoRetrievalContext-v3", "17.3.3")},
		{Name: "subscriberDataMngtContext-v3", OID: SubscriberDataMngtContextV3(), Version: 3, Source: sourceInfo11("subscriberDataMngtContext-v3", "17.3.3")},
		{Name: "tracingContext-v3", OID: TracingContextV3(), Version: 3, Source: sourceInfo11("tracingContext-v3", "17.3.3")},
		{Name: "networkFunctionalSsContext-v2", OID: NetworkFunctionalSsContextV2(), Version: 2, Source: sourceInfo11("networkFunctionalSsContext-v2", "17.3.3")},
		{Name: "networkUnstructuredSsContext-v2", OID: NetworkUnstructuredSsContextV2(), Version: 2, Source: sourceInfo11("networkUnstructuredSsContext-v2", "17.3.3")},
		{Name: "shortMsgGatewayContext-v3", OID: ShortMsgGatewayContextV3(), Version: 3, Source: sourceInfo11("shortMsgGatewayContext-v3", "17.3.3")},
		{Name: "shortMsgMO-RelayContext-v3", OID: ShortMsgMORelayContextV3(), Version: 3, Source: sourceInfo11("shortMsgMO-RelayContext-v3", "17.3.3")},
		{Name: "shortMsgAlertContext-v2", OID: ShortMsgAlertContextV2(), Version: 2, Source: sourceInfo11("shortMsgAlertContext-v2", "17.3.3")},
		{Name: "mwdMngtContext-v3", OID: MwdMngtContextV3(), Version: 3, Source: sourceInfo11("mwdMngtContext-v3", "17.3.3")},
		{Name: "shortMsgMT-RelayContext-v3", OID: ShortMsgMTRelayContextV3(), Version: 3, Source: sourceInfo11("shortMsgMT-RelayContext-v3", "17.3.3")},
		{Name: "shortMsgMT-Relay-VGCS-Context-v3", OID: ShortMsgMTRelayVGCSContextV3(), Version: 3, Source: sourceInfo11("shortMsgMT-Relay-VGCS-Context-v3", "17.3.3")},
		{Name: "imsiRetrievalContext-v2", OID: ImsiRetrievalContextV2(), Version: 2, Source: sourceInfo11("imsiRetrievalContext-v2", "17.3.3")},
		{Name: "msPurgingContext-v3", OID: MsPurgingContextV3(), Version: 3, Source: sourceInfo11("msPurgingContext-v3", "17.3.3")},
		{Name: "subscriberInfoEnquiryContext-v3", OID: SubscriberInfoEnquiryContextV3(), Version: 3, Source: sourceInfo11("subscriberInfoEnquiryContext-v3", "17.3.3")},
		{Name: "anyTimeInfoEnquiryContext-v3", OID: AnyTimeInfoEnquiryContextV3(), Version: 3, Source: sourceInfo11("anyTimeInfoEnquiryContext-v3", "17.3.3")},
		{Name: "callControlTransferContext-v4", OID: CallControlTransferContextV4(), Version: 4, Source: sourceInfo11("callControlTransferContext-v4", "17.3.3")},
		{Name: "ss-InvocationNotificationContext-v3", OID: SsInvocationNotificationContextV3(), Version: 3, Source: sourceInfo11("ss-InvocationNotificationContext-v3", "17.3.3")},
		{Name: "groupCallControlContext-v3", OID: GroupCallControlContextV3(), Version: 3, Source: sourceInfo11("groupCallControlContext-v3", "17.3.3")},
		{Name: "groupCallInfoRetrievalContext-v3", OID: GroupCallInfoRetrievalContextV3(), Version: 3, Source: sourceInfo11("groupCallInfoRetrievalContext-v3", "17.3.3")},
		{Name: "gprsLocationUpdateContext-v3", OID: GprsLocationUpdateContextV3(), Version: 3, Source: sourceInfo11("gprsLocationUpdateContext-v3", "17.3.3")},
		{Name: "gprsLocationInfoRetrievalContext-v4", OID: GprsLocationInfoRetrievalContextV4(), Version: 4, Source: sourceInfo11("gprsLocationInfoRetrievalContext-v4", "17.3.3")},
		{Name: "failureReportContext-v3", OID: FailureReportContextV3(), Version: 3, Source: sourceInfo11("failureReportContext-v3", "17.3.3")},
		{Name: "gprsNotifyContext-v3", OID: GprsNotifyContextV3(), Version: 3, Source: sourceInfo11("gprsNotifyContext-v3", "17.3.3")},
		{Name: "reportingContext-v3", OID: ReportingContextV3(), Version: 3, Source: sourceInfo11("reportingContext-v3", "17.3.3")},
		{Name: "callCompletionContext-v3", OID: CallCompletionContextV3(), Version: 3, Source: sourceInfo11("callCompletionContext-v3", "17.3.3")},
		{Name: "istAlertingContext-v3", OID: IstAlertingContextV3(), Version: 3, Source: sourceInfo11("istAlertingContext-v3", "17.3.3")},
		{Name: "serviceTerminationContext-v3", OID: ServiceTerminationContextV3(), Version: 3, Source: sourceInfo11("serviceTerminationContext-v3", "17.3.3")},
		{Name: "locationSvcGatewayContext-v3", OID: LocationSvcGatewayContextV3(), Version: 3, Source: sourceInfo11("locationSvcGatewayContext-v3", "17.3.3")},
		{Name: "locationSvcEnquiryContext-v3", OID: LocationSvcEnquiryContextV3(), Version: 3, Source: sourceInfo11("locationSvcEnquiryContext-v3", "17.3.3")},
		{Name: "mm-EventReportingContext-v3", OID: MmEventReportingContextV3(), Version: 3, Source: sourceInfo11("mm-EventReportingContext-v3", "17.3.3")},
		{Name: "anyTimeInfoHandlingContext-v3", OID: AnyTimeInfoHandlingContextV3(), Version: 3, Source: sourceInfo11("anyTimeInfoHandlingContext-v3", "17.3.3")},
		{Name: "subscriberDataModificationNotificationContext-v3", OID: SubscriberDataModificationNotificationContextV3(), Version: 3, Source: sourceInfo11("subscriberDataModificationNotificationContext-v3", "17.3.3")},
		{Name: "resourceManagementContext-v3", OID: ResourceManagementContextV3(), Version: 3, Source: sourceInfo11("resourceManagementContext-v3", "17.3.3")},
		{Name: "vcsgLocationUpdateContext-v3", OID: VcsgLocationUpdateContextV3(), Version: 3, Source: sourceInfo11("vcsgLocationUpdateContext-v3", "17.3.3")},
		{Name: "vcsgLocationCancellationContext-v3", OID: VcsgLocationCancellationContextV3(), Version: 3, Source: sourceInfo11("vcsgLocationCancellationContext-v3", "17.3.3")},
	}
}
func LookupApplicationContext(oid runtime.ObjectIdentifier) (ApplicationContext, bool) {
	for _, context := range ApplicationContexts() {
		if context.OID.Equal(oid) {
			return context, true
		}
	}
	return ApplicationContext{}, false
}
func sourceInfo0(assignment, clause string) SourceRef {
	return SourceRef{Document: "3GPP TS 29.002", Edition: "19.1.0", Clause: clause, Module: "MAP-Errors", Assignment: assignment, SHA256: "fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346"}
}
func sourceInfo1(assignment, clause string) SourceRef {
	return SourceRef{Document: "3GPP TS 29.002", Edition: "19.1.0", Clause: clause, Module: "MAP-SupplementaryServiceOperations", Assignment: assignment, SHA256: "b7a0e89547f549f31436610aca8c22b3889ec8e7d8da2928cc0e9c0c392d4982"}
}
func sourceInfo2(assignment, clause string) SourceRef {
	return SourceRef{Document: "3GPP TS 29.002", Edition: "19.1.0", Clause: clause, Module: "MAP-OperationAndMaintenanceOperations", Assignment: assignment, SHA256: "7f706f72645f72d54c8add36cc083c7d20ccbc42f5bdbae5e3cfaf765e369845"}
}
func sourceInfo3(assignment, clause string) SourceRef {
	return SourceRef{Document: "3GPP TS 29.002", Edition: "19.1.0", Clause: clause, Module: "MAP-ShortMessageServiceOperations", Assignment: assignment, SHA256: "6c8edebb3afbfa8e662db4adfd2da590323343c6df8c82f686761e779ed297bb"}
}
func sourceInfo4(assignment, clause string) SourceRef {
	return SourceRef{Document: "3GPP TS 29.002", Edition: "19.1.0", Clause: clause, Module: "MAP-MobileServiceOperations", Assignment: assignment, SHA256: "1ff741e4cfa8e39efd9585cd08d7c5196d14b483dc2776ebc4e8c6e07babc496"}
}
func sourceInfo5(assignment, clause string) SourceRef {
	return SourceRef{Document: "3GPP TS 29.002", Edition: "19.1.0", Clause: clause, Module: "MAP-Group-Call-Operations", Assignment: assignment, SHA256: "2047261424cb7e0de50d6507e142ce3c4439a628ad5a273efc8e4ddefe1087f6"}
}
func sourceInfo6(assignment, clause string) SourceRef {
	return SourceRef{Document: "3GPP TS 29.002", Edition: "19.1.0", Clause: clause, Module: "MAP-CallHandlingOperations", Assignment: assignment, SHA256: "c61f10b3a81b1206acd7d36318c56a7cb3e0a212a4de53d2f5f705bf7cde4a1d"}
}
func sourceInfo7(assignment, clause string) SourceRef {
	return SourceRef{Document: "3GPP TS 29.002", Edition: "19.1.0", Clause: clause, Module: "MAP-LocationServiceOperations", Assignment: assignment, SHA256: "280414f331b25e83c672dc7ce1773e9e4f1585f1d0f3f374bd98637e11ad6b0a"}
}
func sourceInfo8(assignment, clause string) SourceRef {
	return SourceRef{Document: "3GPP TS 24.080", Edition: "19.4.0", Clause: clause, Module: "SS-Errors", Assignment: assignment, SHA256: "b81d2a668e33702414eec4d9210bd4922f1104ccc4384cb6d8d3301ce8fa129e"}
}
func sourceInfo9(assignment, clause string) SourceRef {
	return SourceRef{Document: "3GPP TS 24.080", Edition: "19.4.0", Clause: clause, Module: "SS-Operations", Assignment: assignment, SHA256: "d3eba960d95875df7ffb757f3e944ee68d3172f407fb27cdeebec4e6e1317673"}
}
func sourceInfo10(assignment, clause string) SourceRef {
	return SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: clause, Module: "MAP-Errors", Assignment: assignment, SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}
}
func sourceInfo11(assignment, clause string) SourceRef {
	return SourceRef{Document: "3GPP TS 29.002", Edition: "19.1.0", Clause: clause, Module: "MAP-ApplicationContexts", Assignment: assignment, SHA256: "e044fb2f4876170b1de2199c25c3e94c0e92573a48d325b8f6f9feddeb1c8354"}
}
