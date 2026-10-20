// Code generated from formal ASN.1 objects. DO NOT EDIT.

package bindings

import (
	"fmt"
	mapvalues "github.com/gomaja/go-asn1/telecom/ss7/gsm_map"

	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime/ber"
	__asn1pkg_v21_map_er_datatypes "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes"
	__asn1pkg_v21_map_ss_datatypes "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_ss_datatypes"
)

type errorBinding[P, I, C any] struct {
	code      C
	info      func() I
	parameter mapvalues.ValueCodec[P]
}

func (d errorBinding[P, I, C]) Code() C { return d.code }
func (d errorBinding[P, I, C]) Info() I {
	if d.info == nil {
		var zero I
		return zero
	}
	return d.info()
}
func (d errorBinding[P, I, C]) Parameter() (mapvalues.ValueCodec[P], bool) {
	return d.parameter, d.parameter.Valid()
}
func decodeErrorParameter[P any](data []byte, present bool, codec mapvalues.ValueCodec[P], opts ...ber.DecodeOption) (*mapvalues.ErrorValue[P], error) {
	if !present {
		if len(data) != 0 {
			return nil, fmt.Errorf("%w: absent parameter has bytes", ber.ErrInvalidBinding)
		}
		return &mapvalues.ErrorValue[P]{}, nil
	}
	if !codec.Valid() {
		return nil, fmt.Errorf("%w: source error has no PARAMETER", ber.ErrInvalidBinding)
	}
	v, err := codec.DecodeBER(data, opts...)
	if err != nil {
		return nil, err
	}
	return &mapvalues.ErrorValue[P]{Parameter: &v}, nil
}
func encodeErrorParameter[P any](value *mapvalues.ErrorValue[P], codec mapvalues.ValueCodec[P], opts ...ber.EncodeOption) ([]byte, bool, error) {
	if value.Parameter == nil {
		return nil, false, nil
	}
	if !codec.Valid() {
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
}) mapvalues.ValueCodec[T] {
	return mapvalues.NewValueCodec(codec.DecodeBER, codec.EncodeBER, codec.EncodeDER)
}

type ErrorDescriptor[P any] struct {
	errorBinding[P, mapvalues.ErrorInfo, mapvalues.MAPErrorCode]
}

// AbsentSubscriberErrorDescriptor binds the formal ERROR object MAP-Errors.absentSubscriber (X.880 §8.3).
func AbsentSubscriberErrorDescriptor() ErrorDescriptor[mapvalues.AbsentSubscriberParam] {
	return ErrorDescriptor[mapvalues.AbsentSubscriberParam]{errorBinding[mapvalues.AbsentSubscriberParam, mapvalues.ErrorInfo, mapvalues.MAPErrorCode]{code: mapvalues.AbsentSubscriber, info: infoAbsentSubscriberError, parameter: AbsentSubscriberParamCodec()}}
}
func infoAbsentSubscriberError() mapvalues.ErrorInfo {
	info, _ := mapvalues.LookupError(mapvalues.AbsentSubscriber)
	return info
}

// AbsentSubscriberSMErrorDescriptor binds the formal ERROR object MAP-Errors.absentSubscriberSM (X.880 §8.3).
func AbsentSubscriberSMErrorDescriptor() ErrorDescriptor[mapvalues.AbsentSubscriberSMParam] {
	return ErrorDescriptor[mapvalues.AbsentSubscriberSMParam]{errorBinding[mapvalues.AbsentSubscriberSMParam, mapvalues.ErrorInfo, mapvalues.MAPErrorCode]{code: mapvalues.AbsentSubscriberSM, info: infoAbsentSubscriberSMError, parameter: AbsentSubscriberSMParamCodec()}}
}
func infoAbsentSubscriberSMError() mapvalues.ErrorInfo {
	info, _ := mapvalues.LookupError(mapvalues.AbsentSubscriberSM)
	return info
}

// AtiNotAllowedErrorDescriptor binds the formal ERROR object MAP-Errors.ati-NotAllowed (X.880 §8.3).
func AtiNotAllowedErrorDescriptor() ErrorDescriptor[mapvalues.ATINotAllowedParam] {
	return ErrorDescriptor[mapvalues.ATINotAllowedParam]{errorBinding[mapvalues.ATINotAllowedParam, mapvalues.ErrorInfo, mapvalues.MAPErrorCode]{code: mapvalues.AtiNotAllowed, info: infoAtiNotAllowedError, parameter: ATINotAllowedParamCodec()}}
}
func infoAtiNotAllowedError() mapvalues.ErrorInfo {
	info, _ := mapvalues.LookupError(mapvalues.AtiNotAllowed)
	return info
}

// AtmNotAllowedErrorDescriptor binds the formal ERROR object MAP-Errors.atm-NotAllowed (X.880 §8.3).
func AtmNotAllowedErrorDescriptor() ErrorDescriptor[mapvalues.ATMNotAllowedParam] {
	return ErrorDescriptor[mapvalues.ATMNotAllowedParam]{errorBinding[mapvalues.ATMNotAllowedParam, mapvalues.ErrorInfo, mapvalues.MAPErrorCode]{code: mapvalues.AtmNotAllowed, info: infoAtmNotAllowedError, parameter: ATMNotAllowedParamCodec()}}
}
func infoAtmNotAllowedError() mapvalues.ErrorInfo {
	info, _ := mapvalues.LookupError(mapvalues.AtmNotAllowed)
	return info
}

// AtsiNotAllowedErrorDescriptor binds the formal ERROR object MAP-Errors.atsi-NotAllowed (X.880 §8.3).
func AtsiNotAllowedErrorDescriptor() ErrorDescriptor[mapvalues.ATSINotAllowedParam] {
	return ErrorDescriptor[mapvalues.ATSINotAllowedParam]{errorBinding[mapvalues.ATSINotAllowedParam, mapvalues.ErrorInfo, mapvalues.MAPErrorCode]{code: mapvalues.AtsiNotAllowed, info: infoAtsiNotAllowedError, parameter: ATSINotAllowedParamCodec()}}
}
func infoAtsiNotAllowedError() mapvalues.ErrorInfo {
	info, _ := mapvalues.LookupError(mapvalues.AtsiNotAllowed)
	return info
}

// BearerServiceNotProvisionedErrorDescriptor binds the formal ERROR object MAP-Errors.bearerServiceNotProvisioned (X.880 §8.3).
func BearerServiceNotProvisionedErrorDescriptor() ErrorDescriptor[mapvalues.BearerServNotProvParam] {
	return ErrorDescriptor[mapvalues.BearerServNotProvParam]{errorBinding[mapvalues.BearerServNotProvParam, mapvalues.ErrorInfo, mapvalues.MAPErrorCode]{code: mapvalues.BearerServiceNotProvisioned, info: infoBearerServiceNotProvisionedError, parameter: BearerServNotProvParamCodec()}}
}
func infoBearerServiceNotProvisionedError() mapvalues.ErrorInfo {
	info, _ := mapvalues.LookupError(mapvalues.BearerServiceNotProvisioned)
	return info
}

// BusySubscriberErrorDescriptor binds the formal ERROR object MAP-Errors.busySubscriber (X.880 §8.3).
func BusySubscriberErrorDescriptor() ErrorDescriptor[mapvalues.BusySubscriberParam] {
	return ErrorDescriptor[mapvalues.BusySubscriberParam]{errorBinding[mapvalues.BusySubscriberParam, mapvalues.ErrorInfo, mapvalues.MAPErrorCode]{code: mapvalues.BusySubscriber, info: infoBusySubscriberError, parameter: BusySubscriberParamCodec()}}
}
func infoBusySubscriberError() mapvalues.ErrorInfo {
	info, _ := mapvalues.LookupError(mapvalues.BusySubscriber)
	return info
}

// CallBarredErrorDescriptor binds the formal ERROR object MAP-Errors.callBarred (X.880 §8.3).
func CallBarredErrorDescriptor() ErrorDescriptor[mapvalues.CallBarredParam] {
	return ErrorDescriptor[mapvalues.CallBarredParam]{errorBinding[mapvalues.CallBarredParam, mapvalues.ErrorInfo, mapvalues.MAPErrorCode]{code: mapvalues.CallBarred, info: infoCallBarredError, parameter: CallBarredParamCodec()}}
}
func infoCallBarredError() mapvalues.ErrorInfo {
	info, _ := mapvalues.LookupError(mapvalues.CallBarred)
	return info
}

// CugRejectErrorDescriptor binds the formal ERROR object MAP-Errors.cug-Reject (X.880 §8.3).
func CugRejectErrorDescriptor() ErrorDescriptor[mapvalues.CUGRejectParam] {
	return ErrorDescriptor[mapvalues.CUGRejectParam]{errorBinding[mapvalues.CUGRejectParam, mapvalues.ErrorInfo, mapvalues.MAPErrorCode]{code: mapvalues.CugReject, info: infoCugRejectError, parameter: CUGRejectParamCodec()}}
}
func infoCugRejectError() mapvalues.ErrorInfo {
	info, _ := mapvalues.LookupError(mapvalues.CugReject)
	return info
}

// DataMissingErrorDescriptor binds the formal ERROR object MAP-Errors.dataMissing (X.880 §8.3).
func DataMissingErrorDescriptor() ErrorDescriptor[mapvalues.DataMissingParam] {
	return ErrorDescriptor[mapvalues.DataMissingParam]{errorBinding[mapvalues.DataMissingParam, mapvalues.ErrorInfo, mapvalues.MAPErrorCode]{code: mapvalues.DataMissing, info: infoDataMissingError, parameter: DataMissingParamCodec()}}
}
func infoDataMissingError() mapvalues.ErrorInfo {
	info, _ := mapvalues.LookupError(mapvalues.DataMissing)
	return info
}

// FacilityNotSupportedErrorDescriptor binds the formal ERROR object MAP-Errors.facilityNotSupported (X.880 §8.3).
func FacilityNotSupportedErrorDescriptor() ErrorDescriptor[mapvalues.FacilityNotSupParam] {
	return ErrorDescriptor[mapvalues.FacilityNotSupParam]{errorBinding[mapvalues.FacilityNotSupParam, mapvalues.ErrorInfo, mapvalues.MAPErrorCode]{code: mapvalues.FacilityNotSupported, info: infoFacilityNotSupportedError, parameter: FacilityNotSupParamCodec()}}
}
func infoFacilityNotSupportedError() mapvalues.ErrorInfo {
	info, _ := mapvalues.LookupError(mapvalues.FacilityNotSupported)
	return info
}

// ForwardingFailedErrorDescriptor binds the formal ERROR object MAP-Errors.forwardingFailed (X.880 §8.3).
func ForwardingFailedErrorDescriptor() ErrorDescriptor[mapvalues.ForwardingFailedParam] {
	return ErrorDescriptor[mapvalues.ForwardingFailedParam]{errorBinding[mapvalues.ForwardingFailedParam, mapvalues.ErrorInfo, mapvalues.MAPErrorCode]{code: mapvalues.ForwardingFailed, info: infoForwardingFailedError, parameter: ForwardingFailedParamCodec()}}
}
func infoForwardingFailedError() mapvalues.ErrorInfo {
	info, _ := mapvalues.LookupError(mapvalues.ForwardingFailed)
	return info
}

// ForwardingViolationErrorDescriptor binds the formal ERROR object MAP-Errors.forwardingViolation (X.880 §8.3).
func ForwardingViolationErrorDescriptor() ErrorDescriptor[mapvalues.ForwardingViolationParam] {
	return ErrorDescriptor[mapvalues.ForwardingViolationParam]{errorBinding[mapvalues.ForwardingViolationParam, mapvalues.ErrorInfo, mapvalues.MAPErrorCode]{code: mapvalues.ForwardingViolation, info: infoForwardingViolationError, parameter: ForwardingViolationParamCodec()}}
}
func infoForwardingViolationError() mapvalues.ErrorInfo {
	info, _ := mapvalues.LookupError(mapvalues.ForwardingViolation)
	return info
}

// IllegalEquipmentErrorDescriptor binds the formal ERROR object MAP-Errors.illegalEquipment (X.880 §8.3).
func IllegalEquipmentErrorDescriptor() ErrorDescriptor[mapvalues.IllegalEquipmentParam] {
	return ErrorDescriptor[mapvalues.IllegalEquipmentParam]{errorBinding[mapvalues.IllegalEquipmentParam, mapvalues.ErrorInfo, mapvalues.MAPErrorCode]{code: mapvalues.IllegalEquipment, info: infoIllegalEquipmentError, parameter: IllegalEquipmentParamCodec()}}
}
func infoIllegalEquipmentError() mapvalues.ErrorInfo {
	info, _ := mapvalues.LookupError(mapvalues.IllegalEquipment)
	return info
}

// IllegalSSOperationErrorDescriptor binds the formal ERROR object MAP-Errors.illegalSS-Operation (X.880 §8.3).
func IllegalSSOperationErrorDescriptor() ErrorDescriptor[mapvalues.IllegalSSOperationParam] {
	return ErrorDescriptor[mapvalues.IllegalSSOperationParam]{errorBinding[mapvalues.IllegalSSOperationParam, mapvalues.ErrorInfo, mapvalues.MAPErrorCode]{code: mapvalues.IllegalSSOperation, info: infoIllegalSSOperationError, parameter: IllegalSSOperationParamCodec()}}
}
func infoIllegalSSOperationError() mapvalues.ErrorInfo {
	info, _ := mapvalues.LookupError(mapvalues.IllegalSSOperation)
	return info
}

// IllegalSubscriberErrorDescriptor binds the formal ERROR object MAP-Errors.illegalSubscriber (X.880 §8.3).
func IllegalSubscriberErrorDescriptor() ErrorDescriptor[mapvalues.IllegalSubscriberParam] {
	return ErrorDescriptor[mapvalues.IllegalSubscriberParam]{errorBinding[mapvalues.IllegalSubscriberParam, mapvalues.ErrorInfo, mapvalues.MAPErrorCode]{code: mapvalues.IllegalSubscriber, info: infoIllegalSubscriberError, parameter: IllegalSubscriberParamCodec()}}
}
func infoIllegalSubscriberError() mapvalues.ErrorInfo {
	info, _ := mapvalues.LookupError(mapvalues.IllegalSubscriber)
	return info
}

// IncompatibleTerminalErrorDescriptor binds the formal ERROR object MAP-Errors.incompatibleTerminal (X.880 §8.3).
func IncompatibleTerminalErrorDescriptor() ErrorDescriptor[mapvalues.IncompatibleTerminalParam] {
	return ErrorDescriptor[mapvalues.IncompatibleTerminalParam]{errorBinding[mapvalues.IncompatibleTerminalParam, mapvalues.ErrorInfo, mapvalues.MAPErrorCode]{code: mapvalues.IncompatibleTerminal, info: infoIncompatibleTerminalError, parameter: IncompatibleTerminalParamCodec()}}
}
func infoIncompatibleTerminalError() mapvalues.ErrorInfo {
	info, _ := mapvalues.LookupError(mapvalues.IncompatibleTerminal)
	return info
}

// InformationNotAvailableErrorDescriptor binds the formal ERROR object MAP-Errors.informationNotAvailable (X.880 §8.3).
func InformationNotAvailableErrorDescriptor() ErrorDescriptor[mapvalues.InformationNotAvailableParam] {
	return ErrorDescriptor[mapvalues.InformationNotAvailableParam]{errorBinding[mapvalues.InformationNotAvailableParam, mapvalues.ErrorInfo, mapvalues.MAPErrorCode]{code: mapvalues.InformationNotAvailable, info: infoInformationNotAvailableError, parameter: InformationNotAvailableParamCodec()}}
}
func infoInformationNotAvailableError() mapvalues.ErrorInfo {
	info, _ := mapvalues.LookupError(mapvalues.InformationNotAvailable)
	return info
}

// LongTermDenialErrorDescriptor binds the formal ERROR object MAP-Errors.longTermDenial (X.880 §8.3).
func LongTermDenialErrorDescriptor() ErrorDescriptor[mapvalues.LongTermDenialParam] {
	return ErrorDescriptor[mapvalues.LongTermDenialParam]{errorBinding[mapvalues.LongTermDenialParam, mapvalues.ErrorInfo, mapvalues.MAPErrorCode]{code: mapvalues.LongTermDenial, info: infoLongTermDenialError, parameter: LongTermDenialParamCodec()}}
}
func infoLongTermDenialError() mapvalues.ErrorInfo {
	info, _ := mapvalues.LookupError(mapvalues.LongTermDenial)
	return info
}

// MessageWaitingListFullErrorDescriptor binds the formal ERROR object MAP-Errors.messageWaitingListFull (X.880 §8.3).
func MessageWaitingListFullErrorDescriptor() ErrorDescriptor[mapvalues.MessageWaitListFullParam] {
	return ErrorDescriptor[mapvalues.MessageWaitListFullParam]{errorBinding[mapvalues.MessageWaitListFullParam, mapvalues.ErrorInfo, mapvalues.MAPErrorCode]{code: mapvalues.MessageWaitingListFull, info: infoMessageWaitingListFullError, parameter: MessageWaitListFullParamCodec()}}
}
func infoMessageWaitingListFullError() mapvalues.ErrorInfo {
	info, _ := mapvalues.LookupError(mapvalues.MessageWaitingListFull)
	return info
}

// MmEventNotSupportedErrorDescriptor binds the formal ERROR object MAP-Errors.mm-EventNotSupported (X.880 §8.3).
func MmEventNotSupportedErrorDescriptor() ErrorDescriptor[mapvalues.MMEventNotSupportedParam] {
	return ErrorDescriptor[mapvalues.MMEventNotSupportedParam]{errorBinding[mapvalues.MMEventNotSupportedParam, mapvalues.ErrorInfo, mapvalues.MAPErrorCode]{code: mapvalues.MmEventNotSupported, info: infoMmEventNotSupportedError, parameter: MMEventNotSupportedParamCodec()}}
}
func infoMmEventNotSupportedError() mapvalues.ErrorInfo {
	info, _ := mapvalues.LookupError(mapvalues.MmEventNotSupported)
	return info
}

// NegativePWCheckErrorDescriptor binds the formal ERROR object MAP-Errors.negativePW-Check (X.880 §8.3).
func NegativePWCheckErrorDescriptor() ErrorDescriptor[mapvalues.NoParameter] {
	return ErrorDescriptor[mapvalues.NoParameter]{errorBinding[mapvalues.NoParameter, mapvalues.ErrorInfo, mapvalues.MAPErrorCode]{code: mapvalues.NegativePWCheck, info: infoNegativePWCheckError, parameter: mapvalues.ValueCodec[mapvalues.NoParameter]{}}}
}
func infoNegativePWCheckError() mapvalues.ErrorInfo {
	info, _ := mapvalues.LookupError(mapvalues.NegativePWCheck)
	return info
}

// NoGroupCallNumberAvailableErrorDescriptor binds the formal ERROR object MAP-Errors.noGroupCallNumberAvailable (X.880 §8.3).
func NoGroupCallNumberAvailableErrorDescriptor() ErrorDescriptor[mapvalues.NoGroupCallNbParam] {
	return ErrorDescriptor[mapvalues.NoGroupCallNbParam]{errorBinding[mapvalues.NoGroupCallNbParam, mapvalues.ErrorInfo, mapvalues.MAPErrorCode]{code: mapvalues.NoGroupCallNumberAvailable, info: infoNoGroupCallNumberAvailableError, parameter: NoGroupCallNbParamCodec()}}
}
func infoNoGroupCallNumberAvailableError() mapvalues.ErrorInfo {
	info, _ := mapvalues.LookupError(mapvalues.NoGroupCallNumberAvailable)
	return info
}

// NoHandoverNumberAvailableErrorDescriptor binds the formal ERROR object MAP-Errors.noHandoverNumberAvailable (X.880 §8.3).
func NoHandoverNumberAvailableErrorDescriptor() ErrorDescriptor[mapvalues.NoParameter] {
	return ErrorDescriptor[mapvalues.NoParameter]{errorBinding[mapvalues.NoParameter, mapvalues.ErrorInfo, mapvalues.MAPErrorCode]{code: mapvalues.NoHandoverNumberAvailable, info: infoNoHandoverNumberAvailableError, parameter: mapvalues.ValueCodec[mapvalues.NoParameter]{}}}
}
func infoNoHandoverNumberAvailableError() mapvalues.ErrorInfo {
	info, _ := mapvalues.LookupError(mapvalues.NoHandoverNumberAvailable)
	return info
}

// NoRoamingNumberAvailableErrorDescriptor binds the formal ERROR object MAP-Errors.noRoamingNumberAvailable (X.880 §8.3).
func NoRoamingNumberAvailableErrorDescriptor() ErrorDescriptor[mapvalues.NoRoamingNbParam] {
	return ErrorDescriptor[mapvalues.NoRoamingNbParam]{errorBinding[mapvalues.NoRoamingNbParam, mapvalues.ErrorInfo, mapvalues.MAPErrorCode]{code: mapvalues.NoRoamingNumberAvailable, info: infoNoRoamingNumberAvailableError, parameter: NoRoamingNbParamCodec()}}
}
func infoNoRoamingNumberAvailableError() mapvalues.ErrorInfo {
	info, _ := mapvalues.LookupError(mapvalues.NoRoamingNumberAvailable)
	return info
}

// NoSubscriberReplyErrorDescriptor binds the formal ERROR object MAP-Errors.noSubscriberReply (X.880 §8.3).
func NoSubscriberReplyErrorDescriptor() ErrorDescriptor[mapvalues.NoSubscriberReplyParam] {
	return ErrorDescriptor[mapvalues.NoSubscriberReplyParam]{errorBinding[mapvalues.NoSubscriberReplyParam, mapvalues.ErrorInfo, mapvalues.MAPErrorCode]{code: mapvalues.NoSubscriberReply, info: infoNoSubscriberReplyError, parameter: NoSubscriberReplyParamCodec()}}
}
func infoNoSubscriberReplyError() mapvalues.ErrorInfo {
	info, _ := mapvalues.LookupError(mapvalues.NoSubscriberReply)
	return info
}

// NumberChangedErrorDescriptor binds the formal ERROR object MAP-Errors.numberChanged (X.880 §8.3).
func NumberChangedErrorDescriptor() ErrorDescriptor[mapvalues.NumberChangedParam] {
	return ErrorDescriptor[mapvalues.NumberChangedParam]{errorBinding[mapvalues.NumberChangedParam, mapvalues.ErrorInfo, mapvalues.MAPErrorCode]{code: mapvalues.NumberChanged, info: infoNumberChangedError, parameter: NumberChangedParamCodec()}}
}
func infoNumberChangedError() mapvalues.ErrorInfo {
	info, _ := mapvalues.LookupError(mapvalues.NumberChanged)
	return info
}

// NumberOfPWAttemptsViolationErrorDescriptor binds the formal ERROR object MAP-Errors.numberOfPW-AttemptsViolation (X.880 §8.3).
func NumberOfPWAttemptsViolationErrorDescriptor() ErrorDescriptor[mapvalues.NoParameter] {
	return ErrorDescriptor[mapvalues.NoParameter]{errorBinding[mapvalues.NoParameter, mapvalues.ErrorInfo, mapvalues.MAPErrorCode]{code: mapvalues.NumberOfPWAttemptsViolation, info: infoNumberOfPWAttemptsViolationError, parameter: mapvalues.ValueCodec[mapvalues.NoParameter]{}}}
}
func infoNumberOfPWAttemptsViolationError() mapvalues.ErrorInfo {
	info, _ := mapvalues.LookupError(mapvalues.NumberOfPWAttemptsViolation)
	return info
}

// OngoingGroupCallErrorDescriptor binds the formal ERROR object MAP-Errors.ongoingGroupCall (X.880 §8.3).
func OngoingGroupCallErrorDescriptor() ErrorDescriptor[mapvalues.OngoingGroupCallParam] {
	return ErrorDescriptor[mapvalues.OngoingGroupCallParam]{errorBinding[mapvalues.OngoingGroupCallParam, mapvalues.ErrorInfo, mapvalues.MAPErrorCode]{code: mapvalues.OngoingGroupCall, info: infoOngoingGroupCallError, parameter: OngoingGroupCallParamCodec()}}
}
func infoOngoingGroupCallError() mapvalues.ErrorInfo {
	info, _ := mapvalues.LookupError(mapvalues.OngoingGroupCall)
	return info
}

// OrNotAllowedErrorDescriptor binds the formal ERROR object MAP-Errors.or-NotAllowed (X.880 §8.3).
func OrNotAllowedErrorDescriptor() ErrorDescriptor[mapvalues.ORNotAllowedParam] {
	return ErrorDescriptor[mapvalues.ORNotAllowedParam]{errorBinding[mapvalues.ORNotAllowedParam, mapvalues.ErrorInfo, mapvalues.MAPErrorCode]{code: mapvalues.OrNotAllowed, info: infoOrNotAllowedError, parameter: ORNotAllowedParamCodec()}}
}
func infoOrNotAllowedError() mapvalues.ErrorInfo {
	info, _ := mapvalues.LookupError(mapvalues.OrNotAllowed)
	return info
}

// PositionMethodFailureErrorDescriptor binds the formal ERROR object MAP-Errors.positionMethodFailure (X.880 §8.3).
func PositionMethodFailureErrorDescriptor() ErrorDescriptor[mapvalues.PositionMethodFailureParam] {
	return ErrorDescriptor[mapvalues.PositionMethodFailureParam]{errorBinding[mapvalues.PositionMethodFailureParam, mapvalues.ErrorInfo, mapvalues.MAPErrorCode]{code: mapvalues.PositionMethodFailure, info: infoPositionMethodFailureError, parameter: PositionMethodFailureParamCodec()}}
}
func infoPositionMethodFailureError() mapvalues.ErrorInfo {
	info, _ := mapvalues.LookupError(mapvalues.PositionMethodFailure)
	return info
}

// PwRegistrationFailureErrorDescriptor binds the formal ERROR object MAP-Errors.pw-RegistrationFailure (X.880 §8.3).
func PwRegistrationFailureErrorDescriptor() ErrorDescriptor[mapvalues.BERValue[mapvalues.PWRegistrationFailureCause]] {
	return ErrorDescriptor[mapvalues.BERValue[mapvalues.PWRegistrationFailureCause]]{errorBinding[mapvalues.BERValue[mapvalues.PWRegistrationFailureCause], mapvalues.ErrorInfo, mapvalues.MAPErrorCode]{code: mapvalues.PwRegistrationFailure, info: infoPwRegistrationFailureError, parameter: PWRegistrationFailureCauseCodec()}}
}
func infoPwRegistrationFailureError() mapvalues.ErrorInfo {
	info, _ := mapvalues.LookupError(mapvalues.PwRegistrationFailure)
	return info
}

// ResourceLimitationErrorDescriptor binds the formal ERROR object MAP-Errors.resourceLimitation (X.880 §8.3).
func ResourceLimitationErrorDescriptor() ErrorDescriptor[mapvalues.ResourceLimitationParam] {
	return ErrorDescriptor[mapvalues.ResourceLimitationParam]{errorBinding[mapvalues.ResourceLimitationParam, mapvalues.ErrorInfo, mapvalues.MAPErrorCode]{code: mapvalues.ResourceLimitation, info: infoResourceLimitationError, parameter: ResourceLimitationParamCodec()}}
}
func infoResourceLimitationError() mapvalues.ErrorInfo {
	info, _ := mapvalues.LookupError(mapvalues.ResourceLimitation)
	return info
}

// RoamingNotAllowedErrorDescriptor binds the formal ERROR object MAP-Errors.roamingNotAllowed (X.880 §8.3).
func RoamingNotAllowedErrorDescriptor() ErrorDescriptor[mapvalues.RoamingNotAllowedParam] {
	return ErrorDescriptor[mapvalues.RoamingNotAllowedParam]{errorBinding[mapvalues.RoamingNotAllowedParam, mapvalues.ErrorInfo, mapvalues.MAPErrorCode]{code: mapvalues.RoamingNotAllowed, info: infoRoamingNotAllowedError, parameter: RoamingNotAllowedParamCodec()}}
}
func infoRoamingNotAllowedError() mapvalues.ErrorInfo {
	info, _ := mapvalues.LookupError(mapvalues.RoamingNotAllowed)
	return info
}

// ShortTermDenialErrorDescriptor binds the formal ERROR object MAP-Errors.shortTermDenial (X.880 §8.3).
func ShortTermDenialErrorDescriptor() ErrorDescriptor[mapvalues.ShortTermDenialParam] {
	return ErrorDescriptor[mapvalues.ShortTermDenialParam]{errorBinding[mapvalues.ShortTermDenialParam, mapvalues.ErrorInfo, mapvalues.MAPErrorCode]{code: mapvalues.ShortTermDenial, info: infoShortTermDenialError, parameter: ShortTermDenialParamCodec()}}
}
func infoShortTermDenialError() mapvalues.ErrorInfo {
	info, _ := mapvalues.LookupError(mapvalues.ShortTermDenial)
	return info
}

// SmDeliveryFailureErrorDescriptor binds the formal ERROR object MAP-Errors.sm-DeliveryFailure (X.880 §8.3).
func SmDeliveryFailureErrorDescriptor() ErrorDescriptor[mapvalues.SMDeliveryFailureCause] {
	return ErrorDescriptor[mapvalues.SMDeliveryFailureCause]{errorBinding[mapvalues.SMDeliveryFailureCause, mapvalues.ErrorInfo, mapvalues.MAPErrorCode]{code: mapvalues.SmDeliveryFailure, info: infoSmDeliveryFailureError, parameter: SMDeliveryFailureCauseCodec()}}
}
func infoSmDeliveryFailureError() mapvalues.ErrorInfo {
	info, _ := mapvalues.LookupError(mapvalues.SmDeliveryFailure)
	return info
}

// SsErrorStatusErrorDescriptor binds the formal ERROR object MAP-Errors.ss-ErrorStatus (X.880 §8.3).
func SsErrorStatusErrorDescriptor() ErrorDescriptor[mapvalues.BERValue[mapvalues.SSStatus]] {
	return ErrorDescriptor[mapvalues.BERValue[mapvalues.SSStatus]]{errorBinding[mapvalues.BERValue[mapvalues.SSStatus], mapvalues.ErrorInfo, mapvalues.MAPErrorCode]{code: mapvalues.SsErrorStatus, info: infoSsErrorStatusError, parameter: SSStatusCodec()}}
}
func infoSsErrorStatusError() mapvalues.ErrorInfo {
	info, _ := mapvalues.LookupError(mapvalues.SsErrorStatus)
	return info
}

// SsIncompatibilityErrorDescriptor binds the formal ERROR object MAP-Errors.ss-Incompatibility (X.880 §8.3).
func SsIncompatibilityErrorDescriptor() ErrorDescriptor[mapvalues.SSIncompatibilityCause] {
	return ErrorDescriptor[mapvalues.SSIncompatibilityCause]{errorBinding[mapvalues.SSIncompatibilityCause, mapvalues.ErrorInfo, mapvalues.MAPErrorCode]{code: mapvalues.SsIncompatibility, info: infoSsIncompatibilityError, parameter: SSIncompatibilityCauseCodec()}}
}
func infoSsIncompatibilityError() mapvalues.ErrorInfo {
	info, _ := mapvalues.LookupError(mapvalues.SsIncompatibility)
	return info
}

// SsNotAvailableErrorDescriptor binds the formal ERROR object MAP-Errors.ss-NotAvailable (X.880 §8.3).
func SsNotAvailableErrorDescriptor() ErrorDescriptor[mapvalues.SSNotAvailableParam] {
	return ErrorDescriptor[mapvalues.SSNotAvailableParam]{errorBinding[mapvalues.SSNotAvailableParam, mapvalues.ErrorInfo, mapvalues.MAPErrorCode]{code: mapvalues.SsNotAvailable, info: infoSsNotAvailableError, parameter: SSNotAvailableParamCodec()}}
}
func infoSsNotAvailableError() mapvalues.ErrorInfo {
	info, _ := mapvalues.LookupError(mapvalues.SsNotAvailable)
	return info
}

// SsSubscriptionViolationErrorDescriptor binds the formal ERROR object MAP-Errors.ss-SubscriptionViolation (X.880 §8.3).
func SsSubscriptionViolationErrorDescriptor() ErrorDescriptor[mapvalues.SSSubscriptionViolationParam] {
	return ErrorDescriptor[mapvalues.SSSubscriptionViolationParam]{errorBinding[mapvalues.SSSubscriptionViolationParam, mapvalues.ErrorInfo, mapvalues.MAPErrorCode]{code: mapvalues.SsSubscriptionViolation, info: infoSsSubscriptionViolationError, parameter: SSSubscriptionViolationParamCodec()}}
}
func infoSsSubscriptionViolationError() mapvalues.ErrorInfo {
	info, _ := mapvalues.LookupError(mapvalues.SsSubscriptionViolation)
	return info
}

// SubscriberBusyForMTSMSErrorDescriptor binds the formal ERROR object MAP-Errors.subscriberBusyForMT-SMS (X.880 §8.3).
func SubscriberBusyForMTSMSErrorDescriptor() ErrorDescriptor[mapvalues.SubBusyForMTSMSParam] {
	return ErrorDescriptor[mapvalues.SubBusyForMTSMSParam]{errorBinding[mapvalues.SubBusyForMTSMSParam, mapvalues.ErrorInfo, mapvalues.MAPErrorCode]{code: mapvalues.SubscriberBusyForMTSMS, info: infoSubscriberBusyForMTSMSError, parameter: SubBusyForMTSMSParamCodec()}}
}
func infoSubscriberBusyForMTSMSError() mapvalues.ErrorInfo {
	info, _ := mapvalues.LookupError(mapvalues.SubscriberBusyForMTSMS)
	return info
}

// SubsequentHandoverFailureErrorDescriptor binds the formal ERROR object MAP-Errors.subsequentHandoverFailure (X.880 §8.3).
func SubsequentHandoverFailureErrorDescriptor() ErrorDescriptor[mapvalues.NoParameter] {
	return ErrorDescriptor[mapvalues.NoParameter]{errorBinding[mapvalues.NoParameter, mapvalues.ErrorInfo, mapvalues.MAPErrorCode]{code: mapvalues.SubsequentHandoverFailure, info: infoSubsequentHandoverFailureError, parameter: mapvalues.ValueCodec[mapvalues.NoParameter]{}}}
}
func infoSubsequentHandoverFailureError() mapvalues.ErrorInfo {
	info, _ := mapvalues.LookupError(mapvalues.SubsequentHandoverFailure)
	return info
}

// SystemFailureErrorDescriptor binds the formal ERROR object MAP-Errors.systemFailure (X.880 §8.3).
func SystemFailureErrorDescriptor() ErrorDescriptor[mapvalues.SystemFailureParam] {
	return ErrorDescriptor[mapvalues.SystemFailureParam]{errorBinding[mapvalues.SystemFailureParam, mapvalues.ErrorInfo, mapvalues.MAPErrorCode]{code: mapvalues.SystemFailure, info: infoSystemFailureError, parameter: SystemFailureParamCodec()}}
}
func infoSystemFailureError() mapvalues.ErrorInfo {
	info, _ := mapvalues.LookupError(mapvalues.SystemFailure)
	return info
}

// TargetCellOutsideGroupCallAreaErrorDescriptor binds the formal ERROR object MAP-Errors.targetCellOutsideGroupCallArea (X.880 §8.3).
func TargetCellOutsideGroupCallAreaErrorDescriptor() ErrorDescriptor[mapvalues.TargetCellOutsideGCAParam] {
	return ErrorDescriptor[mapvalues.TargetCellOutsideGCAParam]{errorBinding[mapvalues.TargetCellOutsideGCAParam, mapvalues.ErrorInfo, mapvalues.MAPErrorCode]{code: mapvalues.TargetCellOutsideGroupCallArea, info: infoTargetCellOutsideGroupCallAreaError, parameter: TargetCellOutsideGCAParamCodec()}}
}
func infoTargetCellOutsideGroupCallAreaError() mapvalues.ErrorInfo {
	info, _ := mapvalues.LookupError(mapvalues.TargetCellOutsideGroupCallArea)
	return info
}

// TeleserviceNotProvisionedErrorDescriptor binds the formal ERROR object MAP-Errors.teleserviceNotProvisioned (X.880 §8.3).
func TeleserviceNotProvisionedErrorDescriptor() ErrorDescriptor[mapvalues.TeleservNotProvParam] {
	return ErrorDescriptor[mapvalues.TeleservNotProvParam]{errorBinding[mapvalues.TeleservNotProvParam, mapvalues.ErrorInfo, mapvalues.MAPErrorCode]{code: mapvalues.TeleserviceNotProvisioned, info: infoTeleserviceNotProvisionedError, parameter: TeleservNotProvParamCodec()}}
}
func infoTeleserviceNotProvisionedError() mapvalues.ErrorInfo {
	info, _ := mapvalues.LookupError(mapvalues.TeleserviceNotProvisioned)
	return info
}

// TracingBufferFullErrorDescriptor binds the formal ERROR object MAP-Errors.tracingBufferFull (X.880 §8.3).
func TracingBufferFullErrorDescriptor() ErrorDescriptor[mapvalues.TracingBufferFullParam] {
	return ErrorDescriptor[mapvalues.TracingBufferFullParam]{errorBinding[mapvalues.TracingBufferFullParam, mapvalues.ErrorInfo, mapvalues.MAPErrorCode]{code: mapvalues.TracingBufferFull, info: infoTracingBufferFullError, parameter: TracingBufferFullParamCodec()}}
}
func infoTracingBufferFullError() mapvalues.ErrorInfo {
	info, _ := mapvalues.LookupError(mapvalues.TracingBufferFull)
	return info
}

// UnauthorizedLCSClientErrorDescriptor binds the formal ERROR object MAP-Errors.unauthorizedLCSClient (X.880 §8.3).
func UnauthorizedLCSClientErrorDescriptor() ErrorDescriptor[mapvalues.UnauthorizedLCSClientParam] {
	return ErrorDescriptor[mapvalues.UnauthorizedLCSClientParam]{errorBinding[mapvalues.UnauthorizedLCSClientParam, mapvalues.ErrorInfo, mapvalues.MAPErrorCode]{code: mapvalues.UnauthorizedLCSClient, info: infoUnauthorizedLCSClientError, parameter: UnauthorizedLCSClientParamCodec()}}
}
func infoUnauthorizedLCSClientError() mapvalues.ErrorInfo {
	info, _ := mapvalues.LookupError(mapvalues.UnauthorizedLCSClient)
	return info
}

// UnauthorizedRequestingNetworkErrorDescriptor binds the formal ERROR object MAP-Errors.unauthorizedRequestingNetwork (X.880 §8.3).
func UnauthorizedRequestingNetworkErrorDescriptor() ErrorDescriptor[mapvalues.UnauthorizedRequestingNetworkParam] {
	return ErrorDescriptor[mapvalues.UnauthorizedRequestingNetworkParam]{errorBinding[mapvalues.UnauthorizedRequestingNetworkParam, mapvalues.ErrorInfo, mapvalues.MAPErrorCode]{code: mapvalues.UnauthorizedRequestingNetwork, info: infoUnauthorizedRequestingNetworkError, parameter: UnauthorizedRequestingNetworkParamCodec()}}
}
func infoUnauthorizedRequestingNetworkError() mapvalues.ErrorInfo {
	info, _ := mapvalues.LookupError(mapvalues.UnauthorizedRequestingNetwork)
	return info
}

// UnexpectedDataValueErrorDescriptor binds the formal ERROR object MAP-Errors.unexpectedDataValue (X.880 §8.3).
func UnexpectedDataValueErrorDescriptor() ErrorDescriptor[mapvalues.UnexpectedDataParam] {
	return ErrorDescriptor[mapvalues.UnexpectedDataParam]{errorBinding[mapvalues.UnexpectedDataParam, mapvalues.ErrorInfo, mapvalues.MAPErrorCode]{code: mapvalues.UnexpectedDataValue, info: infoUnexpectedDataValueError, parameter: UnexpectedDataParamCodec()}}
}
func infoUnexpectedDataValueError() mapvalues.ErrorInfo {
	info, _ := mapvalues.LookupError(mapvalues.UnexpectedDataValue)
	return info
}

// UnidentifiedSubscriberErrorDescriptor binds the formal ERROR object MAP-Errors.unidentifiedSubscriber (X.880 §8.3).
func UnidentifiedSubscriberErrorDescriptor() ErrorDescriptor[mapvalues.UnidentifiedSubParam] {
	return ErrorDescriptor[mapvalues.UnidentifiedSubParam]{errorBinding[mapvalues.UnidentifiedSubParam, mapvalues.ErrorInfo, mapvalues.MAPErrorCode]{code: mapvalues.UnidentifiedSubscriber, info: infoUnidentifiedSubscriberError, parameter: UnidentifiedSubParamCodec()}}
}
func infoUnidentifiedSubscriberError() mapvalues.ErrorInfo {
	info, _ := mapvalues.LookupError(mapvalues.UnidentifiedSubscriber)
	return info
}

// UnknownAlphabetErrorDescriptor binds the formal ERROR object MAP-Errors.unknownAlphabet (X.880 §8.3).
func UnknownAlphabetErrorDescriptor() ErrorDescriptor[mapvalues.NoParameter] {
	return ErrorDescriptor[mapvalues.NoParameter]{errorBinding[mapvalues.NoParameter, mapvalues.ErrorInfo, mapvalues.MAPErrorCode]{code: mapvalues.UnknownAlphabet, info: infoUnknownAlphabetError, parameter: mapvalues.ValueCodec[mapvalues.NoParameter]{}}}
}
func infoUnknownAlphabetError() mapvalues.ErrorInfo {
	info, _ := mapvalues.LookupError(mapvalues.UnknownAlphabet)
	return info
}

// UnknownEquipmentErrorDescriptor binds the formal ERROR object MAP-Errors.unknownEquipment (X.880 §8.3).
func UnknownEquipmentErrorDescriptor() ErrorDescriptor[mapvalues.NoParameter] {
	return ErrorDescriptor[mapvalues.NoParameter]{errorBinding[mapvalues.NoParameter, mapvalues.ErrorInfo, mapvalues.MAPErrorCode]{code: mapvalues.UnknownEquipment, info: infoUnknownEquipmentError, parameter: mapvalues.ValueCodec[mapvalues.NoParameter]{}}}
}
func infoUnknownEquipmentError() mapvalues.ErrorInfo {
	info, _ := mapvalues.LookupError(mapvalues.UnknownEquipment)
	return info
}

// UnknownMSCErrorDescriptor binds the formal ERROR object MAP-Errors.unknownMSC (X.880 §8.3).
func UnknownMSCErrorDescriptor() ErrorDescriptor[mapvalues.NoParameter] {
	return ErrorDescriptor[mapvalues.NoParameter]{errorBinding[mapvalues.NoParameter, mapvalues.ErrorInfo, mapvalues.MAPErrorCode]{code: mapvalues.UnknownMSC, info: infoUnknownMSCError, parameter: mapvalues.ValueCodec[mapvalues.NoParameter]{}}}
}
func infoUnknownMSCError() mapvalues.ErrorInfo {
	info, _ := mapvalues.LookupError(mapvalues.UnknownMSC)
	return info
}

// UnknownOrUnreachableLCSClientErrorDescriptor binds the formal ERROR object MAP-Errors.unknownOrUnreachableLCSClient (X.880 §8.3).
func UnknownOrUnreachableLCSClientErrorDescriptor() ErrorDescriptor[mapvalues.UnknownOrUnreachableLCSClientParam] {
	return ErrorDescriptor[mapvalues.UnknownOrUnreachableLCSClientParam]{errorBinding[mapvalues.UnknownOrUnreachableLCSClientParam, mapvalues.ErrorInfo, mapvalues.MAPErrorCode]{code: mapvalues.UnknownOrUnreachableLCSClient, info: infoUnknownOrUnreachableLCSClientError, parameter: UnknownOrUnreachableLCSClientParamCodec()}}
}
func infoUnknownOrUnreachableLCSClientError() mapvalues.ErrorInfo {
	info, _ := mapvalues.LookupError(mapvalues.UnknownOrUnreachableLCSClient)
	return info
}

// UnknownSubscriberErrorDescriptor binds the formal ERROR object MAP-Errors.unknownSubscriber (X.880 §8.3).
func UnknownSubscriberErrorDescriptor() ErrorDescriptor[mapvalues.UnknownSubscriberParam] {
	return ErrorDescriptor[mapvalues.UnknownSubscriberParam]{errorBinding[mapvalues.UnknownSubscriberParam, mapvalues.ErrorInfo, mapvalues.MAPErrorCode]{code: mapvalues.UnknownSubscriber, info: infoUnknownSubscriberError, parameter: UnknownSubscriberParamCodec()}}
}
func infoUnknownSubscriberError() mapvalues.ErrorInfo {
	info, _ := mapvalues.LookupError(mapvalues.UnknownSubscriber)
	return info
}

// UssdBusyErrorDescriptor binds the formal ERROR object MAP-Errors.ussd-Busy (X.880 §8.3).
func UssdBusyErrorDescriptor() ErrorDescriptor[mapvalues.NoParameter] {
	return ErrorDescriptor[mapvalues.NoParameter]{errorBinding[mapvalues.NoParameter, mapvalues.ErrorInfo, mapvalues.MAPErrorCode]{code: mapvalues.UssdBusy, info: infoUssdBusyError, parameter: mapvalues.ValueCodec[mapvalues.NoParameter]{}}}
}
func infoUssdBusyError() mapvalues.ErrorInfo {
	info, _ := mapvalues.LookupError(mapvalues.UssdBusy)
	return info
}
func encodeMAPErrorMember[P any](code mapvalues.MAPErrorCode, value *mapvalues.ErrorValue[P], codec mapvalues.ValueCodec[P], opts ...ber.EncodeOption) (mapvalues.EncodedError, error) {
	data, present, err := encodeErrorParameter(value, codec, opts...)
	if err != nil {
		return mapvalues.EncodedError{}, err
	}
	return mapvalues.EncodedError{Code: code, Parameter: data, HasParameter: present}, nil
}

type Operation[A, R, E any] struct {
	code     mapvalues.MAPOperationCode
	info     func() mapvalues.OperationInfo
	argument mapvalues.ValueCodec[A]
	result   mapvalues.ValueCodec[R]
	decode   func(int64, []byte, bool, ...ber.DecodeOption) (E, error)
	encode   func(E, ...ber.EncodeOption) (mapvalues.EncodedError, error)
}

func (d Operation[A, R, E]) Code() mapvalues.MAPOperationCode { return d.code }
func (d Operation[A, R, E]) Info() mapvalues.OperationInfo {
	if d.info == nil {
		return mapvalues.OperationInfo{}
	}
	return d.info()
}
func (d Operation[A, R, E]) Argument() (mapvalues.ValueCodec[A], bool) {
	return d.argument, d.argument.Valid()
}
func (d Operation[A, R, E]) Result() (mapvalues.ValueCodec[R], bool) {
	return d.result, d.result.Valid()
}
func (d Operation[A, R, E]) DecodeError(code mapvalues.MAPErrorCode, data []byte, present bool, opts ...ber.DecodeOption) (E, error) {
	if d.decode == nil {
		var zero E
		return zero, ber.ErrInvalidBinding
	}
	return d.decode(int64(code), data, present, opts...)
}
func (d Operation[A, R, E]) EncodeError(v E, opts ...ber.EncodeOption) (mapvalues.EncodedError, error) {
	if d.encode == nil {
		return mapvalues.EncodedError{}, ber.ErrInvalidBinding
	}
	return d.encode(v, opts...)
}
func infoActivateSSOperation() mapvalues.OperationInfo {
	info, _ := mapvalues.LookupOperation(mapvalues.ActivateSS)
	return info
}

// ActivateSSOperation binds the formal object in TS 29.002 V19.1.0 §17.6.4 (X.880 §§8.2–8.3).
func ActivateSSOperation() Operation[mapvalues.SSForBSCode, mapvalues.SSInfo, mapvalues.ActivateSSErrors] {
	return Operation[mapvalues.SSForBSCode, mapvalues.SSInfo, mapvalues.ActivateSSErrors]{code: mapvalues.ActivateSS, info: infoActivateSSOperation, argument: SSForBSCodeCodec(), result: SSInfoCodec(), decode: decodeActivateSSError, encode: encodeActivateSSError}
}
func decodeActivateSSError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (mapvalues.ActivateSSErrors, error) {
	switch code {
	case 34:
		p, err := decodeErrorParameter(data, present, SystemFailureParamCodec(), opts...)
		if err != nil {
			return mapvalues.ActivateSSErrors{}, err
		}
		return mapvalues.ActivateSSErrors{SystemFailure: p}, nil
	case 35:
		p, err := decodeErrorParameter(data, present, DataMissingParamCodec(), opts...)
		if err != nil {
			return mapvalues.ActivateSSErrors{}, err
		}
		return mapvalues.ActivateSSErrors{DataMissing: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return mapvalues.ActivateSSErrors{}, err
		}
		return mapvalues.ActivateSSErrors{UnexpectedDataValue: p}, nil
	case 10:
		p, err := decodeErrorParameter(data, present, BearerServNotProvParamCodec(), opts...)
		if err != nil {
			return mapvalues.ActivateSSErrors{}, err
		}
		return mapvalues.ActivateSSErrors{BearerServiceNotProvisioned: p}, nil
	case 11:
		p, err := decodeErrorParameter(data, present, TeleservNotProvParamCodec(), opts...)
		if err != nil {
			return mapvalues.ActivateSSErrors{}, err
		}
		return mapvalues.ActivateSSErrors{TeleserviceNotProvisioned: p}, nil
	case 13:
		p, err := decodeErrorParameter(data, present, CallBarredParamCodec(), opts...)
		if err != nil {
			return mapvalues.ActivateSSErrors{}, err
		}
		return mapvalues.ActivateSSErrors{CallBarred: p}, nil
	case 16:
		p, err := decodeErrorParameter(data, present, IllegalSSOperationParamCodec(), opts...)
		if err != nil {
			return mapvalues.ActivateSSErrors{}, err
		}
		return mapvalues.ActivateSSErrors{IllegalSSOperation: p}, nil
	case 17:
		p, err := decodeErrorParameter(data, present, SSStatusCodec(), opts...)
		if err != nil {
			return mapvalues.ActivateSSErrors{}, err
		}
		return mapvalues.ActivateSSErrors{SsErrorStatus: p}, nil
	case 19:
		p, err := decodeErrorParameter(data, present, SSSubscriptionViolationParamCodec(), opts...)
		if err != nil {
			return mapvalues.ActivateSSErrors{}, err
		}
		return mapvalues.ActivateSSErrors{SsSubscriptionViolation: p}, nil
	case 20:
		p, err := decodeErrorParameter(data, present, SSIncompatibilityCauseCodec(), opts...)
		if err != nil {
			return mapvalues.ActivateSSErrors{}, err
		}
		return mapvalues.ActivateSSErrors{SsIncompatibility: p}, nil
	case 38:
		p, err := decodeErrorParameter(data, present, mapvalues.ValueCodec[mapvalues.NoParameter]{}, opts...)
		if err != nil {
			return mapvalues.ActivateSSErrors{}, err
		}
		return mapvalues.ActivateSSErrors{NegativePWCheck: p}, nil
	case 43:
		p, err := decodeErrorParameter(data, present, mapvalues.ValueCodec[mapvalues.NoParameter]{}, opts...)
		if err != nil {
			return mapvalues.ActivateSSErrors{}, err
		}
		return mapvalues.ActivateSSErrors{NumberOfPWAttemptsViolation: p}, nil
	default:
		return mapvalues.ActivateSSErrors{}, fmt.Errorf("%w: error code %d is not in activateSS ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeActivateSSError(value mapvalues.ActivateSSErrors, opts ...ber.EncodeOption) (mapvalues.EncodedError, error) {
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
		return mapvalues.EncodedError{}, fmt.Errorf("%w: exactly one activateSS error arm is required", ber.ErrInvalidBinding)
	}
	if value.SystemFailure != nil {
		return encodeMAPErrorMember(mapvalues.SystemFailure, value.SystemFailure, SystemFailureParamCodec(), opts...)
	}
	if value.DataMissing != nil {
		return encodeMAPErrorMember(mapvalues.DataMissing, value.DataMissing, DataMissingParamCodec(), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(mapvalues.UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	if value.BearerServiceNotProvisioned != nil {
		return encodeMAPErrorMember(mapvalues.BearerServiceNotProvisioned, value.BearerServiceNotProvisioned, BearerServNotProvParamCodec(), opts...)
	}
	if value.TeleserviceNotProvisioned != nil {
		return encodeMAPErrorMember(mapvalues.TeleserviceNotProvisioned, value.TeleserviceNotProvisioned, TeleservNotProvParamCodec(), opts...)
	}
	if value.CallBarred != nil {
		return encodeMAPErrorMember(mapvalues.CallBarred, value.CallBarred, CallBarredParamCodec(), opts...)
	}
	if value.IllegalSSOperation != nil {
		return encodeMAPErrorMember(mapvalues.IllegalSSOperation, value.IllegalSSOperation, IllegalSSOperationParamCodec(), opts...)
	}
	if value.SsErrorStatus != nil {
		return encodeMAPErrorMember(mapvalues.SsErrorStatus, value.SsErrorStatus, SSStatusCodec(), opts...)
	}
	if value.SsSubscriptionViolation != nil {
		return encodeMAPErrorMember(mapvalues.SsSubscriptionViolation, value.SsSubscriptionViolation, SSSubscriptionViolationParamCodec(), opts...)
	}
	if value.SsIncompatibility != nil {
		return encodeMAPErrorMember(mapvalues.SsIncompatibility, value.SsIncompatibility, SSIncompatibilityCauseCodec(), opts...)
	}
	if value.NegativePWCheck != nil {
		return encodeMAPErrorMember(mapvalues.NegativePWCheck, value.NegativePWCheck, mapvalues.ValueCodec[mapvalues.NoParameter]{}, opts...)
	}
	if value.NumberOfPWAttemptsViolation != nil {
		return encodeMAPErrorMember(mapvalues.NumberOfPWAttemptsViolation, value.NumberOfPWAttemptsViolation, mapvalues.ValueCodec[mapvalues.NoParameter]{}, opts...)
	}
	return mapvalues.EncodedError{}, fmt.Errorf("%w: no selected activateSS error", ber.ErrInvalidBinding)
}
func infoActivateTraceModeOperation() mapvalues.OperationInfo {
	info, _ := mapvalues.LookupOperation(mapvalues.ActivateTraceMode)
	return info
}

// ActivateTraceModeOperation binds the formal object in TS 29.002 V19.1.0 §17.6.2 (X.880 §§8.2–8.3).
func ActivateTraceModeOperation() Operation[mapvalues.ActivateTraceModeArg, mapvalues.ActivateTraceModeRes, mapvalues.ActivateTraceModeErrors] {
	return Operation[mapvalues.ActivateTraceModeArg, mapvalues.ActivateTraceModeRes, mapvalues.ActivateTraceModeErrors]{code: mapvalues.ActivateTraceMode, info: infoActivateTraceModeOperation, argument: ActivateTraceModeArgCodec(), result: ActivateTraceModeResCodec(), decode: decodeActivateTraceModeError, encode: encodeActivateTraceModeError}
}
func decodeActivateTraceModeError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (mapvalues.ActivateTraceModeErrors, error) {
	switch code {
	case 34:
		p, err := decodeErrorParameter(data, present, SystemFailureParamCodec(), opts...)
		if err != nil {
			return mapvalues.ActivateTraceModeErrors{}, err
		}
		return mapvalues.ActivateTraceModeErrors{SystemFailure: p}, nil
	case 35:
		p, err := decodeErrorParameter(data, present, DataMissingParamCodec(), opts...)
		if err != nil {
			return mapvalues.ActivateTraceModeErrors{}, err
		}
		return mapvalues.ActivateTraceModeErrors{DataMissing: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return mapvalues.ActivateTraceModeErrors{}, err
		}
		return mapvalues.ActivateTraceModeErrors{UnexpectedDataValue: p}, nil
	case 21:
		p, err := decodeErrorParameter(data, present, FacilityNotSupParamCodec(), opts...)
		if err != nil {
			return mapvalues.ActivateTraceModeErrors{}, err
		}
		return mapvalues.ActivateTraceModeErrors{FacilityNotSupported: p}, nil
	case 5:
		p, err := decodeErrorParameter(data, present, UnidentifiedSubParamCodec(), opts...)
		if err != nil {
			return mapvalues.ActivateTraceModeErrors{}, err
		}
		return mapvalues.ActivateTraceModeErrors{UnidentifiedSubscriber: p}, nil
	case 40:
		p, err := decodeErrorParameter(data, present, TracingBufferFullParamCodec(), opts...)
		if err != nil {
			return mapvalues.ActivateTraceModeErrors{}, err
		}
		return mapvalues.ActivateTraceModeErrors{TracingBufferFull: p}, nil
	default:
		return mapvalues.ActivateTraceModeErrors{}, fmt.Errorf("%w: error code %d is not in activateTraceMode ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeActivateTraceModeError(value mapvalues.ActivateTraceModeErrors, opts ...ber.EncodeOption) (mapvalues.EncodedError, error) {
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
		return mapvalues.EncodedError{}, fmt.Errorf("%w: exactly one activateTraceMode error arm is required", ber.ErrInvalidBinding)
	}
	if value.SystemFailure != nil {
		return encodeMAPErrorMember(mapvalues.SystemFailure, value.SystemFailure, SystemFailureParamCodec(), opts...)
	}
	if value.DataMissing != nil {
		return encodeMAPErrorMember(mapvalues.DataMissing, value.DataMissing, DataMissingParamCodec(), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(mapvalues.UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	if value.FacilityNotSupported != nil {
		return encodeMAPErrorMember(mapvalues.FacilityNotSupported, value.FacilityNotSupported, FacilityNotSupParamCodec(), opts...)
	}
	if value.UnidentifiedSubscriber != nil {
		return encodeMAPErrorMember(mapvalues.UnidentifiedSubscriber, value.UnidentifiedSubscriber, UnidentifiedSubParamCodec(), opts...)
	}
	if value.TracingBufferFull != nil {
		return encodeMAPErrorMember(mapvalues.TracingBufferFull, value.TracingBufferFull, TracingBufferFullParamCodec(), opts...)
	}
	return mapvalues.EncodedError{}, fmt.Errorf("%w: no selected activateTraceMode error", ber.ErrInvalidBinding)
}
func infoAlertServiceCentreOperation() mapvalues.OperationInfo {
	info, _ := mapvalues.LookupOperation(mapvalues.AlertServiceCentre)
	return info
}

// AlertServiceCentreOperation binds the formal object in TS 29.002 V19.1.0 §17.6.5 (X.880 §§8.2–8.3).
func AlertServiceCentreOperation() Operation[mapvalues.AlertServiceCentreArg, mapvalues.NoParameter, mapvalues.AlertServiceCentreErrors] {
	return Operation[mapvalues.AlertServiceCentreArg, mapvalues.NoParameter, mapvalues.AlertServiceCentreErrors]{code: mapvalues.AlertServiceCentre, info: infoAlertServiceCentreOperation, argument: AlertServiceCentreArgCodec(), result: mapvalues.ValueCodec[mapvalues.NoParameter]{}, decode: decodeAlertServiceCentreError, encode: encodeAlertServiceCentreError}
}
func decodeAlertServiceCentreError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (mapvalues.AlertServiceCentreErrors, error) {
	switch code {
	case 34:
		p, err := decodeErrorParameter(data, present, SystemFailureParamCodec(), opts...)
		if err != nil {
			return mapvalues.AlertServiceCentreErrors{}, err
		}
		return mapvalues.AlertServiceCentreErrors{SystemFailure: p}, nil
	case 35:
		p, err := decodeErrorParameter(data, present, DataMissingParamCodec(), opts...)
		if err != nil {
			return mapvalues.AlertServiceCentreErrors{}, err
		}
		return mapvalues.AlertServiceCentreErrors{DataMissing: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return mapvalues.AlertServiceCentreErrors{}, err
		}
		return mapvalues.AlertServiceCentreErrors{UnexpectedDataValue: p}, nil
	default:
		return mapvalues.AlertServiceCentreErrors{}, fmt.Errorf("%w: error code %d is not in alertServiceCentre ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeAlertServiceCentreError(value mapvalues.AlertServiceCentreErrors, opts ...ber.EncodeOption) (mapvalues.EncodedError, error) {
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
		return mapvalues.EncodedError{}, fmt.Errorf("%w: exactly one alertServiceCentre error arm is required", ber.ErrInvalidBinding)
	}
	if value.SystemFailure != nil {
		return encodeMAPErrorMember(mapvalues.SystemFailure, value.SystemFailure, SystemFailureParamCodec(), opts...)
	}
	if value.DataMissing != nil {
		return encodeMAPErrorMember(mapvalues.DataMissing, value.DataMissing, DataMissingParamCodec(), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(mapvalues.UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	return mapvalues.EncodedError{}, fmt.Errorf("%w: no selected alertServiceCentre error", ber.ErrInvalidBinding)
}
func infoAnyTimeInterrogationOperation() mapvalues.OperationInfo {
	info, _ := mapvalues.LookupOperation(mapvalues.AnyTimeInterrogation)
	return info
}

// AnyTimeInterrogationOperation binds the formal object in TS 29.002 V19.1.0 §17.6.1 (X.880 §§8.2–8.3).
func AnyTimeInterrogationOperation() Operation[mapvalues.AnyTimeInterrogationArg, mapvalues.AnyTimeInterrogationRes, mapvalues.AnyTimeInterrogationErrors] {
	return Operation[mapvalues.AnyTimeInterrogationArg, mapvalues.AnyTimeInterrogationRes, mapvalues.AnyTimeInterrogationErrors]{code: mapvalues.AnyTimeInterrogation, info: infoAnyTimeInterrogationOperation, argument: AnyTimeInterrogationArgCodec(), result: AnyTimeInterrogationResCodec(), decode: decodeAnyTimeInterrogationError, encode: encodeAnyTimeInterrogationError}
}
func decodeAnyTimeInterrogationError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (mapvalues.AnyTimeInterrogationErrors, error) {
	switch code {
	case 34:
		p, err := decodeErrorParameter(data, present, SystemFailureParamCodec(), opts...)
		if err != nil {
			return mapvalues.AnyTimeInterrogationErrors{}, err
		}
		return mapvalues.AnyTimeInterrogationErrors{SystemFailure: p}, nil
	case 49:
		p, err := decodeErrorParameter(data, present, ATINotAllowedParamCodec(), opts...)
		if err != nil {
			return mapvalues.AnyTimeInterrogationErrors{}, err
		}
		return mapvalues.AnyTimeInterrogationErrors{AtiNotAllowed: p}, nil
	case 35:
		p, err := decodeErrorParameter(data, present, DataMissingParamCodec(), opts...)
		if err != nil {
			return mapvalues.AnyTimeInterrogationErrors{}, err
		}
		return mapvalues.AnyTimeInterrogationErrors{DataMissing: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return mapvalues.AnyTimeInterrogationErrors{}, err
		}
		return mapvalues.AnyTimeInterrogationErrors{UnexpectedDataValue: p}, nil
	case 1:
		p, err := decodeErrorParameter(data, present, UnknownSubscriberParamCodec(), opts...)
		if err != nil {
			return mapvalues.AnyTimeInterrogationErrors{}, err
		}
		return mapvalues.AnyTimeInterrogationErrors{UnknownSubscriber: p}, nil
	default:
		return mapvalues.AnyTimeInterrogationErrors{}, fmt.Errorf("%w: error code %d is not in anyTimeInterrogation ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeAnyTimeInterrogationError(value mapvalues.AnyTimeInterrogationErrors, opts ...ber.EncodeOption) (mapvalues.EncodedError, error) {
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
		return mapvalues.EncodedError{}, fmt.Errorf("%w: exactly one anyTimeInterrogation error arm is required", ber.ErrInvalidBinding)
	}
	if value.SystemFailure != nil {
		return encodeMAPErrorMember(mapvalues.SystemFailure, value.SystemFailure, SystemFailureParamCodec(), opts...)
	}
	if value.AtiNotAllowed != nil {
		return encodeMAPErrorMember(mapvalues.AtiNotAllowed, value.AtiNotAllowed, ATINotAllowedParamCodec(), opts...)
	}
	if value.DataMissing != nil {
		return encodeMAPErrorMember(mapvalues.DataMissing, value.DataMissing, DataMissingParamCodec(), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(mapvalues.UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	if value.UnknownSubscriber != nil {
		return encodeMAPErrorMember(mapvalues.UnknownSubscriber, value.UnknownSubscriber, UnknownSubscriberParamCodec(), opts...)
	}
	return mapvalues.EncodedError{}, fmt.Errorf("%w: no selected anyTimeInterrogation error", ber.ErrInvalidBinding)
}
func infoAnyTimeModificationOperation() mapvalues.OperationInfo {
	info, _ := mapvalues.LookupOperation(mapvalues.AnyTimeModification)
	return info
}

// AnyTimeModificationOperation binds the formal object in TS 29.002 V19.1.0 §17.6.1 (X.880 §§8.2–8.3).
func AnyTimeModificationOperation() Operation[mapvalues.AnyTimeModificationArg, mapvalues.AnyTimeModificationRes, mapvalues.AnyTimeModificationErrors] {
	return Operation[mapvalues.AnyTimeModificationArg, mapvalues.AnyTimeModificationRes, mapvalues.AnyTimeModificationErrors]{code: mapvalues.AnyTimeModification, info: infoAnyTimeModificationOperation, argument: AnyTimeModificationArgCodec(), result: AnyTimeModificationResCodec(), decode: decodeAnyTimeModificationError, encode: encodeAnyTimeModificationError}
}
func decodeAnyTimeModificationError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (mapvalues.AnyTimeModificationErrors, error) {
	switch code {
	case 61:
		p, err := decodeErrorParameter(data, present, ATMNotAllowedParamCodec(), opts...)
		if err != nil {
			return mapvalues.AnyTimeModificationErrors{}, err
		}
		return mapvalues.AnyTimeModificationErrors{AtmNotAllowed: p}, nil
	case 35:
		p, err := decodeErrorParameter(data, present, DataMissingParamCodec(), opts...)
		if err != nil {
			return mapvalues.AnyTimeModificationErrors{}, err
		}
		return mapvalues.AnyTimeModificationErrors{DataMissing: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return mapvalues.AnyTimeModificationErrors{}, err
		}
		return mapvalues.AnyTimeModificationErrors{UnexpectedDataValue: p}, nil
	case 1:
		p, err := decodeErrorParameter(data, present, UnknownSubscriberParamCodec(), opts...)
		if err != nil {
			return mapvalues.AnyTimeModificationErrors{}, err
		}
		return mapvalues.AnyTimeModificationErrors{UnknownSubscriber: p}, nil
	case 10:
		p, err := decodeErrorParameter(data, present, BearerServNotProvParamCodec(), opts...)
		if err != nil {
			return mapvalues.AnyTimeModificationErrors{}, err
		}
		return mapvalues.AnyTimeModificationErrors{BearerServiceNotProvisioned: p}, nil
	case 11:
		p, err := decodeErrorParameter(data, present, TeleservNotProvParamCodec(), opts...)
		if err != nil {
			return mapvalues.AnyTimeModificationErrors{}, err
		}
		return mapvalues.AnyTimeModificationErrors{TeleserviceNotProvisioned: p}, nil
	case 13:
		p, err := decodeErrorParameter(data, present, CallBarredParamCodec(), opts...)
		if err != nil {
			return mapvalues.AnyTimeModificationErrors{}, err
		}
		return mapvalues.AnyTimeModificationErrors{CallBarred: p}, nil
	case 16:
		p, err := decodeErrorParameter(data, present, IllegalSSOperationParamCodec(), opts...)
		if err != nil {
			return mapvalues.AnyTimeModificationErrors{}, err
		}
		return mapvalues.AnyTimeModificationErrors{IllegalSSOperation: p}, nil
	case 19:
		p, err := decodeErrorParameter(data, present, SSSubscriptionViolationParamCodec(), opts...)
		if err != nil {
			return mapvalues.AnyTimeModificationErrors{}, err
		}
		return mapvalues.AnyTimeModificationErrors{SsSubscriptionViolation: p}, nil
	case 17:
		p, err := decodeErrorParameter(data, present, SSStatusCodec(), opts...)
		if err != nil {
			return mapvalues.AnyTimeModificationErrors{}, err
		}
		return mapvalues.AnyTimeModificationErrors{SsErrorStatus: p}, nil
	case 20:
		p, err := decodeErrorParameter(data, present, SSIncompatibilityCauseCodec(), opts...)
		if err != nil {
			return mapvalues.AnyTimeModificationErrors{}, err
		}
		return mapvalues.AnyTimeModificationErrors{SsIncompatibility: p}, nil
	case 62:
		p, err := decodeErrorParameter(data, present, InformationNotAvailableParamCodec(), opts...)
		if err != nil {
			return mapvalues.AnyTimeModificationErrors{}, err
		}
		return mapvalues.AnyTimeModificationErrors{InformationNotAvailable: p}, nil
	default:
		return mapvalues.AnyTimeModificationErrors{}, fmt.Errorf("%w: error code %d is not in anyTimeModification ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeAnyTimeModificationError(value mapvalues.AnyTimeModificationErrors, opts ...ber.EncodeOption) (mapvalues.EncodedError, error) {
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
		return mapvalues.EncodedError{}, fmt.Errorf("%w: exactly one anyTimeModification error arm is required", ber.ErrInvalidBinding)
	}
	if value.AtmNotAllowed != nil {
		return encodeMAPErrorMember(mapvalues.AtmNotAllowed, value.AtmNotAllowed, ATMNotAllowedParamCodec(), opts...)
	}
	if value.DataMissing != nil {
		return encodeMAPErrorMember(mapvalues.DataMissing, value.DataMissing, DataMissingParamCodec(), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(mapvalues.UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	if value.UnknownSubscriber != nil {
		return encodeMAPErrorMember(mapvalues.UnknownSubscriber, value.UnknownSubscriber, UnknownSubscriberParamCodec(), opts...)
	}
	if value.BearerServiceNotProvisioned != nil {
		return encodeMAPErrorMember(mapvalues.BearerServiceNotProvisioned, value.BearerServiceNotProvisioned, BearerServNotProvParamCodec(), opts...)
	}
	if value.TeleserviceNotProvisioned != nil {
		return encodeMAPErrorMember(mapvalues.TeleserviceNotProvisioned, value.TeleserviceNotProvisioned, TeleservNotProvParamCodec(), opts...)
	}
	if value.CallBarred != nil {
		return encodeMAPErrorMember(mapvalues.CallBarred, value.CallBarred, CallBarredParamCodec(), opts...)
	}
	if value.IllegalSSOperation != nil {
		return encodeMAPErrorMember(mapvalues.IllegalSSOperation, value.IllegalSSOperation, IllegalSSOperationParamCodec(), opts...)
	}
	if value.SsSubscriptionViolation != nil {
		return encodeMAPErrorMember(mapvalues.SsSubscriptionViolation, value.SsSubscriptionViolation, SSSubscriptionViolationParamCodec(), opts...)
	}
	if value.SsErrorStatus != nil {
		return encodeMAPErrorMember(mapvalues.SsErrorStatus, value.SsErrorStatus, SSStatusCodec(), opts...)
	}
	if value.SsIncompatibility != nil {
		return encodeMAPErrorMember(mapvalues.SsIncompatibility, value.SsIncompatibility, SSIncompatibilityCauseCodec(), opts...)
	}
	if value.InformationNotAvailable != nil {
		return encodeMAPErrorMember(mapvalues.InformationNotAvailable, value.InformationNotAvailable, InformationNotAvailableParamCodec(), opts...)
	}
	return mapvalues.EncodedError{}, fmt.Errorf("%w: no selected anyTimeModification error", ber.ErrInvalidBinding)
}
func infoAnyTimeSubscriptionInterrogationOperation() mapvalues.OperationInfo {
	info, _ := mapvalues.LookupOperation(mapvalues.AnyTimeSubscriptionInterrogation)
	return info
}

// AnyTimeSubscriptionInterrogationOperation binds the formal object in TS 29.002 V19.1.0 §17.6.1 (X.880 §§8.2–8.3).
func AnyTimeSubscriptionInterrogationOperation() Operation[mapvalues.AnyTimeSubscriptionInterrogationArg, mapvalues.AnyTimeSubscriptionInterrogationRes, mapvalues.AnyTimeSubscriptionInterrogationErrors] {
	return Operation[mapvalues.AnyTimeSubscriptionInterrogationArg, mapvalues.AnyTimeSubscriptionInterrogationRes, mapvalues.AnyTimeSubscriptionInterrogationErrors]{code: mapvalues.AnyTimeSubscriptionInterrogation, info: infoAnyTimeSubscriptionInterrogationOperation, argument: AnyTimeSubscriptionInterrogationArgCodec(), result: AnyTimeSubscriptionInterrogationResCodec(), decode: decodeAnyTimeSubscriptionInterrogationError, encode: encodeAnyTimeSubscriptionInterrogationError}
}
func decodeAnyTimeSubscriptionInterrogationError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (mapvalues.AnyTimeSubscriptionInterrogationErrors, error) {
	switch code {
	case 60:
		p, err := decodeErrorParameter(data, present, ATSINotAllowedParamCodec(), opts...)
		if err != nil {
			return mapvalues.AnyTimeSubscriptionInterrogationErrors{}, err
		}
		return mapvalues.AnyTimeSubscriptionInterrogationErrors{AtsiNotAllowed: p}, nil
	case 35:
		p, err := decodeErrorParameter(data, present, DataMissingParamCodec(), opts...)
		if err != nil {
			return mapvalues.AnyTimeSubscriptionInterrogationErrors{}, err
		}
		return mapvalues.AnyTimeSubscriptionInterrogationErrors{DataMissing: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return mapvalues.AnyTimeSubscriptionInterrogationErrors{}, err
		}
		return mapvalues.AnyTimeSubscriptionInterrogationErrors{UnexpectedDataValue: p}, nil
	case 1:
		p, err := decodeErrorParameter(data, present, UnknownSubscriberParamCodec(), opts...)
		if err != nil {
			return mapvalues.AnyTimeSubscriptionInterrogationErrors{}, err
		}
		return mapvalues.AnyTimeSubscriptionInterrogationErrors{UnknownSubscriber: p}, nil
	case 10:
		p, err := decodeErrorParameter(data, present, BearerServNotProvParamCodec(), opts...)
		if err != nil {
			return mapvalues.AnyTimeSubscriptionInterrogationErrors{}, err
		}
		return mapvalues.AnyTimeSubscriptionInterrogationErrors{BearerServiceNotProvisioned: p}, nil
	case 11:
		p, err := decodeErrorParameter(data, present, TeleservNotProvParamCodec(), opts...)
		if err != nil {
			return mapvalues.AnyTimeSubscriptionInterrogationErrors{}, err
		}
		return mapvalues.AnyTimeSubscriptionInterrogationErrors{TeleserviceNotProvisioned: p}, nil
	case 13:
		p, err := decodeErrorParameter(data, present, CallBarredParamCodec(), opts...)
		if err != nil {
			return mapvalues.AnyTimeSubscriptionInterrogationErrors{}, err
		}
		return mapvalues.AnyTimeSubscriptionInterrogationErrors{CallBarred: p}, nil
	case 16:
		p, err := decodeErrorParameter(data, present, IllegalSSOperationParamCodec(), opts...)
		if err != nil {
			return mapvalues.AnyTimeSubscriptionInterrogationErrors{}, err
		}
		return mapvalues.AnyTimeSubscriptionInterrogationErrors{IllegalSSOperation: p}, nil
	case 18:
		p, err := decodeErrorParameter(data, present, SSNotAvailableParamCodec(), opts...)
		if err != nil {
			return mapvalues.AnyTimeSubscriptionInterrogationErrors{}, err
		}
		return mapvalues.AnyTimeSubscriptionInterrogationErrors{SsNotAvailable: p}, nil
	case 62:
		p, err := decodeErrorParameter(data, present, InformationNotAvailableParamCodec(), opts...)
		if err != nil {
			return mapvalues.AnyTimeSubscriptionInterrogationErrors{}, err
		}
		return mapvalues.AnyTimeSubscriptionInterrogationErrors{InformationNotAvailable: p}, nil
	default:
		return mapvalues.AnyTimeSubscriptionInterrogationErrors{}, fmt.Errorf("%w: error code %d is not in anyTimeSubscriptionInterrogation ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeAnyTimeSubscriptionInterrogationError(value mapvalues.AnyTimeSubscriptionInterrogationErrors, opts ...ber.EncodeOption) (mapvalues.EncodedError, error) {
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
		return mapvalues.EncodedError{}, fmt.Errorf("%w: exactly one anyTimeSubscriptionInterrogation error arm is required", ber.ErrInvalidBinding)
	}
	if value.AtsiNotAllowed != nil {
		return encodeMAPErrorMember(mapvalues.AtsiNotAllowed, value.AtsiNotAllowed, ATSINotAllowedParamCodec(), opts...)
	}
	if value.DataMissing != nil {
		return encodeMAPErrorMember(mapvalues.DataMissing, value.DataMissing, DataMissingParamCodec(), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(mapvalues.UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	if value.UnknownSubscriber != nil {
		return encodeMAPErrorMember(mapvalues.UnknownSubscriber, value.UnknownSubscriber, UnknownSubscriberParamCodec(), opts...)
	}
	if value.BearerServiceNotProvisioned != nil {
		return encodeMAPErrorMember(mapvalues.BearerServiceNotProvisioned, value.BearerServiceNotProvisioned, BearerServNotProvParamCodec(), opts...)
	}
	if value.TeleserviceNotProvisioned != nil {
		return encodeMAPErrorMember(mapvalues.TeleserviceNotProvisioned, value.TeleserviceNotProvisioned, TeleservNotProvParamCodec(), opts...)
	}
	if value.CallBarred != nil {
		return encodeMAPErrorMember(mapvalues.CallBarred, value.CallBarred, CallBarredParamCodec(), opts...)
	}
	if value.IllegalSSOperation != nil {
		return encodeMAPErrorMember(mapvalues.IllegalSSOperation, value.IllegalSSOperation, IllegalSSOperationParamCodec(), opts...)
	}
	if value.SsNotAvailable != nil {
		return encodeMAPErrorMember(mapvalues.SsNotAvailable, value.SsNotAvailable, SSNotAvailableParamCodec(), opts...)
	}
	if value.InformationNotAvailable != nil {
		return encodeMAPErrorMember(mapvalues.InformationNotAvailable, value.InformationNotAvailable, InformationNotAvailableParamCodec(), opts...)
	}
	return mapvalues.EncodedError{}, fmt.Errorf("%w: no selected anyTimeSubscriptionInterrogation error", ber.ErrInvalidBinding)
}
func infoAuthenticationFailureReportOperation() mapvalues.OperationInfo {
	info, _ := mapvalues.LookupOperation(mapvalues.AuthenticationFailureReport)
	return info
}

// AuthenticationFailureReportOperation binds the formal object in TS 29.002 V19.1.0 §17.6.1 (X.880 §§8.2–8.3).
func AuthenticationFailureReportOperation() Operation[mapvalues.AuthenticationFailureReportArg, mapvalues.AuthenticationFailureReportRes, mapvalues.AuthenticationFailureReportErrors] {
	return Operation[mapvalues.AuthenticationFailureReportArg, mapvalues.AuthenticationFailureReportRes, mapvalues.AuthenticationFailureReportErrors]{code: mapvalues.AuthenticationFailureReport, info: infoAuthenticationFailureReportOperation, argument: AuthenticationFailureReportArgCodec(), result: AuthenticationFailureReportResCodec(), decode: decodeAuthenticationFailureReportError, encode: encodeAuthenticationFailureReportError}
}
func decodeAuthenticationFailureReportError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (mapvalues.AuthenticationFailureReportErrors, error) {
	switch code {
	case 34:
		p, err := decodeErrorParameter(data, present, SystemFailureParamCodec(), opts...)
		if err != nil {
			return mapvalues.AuthenticationFailureReportErrors{}, err
		}
		return mapvalues.AuthenticationFailureReportErrors{SystemFailure: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return mapvalues.AuthenticationFailureReportErrors{}, err
		}
		return mapvalues.AuthenticationFailureReportErrors{UnexpectedDataValue: p}, nil
	case 1:
		p, err := decodeErrorParameter(data, present, UnknownSubscriberParamCodec(), opts...)
		if err != nil {
			return mapvalues.AuthenticationFailureReportErrors{}, err
		}
		return mapvalues.AuthenticationFailureReportErrors{UnknownSubscriber: p}, nil
	default:
		return mapvalues.AuthenticationFailureReportErrors{}, fmt.Errorf("%w: error code %d is not in authenticationFailureReport ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeAuthenticationFailureReportError(value mapvalues.AuthenticationFailureReportErrors, opts ...ber.EncodeOption) (mapvalues.EncodedError, error) {
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
		return mapvalues.EncodedError{}, fmt.Errorf("%w: exactly one authenticationFailureReport error arm is required", ber.ErrInvalidBinding)
	}
	if value.SystemFailure != nil {
		return encodeMAPErrorMember(mapvalues.SystemFailure, value.SystemFailure, SystemFailureParamCodec(), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(mapvalues.UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	if value.UnknownSubscriber != nil {
		return encodeMAPErrorMember(mapvalues.UnknownSubscriber, value.UnknownSubscriber, UnknownSubscriberParamCodec(), opts...)
	}
	return mapvalues.EncodedError{}, fmt.Errorf("%w: no selected authenticationFailureReport error", ber.ErrInvalidBinding)
}
func infoCancelLocationOperation() mapvalues.OperationInfo {
	info, _ := mapvalues.LookupOperation(mapvalues.CancelLocation)
	return info
}

// CancelLocationOperation binds the formal object in TS 29.002 V19.1.0 §17.6.1 (X.880 §§8.2–8.3).
func CancelLocationOperation() Operation[mapvalues.CancelLocationArg, mapvalues.CancelLocationRes, mapvalues.CancelLocationErrors] {
	return Operation[mapvalues.CancelLocationArg, mapvalues.CancelLocationRes, mapvalues.CancelLocationErrors]{code: mapvalues.CancelLocation, info: infoCancelLocationOperation, argument: CancelLocationArgCodec(), result: CancelLocationResCodec(), decode: decodeCancelLocationError, encode: encodeCancelLocationError}
}
func decodeCancelLocationError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (mapvalues.CancelLocationErrors, error) {
	switch code {
	case 35:
		p, err := decodeErrorParameter(data, present, DataMissingParamCodec(), opts...)
		if err != nil {
			return mapvalues.CancelLocationErrors{}, err
		}
		return mapvalues.CancelLocationErrors{DataMissing: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return mapvalues.CancelLocationErrors{}, err
		}
		return mapvalues.CancelLocationErrors{UnexpectedDataValue: p}, nil
	default:
		return mapvalues.CancelLocationErrors{}, fmt.Errorf("%w: error code %d is not in cancelLocation ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeCancelLocationError(value mapvalues.CancelLocationErrors, opts ...ber.EncodeOption) (mapvalues.EncodedError, error) {
	selected := 0
	if value.DataMissing != nil {
		selected++
	}
	if value.UnexpectedDataValue != nil {
		selected++
	}
	if selected != 1 {
		return mapvalues.EncodedError{}, fmt.Errorf("%w: exactly one cancelLocation error arm is required", ber.ErrInvalidBinding)
	}
	if value.DataMissing != nil {
		return encodeMAPErrorMember(mapvalues.DataMissing, value.DataMissing, DataMissingParamCodec(), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(mapvalues.UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	return mapvalues.EncodedError{}, fmt.Errorf("%w: no selected cancelLocation error", ber.ErrInvalidBinding)
}
func infoCancelVcsgLocationOperation() mapvalues.OperationInfo {
	info, _ := mapvalues.LookupOperation(mapvalues.CancelVcsgLocation)
	return info
}

// CancelVcsgLocationOperation binds the formal object in TS 29.002 V19.1.0 §17.6.1 (X.880 §§8.2–8.3).
func CancelVcsgLocationOperation() Operation[mapvalues.CancelVcsgLocationArg, mapvalues.CancelVcsgLocationRes, mapvalues.CancelVcsgLocationErrors] {
	return Operation[mapvalues.CancelVcsgLocationArg, mapvalues.CancelVcsgLocationRes, mapvalues.CancelVcsgLocationErrors]{code: mapvalues.CancelVcsgLocation, info: infoCancelVcsgLocationOperation, argument: CancelVcsgLocationArgCodec(), result: CancelVcsgLocationResCodec(), decode: decodeCancelVcsgLocationError, encode: encodeCancelVcsgLocationError}
}
func decodeCancelVcsgLocationError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (mapvalues.CancelVcsgLocationErrors, error) {
	switch code {
	case 35:
		p, err := decodeErrorParameter(data, present, DataMissingParamCodec(), opts...)
		if err != nil {
			return mapvalues.CancelVcsgLocationErrors{}, err
		}
		return mapvalues.CancelVcsgLocationErrors{DataMissing: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return mapvalues.CancelVcsgLocationErrors{}, err
		}
		return mapvalues.CancelVcsgLocationErrors{UnexpectedDataValue: p}, nil
	default:
		return mapvalues.CancelVcsgLocationErrors{}, fmt.Errorf("%w: error code %d is not in cancelVcsgLocation ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeCancelVcsgLocationError(value mapvalues.CancelVcsgLocationErrors, opts ...ber.EncodeOption) (mapvalues.EncodedError, error) {
	selected := 0
	if value.DataMissing != nil {
		selected++
	}
	if value.UnexpectedDataValue != nil {
		selected++
	}
	if selected != 1 {
		return mapvalues.EncodedError{}, fmt.Errorf("%w: exactly one cancelVcsgLocation error arm is required", ber.ErrInvalidBinding)
	}
	if value.DataMissing != nil {
		return encodeMAPErrorMember(mapvalues.DataMissing, value.DataMissing, DataMissingParamCodec(), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(mapvalues.UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	return mapvalues.EncodedError{}, fmt.Errorf("%w: no selected cancelVcsgLocation error", ber.ErrInvalidBinding)
}
func infoCheckIMEIOperation() mapvalues.OperationInfo {
	info, _ := mapvalues.LookupOperation(mapvalues.CheckIMEI)
	return info
}

// CheckIMEIOperation binds the formal object in TS 29.002 V19.1.0 §17.6.1 (X.880 §§8.2–8.3).
func CheckIMEIOperation() Operation[mapvalues.CheckIMEIArg, mapvalues.CheckIMEIRes, mapvalues.CheckIMEIErrors] {
	return Operation[mapvalues.CheckIMEIArg, mapvalues.CheckIMEIRes, mapvalues.CheckIMEIErrors]{code: mapvalues.CheckIMEI, info: infoCheckIMEIOperation, argument: CheckIMEIArgCodec(), result: CheckIMEIResCodec(), decode: decodeCheckIMEIError, encode: encodeCheckIMEIError}
}
func decodeCheckIMEIError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (mapvalues.CheckIMEIErrors, error) {
	switch code {
	case 34:
		p, err := decodeErrorParameter(data, present, SystemFailureParamCodec(), opts...)
		if err != nil {
			return mapvalues.CheckIMEIErrors{}, err
		}
		return mapvalues.CheckIMEIErrors{SystemFailure: p}, nil
	case 35:
		p, err := decodeErrorParameter(data, present, DataMissingParamCodec(), opts...)
		if err != nil {
			return mapvalues.CheckIMEIErrors{}, err
		}
		return mapvalues.CheckIMEIErrors{DataMissing: p}, nil
	case 7:
		p, err := decodeErrorParameter(data, present, mapvalues.ValueCodec[mapvalues.NoParameter]{}, opts...)
		if err != nil {
			return mapvalues.CheckIMEIErrors{}, err
		}
		return mapvalues.CheckIMEIErrors{UnknownEquipment: p}, nil
	default:
		return mapvalues.CheckIMEIErrors{}, fmt.Errorf("%w: error code %d is not in checkIMEI ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeCheckIMEIError(value mapvalues.CheckIMEIErrors, opts ...ber.EncodeOption) (mapvalues.EncodedError, error) {
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
		return mapvalues.EncodedError{}, fmt.Errorf("%w: exactly one checkIMEI error arm is required", ber.ErrInvalidBinding)
	}
	if value.SystemFailure != nil {
		return encodeMAPErrorMember(mapvalues.SystemFailure, value.SystemFailure, SystemFailureParamCodec(), opts...)
	}
	if value.DataMissing != nil {
		return encodeMAPErrorMember(mapvalues.DataMissing, value.DataMissing, DataMissingParamCodec(), opts...)
	}
	if value.UnknownEquipment != nil {
		return encodeMAPErrorMember(mapvalues.UnknownEquipment, value.UnknownEquipment, mapvalues.ValueCodec[mapvalues.NoParameter]{}, opts...)
	}
	return mapvalues.EncodedError{}, fmt.Errorf("%w: no selected checkIMEI error", ber.ErrInvalidBinding)
}
func infoDeactivateSSOperation() mapvalues.OperationInfo {
	info, _ := mapvalues.LookupOperation(mapvalues.DeactivateSS)
	return info
}

// DeactivateSSOperation binds the formal object in TS 29.002 V19.1.0 §17.6.4 (X.880 §§8.2–8.3).
func DeactivateSSOperation() Operation[mapvalues.SSForBSCode, mapvalues.SSInfo, mapvalues.DeactivateSSErrors] {
	return Operation[mapvalues.SSForBSCode, mapvalues.SSInfo, mapvalues.DeactivateSSErrors]{code: mapvalues.DeactivateSS, info: infoDeactivateSSOperation, argument: SSForBSCodeCodec(), result: SSInfoCodec(), decode: decodeDeactivateSSError, encode: encodeDeactivateSSError}
}
func decodeDeactivateSSError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (mapvalues.DeactivateSSErrors, error) {
	switch code {
	case 34:
		p, err := decodeErrorParameter(data, present, SystemFailureParamCodec(), opts...)
		if err != nil {
			return mapvalues.DeactivateSSErrors{}, err
		}
		return mapvalues.DeactivateSSErrors{SystemFailure: p}, nil
	case 35:
		p, err := decodeErrorParameter(data, present, DataMissingParamCodec(), opts...)
		if err != nil {
			return mapvalues.DeactivateSSErrors{}, err
		}
		return mapvalues.DeactivateSSErrors{DataMissing: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return mapvalues.DeactivateSSErrors{}, err
		}
		return mapvalues.DeactivateSSErrors{UnexpectedDataValue: p}, nil
	case 10:
		p, err := decodeErrorParameter(data, present, BearerServNotProvParamCodec(), opts...)
		if err != nil {
			return mapvalues.DeactivateSSErrors{}, err
		}
		return mapvalues.DeactivateSSErrors{BearerServiceNotProvisioned: p}, nil
	case 11:
		p, err := decodeErrorParameter(data, present, TeleservNotProvParamCodec(), opts...)
		if err != nil {
			return mapvalues.DeactivateSSErrors{}, err
		}
		return mapvalues.DeactivateSSErrors{TeleserviceNotProvisioned: p}, nil
	case 13:
		p, err := decodeErrorParameter(data, present, CallBarredParamCodec(), opts...)
		if err != nil {
			return mapvalues.DeactivateSSErrors{}, err
		}
		return mapvalues.DeactivateSSErrors{CallBarred: p}, nil
	case 16:
		p, err := decodeErrorParameter(data, present, IllegalSSOperationParamCodec(), opts...)
		if err != nil {
			return mapvalues.DeactivateSSErrors{}, err
		}
		return mapvalues.DeactivateSSErrors{IllegalSSOperation: p}, nil
	case 17:
		p, err := decodeErrorParameter(data, present, SSStatusCodec(), opts...)
		if err != nil {
			return mapvalues.DeactivateSSErrors{}, err
		}
		return mapvalues.DeactivateSSErrors{SsErrorStatus: p}, nil
	case 19:
		p, err := decodeErrorParameter(data, present, SSSubscriptionViolationParamCodec(), opts...)
		if err != nil {
			return mapvalues.DeactivateSSErrors{}, err
		}
		return mapvalues.DeactivateSSErrors{SsSubscriptionViolation: p}, nil
	case 38:
		p, err := decodeErrorParameter(data, present, mapvalues.ValueCodec[mapvalues.NoParameter]{}, opts...)
		if err != nil {
			return mapvalues.DeactivateSSErrors{}, err
		}
		return mapvalues.DeactivateSSErrors{NegativePWCheck: p}, nil
	case 43:
		p, err := decodeErrorParameter(data, present, mapvalues.ValueCodec[mapvalues.NoParameter]{}, opts...)
		if err != nil {
			return mapvalues.DeactivateSSErrors{}, err
		}
		return mapvalues.DeactivateSSErrors{NumberOfPWAttemptsViolation: p}, nil
	default:
		return mapvalues.DeactivateSSErrors{}, fmt.Errorf("%w: error code %d is not in deactivateSS ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeDeactivateSSError(value mapvalues.DeactivateSSErrors, opts ...ber.EncodeOption) (mapvalues.EncodedError, error) {
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
		return mapvalues.EncodedError{}, fmt.Errorf("%w: exactly one deactivateSS error arm is required", ber.ErrInvalidBinding)
	}
	if value.SystemFailure != nil {
		return encodeMAPErrorMember(mapvalues.SystemFailure, value.SystemFailure, SystemFailureParamCodec(), opts...)
	}
	if value.DataMissing != nil {
		return encodeMAPErrorMember(mapvalues.DataMissing, value.DataMissing, DataMissingParamCodec(), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(mapvalues.UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	if value.BearerServiceNotProvisioned != nil {
		return encodeMAPErrorMember(mapvalues.BearerServiceNotProvisioned, value.BearerServiceNotProvisioned, BearerServNotProvParamCodec(), opts...)
	}
	if value.TeleserviceNotProvisioned != nil {
		return encodeMAPErrorMember(mapvalues.TeleserviceNotProvisioned, value.TeleserviceNotProvisioned, TeleservNotProvParamCodec(), opts...)
	}
	if value.CallBarred != nil {
		return encodeMAPErrorMember(mapvalues.CallBarred, value.CallBarred, CallBarredParamCodec(), opts...)
	}
	if value.IllegalSSOperation != nil {
		return encodeMAPErrorMember(mapvalues.IllegalSSOperation, value.IllegalSSOperation, IllegalSSOperationParamCodec(), opts...)
	}
	if value.SsErrorStatus != nil {
		return encodeMAPErrorMember(mapvalues.SsErrorStatus, value.SsErrorStatus, SSStatusCodec(), opts...)
	}
	if value.SsSubscriptionViolation != nil {
		return encodeMAPErrorMember(mapvalues.SsSubscriptionViolation, value.SsSubscriptionViolation, SSSubscriptionViolationParamCodec(), opts...)
	}
	if value.NegativePWCheck != nil {
		return encodeMAPErrorMember(mapvalues.NegativePWCheck, value.NegativePWCheck, mapvalues.ValueCodec[mapvalues.NoParameter]{}, opts...)
	}
	if value.NumberOfPWAttemptsViolation != nil {
		return encodeMAPErrorMember(mapvalues.NumberOfPWAttemptsViolation, value.NumberOfPWAttemptsViolation, mapvalues.ValueCodec[mapvalues.NoParameter]{}, opts...)
	}
	return mapvalues.EncodedError{}, fmt.Errorf("%w: no selected deactivateSS error", ber.ErrInvalidBinding)
}
func infoDeactivateTraceModeOperation() mapvalues.OperationInfo {
	info, _ := mapvalues.LookupOperation(mapvalues.DeactivateTraceMode)
	return info
}

// DeactivateTraceModeOperation binds the formal object in TS 29.002 V19.1.0 §17.6.2 (X.880 §§8.2–8.3).
func DeactivateTraceModeOperation() Operation[mapvalues.DeactivateTraceModeArg, mapvalues.DeactivateTraceModeRes, mapvalues.DeactivateTraceModeErrors] {
	return Operation[mapvalues.DeactivateTraceModeArg, mapvalues.DeactivateTraceModeRes, mapvalues.DeactivateTraceModeErrors]{code: mapvalues.DeactivateTraceMode, info: infoDeactivateTraceModeOperation, argument: DeactivateTraceModeArgCodec(), result: DeactivateTraceModeResCodec(), decode: decodeDeactivateTraceModeError, encode: encodeDeactivateTraceModeError}
}
func decodeDeactivateTraceModeError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (mapvalues.DeactivateTraceModeErrors, error) {
	switch code {
	case 34:
		p, err := decodeErrorParameter(data, present, SystemFailureParamCodec(), opts...)
		if err != nil {
			return mapvalues.DeactivateTraceModeErrors{}, err
		}
		return mapvalues.DeactivateTraceModeErrors{SystemFailure: p}, nil
	case 35:
		p, err := decodeErrorParameter(data, present, DataMissingParamCodec(), opts...)
		if err != nil {
			return mapvalues.DeactivateTraceModeErrors{}, err
		}
		return mapvalues.DeactivateTraceModeErrors{DataMissing: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return mapvalues.DeactivateTraceModeErrors{}, err
		}
		return mapvalues.DeactivateTraceModeErrors{UnexpectedDataValue: p}, nil
	case 21:
		p, err := decodeErrorParameter(data, present, FacilityNotSupParamCodec(), opts...)
		if err != nil {
			return mapvalues.DeactivateTraceModeErrors{}, err
		}
		return mapvalues.DeactivateTraceModeErrors{FacilityNotSupported: p}, nil
	case 5:
		p, err := decodeErrorParameter(data, present, UnidentifiedSubParamCodec(), opts...)
		if err != nil {
			return mapvalues.DeactivateTraceModeErrors{}, err
		}
		return mapvalues.DeactivateTraceModeErrors{UnidentifiedSubscriber: p}, nil
	default:
		return mapvalues.DeactivateTraceModeErrors{}, fmt.Errorf("%w: error code %d is not in deactivateTraceMode ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeDeactivateTraceModeError(value mapvalues.DeactivateTraceModeErrors, opts ...ber.EncodeOption) (mapvalues.EncodedError, error) {
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
		return mapvalues.EncodedError{}, fmt.Errorf("%w: exactly one deactivateTraceMode error arm is required", ber.ErrInvalidBinding)
	}
	if value.SystemFailure != nil {
		return encodeMAPErrorMember(mapvalues.SystemFailure, value.SystemFailure, SystemFailureParamCodec(), opts...)
	}
	if value.DataMissing != nil {
		return encodeMAPErrorMember(mapvalues.DataMissing, value.DataMissing, DataMissingParamCodec(), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(mapvalues.UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	if value.FacilityNotSupported != nil {
		return encodeMAPErrorMember(mapvalues.FacilityNotSupported, value.FacilityNotSupported, FacilityNotSupParamCodec(), opts...)
	}
	if value.UnidentifiedSubscriber != nil {
		return encodeMAPErrorMember(mapvalues.UnidentifiedSubscriber, value.UnidentifiedSubscriber, UnidentifiedSubParamCodec(), opts...)
	}
	return mapvalues.EncodedError{}, fmt.Errorf("%w: no selected deactivateTraceMode error", ber.ErrInvalidBinding)
}
func infoDeleteSubscriberDataOperation() mapvalues.OperationInfo {
	info, _ := mapvalues.LookupOperation(mapvalues.DeleteSubscriberData)
	return info
}

// DeleteSubscriberDataOperation binds the formal object in TS 29.002 V19.1.0 §17.6.1 (X.880 §§8.2–8.3).
func DeleteSubscriberDataOperation() Operation[mapvalues.DeleteSubscriberDataArg, mapvalues.DeleteSubscriberDataRes, mapvalues.DeleteSubscriberDataErrors] {
	return Operation[mapvalues.DeleteSubscriberDataArg, mapvalues.DeleteSubscriberDataRes, mapvalues.DeleteSubscriberDataErrors]{code: mapvalues.DeleteSubscriberData, info: infoDeleteSubscriberDataOperation, argument: DeleteSubscriberDataArgCodec(), result: DeleteSubscriberDataResCodec(), decode: decodeDeleteSubscriberDataError, encode: encodeDeleteSubscriberDataError}
}
func decodeDeleteSubscriberDataError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (mapvalues.DeleteSubscriberDataErrors, error) {
	switch code {
	case 35:
		p, err := decodeErrorParameter(data, present, DataMissingParamCodec(), opts...)
		if err != nil {
			return mapvalues.DeleteSubscriberDataErrors{}, err
		}
		return mapvalues.DeleteSubscriberDataErrors{DataMissing: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return mapvalues.DeleteSubscriberDataErrors{}, err
		}
		return mapvalues.DeleteSubscriberDataErrors{UnexpectedDataValue: p}, nil
	case 5:
		p, err := decodeErrorParameter(data, present, UnidentifiedSubParamCodec(), opts...)
		if err != nil {
			return mapvalues.DeleteSubscriberDataErrors{}, err
		}
		return mapvalues.DeleteSubscriberDataErrors{UnidentifiedSubscriber: p}, nil
	default:
		return mapvalues.DeleteSubscriberDataErrors{}, fmt.Errorf("%w: error code %d is not in deleteSubscriberData ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeDeleteSubscriberDataError(value mapvalues.DeleteSubscriberDataErrors, opts ...ber.EncodeOption) (mapvalues.EncodedError, error) {
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
		return mapvalues.EncodedError{}, fmt.Errorf("%w: exactly one deleteSubscriberData error arm is required", ber.ErrInvalidBinding)
	}
	if value.DataMissing != nil {
		return encodeMAPErrorMember(mapvalues.DataMissing, value.DataMissing, DataMissingParamCodec(), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(mapvalues.UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	if value.UnidentifiedSubscriber != nil {
		return encodeMAPErrorMember(mapvalues.UnidentifiedSubscriber, value.UnidentifiedSubscriber, UnidentifiedSubParamCodec(), opts...)
	}
	return mapvalues.EncodedError{}, fmt.Errorf("%w: no selected deleteSubscriberData error", ber.ErrInvalidBinding)
}
func infoEraseCCEntryOperation() mapvalues.OperationInfo {
	info, _ := mapvalues.LookupOperation(mapvalues.EraseCCEntry)
	return info
}

// EraseCCEntryOperation binds the formal object in TS 29.002 V19.1.0 §17.6.4 (X.880 §§8.2–8.3).
func EraseCCEntryOperation() Operation[mapvalues.EraseCCEntryArg, mapvalues.EraseCCEntryRes, mapvalues.EraseCCEntryErrors] {
	return Operation[mapvalues.EraseCCEntryArg, mapvalues.EraseCCEntryRes, mapvalues.EraseCCEntryErrors]{code: mapvalues.EraseCCEntry, info: infoEraseCCEntryOperation, argument: EraseCCEntryArgCodec(), result: EraseCCEntryResCodec(), decode: decodeEraseCCEntryError, encode: encodeEraseCCEntryError}
}
func decodeEraseCCEntryError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (mapvalues.EraseCCEntryErrors, error) {
	switch code {
	case 34:
		p, err := decodeErrorParameter(data, present, SystemFailureParamCodec(), opts...)
		if err != nil {
			return mapvalues.EraseCCEntryErrors{}, err
		}
		return mapvalues.EraseCCEntryErrors{SystemFailure: p}, nil
	case 35:
		p, err := decodeErrorParameter(data, present, DataMissingParamCodec(), opts...)
		if err != nil {
			return mapvalues.EraseCCEntryErrors{}, err
		}
		return mapvalues.EraseCCEntryErrors{DataMissing: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return mapvalues.EraseCCEntryErrors{}, err
		}
		return mapvalues.EraseCCEntryErrors{UnexpectedDataValue: p}, nil
	case 13:
		p, err := decodeErrorParameter(data, present, CallBarredParamCodec(), opts...)
		if err != nil {
			return mapvalues.EraseCCEntryErrors{}, err
		}
		return mapvalues.EraseCCEntryErrors{CallBarred: p}, nil
	case 16:
		p, err := decodeErrorParameter(data, present, IllegalSSOperationParamCodec(), opts...)
		if err != nil {
			return mapvalues.EraseCCEntryErrors{}, err
		}
		return mapvalues.EraseCCEntryErrors{IllegalSSOperation: p}, nil
	case 17:
		p, err := decodeErrorParameter(data, present, SSStatusCodec(), opts...)
		if err != nil {
			return mapvalues.EraseCCEntryErrors{}, err
		}
		return mapvalues.EraseCCEntryErrors{SsErrorStatus: p}, nil
	default:
		return mapvalues.EraseCCEntryErrors{}, fmt.Errorf("%w: error code %d is not in eraseCC-Entry ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeEraseCCEntryError(value mapvalues.EraseCCEntryErrors, opts ...ber.EncodeOption) (mapvalues.EncodedError, error) {
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
		return mapvalues.EncodedError{}, fmt.Errorf("%w: exactly one eraseCC-Entry error arm is required", ber.ErrInvalidBinding)
	}
	if value.SystemFailure != nil {
		return encodeMAPErrorMember(mapvalues.SystemFailure, value.SystemFailure, SystemFailureParamCodec(), opts...)
	}
	if value.DataMissing != nil {
		return encodeMAPErrorMember(mapvalues.DataMissing, value.DataMissing, DataMissingParamCodec(), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(mapvalues.UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	if value.CallBarred != nil {
		return encodeMAPErrorMember(mapvalues.CallBarred, value.CallBarred, CallBarredParamCodec(), opts...)
	}
	if value.IllegalSSOperation != nil {
		return encodeMAPErrorMember(mapvalues.IllegalSSOperation, value.IllegalSSOperation, IllegalSSOperationParamCodec(), opts...)
	}
	if value.SsErrorStatus != nil {
		return encodeMAPErrorMember(mapvalues.SsErrorStatus, value.SsErrorStatus, SSStatusCodec(), opts...)
	}
	return mapvalues.EncodedError{}, fmt.Errorf("%w: no selected eraseCC-Entry error", ber.ErrInvalidBinding)
}
func infoEraseSSOperation() mapvalues.OperationInfo {
	info, _ := mapvalues.LookupOperation(mapvalues.EraseSS)
	return info
}

// EraseSSOperation binds the formal object in TS 29.002 V19.1.0 §17.6.4 (X.880 §§8.2–8.3).
func EraseSSOperation() Operation[mapvalues.SSForBSCode, mapvalues.SSInfo, mapvalues.EraseSSErrors] {
	return Operation[mapvalues.SSForBSCode, mapvalues.SSInfo, mapvalues.EraseSSErrors]{code: mapvalues.EraseSS, info: infoEraseSSOperation, argument: SSForBSCodeCodec(), result: SSInfoCodec(), decode: decodeEraseSSError, encode: encodeEraseSSError}
}
func decodeEraseSSError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (mapvalues.EraseSSErrors, error) {
	switch code {
	case 34:
		p, err := decodeErrorParameter(data, present, SystemFailureParamCodec(), opts...)
		if err != nil {
			return mapvalues.EraseSSErrors{}, err
		}
		return mapvalues.EraseSSErrors{SystemFailure: p}, nil
	case 35:
		p, err := decodeErrorParameter(data, present, DataMissingParamCodec(), opts...)
		if err != nil {
			return mapvalues.EraseSSErrors{}, err
		}
		return mapvalues.EraseSSErrors{DataMissing: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return mapvalues.EraseSSErrors{}, err
		}
		return mapvalues.EraseSSErrors{UnexpectedDataValue: p}, nil
	case 10:
		p, err := decodeErrorParameter(data, present, BearerServNotProvParamCodec(), opts...)
		if err != nil {
			return mapvalues.EraseSSErrors{}, err
		}
		return mapvalues.EraseSSErrors{BearerServiceNotProvisioned: p}, nil
	case 11:
		p, err := decodeErrorParameter(data, present, TeleservNotProvParamCodec(), opts...)
		if err != nil {
			return mapvalues.EraseSSErrors{}, err
		}
		return mapvalues.EraseSSErrors{TeleserviceNotProvisioned: p}, nil
	case 13:
		p, err := decodeErrorParameter(data, present, CallBarredParamCodec(), opts...)
		if err != nil {
			return mapvalues.EraseSSErrors{}, err
		}
		return mapvalues.EraseSSErrors{CallBarred: p}, nil
	case 16:
		p, err := decodeErrorParameter(data, present, IllegalSSOperationParamCodec(), opts...)
		if err != nil {
			return mapvalues.EraseSSErrors{}, err
		}
		return mapvalues.EraseSSErrors{IllegalSSOperation: p}, nil
	case 17:
		p, err := decodeErrorParameter(data, present, SSStatusCodec(), opts...)
		if err != nil {
			return mapvalues.EraseSSErrors{}, err
		}
		return mapvalues.EraseSSErrors{SsErrorStatus: p}, nil
	default:
		return mapvalues.EraseSSErrors{}, fmt.Errorf("%w: error code %d is not in eraseSS ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeEraseSSError(value mapvalues.EraseSSErrors, opts ...ber.EncodeOption) (mapvalues.EncodedError, error) {
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
		return mapvalues.EncodedError{}, fmt.Errorf("%w: exactly one eraseSS error arm is required", ber.ErrInvalidBinding)
	}
	if value.SystemFailure != nil {
		return encodeMAPErrorMember(mapvalues.SystemFailure, value.SystemFailure, SystemFailureParamCodec(), opts...)
	}
	if value.DataMissing != nil {
		return encodeMAPErrorMember(mapvalues.DataMissing, value.DataMissing, DataMissingParamCodec(), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(mapvalues.UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	if value.BearerServiceNotProvisioned != nil {
		return encodeMAPErrorMember(mapvalues.BearerServiceNotProvisioned, value.BearerServiceNotProvisioned, BearerServNotProvParamCodec(), opts...)
	}
	if value.TeleserviceNotProvisioned != nil {
		return encodeMAPErrorMember(mapvalues.TeleserviceNotProvisioned, value.TeleserviceNotProvisioned, TeleservNotProvParamCodec(), opts...)
	}
	if value.CallBarred != nil {
		return encodeMAPErrorMember(mapvalues.CallBarred, value.CallBarred, CallBarredParamCodec(), opts...)
	}
	if value.IllegalSSOperation != nil {
		return encodeMAPErrorMember(mapvalues.IllegalSSOperation, value.IllegalSSOperation, IllegalSSOperationParamCodec(), opts...)
	}
	if value.SsErrorStatus != nil {
		return encodeMAPErrorMember(mapvalues.SsErrorStatus, value.SsErrorStatus, SSStatusCodec(), opts...)
	}
	return mapvalues.EncodedError{}, fmt.Errorf("%w: no selected eraseSS error", ber.ErrInvalidBinding)
}
func infoFailureReportOperation() mapvalues.OperationInfo {
	info, _ := mapvalues.LookupOperation(mapvalues.FailureReport)
	return info
}

// FailureReportOperation binds the formal object in TS 29.002 V19.1.0 §17.6.1 (X.880 §§8.2–8.3).
func FailureReportOperation() Operation[mapvalues.FailureReportArg, mapvalues.FailureReportRes, mapvalues.FailureReportErrors] {
	return Operation[mapvalues.FailureReportArg, mapvalues.FailureReportRes, mapvalues.FailureReportErrors]{code: mapvalues.FailureReport, info: infoFailureReportOperation, argument: FailureReportArgCodec(), result: FailureReportResCodec(), decode: decodeFailureReportError, encode: encodeFailureReportError}
}
func decodeFailureReportError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (mapvalues.FailureReportErrors, error) {
	switch code {
	case 34:
		p, err := decodeErrorParameter(data, present, SystemFailureParamCodec(), opts...)
		if err != nil {
			return mapvalues.FailureReportErrors{}, err
		}
		return mapvalues.FailureReportErrors{SystemFailure: p}, nil
	case 35:
		p, err := decodeErrorParameter(data, present, DataMissingParamCodec(), opts...)
		if err != nil {
			return mapvalues.FailureReportErrors{}, err
		}
		return mapvalues.FailureReportErrors{DataMissing: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return mapvalues.FailureReportErrors{}, err
		}
		return mapvalues.FailureReportErrors{UnexpectedDataValue: p}, nil
	case 1:
		p, err := decodeErrorParameter(data, present, UnknownSubscriberParamCodec(), opts...)
		if err != nil {
			return mapvalues.FailureReportErrors{}, err
		}
		return mapvalues.FailureReportErrors{UnknownSubscriber: p}, nil
	default:
		return mapvalues.FailureReportErrors{}, fmt.Errorf("%w: error code %d is not in failureReport ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeFailureReportError(value mapvalues.FailureReportErrors, opts ...ber.EncodeOption) (mapvalues.EncodedError, error) {
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
		return mapvalues.EncodedError{}, fmt.Errorf("%w: exactly one failureReport error arm is required", ber.ErrInvalidBinding)
	}
	if value.SystemFailure != nil {
		return encodeMAPErrorMember(mapvalues.SystemFailure, value.SystemFailure, SystemFailureParamCodec(), opts...)
	}
	if value.DataMissing != nil {
		return encodeMAPErrorMember(mapvalues.DataMissing, value.DataMissing, DataMissingParamCodec(), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(mapvalues.UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	if value.UnknownSubscriber != nil {
		return encodeMAPErrorMember(mapvalues.UnknownSubscriber, value.UnknownSubscriber, UnknownSubscriberParamCodec(), opts...)
	}
	return mapvalues.EncodedError{}, fmt.Errorf("%w: no selected failureReport error", ber.ErrInvalidBinding)
}
func infoForwardAccessSignallingOperation() mapvalues.OperationInfo {
	info, _ := mapvalues.LookupOperation(mapvalues.ForwardAccessSignalling)
	return info
}

// ForwardAccessSignallingOperation binds the formal object in TS 29.002 V19.1.0 §17.6.1 (X.880 §§8.2–8.3).
func ForwardAccessSignallingOperation() Operation[mapvalues.ForwardAccessSignallingArg, mapvalues.NoParameter, mapvalues.ForwardAccessSignallingErrors] {
	return Operation[mapvalues.ForwardAccessSignallingArg, mapvalues.NoParameter, mapvalues.ForwardAccessSignallingErrors]{code: mapvalues.ForwardAccessSignalling, info: infoForwardAccessSignallingOperation, argument: ForwardAccessSignallingArgCodec(), result: mapvalues.ValueCodec[mapvalues.NoParameter]{}, decode: decodeForwardAccessSignallingError, encode: encodeForwardAccessSignallingError}
}
func decodeForwardAccessSignallingError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (mapvalues.ForwardAccessSignallingErrors, error) {
	switch code {
	default:
		return mapvalues.ForwardAccessSignallingErrors{}, fmt.Errorf("%w: error code %d is not in forwardAccessSignalling ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeForwardAccessSignallingError(value mapvalues.ForwardAccessSignallingErrors, opts ...ber.EncodeOption) (mapvalues.EncodedError, error) {
	return mapvalues.EncodedError{}, fmt.Errorf("%w: no selected forwardAccessSignalling error", ber.ErrInvalidBinding)
}
func infoForwardCheckSSIndicationOperation() mapvalues.OperationInfo {
	info, _ := mapvalues.LookupOperation(mapvalues.ForwardCheckSSIndication)
	return info
}

// ForwardCheckSSIndicationOperation binds the formal object in TS 29.002 V19.1.0 §17.6.1 (X.880 §§8.2–8.3).
func ForwardCheckSSIndicationOperation() Operation[mapvalues.NoParameter, mapvalues.NoParameter, mapvalues.ForwardCheckSSIndicationErrors] {
	return Operation[mapvalues.NoParameter, mapvalues.NoParameter, mapvalues.ForwardCheckSSIndicationErrors]{code: mapvalues.ForwardCheckSSIndication, info: infoForwardCheckSSIndicationOperation, argument: mapvalues.ValueCodec[mapvalues.NoParameter]{}, result: mapvalues.ValueCodec[mapvalues.NoParameter]{}, decode: decodeForwardCheckSSIndicationError, encode: encodeForwardCheckSSIndicationError}
}
func decodeForwardCheckSSIndicationError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (mapvalues.ForwardCheckSSIndicationErrors, error) {
	switch code {
	default:
		return mapvalues.ForwardCheckSSIndicationErrors{}, fmt.Errorf("%w: error code %d is not in forwardCheckSS-Indication ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeForwardCheckSSIndicationError(value mapvalues.ForwardCheckSSIndicationErrors, opts ...ber.EncodeOption) (mapvalues.EncodedError, error) {
	return mapvalues.EncodedError{}, fmt.Errorf("%w: no selected forwardCheckSS-Indication error", ber.ErrInvalidBinding)
}
func infoForwardGroupCallSignallingOperation() mapvalues.OperationInfo {
	info, _ := mapvalues.LookupOperation(mapvalues.ForwardGroupCallSignalling)
	return info
}

// ForwardGroupCallSignallingOperation binds the formal object in TS 29.002 V19.1.0 §17.6.7 (X.880 §§8.2–8.3).
func ForwardGroupCallSignallingOperation() Operation[mapvalues.ForwardGroupCallSignallingArg, mapvalues.NoParameter, mapvalues.ForwardGroupCallSignallingErrors] {
	return Operation[mapvalues.ForwardGroupCallSignallingArg, mapvalues.NoParameter, mapvalues.ForwardGroupCallSignallingErrors]{code: mapvalues.ForwardGroupCallSignalling, info: infoForwardGroupCallSignallingOperation, argument: ForwardGroupCallSignallingArgCodec(), result: mapvalues.ValueCodec[mapvalues.NoParameter]{}, decode: decodeForwardGroupCallSignallingError, encode: encodeForwardGroupCallSignallingError}
}
func decodeForwardGroupCallSignallingError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (mapvalues.ForwardGroupCallSignallingErrors, error) {
	switch code {
	default:
		return mapvalues.ForwardGroupCallSignallingErrors{}, fmt.Errorf("%w: error code %d is not in forwardGroupCallSignalling ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeForwardGroupCallSignallingError(value mapvalues.ForwardGroupCallSignallingErrors, opts ...ber.EncodeOption) (mapvalues.EncodedError, error) {
	return mapvalues.EncodedError{}, fmt.Errorf("%w: no selected forwardGroupCallSignalling error", ber.ErrInvalidBinding)
}
func infoGetPasswordOperation() mapvalues.OperationInfo {
	info, _ := mapvalues.LookupOperation(mapvalues.GetPassword)
	return info
}

// GetPasswordOperation binds the formal object in TS 29.002 V19.1.0 §17.6.4 (X.880 §§8.2–8.3).
func GetPasswordOperation() Operation[mapvalues.BERValue[mapvalues.GuidanceInfo], mapvalues.BERValue[mapvalues.Password], mapvalues.GetPasswordErrors] {
	return Operation[mapvalues.BERValue[mapvalues.GuidanceInfo], mapvalues.BERValue[mapvalues.Password], mapvalues.GetPasswordErrors]{code: mapvalues.GetPassword, info: infoGetPasswordOperation, argument: GuidanceInfoCodec(), result: PasswordCodec(), decode: decodeGetPasswordError, encode: encodeGetPasswordError}
}
func decodeGetPasswordError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (mapvalues.GetPasswordErrors, error) {
	switch code {
	default:
		return mapvalues.GetPasswordErrors{}, fmt.Errorf("%w: error code %d is not in getPassword ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeGetPasswordError(value mapvalues.GetPasswordErrors, opts ...ber.EncodeOption) (mapvalues.EncodedError, error) {
	return mapvalues.EncodedError{}, fmt.Errorf("%w: no selected getPassword error", ber.ErrInvalidBinding)
}
func infoInformServiceCentreOperation() mapvalues.OperationInfo {
	info, _ := mapvalues.LookupOperation(mapvalues.InformServiceCentre)
	return info
}

// InformServiceCentreOperation binds the formal object in TS 29.002 V19.1.0 §17.6.5 (X.880 §§8.2–8.3).
func InformServiceCentreOperation() Operation[mapvalues.InformServiceCentreArg, mapvalues.NoParameter, mapvalues.InformServiceCentreErrors] {
	return Operation[mapvalues.InformServiceCentreArg, mapvalues.NoParameter, mapvalues.InformServiceCentreErrors]{code: mapvalues.InformServiceCentre, info: infoInformServiceCentreOperation, argument: InformServiceCentreArgCodec(), result: mapvalues.ValueCodec[mapvalues.NoParameter]{}, decode: decodeInformServiceCentreError, encode: encodeInformServiceCentreError}
}
func decodeInformServiceCentreError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (mapvalues.InformServiceCentreErrors, error) {
	switch code {
	default:
		return mapvalues.InformServiceCentreErrors{}, fmt.Errorf("%w: error code %d is not in informServiceCentre ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeInformServiceCentreError(value mapvalues.InformServiceCentreErrors, opts ...ber.EncodeOption) (mapvalues.EncodedError, error) {
	return mapvalues.EncodedError{}, fmt.Errorf("%w: no selected informServiceCentre error", ber.ErrInvalidBinding)
}
func infoInsertSubscriberDataOperation() mapvalues.OperationInfo {
	info, _ := mapvalues.LookupOperation(mapvalues.InsertSubscriberData)
	return info
}

// InsertSubscriberDataOperation binds the formal object in TS 29.002 V19.1.0 §17.6.1 (X.880 §§8.2–8.3).
func InsertSubscriberDataOperation() Operation[mapvalues.InsertSubscriberDataArg, mapvalues.InsertSubscriberDataRes, mapvalues.InsertSubscriberDataErrors] {
	return Operation[mapvalues.InsertSubscriberDataArg, mapvalues.InsertSubscriberDataRes, mapvalues.InsertSubscriberDataErrors]{code: mapvalues.InsertSubscriberData, info: infoInsertSubscriberDataOperation, argument: InsertSubscriberDataArgCodec(), result: InsertSubscriberDataResCodec(), decode: decodeInsertSubscriberDataError, encode: encodeInsertSubscriberDataError}
}
func decodeInsertSubscriberDataError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (mapvalues.InsertSubscriberDataErrors, error) {
	switch code {
	case 35:
		p, err := decodeErrorParameter(data, present, DataMissingParamCodec(), opts...)
		if err != nil {
			return mapvalues.InsertSubscriberDataErrors{}, err
		}
		return mapvalues.InsertSubscriberDataErrors{DataMissing: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return mapvalues.InsertSubscriberDataErrors{}, err
		}
		return mapvalues.InsertSubscriberDataErrors{UnexpectedDataValue: p}, nil
	case 5:
		p, err := decodeErrorParameter(data, present, UnidentifiedSubParamCodec(), opts...)
		if err != nil {
			return mapvalues.InsertSubscriberDataErrors{}, err
		}
		return mapvalues.InsertSubscriberDataErrors{UnidentifiedSubscriber: p}, nil
	default:
		return mapvalues.InsertSubscriberDataErrors{}, fmt.Errorf("%w: error code %d is not in insertSubscriberData ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeInsertSubscriberDataError(value mapvalues.InsertSubscriberDataErrors, opts ...ber.EncodeOption) (mapvalues.EncodedError, error) {
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
		return mapvalues.EncodedError{}, fmt.Errorf("%w: exactly one insertSubscriberData error arm is required", ber.ErrInvalidBinding)
	}
	if value.DataMissing != nil {
		return encodeMAPErrorMember(mapvalues.DataMissing, value.DataMissing, DataMissingParamCodec(), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(mapvalues.UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	if value.UnidentifiedSubscriber != nil {
		return encodeMAPErrorMember(mapvalues.UnidentifiedSubscriber, value.UnidentifiedSubscriber, UnidentifiedSubParamCodec(), opts...)
	}
	return mapvalues.EncodedError{}, fmt.Errorf("%w: no selected insertSubscriberData error", ber.ErrInvalidBinding)
}
func infoInterrogateSSOperation() mapvalues.OperationInfo {
	info, _ := mapvalues.LookupOperation(mapvalues.InterrogateSS)
	return info
}

// InterrogateSSOperation binds the formal object in TS 29.002 V19.1.0 §17.6.4 (X.880 §§8.2–8.3).
func InterrogateSSOperation() Operation[mapvalues.SSForBSCode, mapvalues.InterrogateSSRes, mapvalues.InterrogateSSErrors] {
	return Operation[mapvalues.SSForBSCode, mapvalues.InterrogateSSRes, mapvalues.InterrogateSSErrors]{code: mapvalues.InterrogateSS, info: infoInterrogateSSOperation, argument: SSForBSCodeCodec(), result: InterrogateSSResCodec(), decode: decodeInterrogateSSError, encode: encodeInterrogateSSError}
}
func decodeInterrogateSSError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (mapvalues.InterrogateSSErrors, error) {
	switch code {
	case 34:
		p, err := decodeErrorParameter(data, present, SystemFailureParamCodec(), opts...)
		if err != nil {
			return mapvalues.InterrogateSSErrors{}, err
		}
		return mapvalues.InterrogateSSErrors{SystemFailure: p}, nil
	case 35:
		p, err := decodeErrorParameter(data, present, DataMissingParamCodec(), opts...)
		if err != nil {
			return mapvalues.InterrogateSSErrors{}, err
		}
		return mapvalues.InterrogateSSErrors{DataMissing: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return mapvalues.InterrogateSSErrors{}, err
		}
		return mapvalues.InterrogateSSErrors{UnexpectedDataValue: p}, nil
	case 10:
		p, err := decodeErrorParameter(data, present, BearerServNotProvParamCodec(), opts...)
		if err != nil {
			return mapvalues.InterrogateSSErrors{}, err
		}
		return mapvalues.InterrogateSSErrors{BearerServiceNotProvisioned: p}, nil
	case 11:
		p, err := decodeErrorParameter(data, present, TeleservNotProvParamCodec(), opts...)
		if err != nil {
			return mapvalues.InterrogateSSErrors{}, err
		}
		return mapvalues.InterrogateSSErrors{TeleserviceNotProvisioned: p}, nil
	case 13:
		p, err := decodeErrorParameter(data, present, CallBarredParamCodec(), opts...)
		if err != nil {
			return mapvalues.InterrogateSSErrors{}, err
		}
		return mapvalues.InterrogateSSErrors{CallBarred: p}, nil
	case 16:
		p, err := decodeErrorParameter(data, present, IllegalSSOperationParamCodec(), opts...)
		if err != nil {
			return mapvalues.InterrogateSSErrors{}, err
		}
		return mapvalues.InterrogateSSErrors{IllegalSSOperation: p}, nil
	case 18:
		p, err := decodeErrorParameter(data, present, SSNotAvailableParamCodec(), opts...)
		if err != nil {
			return mapvalues.InterrogateSSErrors{}, err
		}
		return mapvalues.InterrogateSSErrors{SsNotAvailable: p}, nil
	default:
		return mapvalues.InterrogateSSErrors{}, fmt.Errorf("%w: error code %d is not in interrogateSS ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeInterrogateSSError(value mapvalues.InterrogateSSErrors, opts ...ber.EncodeOption) (mapvalues.EncodedError, error) {
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
		return mapvalues.EncodedError{}, fmt.Errorf("%w: exactly one interrogateSS error arm is required", ber.ErrInvalidBinding)
	}
	if value.SystemFailure != nil {
		return encodeMAPErrorMember(mapvalues.SystemFailure, value.SystemFailure, SystemFailureParamCodec(), opts...)
	}
	if value.DataMissing != nil {
		return encodeMAPErrorMember(mapvalues.DataMissing, value.DataMissing, DataMissingParamCodec(), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(mapvalues.UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	if value.BearerServiceNotProvisioned != nil {
		return encodeMAPErrorMember(mapvalues.BearerServiceNotProvisioned, value.BearerServiceNotProvisioned, BearerServNotProvParamCodec(), opts...)
	}
	if value.TeleserviceNotProvisioned != nil {
		return encodeMAPErrorMember(mapvalues.TeleserviceNotProvisioned, value.TeleserviceNotProvisioned, TeleservNotProvParamCodec(), opts...)
	}
	if value.CallBarred != nil {
		return encodeMAPErrorMember(mapvalues.CallBarred, value.CallBarred, CallBarredParamCodec(), opts...)
	}
	if value.IllegalSSOperation != nil {
		return encodeMAPErrorMember(mapvalues.IllegalSSOperation, value.IllegalSSOperation, IllegalSSOperationParamCodec(), opts...)
	}
	if value.SsNotAvailable != nil {
		return encodeMAPErrorMember(mapvalues.SsNotAvailable, value.SsNotAvailable, SSNotAvailableParamCodec(), opts...)
	}
	return mapvalues.EncodedError{}, fmt.Errorf("%w: no selected interrogateSS error", ber.ErrInvalidBinding)
}
func infoIstAlertOperation() mapvalues.OperationInfo {
	info, _ := mapvalues.LookupOperation(mapvalues.IstAlert)
	return info
}

// IstAlertOperation binds the formal object in TS 29.002 V19.1.0 §17.6.3 (X.880 §§8.2–8.3).
func IstAlertOperation() Operation[mapvalues.ISTAlertArg, mapvalues.ISTAlertRes, mapvalues.IstAlertErrors] {
	return Operation[mapvalues.ISTAlertArg, mapvalues.ISTAlertRes, mapvalues.IstAlertErrors]{code: mapvalues.IstAlert, info: infoIstAlertOperation, argument: ISTAlertArgCodec(), result: ISTAlertResCodec(), decode: decodeIstAlertError, encode: encodeIstAlertError}
}
func decodeIstAlertError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (mapvalues.IstAlertErrors, error) {
	switch code {
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return mapvalues.IstAlertErrors{}, err
		}
		return mapvalues.IstAlertErrors{UnexpectedDataValue: p}, nil
	case 51:
		p, err := decodeErrorParameter(data, present, ResourceLimitationParamCodec(), opts...)
		if err != nil {
			return mapvalues.IstAlertErrors{}, err
		}
		return mapvalues.IstAlertErrors{ResourceLimitation: p}, nil
	case 1:
		p, err := decodeErrorParameter(data, present, UnknownSubscriberParamCodec(), opts...)
		if err != nil {
			return mapvalues.IstAlertErrors{}, err
		}
		return mapvalues.IstAlertErrors{UnknownSubscriber: p}, nil
	case 34:
		p, err := decodeErrorParameter(data, present, SystemFailureParamCodec(), opts...)
		if err != nil {
			return mapvalues.IstAlertErrors{}, err
		}
		return mapvalues.IstAlertErrors{SystemFailure: p}, nil
	case 21:
		p, err := decodeErrorParameter(data, present, FacilityNotSupParamCodec(), opts...)
		if err != nil {
			return mapvalues.IstAlertErrors{}, err
		}
		return mapvalues.IstAlertErrors{FacilityNotSupported: p}, nil
	default:
		return mapvalues.IstAlertErrors{}, fmt.Errorf("%w: error code %d is not in ist-Alert ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeIstAlertError(value mapvalues.IstAlertErrors, opts ...ber.EncodeOption) (mapvalues.EncodedError, error) {
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
		return mapvalues.EncodedError{}, fmt.Errorf("%w: exactly one ist-Alert error arm is required", ber.ErrInvalidBinding)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(mapvalues.UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	if value.ResourceLimitation != nil {
		return encodeMAPErrorMember(mapvalues.ResourceLimitation, value.ResourceLimitation, ResourceLimitationParamCodec(), opts...)
	}
	if value.UnknownSubscriber != nil {
		return encodeMAPErrorMember(mapvalues.UnknownSubscriber, value.UnknownSubscriber, UnknownSubscriberParamCodec(), opts...)
	}
	if value.SystemFailure != nil {
		return encodeMAPErrorMember(mapvalues.SystemFailure, value.SystemFailure, SystemFailureParamCodec(), opts...)
	}
	if value.FacilityNotSupported != nil {
		return encodeMAPErrorMember(mapvalues.FacilityNotSupported, value.FacilityNotSupported, FacilityNotSupParamCodec(), opts...)
	}
	return mapvalues.EncodedError{}, fmt.Errorf("%w: no selected ist-Alert error", ber.ErrInvalidBinding)
}
func infoIstCommandOperation() mapvalues.OperationInfo {
	info, _ := mapvalues.LookupOperation(mapvalues.IstCommand)
	return info
}

// IstCommandOperation binds the formal object in TS 29.002 V19.1.0 §17.6.3 (X.880 §§8.2–8.3).
func IstCommandOperation() Operation[mapvalues.ISTCommandArg, mapvalues.ISTCommandRes, mapvalues.IstCommandErrors] {
	return Operation[mapvalues.ISTCommandArg, mapvalues.ISTCommandRes, mapvalues.IstCommandErrors]{code: mapvalues.IstCommand, info: infoIstCommandOperation, argument: ISTCommandArgCodec(), result: ISTCommandResCodec(), decode: decodeIstCommandError, encode: encodeIstCommandError}
}
func decodeIstCommandError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (mapvalues.IstCommandErrors, error) {
	switch code {
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return mapvalues.IstCommandErrors{}, err
		}
		return mapvalues.IstCommandErrors{UnexpectedDataValue: p}, nil
	case 51:
		p, err := decodeErrorParameter(data, present, ResourceLimitationParamCodec(), opts...)
		if err != nil {
			return mapvalues.IstCommandErrors{}, err
		}
		return mapvalues.IstCommandErrors{ResourceLimitation: p}, nil
	case 1:
		p, err := decodeErrorParameter(data, present, UnknownSubscriberParamCodec(), opts...)
		if err != nil {
			return mapvalues.IstCommandErrors{}, err
		}
		return mapvalues.IstCommandErrors{UnknownSubscriber: p}, nil
	case 34:
		p, err := decodeErrorParameter(data, present, SystemFailureParamCodec(), opts...)
		if err != nil {
			return mapvalues.IstCommandErrors{}, err
		}
		return mapvalues.IstCommandErrors{SystemFailure: p}, nil
	case 21:
		p, err := decodeErrorParameter(data, present, FacilityNotSupParamCodec(), opts...)
		if err != nil {
			return mapvalues.IstCommandErrors{}, err
		}
		return mapvalues.IstCommandErrors{FacilityNotSupported: p}, nil
	default:
		return mapvalues.IstCommandErrors{}, fmt.Errorf("%w: error code %d is not in ist-Command ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeIstCommandError(value mapvalues.IstCommandErrors, opts ...ber.EncodeOption) (mapvalues.EncodedError, error) {
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
		return mapvalues.EncodedError{}, fmt.Errorf("%w: exactly one ist-Command error arm is required", ber.ErrInvalidBinding)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(mapvalues.UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	if value.ResourceLimitation != nil {
		return encodeMAPErrorMember(mapvalues.ResourceLimitation, value.ResourceLimitation, ResourceLimitationParamCodec(), opts...)
	}
	if value.UnknownSubscriber != nil {
		return encodeMAPErrorMember(mapvalues.UnknownSubscriber, value.UnknownSubscriber, UnknownSubscriberParamCodec(), opts...)
	}
	if value.SystemFailure != nil {
		return encodeMAPErrorMember(mapvalues.SystemFailure, value.SystemFailure, SystemFailureParamCodec(), opts...)
	}
	if value.FacilityNotSupported != nil {
		return encodeMAPErrorMember(mapvalues.FacilityNotSupported, value.FacilityNotSupported, FacilityNotSupParamCodec(), opts...)
	}
	return mapvalues.EncodedError{}, fmt.Errorf("%w: no selected ist-Command error", ber.ErrInvalidBinding)
}
func infoMoForwardSMOperation() mapvalues.OperationInfo {
	info, _ := mapvalues.LookupOperation(mapvalues.MoForwardSM)
	return info
}

// MoForwardSMOperation binds the formal object in TS 29.002 V19.1.0 §17.6.5 (X.880 §§8.2–8.3).
func MoForwardSMOperation() Operation[mapvalues.MOForwardSMArg, mapvalues.MOForwardSMRes, mapvalues.MoForwardSMErrors] {
	return Operation[mapvalues.MOForwardSMArg, mapvalues.MOForwardSMRes, mapvalues.MoForwardSMErrors]{code: mapvalues.MoForwardSM, info: infoMoForwardSMOperation, argument: MOForwardSMArgCodec(), result: MOForwardSMResCodec(), decode: decodeMoForwardSMError, encode: encodeMoForwardSMError}
}
func decodeMoForwardSMError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (mapvalues.MoForwardSMErrors, error) {
	switch code {
	case 34:
		p, err := decodeErrorParameter(data, present, SystemFailureParamCodec(), opts...)
		if err != nil {
			return mapvalues.MoForwardSMErrors{}, err
		}
		return mapvalues.MoForwardSMErrors{SystemFailure: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return mapvalues.MoForwardSMErrors{}, err
		}
		return mapvalues.MoForwardSMErrors{UnexpectedDataValue: p}, nil
	case 21:
		p, err := decodeErrorParameter(data, present, FacilityNotSupParamCodec(), opts...)
		if err != nil {
			return mapvalues.MoForwardSMErrors{}, err
		}
		return mapvalues.MoForwardSMErrors{FacilityNotSupported: p}, nil
	case 32:
		p, err := decodeErrorParameter(data, present, SMDeliveryFailureCauseCodec(), opts...)
		if err != nil {
			return mapvalues.MoForwardSMErrors{}, err
		}
		return mapvalues.MoForwardSMErrors{SmDeliveryFailure: p}, nil
	default:
		return mapvalues.MoForwardSMErrors{}, fmt.Errorf("%w: error code %d is not in mo-ForwardSM ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeMoForwardSMError(value mapvalues.MoForwardSMErrors, opts ...ber.EncodeOption) (mapvalues.EncodedError, error) {
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
		return mapvalues.EncodedError{}, fmt.Errorf("%w: exactly one mo-ForwardSM error arm is required", ber.ErrInvalidBinding)
	}
	if value.SystemFailure != nil {
		return encodeMAPErrorMember(mapvalues.SystemFailure, value.SystemFailure, SystemFailureParamCodec(), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(mapvalues.UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	if value.FacilityNotSupported != nil {
		return encodeMAPErrorMember(mapvalues.FacilityNotSupported, value.FacilityNotSupported, FacilityNotSupParamCodec(), opts...)
	}
	if value.SmDeliveryFailure != nil {
		return encodeMAPErrorMember(mapvalues.SmDeliveryFailure, value.SmDeliveryFailure, SMDeliveryFailureCauseCodec(), opts...)
	}
	return mapvalues.EncodedError{}, fmt.Errorf("%w: no selected mo-ForwardSM error", ber.ErrInvalidBinding)
}
func infoMtForwardSMOperation() mapvalues.OperationInfo {
	info, _ := mapvalues.LookupOperation(mapvalues.MtForwardSM)
	return info
}

// MtForwardSMOperation binds the formal object in TS 29.002 V19.1.0 §17.6.5 (X.880 §§8.2–8.3).
func MtForwardSMOperation() Operation[mapvalues.MTForwardSMArg, mapvalues.MTForwardSMRes, mapvalues.MtForwardSMErrors] {
	return Operation[mapvalues.MTForwardSMArg, mapvalues.MTForwardSMRes, mapvalues.MtForwardSMErrors]{code: mapvalues.MtForwardSM, info: infoMtForwardSMOperation, argument: MTForwardSMArgCodec(), result: MTForwardSMResCodec(), decode: decodeMtForwardSMError, encode: encodeMtForwardSMError}
}
func decodeMtForwardSMError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (mapvalues.MtForwardSMErrors, error) {
	switch code {
	case 34:
		p, err := decodeErrorParameter(data, present, SystemFailureParamCodec(), opts...)
		if err != nil {
			return mapvalues.MtForwardSMErrors{}, err
		}
		return mapvalues.MtForwardSMErrors{SystemFailure: p}, nil
	case 35:
		p, err := decodeErrorParameter(data, present, DataMissingParamCodec(), opts...)
		if err != nil {
			return mapvalues.MtForwardSMErrors{}, err
		}
		return mapvalues.MtForwardSMErrors{DataMissing: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return mapvalues.MtForwardSMErrors{}, err
		}
		return mapvalues.MtForwardSMErrors{UnexpectedDataValue: p}, nil
	case 21:
		p, err := decodeErrorParameter(data, present, FacilityNotSupParamCodec(), opts...)
		if err != nil {
			return mapvalues.MtForwardSMErrors{}, err
		}
		return mapvalues.MtForwardSMErrors{FacilityNotSupported: p}, nil
	case 5:
		p, err := decodeErrorParameter(data, present, UnidentifiedSubParamCodec(), opts...)
		if err != nil {
			return mapvalues.MtForwardSMErrors{}, err
		}
		return mapvalues.MtForwardSMErrors{UnidentifiedSubscriber: p}, nil
	case 9:
		p, err := decodeErrorParameter(data, present, IllegalSubscriberParamCodec(), opts...)
		if err != nil {
			return mapvalues.MtForwardSMErrors{}, err
		}
		return mapvalues.MtForwardSMErrors{IllegalSubscriber: p}, nil
	case 12:
		p, err := decodeErrorParameter(data, present, IllegalEquipmentParamCodec(), opts...)
		if err != nil {
			return mapvalues.MtForwardSMErrors{}, err
		}
		return mapvalues.MtForwardSMErrors{IllegalEquipment: p}, nil
	case 31:
		p, err := decodeErrorParameter(data, present, SubBusyForMTSMSParamCodec(), opts...)
		if err != nil {
			return mapvalues.MtForwardSMErrors{}, err
		}
		return mapvalues.MtForwardSMErrors{SubscriberBusyForMTSMS: p}, nil
	case 32:
		p, err := decodeErrorParameter(data, present, SMDeliveryFailureCauseCodec(), opts...)
		if err != nil {
			return mapvalues.MtForwardSMErrors{}, err
		}
		return mapvalues.MtForwardSMErrors{SmDeliveryFailure: p}, nil
	case 6:
		p, err := decodeErrorParameter(data, present, AbsentSubscriberSMParamCodec(), opts...)
		if err != nil {
			return mapvalues.MtForwardSMErrors{}, err
		}
		return mapvalues.MtForwardSMErrors{AbsentSubscriberSM: p}, nil
	default:
		return mapvalues.MtForwardSMErrors{}, fmt.Errorf("%w: error code %d is not in mt-ForwardSM ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeMtForwardSMError(value mapvalues.MtForwardSMErrors, opts ...ber.EncodeOption) (mapvalues.EncodedError, error) {
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
		return mapvalues.EncodedError{}, fmt.Errorf("%w: exactly one mt-ForwardSM error arm is required", ber.ErrInvalidBinding)
	}
	if value.SystemFailure != nil {
		return encodeMAPErrorMember(mapvalues.SystemFailure, value.SystemFailure, SystemFailureParamCodec(), opts...)
	}
	if value.DataMissing != nil {
		return encodeMAPErrorMember(mapvalues.DataMissing, value.DataMissing, DataMissingParamCodec(), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(mapvalues.UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	if value.FacilityNotSupported != nil {
		return encodeMAPErrorMember(mapvalues.FacilityNotSupported, value.FacilityNotSupported, FacilityNotSupParamCodec(), opts...)
	}
	if value.UnidentifiedSubscriber != nil {
		return encodeMAPErrorMember(mapvalues.UnidentifiedSubscriber, value.UnidentifiedSubscriber, UnidentifiedSubParamCodec(), opts...)
	}
	if value.IllegalSubscriber != nil {
		return encodeMAPErrorMember(mapvalues.IllegalSubscriber, value.IllegalSubscriber, IllegalSubscriberParamCodec(), opts...)
	}
	if value.IllegalEquipment != nil {
		return encodeMAPErrorMember(mapvalues.IllegalEquipment, value.IllegalEquipment, IllegalEquipmentParamCodec(), opts...)
	}
	if value.SubscriberBusyForMTSMS != nil {
		return encodeMAPErrorMember(mapvalues.SubscriberBusyForMTSMS, value.SubscriberBusyForMTSMS, SubBusyForMTSMSParamCodec(), opts...)
	}
	if value.SmDeliveryFailure != nil {
		return encodeMAPErrorMember(mapvalues.SmDeliveryFailure, value.SmDeliveryFailure, SMDeliveryFailureCauseCodec(), opts...)
	}
	if value.AbsentSubscriberSM != nil {
		return encodeMAPErrorMember(mapvalues.AbsentSubscriberSM, value.AbsentSubscriberSM, AbsentSubscriberSMParamCodec(), opts...)
	}
	return mapvalues.EncodedError{}, fmt.Errorf("%w: no selected mt-ForwardSM error", ber.ErrInvalidBinding)
}
func infoMtForwardSMVGCSOperation() mapvalues.OperationInfo {
	info, _ := mapvalues.LookupOperation(mapvalues.MtForwardSMVGCS)
	return info
}

// MtForwardSMVGCSOperation binds the formal object in TS 29.002 V19.1.0 §17.6.5 (X.880 §§8.2–8.3).
func MtForwardSMVGCSOperation() Operation[mapvalues.MTForwardSMVGCSArg, mapvalues.MTForwardSMVGCSRes, mapvalues.MtForwardSMVGCSErrors] {
	return Operation[mapvalues.MTForwardSMVGCSArg, mapvalues.MTForwardSMVGCSRes, mapvalues.MtForwardSMVGCSErrors]{code: mapvalues.MtForwardSMVGCS, info: infoMtForwardSMVGCSOperation, argument: MTForwardSMVGCSArgCodec(), result: MTForwardSMVGCSResCodec(), decode: decodeMtForwardSMVGCSError, encode: encodeMtForwardSMVGCSError}
}
func decodeMtForwardSMVGCSError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (mapvalues.MtForwardSMVGCSErrors, error) {
	switch code {
	case 34:
		p, err := decodeErrorParameter(data, present, SystemFailureParamCodec(), opts...)
		if err != nil {
			return mapvalues.MtForwardSMVGCSErrors{}, err
		}
		return mapvalues.MtForwardSMVGCSErrors{SystemFailure: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return mapvalues.MtForwardSMVGCSErrors{}, err
		}
		return mapvalues.MtForwardSMVGCSErrors{UnexpectedDataValue: p}, nil
	default:
		return mapvalues.MtForwardSMVGCSErrors{}, fmt.Errorf("%w: error code %d is not in mt-ForwardSM-VGCS ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeMtForwardSMVGCSError(value mapvalues.MtForwardSMVGCSErrors, opts ...ber.EncodeOption) (mapvalues.EncodedError, error) {
	selected := 0
	if value.SystemFailure != nil {
		selected++
	}
	if value.UnexpectedDataValue != nil {
		selected++
	}
	if selected != 1 {
		return mapvalues.EncodedError{}, fmt.Errorf("%w: exactly one mt-ForwardSM-VGCS error arm is required", ber.ErrInvalidBinding)
	}
	if value.SystemFailure != nil {
		return encodeMAPErrorMember(mapvalues.SystemFailure, value.SystemFailure, SystemFailureParamCodec(), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(mapvalues.UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	return mapvalues.EncodedError{}, fmt.Errorf("%w: no selected mt-ForwardSM-VGCS error", ber.ErrInvalidBinding)
}
func infoNoteMMEventOperation() mapvalues.OperationInfo {
	info, _ := mapvalues.LookupOperation(mapvalues.NoteMMEvent)
	return info
}

// NoteMMEventOperation binds the formal object in TS 29.002 V19.1.0 §17.6.1 (X.880 §§8.2–8.3).
func NoteMMEventOperation() Operation[mapvalues.NoteMMEventArg, mapvalues.NoteMMEventRes, mapvalues.NoteMMEventErrors] {
	return Operation[mapvalues.NoteMMEventArg, mapvalues.NoteMMEventRes, mapvalues.NoteMMEventErrors]{code: mapvalues.NoteMMEvent, info: infoNoteMMEventOperation, argument: NoteMMEventArgCodec(), result: NoteMMEventResCodec(), decode: decodeNoteMMEventError, encode: encodeNoteMMEventError}
}
func decodeNoteMMEventError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (mapvalues.NoteMMEventErrors, error) {
	switch code {
	case 35:
		p, err := decodeErrorParameter(data, present, DataMissingParamCodec(), opts...)
		if err != nil {
			return mapvalues.NoteMMEventErrors{}, err
		}
		return mapvalues.NoteMMEventErrors{DataMissing: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return mapvalues.NoteMMEventErrors{}, err
		}
		return mapvalues.NoteMMEventErrors{UnexpectedDataValue: p}, nil
	case 1:
		p, err := decodeErrorParameter(data, present, UnknownSubscriberParamCodec(), opts...)
		if err != nil {
			return mapvalues.NoteMMEventErrors{}, err
		}
		return mapvalues.NoteMMEventErrors{UnknownSubscriber: p}, nil
	case 59:
		p, err := decodeErrorParameter(data, present, MMEventNotSupportedParamCodec(), opts...)
		if err != nil {
			return mapvalues.NoteMMEventErrors{}, err
		}
		return mapvalues.NoteMMEventErrors{MmEventNotSupported: p}, nil
	default:
		return mapvalues.NoteMMEventErrors{}, fmt.Errorf("%w: error code %d is not in noteMM-Event ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeNoteMMEventError(value mapvalues.NoteMMEventErrors, opts ...ber.EncodeOption) (mapvalues.EncodedError, error) {
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
		return mapvalues.EncodedError{}, fmt.Errorf("%w: exactly one noteMM-Event error arm is required", ber.ErrInvalidBinding)
	}
	if value.DataMissing != nil {
		return encodeMAPErrorMember(mapvalues.DataMissing, value.DataMissing, DataMissingParamCodec(), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(mapvalues.UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	if value.UnknownSubscriber != nil {
		return encodeMAPErrorMember(mapvalues.UnknownSubscriber, value.UnknownSubscriber, UnknownSubscriberParamCodec(), opts...)
	}
	if value.MmEventNotSupported != nil {
		return encodeMAPErrorMember(mapvalues.MmEventNotSupported, value.MmEventNotSupported, MMEventNotSupportedParamCodec(), opts...)
	}
	return mapvalues.EncodedError{}, fmt.Errorf("%w: no selected noteMM-Event error", ber.ErrInvalidBinding)
}
func infoNoteMsPresentForGprsOperation() mapvalues.OperationInfo {
	info, _ := mapvalues.LookupOperation(mapvalues.NoteMsPresentForGprs)
	return info
}

// NoteMsPresentForGprsOperation binds the formal object in TS 29.002 V19.1.0 §17.6.1 (X.880 §§8.2–8.3).
func NoteMsPresentForGprsOperation() Operation[mapvalues.NoteMsPresentForGprsArg, mapvalues.NoteMsPresentForGprsRes, mapvalues.NoteMsPresentForGprsErrors] {
	return Operation[mapvalues.NoteMsPresentForGprsArg, mapvalues.NoteMsPresentForGprsRes, mapvalues.NoteMsPresentForGprsErrors]{code: mapvalues.NoteMsPresentForGprs, info: infoNoteMsPresentForGprsOperation, argument: NoteMsPresentForGprsArgCodec(), result: NoteMsPresentForGprsResCodec(), decode: decodeNoteMsPresentForGprsError, encode: encodeNoteMsPresentForGprsError}
}
func decodeNoteMsPresentForGprsError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (mapvalues.NoteMsPresentForGprsErrors, error) {
	switch code {
	case 34:
		p, err := decodeErrorParameter(data, present, SystemFailureParamCodec(), opts...)
		if err != nil {
			return mapvalues.NoteMsPresentForGprsErrors{}, err
		}
		return mapvalues.NoteMsPresentForGprsErrors{SystemFailure: p}, nil
	case 35:
		p, err := decodeErrorParameter(data, present, DataMissingParamCodec(), opts...)
		if err != nil {
			return mapvalues.NoteMsPresentForGprsErrors{}, err
		}
		return mapvalues.NoteMsPresentForGprsErrors{DataMissing: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return mapvalues.NoteMsPresentForGprsErrors{}, err
		}
		return mapvalues.NoteMsPresentForGprsErrors{UnexpectedDataValue: p}, nil
	case 1:
		p, err := decodeErrorParameter(data, present, UnknownSubscriberParamCodec(), opts...)
		if err != nil {
			return mapvalues.NoteMsPresentForGprsErrors{}, err
		}
		return mapvalues.NoteMsPresentForGprsErrors{UnknownSubscriber: p}, nil
	default:
		return mapvalues.NoteMsPresentForGprsErrors{}, fmt.Errorf("%w: error code %d is not in noteMsPresentForGprs ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeNoteMsPresentForGprsError(value mapvalues.NoteMsPresentForGprsErrors, opts ...ber.EncodeOption) (mapvalues.EncodedError, error) {
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
		return mapvalues.EncodedError{}, fmt.Errorf("%w: exactly one noteMsPresentForGprs error arm is required", ber.ErrInvalidBinding)
	}
	if value.SystemFailure != nil {
		return encodeMAPErrorMember(mapvalues.SystemFailure, value.SystemFailure, SystemFailureParamCodec(), opts...)
	}
	if value.DataMissing != nil {
		return encodeMAPErrorMember(mapvalues.DataMissing, value.DataMissing, DataMissingParamCodec(), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(mapvalues.UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	if value.UnknownSubscriber != nil {
		return encodeMAPErrorMember(mapvalues.UnknownSubscriber, value.UnknownSubscriber, UnknownSubscriberParamCodec(), opts...)
	}
	return mapvalues.EncodedError{}, fmt.Errorf("%w: no selected noteMsPresentForGprs error", ber.ErrInvalidBinding)
}
func infoNoteSubscriberDataModifiedOperation() mapvalues.OperationInfo {
	info, _ := mapvalues.LookupOperation(mapvalues.NoteSubscriberDataModified)
	return info
}

// NoteSubscriberDataModifiedOperation binds the formal object in TS 29.002 V19.1.0 §17.6.1 (X.880 §§8.2–8.3).
func NoteSubscriberDataModifiedOperation() Operation[mapvalues.NoteSubscriberDataModifiedArg, mapvalues.NoteSubscriberDataModifiedRes, mapvalues.NoteSubscriberDataModifiedErrors] {
	return Operation[mapvalues.NoteSubscriberDataModifiedArg, mapvalues.NoteSubscriberDataModifiedRes, mapvalues.NoteSubscriberDataModifiedErrors]{code: mapvalues.NoteSubscriberDataModified, info: infoNoteSubscriberDataModifiedOperation, argument: NoteSubscriberDataModifiedArgCodec(), result: NoteSubscriberDataModifiedResCodec(), decode: decodeNoteSubscriberDataModifiedError, encode: encodeNoteSubscriberDataModifiedError}
}
func decodeNoteSubscriberDataModifiedError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (mapvalues.NoteSubscriberDataModifiedErrors, error) {
	switch code {
	case 35:
		p, err := decodeErrorParameter(data, present, DataMissingParamCodec(), opts...)
		if err != nil {
			return mapvalues.NoteSubscriberDataModifiedErrors{}, err
		}
		return mapvalues.NoteSubscriberDataModifiedErrors{DataMissing: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return mapvalues.NoteSubscriberDataModifiedErrors{}, err
		}
		return mapvalues.NoteSubscriberDataModifiedErrors{UnexpectedDataValue: p}, nil
	case 1:
		p, err := decodeErrorParameter(data, present, UnknownSubscriberParamCodec(), opts...)
		if err != nil {
			return mapvalues.NoteSubscriberDataModifiedErrors{}, err
		}
		return mapvalues.NoteSubscriberDataModifiedErrors{UnknownSubscriber: p}, nil
	default:
		return mapvalues.NoteSubscriberDataModifiedErrors{}, fmt.Errorf("%w: error code %d is not in noteSubscriberDataModified ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeNoteSubscriberDataModifiedError(value mapvalues.NoteSubscriberDataModifiedErrors, opts ...ber.EncodeOption) (mapvalues.EncodedError, error) {
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
		return mapvalues.EncodedError{}, fmt.Errorf("%w: exactly one noteSubscriberDataModified error arm is required", ber.ErrInvalidBinding)
	}
	if value.DataMissing != nil {
		return encodeMAPErrorMember(mapvalues.DataMissing, value.DataMissing, DataMissingParamCodec(), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(mapvalues.UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	if value.UnknownSubscriber != nil {
		return encodeMAPErrorMember(mapvalues.UnknownSubscriber, value.UnknownSubscriber, UnknownSubscriberParamCodec(), opts...)
	}
	return mapvalues.EncodedError{}, fmt.Errorf("%w: no selected noteSubscriberDataModified error", ber.ErrInvalidBinding)
}
func infoPrepareGroupCallOperation() mapvalues.OperationInfo {
	info, _ := mapvalues.LookupOperation(mapvalues.PrepareGroupCall)
	return info
}

// PrepareGroupCallOperation binds the formal object in TS 29.002 V19.1.0 §17.6.7 (X.880 §§8.2–8.3).
func PrepareGroupCallOperation() Operation[mapvalues.PrepareGroupCallArg, mapvalues.PrepareGroupCallRes, mapvalues.PrepareGroupCallErrors] {
	return Operation[mapvalues.PrepareGroupCallArg, mapvalues.PrepareGroupCallRes, mapvalues.PrepareGroupCallErrors]{code: mapvalues.PrepareGroupCall, info: infoPrepareGroupCallOperation, argument: PrepareGroupCallArgCodec(), result: PrepareGroupCallResCodec(), decode: decodePrepareGroupCallError, encode: encodePrepareGroupCallError}
}
func decodePrepareGroupCallError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (mapvalues.PrepareGroupCallErrors, error) {
	switch code {
	case 34:
		p, err := decodeErrorParameter(data, present, SystemFailureParamCodec(), opts...)
		if err != nil {
			return mapvalues.PrepareGroupCallErrors{}, err
		}
		return mapvalues.PrepareGroupCallErrors{SystemFailure: p}, nil
	case 50:
		p, err := decodeErrorParameter(data, present, NoGroupCallNbParamCodec(), opts...)
		if err != nil {
			return mapvalues.PrepareGroupCallErrors{}, err
		}
		return mapvalues.PrepareGroupCallErrors{NoGroupCallNumberAvailable: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return mapvalues.PrepareGroupCallErrors{}, err
		}
		return mapvalues.PrepareGroupCallErrors{UnexpectedDataValue: p}, nil
	default:
		return mapvalues.PrepareGroupCallErrors{}, fmt.Errorf("%w: error code %d is not in prepareGroupCall ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodePrepareGroupCallError(value mapvalues.PrepareGroupCallErrors, opts ...ber.EncodeOption) (mapvalues.EncodedError, error) {
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
		return mapvalues.EncodedError{}, fmt.Errorf("%w: exactly one prepareGroupCall error arm is required", ber.ErrInvalidBinding)
	}
	if value.SystemFailure != nil {
		return encodeMAPErrorMember(mapvalues.SystemFailure, value.SystemFailure, SystemFailureParamCodec(), opts...)
	}
	if value.NoGroupCallNumberAvailable != nil {
		return encodeMAPErrorMember(mapvalues.NoGroupCallNumberAvailable, value.NoGroupCallNumberAvailable, NoGroupCallNbParamCodec(), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(mapvalues.UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	return mapvalues.EncodedError{}, fmt.Errorf("%w: no selected prepareGroupCall error", ber.ErrInvalidBinding)
}
func infoPrepareHandoverOperation() mapvalues.OperationInfo {
	info, _ := mapvalues.LookupOperation(mapvalues.PrepareHandover)
	return info
}

// PrepareHandoverOperation binds the formal object in TS 29.002 V19.1.0 §17.6.1 (X.880 §§8.2–8.3).
func PrepareHandoverOperation() Operation[mapvalues.PrepareHOArg, mapvalues.PrepareHORes, mapvalues.PrepareHandoverErrors] {
	return Operation[mapvalues.PrepareHOArg, mapvalues.PrepareHORes, mapvalues.PrepareHandoverErrors]{code: mapvalues.PrepareHandover, info: infoPrepareHandoverOperation, argument: PrepareHOArgCodec(), result: PrepareHOResCodec(), decode: decodePrepareHandoverError, encode: encodePrepareHandoverError}
}
func decodePrepareHandoverError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (mapvalues.PrepareHandoverErrors, error) {
	switch code {
	case 34:
		p, err := decodeErrorParameter(data, present, SystemFailureParamCodec(), opts...)
		if err != nil {
			return mapvalues.PrepareHandoverErrors{}, err
		}
		return mapvalues.PrepareHandoverErrors{SystemFailure: p}, nil
	case 35:
		p, err := decodeErrorParameter(data, present, DataMissingParamCodec(), opts...)
		if err != nil {
			return mapvalues.PrepareHandoverErrors{}, err
		}
		return mapvalues.PrepareHandoverErrors{DataMissing: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return mapvalues.PrepareHandoverErrors{}, err
		}
		return mapvalues.PrepareHandoverErrors{UnexpectedDataValue: p}, nil
	case 25:
		p, err := decodeErrorParameter(data, present, mapvalues.ValueCodec[mapvalues.NoParameter]{}, opts...)
		if err != nil {
			return mapvalues.PrepareHandoverErrors{}, err
		}
		return mapvalues.PrepareHandoverErrors{NoHandoverNumberAvailable: p}, nil
	case 42:
		p, err := decodeErrorParameter(data, present, TargetCellOutsideGCAParamCodec(), opts...)
		if err != nil {
			return mapvalues.PrepareHandoverErrors{}, err
		}
		return mapvalues.PrepareHandoverErrors{TargetCellOutsideGroupCallArea: p}, nil
	default:
		return mapvalues.PrepareHandoverErrors{}, fmt.Errorf("%w: error code %d is not in prepareHandover ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodePrepareHandoverError(value mapvalues.PrepareHandoverErrors, opts ...ber.EncodeOption) (mapvalues.EncodedError, error) {
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
		return mapvalues.EncodedError{}, fmt.Errorf("%w: exactly one prepareHandover error arm is required", ber.ErrInvalidBinding)
	}
	if value.SystemFailure != nil {
		return encodeMAPErrorMember(mapvalues.SystemFailure, value.SystemFailure, SystemFailureParamCodec(), opts...)
	}
	if value.DataMissing != nil {
		return encodeMAPErrorMember(mapvalues.DataMissing, value.DataMissing, DataMissingParamCodec(), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(mapvalues.UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	if value.NoHandoverNumberAvailable != nil {
		return encodeMAPErrorMember(mapvalues.NoHandoverNumberAvailable, value.NoHandoverNumberAvailable, mapvalues.ValueCodec[mapvalues.NoParameter]{}, opts...)
	}
	if value.TargetCellOutsideGroupCallArea != nil {
		return encodeMAPErrorMember(mapvalues.TargetCellOutsideGroupCallArea, value.TargetCellOutsideGroupCallArea, TargetCellOutsideGCAParamCodec(), opts...)
	}
	return mapvalues.EncodedError{}, fmt.Errorf("%w: no selected prepareHandover error", ber.ErrInvalidBinding)
}
func infoPrepareSubsequentHandoverOperation() mapvalues.OperationInfo {
	info, _ := mapvalues.LookupOperation(mapvalues.PrepareSubsequentHandover)
	return info
}

// PrepareSubsequentHandoverOperation binds the formal object in TS 29.002 V19.1.0 §17.6.1 (X.880 §§8.2–8.3).
func PrepareSubsequentHandoverOperation() Operation[mapvalues.PrepareSubsequentHOArg, mapvalues.PrepareSubsequentHORes, mapvalues.PrepareSubsequentHandoverErrors] {
	return Operation[mapvalues.PrepareSubsequentHOArg, mapvalues.PrepareSubsequentHORes, mapvalues.PrepareSubsequentHandoverErrors]{code: mapvalues.PrepareSubsequentHandover, info: infoPrepareSubsequentHandoverOperation, argument: PrepareSubsequentHOArgCodec(), result: PrepareSubsequentHOResCodec(), decode: decodePrepareSubsequentHandoverError, encode: encodePrepareSubsequentHandoverError}
}
func decodePrepareSubsequentHandoverError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (mapvalues.PrepareSubsequentHandoverErrors, error) {
	switch code {
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return mapvalues.PrepareSubsequentHandoverErrors{}, err
		}
		return mapvalues.PrepareSubsequentHandoverErrors{UnexpectedDataValue: p}, nil
	case 35:
		p, err := decodeErrorParameter(data, present, DataMissingParamCodec(), opts...)
		if err != nil {
			return mapvalues.PrepareSubsequentHandoverErrors{}, err
		}
		return mapvalues.PrepareSubsequentHandoverErrors{DataMissing: p}, nil
	case 3:
		p, err := decodeErrorParameter(data, present, mapvalues.ValueCodec[mapvalues.NoParameter]{}, opts...)
		if err != nil {
			return mapvalues.PrepareSubsequentHandoverErrors{}, err
		}
		return mapvalues.PrepareSubsequentHandoverErrors{UnknownMSC: p}, nil
	case 26:
		p, err := decodeErrorParameter(data, present, mapvalues.ValueCodec[mapvalues.NoParameter]{}, opts...)
		if err != nil {
			return mapvalues.PrepareSubsequentHandoverErrors{}, err
		}
		return mapvalues.PrepareSubsequentHandoverErrors{SubsequentHandoverFailure: p}, nil
	default:
		return mapvalues.PrepareSubsequentHandoverErrors{}, fmt.Errorf("%w: error code %d is not in prepareSubsequentHandover ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodePrepareSubsequentHandoverError(value mapvalues.PrepareSubsequentHandoverErrors, opts ...ber.EncodeOption) (mapvalues.EncodedError, error) {
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
		return mapvalues.EncodedError{}, fmt.Errorf("%w: exactly one prepareSubsequentHandover error arm is required", ber.ErrInvalidBinding)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(mapvalues.UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	if value.DataMissing != nil {
		return encodeMAPErrorMember(mapvalues.DataMissing, value.DataMissing, DataMissingParamCodec(), opts...)
	}
	if value.UnknownMSC != nil {
		return encodeMAPErrorMember(mapvalues.UnknownMSC, value.UnknownMSC, mapvalues.ValueCodec[mapvalues.NoParameter]{}, opts...)
	}
	if value.SubsequentHandoverFailure != nil {
		return encodeMAPErrorMember(mapvalues.SubsequentHandoverFailure, value.SubsequentHandoverFailure, mapvalues.ValueCodec[mapvalues.NoParameter]{}, opts...)
	}
	return mapvalues.EncodedError{}, fmt.Errorf("%w: no selected prepareSubsequentHandover error", ber.ErrInvalidBinding)
}
func infoProcessAccessSignallingOperation() mapvalues.OperationInfo {
	info, _ := mapvalues.LookupOperation(mapvalues.ProcessAccessSignalling)
	return info
}

// ProcessAccessSignallingOperation binds the formal object in TS 29.002 V19.1.0 §17.6.1 (X.880 §§8.2–8.3).
func ProcessAccessSignallingOperation() Operation[mapvalues.ProcessAccessSignallingArg, mapvalues.NoParameter, mapvalues.ProcessAccessSignallingErrors] {
	return Operation[mapvalues.ProcessAccessSignallingArg, mapvalues.NoParameter, mapvalues.ProcessAccessSignallingErrors]{code: mapvalues.ProcessAccessSignalling, info: infoProcessAccessSignallingOperation, argument: ProcessAccessSignallingArgCodec(), result: mapvalues.ValueCodec[mapvalues.NoParameter]{}, decode: decodeProcessAccessSignallingError, encode: encodeProcessAccessSignallingError}
}
func decodeProcessAccessSignallingError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (mapvalues.ProcessAccessSignallingErrors, error) {
	switch code {
	default:
		return mapvalues.ProcessAccessSignallingErrors{}, fmt.Errorf("%w: error code %d is not in processAccessSignalling ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeProcessAccessSignallingError(value mapvalues.ProcessAccessSignallingErrors, opts ...ber.EncodeOption) (mapvalues.EncodedError, error) {
	return mapvalues.EncodedError{}, fmt.Errorf("%w: no selected processAccessSignalling error", ber.ErrInvalidBinding)
}
func infoProcessGroupCallSignallingOperation() mapvalues.OperationInfo {
	info, _ := mapvalues.LookupOperation(mapvalues.ProcessGroupCallSignalling)
	return info
}

// ProcessGroupCallSignallingOperation binds the formal object in TS 29.002 V19.1.0 §17.6.7 (X.880 §§8.2–8.3).
func ProcessGroupCallSignallingOperation() Operation[mapvalues.ProcessGroupCallSignallingArg, mapvalues.NoParameter, mapvalues.ProcessGroupCallSignallingErrors] {
	return Operation[mapvalues.ProcessGroupCallSignallingArg, mapvalues.NoParameter, mapvalues.ProcessGroupCallSignallingErrors]{code: mapvalues.ProcessGroupCallSignalling, info: infoProcessGroupCallSignallingOperation, argument: ProcessGroupCallSignallingArgCodec(), result: mapvalues.ValueCodec[mapvalues.NoParameter]{}, decode: decodeProcessGroupCallSignallingError, encode: encodeProcessGroupCallSignallingError}
}
func decodeProcessGroupCallSignallingError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (mapvalues.ProcessGroupCallSignallingErrors, error) {
	switch code {
	default:
		return mapvalues.ProcessGroupCallSignallingErrors{}, fmt.Errorf("%w: error code %d is not in processGroupCallSignalling ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeProcessGroupCallSignallingError(value mapvalues.ProcessGroupCallSignallingErrors, opts ...ber.EncodeOption) (mapvalues.EncodedError, error) {
	return mapvalues.EncodedError{}, fmt.Errorf("%w: no selected processGroupCallSignalling error", ber.ErrInvalidBinding)
}
func infoProcessUnstructuredSSRequestOperation() mapvalues.OperationInfo {
	info, _ := mapvalues.LookupOperation(mapvalues.ProcessUnstructuredSSRequest)
	return info
}

// ProcessUnstructuredSSRequestOperation binds the formal object in TS 29.002 V19.1.0 §17.6.4 (X.880 §§8.2–8.3).
func ProcessUnstructuredSSRequestOperation() Operation[mapvalues.USSDArg, mapvalues.USSDRes, mapvalues.ProcessUnstructuredSSRequestErrors] {
	return Operation[mapvalues.USSDArg, mapvalues.USSDRes, mapvalues.ProcessUnstructuredSSRequestErrors]{code: mapvalues.ProcessUnstructuredSSRequest, info: infoProcessUnstructuredSSRequestOperation, argument: USSDArgCodec(), result: USSDResCodec(), decode: decodeProcessUnstructuredSSRequestError, encode: encodeProcessUnstructuredSSRequestError}
}
func decodeProcessUnstructuredSSRequestError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (mapvalues.ProcessUnstructuredSSRequestErrors, error) {
	switch code {
	case 34:
		p, err := decodeErrorParameter(data, present, SystemFailureParamCodec(), opts...)
		if err != nil {
			return mapvalues.ProcessUnstructuredSSRequestErrors{}, err
		}
		return mapvalues.ProcessUnstructuredSSRequestErrors{SystemFailure: p}, nil
	case 35:
		p, err := decodeErrorParameter(data, present, DataMissingParamCodec(), opts...)
		if err != nil {
			return mapvalues.ProcessUnstructuredSSRequestErrors{}, err
		}
		return mapvalues.ProcessUnstructuredSSRequestErrors{DataMissing: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return mapvalues.ProcessUnstructuredSSRequestErrors{}, err
		}
		return mapvalues.ProcessUnstructuredSSRequestErrors{UnexpectedDataValue: p}, nil
	case 71:
		p, err := decodeErrorParameter(data, present, mapvalues.ValueCodec[mapvalues.NoParameter]{}, opts...)
		if err != nil {
			return mapvalues.ProcessUnstructuredSSRequestErrors{}, err
		}
		return mapvalues.ProcessUnstructuredSSRequestErrors{UnknownAlphabet: p}, nil
	case 13:
		p, err := decodeErrorParameter(data, present, CallBarredParamCodec(), opts...)
		if err != nil {
			return mapvalues.ProcessUnstructuredSSRequestErrors{}, err
		}
		return mapvalues.ProcessUnstructuredSSRequestErrors{CallBarred: p}, nil
	default:
		return mapvalues.ProcessUnstructuredSSRequestErrors{}, fmt.Errorf("%w: error code %d is not in processUnstructuredSS-Request ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeProcessUnstructuredSSRequestError(value mapvalues.ProcessUnstructuredSSRequestErrors, opts ...ber.EncodeOption) (mapvalues.EncodedError, error) {
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
		return mapvalues.EncodedError{}, fmt.Errorf("%w: exactly one processUnstructuredSS-Request error arm is required", ber.ErrInvalidBinding)
	}
	if value.SystemFailure != nil {
		return encodeMAPErrorMember(mapvalues.SystemFailure, value.SystemFailure, SystemFailureParamCodec(), opts...)
	}
	if value.DataMissing != nil {
		return encodeMAPErrorMember(mapvalues.DataMissing, value.DataMissing, DataMissingParamCodec(), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(mapvalues.UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	if value.UnknownAlphabet != nil {
		return encodeMAPErrorMember(mapvalues.UnknownAlphabet, value.UnknownAlphabet, mapvalues.ValueCodec[mapvalues.NoParameter]{}, opts...)
	}
	if value.CallBarred != nil {
		return encodeMAPErrorMember(mapvalues.CallBarred, value.CallBarred, CallBarredParamCodec(), opts...)
	}
	return mapvalues.EncodedError{}, fmt.Errorf("%w: no selected processUnstructuredSS-Request error", ber.ErrInvalidBinding)
}
func infoProvideRoamingNumberOperation() mapvalues.OperationInfo {
	info, _ := mapvalues.LookupOperation(mapvalues.ProvideRoamingNumber)
	return info
}

// ProvideRoamingNumberOperation binds the formal object in TS 29.002 V19.1.0 §17.6.3 (X.880 §§8.2–8.3).
func ProvideRoamingNumberOperation() Operation[mapvalues.ProvideRoamingNumberArg, mapvalues.ProvideRoamingNumberRes, mapvalues.ProvideRoamingNumberErrors] {
	return Operation[mapvalues.ProvideRoamingNumberArg, mapvalues.ProvideRoamingNumberRes, mapvalues.ProvideRoamingNumberErrors]{code: mapvalues.ProvideRoamingNumber, info: infoProvideRoamingNumberOperation, argument: ProvideRoamingNumberArgCodec(), result: ProvideRoamingNumberResCodec(), decode: decodeProvideRoamingNumberError, encode: encodeProvideRoamingNumberError}
}
func decodeProvideRoamingNumberError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (mapvalues.ProvideRoamingNumberErrors, error) {
	switch code {
	case 34:
		p, err := decodeErrorParameter(data, present, SystemFailureParamCodec(), opts...)
		if err != nil {
			return mapvalues.ProvideRoamingNumberErrors{}, err
		}
		return mapvalues.ProvideRoamingNumberErrors{SystemFailure: p}, nil
	case 35:
		p, err := decodeErrorParameter(data, present, DataMissingParamCodec(), opts...)
		if err != nil {
			return mapvalues.ProvideRoamingNumberErrors{}, err
		}
		return mapvalues.ProvideRoamingNumberErrors{DataMissing: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return mapvalues.ProvideRoamingNumberErrors{}, err
		}
		return mapvalues.ProvideRoamingNumberErrors{UnexpectedDataValue: p}, nil
	case 21:
		p, err := decodeErrorParameter(data, present, FacilityNotSupParamCodec(), opts...)
		if err != nil {
			return mapvalues.ProvideRoamingNumberErrors{}, err
		}
		return mapvalues.ProvideRoamingNumberErrors{FacilityNotSupported: p}, nil
	case 48:
		p, err := decodeErrorParameter(data, present, ORNotAllowedParamCodec(), opts...)
		if err != nil {
			return mapvalues.ProvideRoamingNumberErrors{}, err
		}
		return mapvalues.ProvideRoamingNumberErrors{OrNotAllowed: p}, nil
	case 27:
		p, err := decodeErrorParameter(data, present, AbsentSubscriberParamCodec(), opts...)
		if err != nil {
			return mapvalues.ProvideRoamingNumberErrors{}, err
		}
		return mapvalues.ProvideRoamingNumberErrors{AbsentSubscriber: p}, nil
	case 39:
		p, err := decodeErrorParameter(data, present, NoRoamingNbParamCodec(), opts...)
		if err != nil {
			return mapvalues.ProvideRoamingNumberErrors{}, err
		}
		return mapvalues.ProvideRoamingNumberErrors{NoRoamingNumberAvailable: p}, nil
	default:
		return mapvalues.ProvideRoamingNumberErrors{}, fmt.Errorf("%w: error code %d is not in provideRoamingNumber ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeProvideRoamingNumberError(value mapvalues.ProvideRoamingNumberErrors, opts ...ber.EncodeOption) (mapvalues.EncodedError, error) {
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
		return mapvalues.EncodedError{}, fmt.Errorf("%w: exactly one provideRoamingNumber error arm is required", ber.ErrInvalidBinding)
	}
	if value.SystemFailure != nil {
		return encodeMAPErrorMember(mapvalues.SystemFailure, value.SystemFailure, SystemFailureParamCodec(), opts...)
	}
	if value.DataMissing != nil {
		return encodeMAPErrorMember(mapvalues.DataMissing, value.DataMissing, DataMissingParamCodec(), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(mapvalues.UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	if value.FacilityNotSupported != nil {
		return encodeMAPErrorMember(mapvalues.FacilityNotSupported, value.FacilityNotSupported, FacilityNotSupParamCodec(), opts...)
	}
	if value.OrNotAllowed != nil {
		return encodeMAPErrorMember(mapvalues.OrNotAllowed, value.OrNotAllowed, ORNotAllowedParamCodec(), opts...)
	}
	if value.AbsentSubscriber != nil {
		return encodeMAPErrorMember(mapvalues.AbsentSubscriber, value.AbsentSubscriber, AbsentSubscriberParamCodec(), opts...)
	}
	if value.NoRoamingNumberAvailable != nil {
		return encodeMAPErrorMember(mapvalues.NoRoamingNumberAvailable, value.NoRoamingNumberAvailable, NoRoamingNbParamCodec(), opts...)
	}
	return mapvalues.EncodedError{}, fmt.Errorf("%w: no selected provideRoamingNumber error", ber.ErrInvalidBinding)
}
func infoProvideSubscriberInfoOperation() mapvalues.OperationInfo {
	info, _ := mapvalues.LookupOperation(mapvalues.ProvideSubscriberInfo)
	return info
}

// ProvideSubscriberInfoOperation binds the formal object in TS 29.002 V19.1.0 §17.6.1 (X.880 §§8.2–8.3).
func ProvideSubscriberInfoOperation() Operation[mapvalues.ProvideSubscriberInfoArg, mapvalues.ProvideSubscriberInfoRes, mapvalues.ProvideSubscriberInfoErrors] {
	return Operation[mapvalues.ProvideSubscriberInfoArg, mapvalues.ProvideSubscriberInfoRes, mapvalues.ProvideSubscriberInfoErrors]{code: mapvalues.ProvideSubscriberInfo, info: infoProvideSubscriberInfoOperation, argument: ProvideSubscriberInfoArgCodec(), result: ProvideSubscriberInfoResCodec(), decode: decodeProvideSubscriberInfoError, encode: encodeProvideSubscriberInfoError}
}
func decodeProvideSubscriberInfoError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (mapvalues.ProvideSubscriberInfoErrors, error) {
	switch code {
	case 35:
		p, err := decodeErrorParameter(data, present, DataMissingParamCodec(), opts...)
		if err != nil {
			return mapvalues.ProvideSubscriberInfoErrors{}, err
		}
		return mapvalues.ProvideSubscriberInfoErrors{DataMissing: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return mapvalues.ProvideSubscriberInfoErrors{}, err
		}
		return mapvalues.ProvideSubscriberInfoErrors{UnexpectedDataValue: p}, nil
	default:
		return mapvalues.ProvideSubscriberInfoErrors{}, fmt.Errorf("%w: error code %d is not in provideSubscriberInfo ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeProvideSubscriberInfoError(value mapvalues.ProvideSubscriberInfoErrors, opts ...ber.EncodeOption) (mapvalues.EncodedError, error) {
	selected := 0
	if value.DataMissing != nil {
		selected++
	}
	if value.UnexpectedDataValue != nil {
		selected++
	}
	if selected != 1 {
		return mapvalues.EncodedError{}, fmt.Errorf("%w: exactly one provideSubscriberInfo error arm is required", ber.ErrInvalidBinding)
	}
	if value.DataMissing != nil {
		return encodeMAPErrorMember(mapvalues.DataMissing, value.DataMissing, DataMissingParamCodec(), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(mapvalues.UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	return mapvalues.EncodedError{}, fmt.Errorf("%w: no selected provideSubscriberInfo error", ber.ErrInvalidBinding)
}
func infoProvideSubscriberLocationOperation() mapvalues.OperationInfo {
	info, _ := mapvalues.LookupOperation(mapvalues.ProvideSubscriberLocation)
	return info
}

// ProvideSubscriberLocationOperation binds the formal object in TS 29.002 V19.1.0 §17.6.8 (X.880 §§8.2–8.3).
func ProvideSubscriberLocationOperation() Operation[mapvalues.ProvideSubscriberLocationArg, mapvalues.ProvideSubscriberLocationRes, mapvalues.ProvideSubscriberLocationErrors] {
	return Operation[mapvalues.ProvideSubscriberLocationArg, mapvalues.ProvideSubscriberLocationRes, mapvalues.ProvideSubscriberLocationErrors]{code: mapvalues.ProvideSubscriberLocation, info: infoProvideSubscriberLocationOperation, argument: ProvideSubscriberLocationArgCodec(), result: ProvideSubscriberLocationResCodec(), decode: decodeProvideSubscriberLocationError, encode: encodeProvideSubscriberLocationError}
}
func decodeProvideSubscriberLocationError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (mapvalues.ProvideSubscriberLocationErrors, error) {
	switch code {
	case 34:
		p, err := decodeErrorParameter(data, present, SystemFailureParamCodec(), opts...)
		if err != nil {
			return mapvalues.ProvideSubscriberLocationErrors{}, err
		}
		return mapvalues.ProvideSubscriberLocationErrors{SystemFailure: p}, nil
	case 35:
		p, err := decodeErrorParameter(data, present, DataMissingParamCodec(), opts...)
		if err != nil {
			return mapvalues.ProvideSubscriberLocationErrors{}, err
		}
		return mapvalues.ProvideSubscriberLocationErrors{DataMissing: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return mapvalues.ProvideSubscriberLocationErrors{}, err
		}
		return mapvalues.ProvideSubscriberLocationErrors{UnexpectedDataValue: p}, nil
	case 21:
		p, err := decodeErrorParameter(data, present, FacilityNotSupParamCodec(), opts...)
		if err != nil {
			return mapvalues.ProvideSubscriberLocationErrors{}, err
		}
		return mapvalues.ProvideSubscriberLocationErrors{FacilityNotSupported: p}, nil
	case 5:
		p, err := decodeErrorParameter(data, present, UnidentifiedSubParamCodec(), opts...)
		if err != nil {
			return mapvalues.ProvideSubscriberLocationErrors{}, err
		}
		return mapvalues.ProvideSubscriberLocationErrors{UnidentifiedSubscriber: p}, nil
	case 9:
		p, err := decodeErrorParameter(data, present, IllegalSubscriberParamCodec(), opts...)
		if err != nil {
			return mapvalues.ProvideSubscriberLocationErrors{}, err
		}
		return mapvalues.ProvideSubscriberLocationErrors{IllegalSubscriber: p}, nil
	case 12:
		p, err := decodeErrorParameter(data, present, IllegalEquipmentParamCodec(), opts...)
		if err != nil {
			return mapvalues.ProvideSubscriberLocationErrors{}, err
		}
		return mapvalues.ProvideSubscriberLocationErrors{IllegalEquipment: p}, nil
	case 27:
		p, err := decodeErrorParameter(data, present, AbsentSubscriberParamCodec(), opts...)
		if err != nil {
			return mapvalues.ProvideSubscriberLocationErrors{}, err
		}
		return mapvalues.ProvideSubscriberLocationErrors{AbsentSubscriber: p}, nil
	case 52:
		p, err := decodeErrorParameter(data, present, UnauthorizedRequestingNetworkParamCodec(), opts...)
		if err != nil {
			return mapvalues.ProvideSubscriberLocationErrors{}, err
		}
		return mapvalues.ProvideSubscriberLocationErrors{UnauthorizedRequestingNetwork: p}, nil
	case 53:
		p, err := decodeErrorParameter(data, present, UnauthorizedLCSClientParamCodec(), opts...)
		if err != nil {
			return mapvalues.ProvideSubscriberLocationErrors{}, err
		}
		return mapvalues.ProvideSubscriberLocationErrors{UnauthorizedLCSClient: p}, nil
	case 54:
		p, err := decodeErrorParameter(data, present, PositionMethodFailureParamCodec(), opts...)
		if err != nil {
			return mapvalues.ProvideSubscriberLocationErrors{}, err
		}
		return mapvalues.ProvideSubscriberLocationErrors{PositionMethodFailure: p}, nil
	default:
		return mapvalues.ProvideSubscriberLocationErrors{}, fmt.Errorf("%w: error code %d is not in provideSubscriberLocation ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeProvideSubscriberLocationError(value mapvalues.ProvideSubscriberLocationErrors, opts ...ber.EncodeOption) (mapvalues.EncodedError, error) {
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
		return mapvalues.EncodedError{}, fmt.Errorf("%w: exactly one provideSubscriberLocation error arm is required", ber.ErrInvalidBinding)
	}
	if value.SystemFailure != nil {
		return encodeMAPErrorMember(mapvalues.SystemFailure, value.SystemFailure, SystemFailureParamCodec(), opts...)
	}
	if value.DataMissing != nil {
		return encodeMAPErrorMember(mapvalues.DataMissing, value.DataMissing, DataMissingParamCodec(), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(mapvalues.UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	if value.FacilityNotSupported != nil {
		return encodeMAPErrorMember(mapvalues.FacilityNotSupported, value.FacilityNotSupported, FacilityNotSupParamCodec(), opts...)
	}
	if value.UnidentifiedSubscriber != nil {
		return encodeMAPErrorMember(mapvalues.UnidentifiedSubscriber, value.UnidentifiedSubscriber, UnidentifiedSubParamCodec(), opts...)
	}
	if value.IllegalSubscriber != nil {
		return encodeMAPErrorMember(mapvalues.IllegalSubscriber, value.IllegalSubscriber, IllegalSubscriberParamCodec(), opts...)
	}
	if value.IllegalEquipment != nil {
		return encodeMAPErrorMember(mapvalues.IllegalEquipment, value.IllegalEquipment, IllegalEquipmentParamCodec(), opts...)
	}
	if value.AbsentSubscriber != nil {
		return encodeMAPErrorMember(mapvalues.AbsentSubscriber, value.AbsentSubscriber, AbsentSubscriberParamCodec(), opts...)
	}
	if value.UnauthorizedRequestingNetwork != nil {
		return encodeMAPErrorMember(mapvalues.UnauthorizedRequestingNetwork, value.UnauthorizedRequestingNetwork, UnauthorizedRequestingNetworkParamCodec(), opts...)
	}
	if value.UnauthorizedLCSClient != nil {
		return encodeMAPErrorMember(mapvalues.UnauthorizedLCSClient, value.UnauthorizedLCSClient, UnauthorizedLCSClientParamCodec(), opts...)
	}
	if value.PositionMethodFailure != nil {
		return encodeMAPErrorMember(mapvalues.PositionMethodFailure, value.PositionMethodFailure, PositionMethodFailureParamCodec(), opts...)
	}
	return mapvalues.EncodedError{}, fmt.Errorf("%w: no selected provideSubscriberLocation error", ber.ErrInvalidBinding)
}
func infoPurgeMSOperation() mapvalues.OperationInfo {
	info, _ := mapvalues.LookupOperation(mapvalues.PurgeMS)
	return info
}

// PurgeMSOperation binds the formal object in TS 29.002 V19.1.0 §17.6.1 (X.880 §§8.2–8.3).
func PurgeMSOperation() Operation[mapvalues.PurgeMSArg, mapvalues.PurgeMSRes, mapvalues.PurgeMSErrors] {
	return Operation[mapvalues.PurgeMSArg, mapvalues.PurgeMSRes, mapvalues.PurgeMSErrors]{code: mapvalues.PurgeMS, info: infoPurgeMSOperation, argument: PurgeMSArgCodec(), result: PurgeMSResCodec(), decode: decodePurgeMSError, encode: encodePurgeMSError}
}
func decodePurgeMSError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (mapvalues.PurgeMSErrors, error) {
	switch code {
	case 35:
		p, err := decodeErrorParameter(data, present, DataMissingParamCodec(), opts...)
		if err != nil {
			return mapvalues.PurgeMSErrors{}, err
		}
		return mapvalues.PurgeMSErrors{DataMissing: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return mapvalues.PurgeMSErrors{}, err
		}
		return mapvalues.PurgeMSErrors{UnexpectedDataValue: p}, nil
	case 1:
		p, err := decodeErrorParameter(data, present, UnknownSubscriberParamCodec(), opts...)
		if err != nil {
			return mapvalues.PurgeMSErrors{}, err
		}
		return mapvalues.PurgeMSErrors{UnknownSubscriber: p}, nil
	default:
		return mapvalues.PurgeMSErrors{}, fmt.Errorf("%w: error code %d is not in purgeMS ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodePurgeMSError(value mapvalues.PurgeMSErrors, opts ...ber.EncodeOption) (mapvalues.EncodedError, error) {
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
		return mapvalues.EncodedError{}, fmt.Errorf("%w: exactly one purgeMS error arm is required", ber.ErrInvalidBinding)
	}
	if value.DataMissing != nil {
		return encodeMAPErrorMember(mapvalues.DataMissing, value.DataMissing, DataMissingParamCodec(), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(mapvalues.UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	if value.UnknownSubscriber != nil {
		return encodeMAPErrorMember(mapvalues.UnknownSubscriber, value.UnknownSubscriber, UnknownSubscriberParamCodec(), opts...)
	}
	return mapvalues.EncodedError{}, fmt.Errorf("%w: no selected purgeMS error", ber.ErrInvalidBinding)
}
func infoReadyForSMOperation() mapvalues.OperationInfo {
	info, _ := mapvalues.LookupOperation(mapvalues.ReadyForSM)
	return info
}

// ReadyForSMOperation binds the formal object in TS 29.002 V19.1.0 §17.6.5 (X.880 §§8.2–8.3).
func ReadyForSMOperation() Operation[mapvalues.ReadyForSMArg, mapvalues.ReadyForSMRes, mapvalues.ReadyForSMErrors] {
	return Operation[mapvalues.ReadyForSMArg, mapvalues.ReadyForSMRes, mapvalues.ReadyForSMErrors]{code: mapvalues.ReadyForSM, info: infoReadyForSMOperation, argument: ReadyForSMArgCodec(), result: ReadyForSMResCodec(), decode: decodeReadyForSMError, encode: encodeReadyForSMError}
}
func decodeReadyForSMError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (mapvalues.ReadyForSMErrors, error) {
	switch code {
	case 35:
		p, err := decodeErrorParameter(data, present, DataMissingParamCodec(), opts...)
		if err != nil {
			return mapvalues.ReadyForSMErrors{}, err
		}
		return mapvalues.ReadyForSMErrors{DataMissing: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return mapvalues.ReadyForSMErrors{}, err
		}
		return mapvalues.ReadyForSMErrors{UnexpectedDataValue: p}, nil
	case 21:
		p, err := decodeErrorParameter(data, present, FacilityNotSupParamCodec(), opts...)
		if err != nil {
			return mapvalues.ReadyForSMErrors{}, err
		}
		return mapvalues.ReadyForSMErrors{FacilityNotSupported: p}, nil
	case 1:
		p, err := decodeErrorParameter(data, present, UnknownSubscriberParamCodec(), opts...)
		if err != nil {
			return mapvalues.ReadyForSMErrors{}, err
		}
		return mapvalues.ReadyForSMErrors{UnknownSubscriber: p}, nil
	default:
		return mapvalues.ReadyForSMErrors{}, fmt.Errorf("%w: error code %d is not in readyForSM ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeReadyForSMError(value mapvalues.ReadyForSMErrors, opts ...ber.EncodeOption) (mapvalues.EncodedError, error) {
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
		return mapvalues.EncodedError{}, fmt.Errorf("%w: exactly one readyForSM error arm is required", ber.ErrInvalidBinding)
	}
	if value.DataMissing != nil {
		return encodeMAPErrorMember(mapvalues.DataMissing, value.DataMissing, DataMissingParamCodec(), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(mapvalues.UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	if value.FacilityNotSupported != nil {
		return encodeMAPErrorMember(mapvalues.FacilityNotSupported, value.FacilityNotSupported, FacilityNotSupParamCodec(), opts...)
	}
	if value.UnknownSubscriber != nil {
		return encodeMAPErrorMember(mapvalues.UnknownSubscriber, value.UnknownSubscriber, UnknownSubscriberParamCodec(), opts...)
	}
	return mapvalues.EncodedError{}, fmt.Errorf("%w: no selected readyForSM error", ber.ErrInvalidBinding)
}
func infoRegisterCCEntryOperation() mapvalues.OperationInfo {
	info, _ := mapvalues.LookupOperation(mapvalues.RegisterCCEntry)
	return info
}

// RegisterCCEntryOperation binds the formal object in TS 29.002 V19.1.0 §17.6.4 (X.880 §§8.2–8.3).
func RegisterCCEntryOperation() Operation[mapvalues.RegisterCCEntryArg, mapvalues.RegisterCCEntryRes, mapvalues.RegisterCCEntryErrors] {
	return Operation[mapvalues.RegisterCCEntryArg, mapvalues.RegisterCCEntryRes, mapvalues.RegisterCCEntryErrors]{code: mapvalues.RegisterCCEntry, info: infoRegisterCCEntryOperation, argument: RegisterCCEntryArgCodec(), result: RegisterCCEntryResCodec(), decode: decodeRegisterCCEntryError, encode: encodeRegisterCCEntryError}
}
func decodeRegisterCCEntryError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (mapvalues.RegisterCCEntryErrors, error) {
	switch code {
	case 34:
		p, err := decodeErrorParameter(data, present, SystemFailureParamCodec(), opts...)
		if err != nil {
			return mapvalues.RegisterCCEntryErrors{}, err
		}
		return mapvalues.RegisterCCEntryErrors{SystemFailure: p}, nil
	case 35:
		p, err := decodeErrorParameter(data, present, DataMissingParamCodec(), opts...)
		if err != nil {
			return mapvalues.RegisterCCEntryErrors{}, err
		}
		return mapvalues.RegisterCCEntryErrors{DataMissing: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return mapvalues.RegisterCCEntryErrors{}, err
		}
		return mapvalues.RegisterCCEntryErrors{UnexpectedDataValue: p}, nil
	case 13:
		p, err := decodeErrorParameter(data, present, CallBarredParamCodec(), opts...)
		if err != nil {
			return mapvalues.RegisterCCEntryErrors{}, err
		}
		return mapvalues.RegisterCCEntryErrors{CallBarred: p}, nil
	case 16:
		p, err := decodeErrorParameter(data, present, IllegalSSOperationParamCodec(), opts...)
		if err != nil {
			return mapvalues.RegisterCCEntryErrors{}, err
		}
		return mapvalues.RegisterCCEntryErrors{IllegalSSOperation: p}, nil
	case 17:
		p, err := decodeErrorParameter(data, present, SSStatusCodec(), opts...)
		if err != nil {
			return mapvalues.RegisterCCEntryErrors{}, err
		}
		return mapvalues.RegisterCCEntryErrors{SsErrorStatus: p}, nil
	case 20:
		p, err := decodeErrorParameter(data, present, SSIncompatibilityCauseCodec(), opts...)
		if err != nil {
			return mapvalues.RegisterCCEntryErrors{}, err
		}
		return mapvalues.RegisterCCEntryErrors{SsIncompatibility: p}, nil
	case 29:
		p, err := decodeErrorParameter(data, present, ShortTermDenialParamCodec(), opts...)
		if err != nil {
			return mapvalues.RegisterCCEntryErrors{}, err
		}
		return mapvalues.RegisterCCEntryErrors{ShortTermDenial: p}, nil
	case 30:
		p, err := decodeErrorParameter(data, present, LongTermDenialParamCodec(), opts...)
		if err != nil {
			return mapvalues.RegisterCCEntryErrors{}, err
		}
		return mapvalues.RegisterCCEntryErrors{LongTermDenial: p}, nil
	case 21:
		p, err := decodeErrorParameter(data, present, FacilityNotSupParamCodec(), opts...)
		if err != nil {
			return mapvalues.RegisterCCEntryErrors{}, err
		}
		return mapvalues.RegisterCCEntryErrors{FacilityNotSupported: p}, nil
	default:
		return mapvalues.RegisterCCEntryErrors{}, fmt.Errorf("%w: error code %d is not in registerCC-Entry ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeRegisterCCEntryError(value mapvalues.RegisterCCEntryErrors, opts ...ber.EncodeOption) (mapvalues.EncodedError, error) {
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
		return mapvalues.EncodedError{}, fmt.Errorf("%w: exactly one registerCC-Entry error arm is required", ber.ErrInvalidBinding)
	}
	if value.SystemFailure != nil {
		return encodeMAPErrorMember(mapvalues.SystemFailure, value.SystemFailure, SystemFailureParamCodec(), opts...)
	}
	if value.DataMissing != nil {
		return encodeMAPErrorMember(mapvalues.DataMissing, value.DataMissing, DataMissingParamCodec(), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(mapvalues.UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	if value.CallBarred != nil {
		return encodeMAPErrorMember(mapvalues.CallBarred, value.CallBarred, CallBarredParamCodec(), opts...)
	}
	if value.IllegalSSOperation != nil {
		return encodeMAPErrorMember(mapvalues.IllegalSSOperation, value.IllegalSSOperation, IllegalSSOperationParamCodec(), opts...)
	}
	if value.SsErrorStatus != nil {
		return encodeMAPErrorMember(mapvalues.SsErrorStatus, value.SsErrorStatus, SSStatusCodec(), opts...)
	}
	if value.SsIncompatibility != nil {
		return encodeMAPErrorMember(mapvalues.SsIncompatibility, value.SsIncompatibility, SSIncompatibilityCauseCodec(), opts...)
	}
	if value.ShortTermDenial != nil {
		return encodeMAPErrorMember(mapvalues.ShortTermDenial, value.ShortTermDenial, ShortTermDenialParamCodec(), opts...)
	}
	if value.LongTermDenial != nil {
		return encodeMAPErrorMember(mapvalues.LongTermDenial, value.LongTermDenial, LongTermDenialParamCodec(), opts...)
	}
	if value.FacilityNotSupported != nil {
		return encodeMAPErrorMember(mapvalues.FacilityNotSupported, value.FacilityNotSupported, FacilityNotSupParamCodec(), opts...)
	}
	return mapvalues.EncodedError{}, fmt.Errorf("%w: no selected registerCC-Entry error", ber.ErrInvalidBinding)
}
func infoRegisterPasswordOperation() mapvalues.OperationInfo {
	info, _ := mapvalues.LookupOperation(mapvalues.RegisterPassword)
	return info
}

// RegisterPasswordOperation binds the formal object in TS 29.002 V19.1.0 §17.6.4 (X.880 §§8.2–8.3).
func RegisterPasswordOperation() Operation[mapvalues.BERValue[mapvalues.SSCode], mapvalues.BERValue[mapvalues.Password], mapvalues.RegisterPasswordErrors] {
	return Operation[mapvalues.BERValue[mapvalues.SSCode], mapvalues.BERValue[mapvalues.Password], mapvalues.RegisterPasswordErrors]{code: mapvalues.RegisterPassword, info: infoRegisterPasswordOperation, argument: SSCodeCodec(), result: PasswordCodec(), decode: decodeRegisterPasswordError, encode: encodeRegisterPasswordError}
}
func decodeRegisterPasswordError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (mapvalues.RegisterPasswordErrors, error) {
	switch code {
	case 34:
		p, err := decodeErrorParameter(data, present, SystemFailureParamCodec(), opts...)
		if err != nil {
			return mapvalues.RegisterPasswordErrors{}, err
		}
		return mapvalues.RegisterPasswordErrors{SystemFailure: p}, nil
	case 35:
		p, err := decodeErrorParameter(data, present, DataMissingParamCodec(), opts...)
		if err != nil {
			return mapvalues.RegisterPasswordErrors{}, err
		}
		return mapvalues.RegisterPasswordErrors{DataMissing: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return mapvalues.RegisterPasswordErrors{}, err
		}
		return mapvalues.RegisterPasswordErrors{UnexpectedDataValue: p}, nil
	case 13:
		p, err := decodeErrorParameter(data, present, CallBarredParamCodec(), opts...)
		if err != nil {
			return mapvalues.RegisterPasswordErrors{}, err
		}
		return mapvalues.RegisterPasswordErrors{CallBarred: p}, nil
	case 19:
		p, err := decodeErrorParameter(data, present, SSSubscriptionViolationParamCodec(), opts...)
		if err != nil {
			return mapvalues.RegisterPasswordErrors{}, err
		}
		return mapvalues.RegisterPasswordErrors{SsSubscriptionViolation: p}, nil
	case 37:
		p, err := decodeErrorParameter(data, present, PWRegistrationFailureCauseCodec(), opts...)
		if err != nil {
			return mapvalues.RegisterPasswordErrors{}, err
		}
		return mapvalues.RegisterPasswordErrors{PwRegistrationFailure: p}, nil
	case 38:
		p, err := decodeErrorParameter(data, present, mapvalues.ValueCodec[mapvalues.NoParameter]{}, opts...)
		if err != nil {
			return mapvalues.RegisterPasswordErrors{}, err
		}
		return mapvalues.RegisterPasswordErrors{NegativePWCheck: p}, nil
	case 43:
		p, err := decodeErrorParameter(data, present, mapvalues.ValueCodec[mapvalues.NoParameter]{}, opts...)
		if err != nil {
			return mapvalues.RegisterPasswordErrors{}, err
		}
		return mapvalues.RegisterPasswordErrors{NumberOfPWAttemptsViolation: p}, nil
	default:
		return mapvalues.RegisterPasswordErrors{}, fmt.Errorf("%w: error code %d is not in registerPassword ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeRegisterPasswordError(value mapvalues.RegisterPasswordErrors, opts ...ber.EncodeOption) (mapvalues.EncodedError, error) {
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
		return mapvalues.EncodedError{}, fmt.Errorf("%w: exactly one registerPassword error arm is required", ber.ErrInvalidBinding)
	}
	if value.SystemFailure != nil {
		return encodeMAPErrorMember(mapvalues.SystemFailure, value.SystemFailure, SystemFailureParamCodec(), opts...)
	}
	if value.DataMissing != nil {
		return encodeMAPErrorMember(mapvalues.DataMissing, value.DataMissing, DataMissingParamCodec(), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(mapvalues.UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	if value.CallBarred != nil {
		return encodeMAPErrorMember(mapvalues.CallBarred, value.CallBarred, CallBarredParamCodec(), opts...)
	}
	if value.SsSubscriptionViolation != nil {
		return encodeMAPErrorMember(mapvalues.SsSubscriptionViolation, value.SsSubscriptionViolation, SSSubscriptionViolationParamCodec(), opts...)
	}
	if value.PwRegistrationFailure != nil {
		return encodeMAPErrorMember(mapvalues.PwRegistrationFailure, value.PwRegistrationFailure, PWRegistrationFailureCauseCodec(), opts...)
	}
	if value.NegativePWCheck != nil {
		return encodeMAPErrorMember(mapvalues.NegativePWCheck, value.NegativePWCheck, mapvalues.ValueCodec[mapvalues.NoParameter]{}, opts...)
	}
	if value.NumberOfPWAttemptsViolation != nil {
		return encodeMAPErrorMember(mapvalues.NumberOfPWAttemptsViolation, value.NumberOfPWAttemptsViolation, mapvalues.ValueCodec[mapvalues.NoParameter]{}, opts...)
	}
	return mapvalues.EncodedError{}, fmt.Errorf("%w: no selected registerPassword error", ber.ErrInvalidBinding)
}
func infoRegisterSSOperation() mapvalues.OperationInfo {
	info, _ := mapvalues.LookupOperation(mapvalues.RegisterSS)
	return info
}

// RegisterSSOperation binds the formal object in TS 29.002 V19.1.0 §17.6.4 (X.880 §§8.2–8.3).
func RegisterSSOperation() Operation[mapvalues.RegisterSSArg, mapvalues.SSInfo, mapvalues.RegisterSSErrors] {
	return Operation[mapvalues.RegisterSSArg, mapvalues.SSInfo, mapvalues.RegisterSSErrors]{code: mapvalues.RegisterSS, info: infoRegisterSSOperation, argument: RegisterSSArgCodec(), result: SSInfoCodec(), decode: decodeRegisterSSError, encode: encodeRegisterSSError}
}
func decodeRegisterSSError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (mapvalues.RegisterSSErrors, error) {
	switch code {
	case 34:
		p, err := decodeErrorParameter(data, present, SystemFailureParamCodec(), opts...)
		if err != nil {
			return mapvalues.RegisterSSErrors{}, err
		}
		return mapvalues.RegisterSSErrors{SystemFailure: p}, nil
	case 35:
		p, err := decodeErrorParameter(data, present, DataMissingParamCodec(), opts...)
		if err != nil {
			return mapvalues.RegisterSSErrors{}, err
		}
		return mapvalues.RegisterSSErrors{DataMissing: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return mapvalues.RegisterSSErrors{}, err
		}
		return mapvalues.RegisterSSErrors{UnexpectedDataValue: p}, nil
	case 10:
		p, err := decodeErrorParameter(data, present, BearerServNotProvParamCodec(), opts...)
		if err != nil {
			return mapvalues.RegisterSSErrors{}, err
		}
		return mapvalues.RegisterSSErrors{BearerServiceNotProvisioned: p}, nil
	case 11:
		p, err := decodeErrorParameter(data, present, TeleservNotProvParamCodec(), opts...)
		if err != nil {
			return mapvalues.RegisterSSErrors{}, err
		}
		return mapvalues.RegisterSSErrors{TeleserviceNotProvisioned: p}, nil
	case 13:
		p, err := decodeErrorParameter(data, present, CallBarredParamCodec(), opts...)
		if err != nil {
			return mapvalues.RegisterSSErrors{}, err
		}
		return mapvalues.RegisterSSErrors{CallBarred: p}, nil
	case 16:
		p, err := decodeErrorParameter(data, present, IllegalSSOperationParamCodec(), opts...)
		if err != nil {
			return mapvalues.RegisterSSErrors{}, err
		}
		return mapvalues.RegisterSSErrors{IllegalSSOperation: p}, nil
	case 17:
		p, err := decodeErrorParameter(data, present, SSStatusCodec(), opts...)
		if err != nil {
			return mapvalues.RegisterSSErrors{}, err
		}
		return mapvalues.RegisterSSErrors{SsErrorStatus: p}, nil
	case 20:
		p, err := decodeErrorParameter(data, present, SSIncompatibilityCauseCodec(), opts...)
		if err != nil {
			return mapvalues.RegisterSSErrors{}, err
		}
		return mapvalues.RegisterSSErrors{SsIncompatibility: p}, nil
	default:
		return mapvalues.RegisterSSErrors{}, fmt.Errorf("%w: error code %d is not in registerSS ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeRegisterSSError(value mapvalues.RegisterSSErrors, opts ...ber.EncodeOption) (mapvalues.EncodedError, error) {
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
		return mapvalues.EncodedError{}, fmt.Errorf("%w: exactly one registerSS error arm is required", ber.ErrInvalidBinding)
	}
	if value.SystemFailure != nil {
		return encodeMAPErrorMember(mapvalues.SystemFailure, value.SystemFailure, SystemFailureParamCodec(), opts...)
	}
	if value.DataMissing != nil {
		return encodeMAPErrorMember(mapvalues.DataMissing, value.DataMissing, DataMissingParamCodec(), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(mapvalues.UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	if value.BearerServiceNotProvisioned != nil {
		return encodeMAPErrorMember(mapvalues.BearerServiceNotProvisioned, value.BearerServiceNotProvisioned, BearerServNotProvParamCodec(), opts...)
	}
	if value.TeleserviceNotProvisioned != nil {
		return encodeMAPErrorMember(mapvalues.TeleserviceNotProvisioned, value.TeleserviceNotProvisioned, TeleservNotProvParamCodec(), opts...)
	}
	if value.CallBarred != nil {
		return encodeMAPErrorMember(mapvalues.CallBarred, value.CallBarred, CallBarredParamCodec(), opts...)
	}
	if value.IllegalSSOperation != nil {
		return encodeMAPErrorMember(mapvalues.IllegalSSOperation, value.IllegalSSOperation, IllegalSSOperationParamCodec(), opts...)
	}
	if value.SsErrorStatus != nil {
		return encodeMAPErrorMember(mapvalues.SsErrorStatus, value.SsErrorStatus, SSStatusCodec(), opts...)
	}
	if value.SsIncompatibility != nil {
		return encodeMAPErrorMember(mapvalues.SsIncompatibility, value.SsIncompatibility, SSIncompatibilityCauseCodec(), opts...)
	}
	return mapvalues.EncodedError{}, fmt.Errorf("%w: no selected registerSS error", ber.ErrInvalidBinding)
}
func infoReleaseResourcesOperation() mapvalues.OperationInfo {
	info, _ := mapvalues.LookupOperation(mapvalues.ReleaseResources)
	return info
}

// ReleaseResourcesOperation binds the formal object in TS 29.002 V19.1.0 §17.6.3 (X.880 §§8.2–8.3).
func ReleaseResourcesOperation() Operation[mapvalues.ReleaseResourcesArg, mapvalues.ReleaseResourcesRes, mapvalues.ReleaseResourcesErrors] {
	return Operation[mapvalues.ReleaseResourcesArg, mapvalues.ReleaseResourcesRes, mapvalues.ReleaseResourcesErrors]{code: mapvalues.ReleaseResources, info: infoReleaseResourcesOperation, argument: ReleaseResourcesArgCodec(), result: ReleaseResourcesResCodec(), decode: decodeReleaseResourcesError, encode: encodeReleaseResourcesError}
}
func decodeReleaseResourcesError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (mapvalues.ReleaseResourcesErrors, error) {
	switch code {
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return mapvalues.ReleaseResourcesErrors{}, err
		}
		return mapvalues.ReleaseResourcesErrors{UnexpectedDataValue: p}, nil
	case 34:
		p, err := decodeErrorParameter(data, present, SystemFailureParamCodec(), opts...)
		if err != nil {
			return mapvalues.ReleaseResourcesErrors{}, err
		}
		return mapvalues.ReleaseResourcesErrors{SystemFailure: p}, nil
	default:
		return mapvalues.ReleaseResourcesErrors{}, fmt.Errorf("%w: error code %d is not in releaseResources ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeReleaseResourcesError(value mapvalues.ReleaseResourcesErrors, opts ...ber.EncodeOption) (mapvalues.EncodedError, error) {
	selected := 0
	if value.UnexpectedDataValue != nil {
		selected++
	}
	if value.SystemFailure != nil {
		selected++
	}
	if selected != 1 {
		return mapvalues.EncodedError{}, fmt.Errorf("%w: exactly one releaseResources error arm is required", ber.ErrInvalidBinding)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(mapvalues.UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	if value.SystemFailure != nil {
		return encodeMAPErrorMember(mapvalues.SystemFailure, value.SystemFailure, SystemFailureParamCodec(), opts...)
	}
	return mapvalues.EncodedError{}, fmt.Errorf("%w: no selected releaseResources error", ber.ErrInvalidBinding)
}
func infoRemoteUserFreeOperation() mapvalues.OperationInfo {
	info, _ := mapvalues.LookupOperation(mapvalues.RemoteUserFree)
	return info
}

// RemoteUserFreeOperation binds the formal object in TS 29.002 V19.1.0 §17.6.3 (X.880 §§8.2–8.3).
func RemoteUserFreeOperation() Operation[mapvalues.RemoteUserFreeArg, mapvalues.RemoteUserFreeRes, mapvalues.RemoteUserFreeErrors] {
	return Operation[mapvalues.RemoteUserFreeArg, mapvalues.RemoteUserFreeRes, mapvalues.RemoteUserFreeErrors]{code: mapvalues.RemoteUserFree, info: infoRemoteUserFreeOperation, argument: RemoteUserFreeArgCodec(), result: RemoteUserFreeResCodec(), decode: decodeRemoteUserFreeError, encode: encodeRemoteUserFreeError}
}
func decodeRemoteUserFreeError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (mapvalues.RemoteUserFreeErrors, error) {
	switch code {
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return mapvalues.RemoteUserFreeErrors{}, err
		}
		return mapvalues.RemoteUserFreeErrors{UnexpectedDataValue: p}, nil
	case 35:
		p, err := decodeErrorParameter(data, present, DataMissingParamCodec(), opts...)
		if err != nil {
			return mapvalues.RemoteUserFreeErrors{}, err
		}
		return mapvalues.RemoteUserFreeErrors{DataMissing: p}, nil
	case 28:
		p, err := decodeErrorParameter(data, present, IncompatibleTerminalParamCodec(), opts...)
		if err != nil {
			return mapvalues.RemoteUserFreeErrors{}, err
		}
		return mapvalues.RemoteUserFreeErrors{IncompatibleTerminal: p}, nil
	case 27:
		p, err := decodeErrorParameter(data, present, AbsentSubscriberParamCodec(), opts...)
		if err != nil {
			return mapvalues.RemoteUserFreeErrors{}, err
		}
		return mapvalues.RemoteUserFreeErrors{AbsentSubscriber: p}, nil
	case 34:
		p, err := decodeErrorParameter(data, present, SystemFailureParamCodec(), opts...)
		if err != nil {
			return mapvalues.RemoteUserFreeErrors{}, err
		}
		return mapvalues.RemoteUserFreeErrors{SystemFailure: p}, nil
	case 45:
		p, err := decodeErrorParameter(data, present, BusySubscriberParamCodec(), opts...)
		if err != nil {
			return mapvalues.RemoteUserFreeErrors{}, err
		}
		return mapvalues.RemoteUserFreeErrors{BusySubscriber: p}, nil
	default:
		return mapvalues.RemoteUserFreeErrors{}, fmt.Errorf("%w: error code %d is not in remoteUserFree ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeRemoteUserFreeError(value mapvalues.RemoteUserFreeErrors, opts ...ber.EncodeOption) (mapvalues.EncodedError, error) {
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
		return mapvalues.EncodedError{}, fmt.Errorf("%w: exactly one remoteUserFree error arm is required", ber.ErrInvalidBinding)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(mapvalues.UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	if value.DataMissing != nil {
		return encodeMAPErrorMember(mapvalues.DataMissing, value.DataMissing, DataMissingParamCodec(), opts...)
	}
	if value.IncompatibleTerminal != nil {
		return encodeMAPErrorMember(mapvalues.IncompatibleTerminal, value.IncompatibleTerminal, IncompatibleTerminalParamCodec(), opts...)
	}
	if value.AbsentSubscriber != nil {
		return encodeMAPErrorMember(mapvalues.AbsentSubscriber, value.AbsentSubscriber, AbsentSubscriberParamCodec(), opts...)
	}
	if value.SystemFailure != nil {
		return encodeMAPErrorMember(mapvalues.SystemFailure, value.SystemFailure, SystemFailureParamCodec(), opts...)
	}
	if value.BusySubscriber != nil {
		return encodeMAPErrorMember(mapvalues.BusySubscriber, value.BusySubscriber, BusySubscriberParamCodec(), opts...)
	}
	return mapvalues.EncodedError{}, fmt.Errorf("%w: no selected remoteUserFree error", ber.ErrInvalidBinding)
}
func infoReportSMDeliveryStatusOperation() mapvalues.OperationInfo {
	info, _ := mapvalues.LookupOperation(mapvalues.ReportSMDeliveryStatus)
	return info
}

// ReportSMDeliveryStatusOperation binds the formal object in TS 29.002 V19.1.0 §17.6.5 (X.880 §§8.2–8.3).
func ReportSMDeliveryStatusOperation() Operation[mapvalues.ReportSMDeliveryStatusArg, mapvalues.ReportSMDeliveryStatusRes, mapvalues.ReportSMDeliveryStatusErrors] {
	return Operation[mapvalues.ReportSMDeliveryStatusArg, mapvalues.ReportSMDeliveryStatusRes, mapvalues.ReportSMDeliveryStatusErrors]{code: mapvalues.ReportSMDeliveryStatus, info: infoReportSMDeliveryStatusOperation, argument: ReportSMDeliveryStatusArgCodec(), result: ReportSMDeliveryStatusResCodec(), decode: decodeReportSMDeliveryStatusError, encode: encodeReportSMDeliveryStatusError}
}
func decodeReportSMDeliveryStatusError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (mapvalues.ReportSMDeliveryStatusErrors, error) {
	switch code {
	case 35:
		p, err := decodeErrorParameter(data, present, DataMissingParamCodec(), opts...)
		if err != nil {
			return mapvalues.ReportSMDeliveryStatusErrors{}, err
		}
		return mapvalues.ReportSMDeliveryStatusErrors{DataMissing: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return mapvalues.ReportSMDeliveryStatusErrors{}, err
		}
		return mapvalues.ReportSMDeliveryStatusErrors{UnexpectedDataValue: p}, nil
	case 1:
		p, err := decodeErrorParameter(data, present, UnknownSubscriberParamCodec(), opts...)
		if err != nil {
			return mapvalues.ReportSMDeliveryStatusErrors{}, err
		}
		return mapvalues.ReportSMDeliveryStatusErrors{UnknownSubscriber: p}, nil
	case 33:
		p, err := decodeErrorParameter(data, present, MessageWaitListFullParamCodec(), opts...)
		if err != nil {
			return mapvalues.ReportSMDeliveryStatusErrors{}, err
		}
		return mapvalues.ReportSMDeliveryStatusErrors{MessageWaitingListFull: p}, nil
	default:
		return mapvalues.ReportSMDeliveryStatusErrors{}, fmt.Errorf("%w: error code %d is not in reportSM-DeliveryStatus ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeReportSMDeliveryStatusError(value mapvalues.ReportSMDeliveryStatusErrors, opts ...ber.EncodeOption) (mapvalues.EncodedError, error) {
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
		return mapvalues.EncodedError{}, fmt.Errorf("%w: exactly one reportSM-DeliveryStatus error arm is required", ber.ErrInvalidBinding)
	}
	if value.DataMissing != nil {
		return encodeMAPErrorMember(mapvalues.DataMissing, value.DataMissing, DataMissingParamCodec(), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(mapvalues.UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	if value.UnknownSubscriber != nil {
		return encodeMAPErrorMember(mapvalues.UnknownSubscriber, value.UnknownSubscriber, UnknownSubscriberParamCodec(), opts...)
	}
	if value.MessageWaitingListFull != nil {
		return encodeMAPErrorMember(mapvalues.MessageWaitingListFull, value.MessageWaitingListFull, MessageWaitListFullParamCodec(), opts...)
	}
	return mapvalues.EncodedError{}, fmt.Errorf("%w: no selected reportSM-DeliveryStatus error", ber.ErrInvalidBinding)
}
func infoResetOperation() mapvalues.OperationInfo {
	info, _ := mapvalues.LookupOperation(mapvalues.Reset)
	return info
}

// ResetOperation binds the formal object in TS 29.002 V19.1.0 §17.6.1 (X.880 §§8.2–8.3).
func ResetOperation() Operation[mapvalues.ResetArg, mapvalues.NoParameter, mapvalues.ResetErrors] {
	return Operation[mapvalues.ResetArg, mapvalues.NoParameter, mapvalues.ResetErrors]{code: mapvalues.Reset, info: infoResetOperation, argument: ResetArgCodec(), result: mapvalues.ValueCodec[mapvalues.NoParameter]{}, decode: decodeResetError, encode: encodeResetError}
}
func decodeResetError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (mapvalues.ResetErrors, error) {
	switch code {
	default:
		return mapvalues.ResetErrors{}, fmt.Errorf("%w: error code %d is not in reset ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeResetError(value mapvalues.ResetErrors, opts ...ber.EncodeOption) (mapvalues.EncodedError, error) {
	return mapvalues.EncodedError{}, fmt.Errorf("%w: no selected reset error", ber.ErrInvalidBinding)
}
func infoRestoreDataOperation() mapvalues.OperationInfo {
	info, _ := mapvalues.LookupOperation(mapvalues.RestoreData)
	return info
}

// RestoreDataOperation binds the formal object in TS 29.002 V19.1.0 §17.6.1 (X.880 §§8.2–8.3).
func RestoreDataOperation() Operation[mapvalues.RestoreDataArg, mapvalues.RestoreDataRes, mapvalues.RestoreDataErrors] {
	return Operation[mapvalues.RestoreDataArg, mapvalues.RestoreDataRes, mapvalues.RestoreDataErrors]{code: mapvalues.RestoreData, info: infoRestoreDataOperation, argument: RestoreDataArgCodec(), result: RestoreDataResCodec(), decode: decodeRestoreDataError, encode: encodeRestoreDataError}
}
func decodeRestoreDataError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (mapvalues.RestoreDataErrors, error) {
	switch code {
	case 34:
		p, err := decodeErrorParameter(data, present, SystemFailureParamCodec(), opts...)
		if err != nil {
			return mapvalues.RestoreDataErrors{}, err
		}
		return mapvalues.RestoreDataErrors{SystemFailure: p}, nil
	case 35:
		p, err := decodeErrorParameter(data, present, DataMissingParamCodec(), opts...)
		if err != nil {
			return mapvalues.RestoreDataErrors{}, err
		}
		return mapvalues.RestoreDataErrors{DataMissing: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return mapvalues.RestoreDataErrors{}, err
		}
		return mapvalues.RestoreDataErrors{UnexpectedDataValue: p}, nil
	case 1:
		p, err := decodeErrorParameter(data, present, UnknownSubscriberParamCodec(), opts...)
		if err != nil {
			return mapvalues.RestoreDataErrors{}, err
		}
		return mapvalues.RestoreDataErrors{UnknownSubscriber: p}, nil
	default:
		return mapvalues.RestoreDataErrors{}, fmt.Errorf("%w: error code %d is not in restoreData ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeRestoreDataError(value mapvalues.RestoreDataErrors, opts ...ber.EncodeOption) (mapvalues.EncodedError, error) {
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
		return mapvalues.EncodedError{}, fmt.Errorf("%w: exactly one restoreData error arm is required", ber.ErrInvalidBinding)
	}
	if value.SystemFailure != nil {
		return encodeMAPErrorMember(mapvalues.SystemFailure, value.SystemFailure, SystemFailureParamCodec(), opts...)
	}
	if value.DataMissing != nil {
		return encodeMAPErrorMember(mapvalues.DataMissing, value.DataMissing, DataMissingParamCodec(), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(mapvalues.UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	if value.UnknownSubscriber != nil {
		return encodeMAPErrorMember(mapvalues.UnknownSubscriber, value.UnknownSubscriber, UnknownSubscriberParamCodec(), opts...)
	}
	return mapvalues.EncodedError{}, fmt.Errorf("%w: no selected restoreData error", ber.ErrInvalidBinding)
}
func infoResumeCallHandlingOperation() mapvalues.OperationInfo {
	info, _ := mapvalues.LookupOperation(mapvalues.ResumeCallHandling)
	return info
}

// ResumeCallHandlingOperation binds the formal object in TS 29.002 V19.1.0 §17.6.3 (X.880 §§8.2–8.3).
func ResumeCallHandlingOperation() Operation[mapvalues.ResumeCallHandlingArg, mapvalues.ResumeCallHandlingRes, mapvalues.ResumeCallHandlingErrors] {
	return Operation[mapvalues.ResumeCallHandlingArg, mapvalues.ResumeCallHandlingRes, mapvalues.ResumeCallHandlingErrors]{code: mapvalues.ResumeCallHandling, info: infoResumeCallHandlingOperation, argument: ResumeCallHandlingArgCodec(), result: ResumeCallHandlingResCodec(), decode: decodeResumeCallHandlingError, encode: encodeResumeCallHandlingError}
}
func decodeResumeCallHandlingError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (mapvalues.ResumeCallHandlingErrors, error) {
	switch code {
	case 47:
		p, err := decodeErrorParameter(data, present, ForwardingFailedParamCodec(), opts...)
		if err != nil {
			return mapvalues.ResumeCallHandlingErrors{}, err
		}
		return mapvalues.ResumeCallHandlingErrors{ForwardingFailed: p}, nil
	case 48:
		p, err := decodeErrorParameter(data, present, ORNotAllowedParamCodec(), opts...)
		if err != nil {
			return mapvalues.ResumeCallHandlingErrors{}, err
		}
		return mapvalues.ResumeCallHandlingErrors{OrNotAllowed: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return mapvalues.ResumeCallHandlingErrors{}, err
		}
		return mapvalues.ResumeCallHandlingErrors{UnexpectedDataValue: p}, nil
	case 35:
		p, err := decodeErrorParameter(data, present, DataMissingParamCodec(), opts...)
		if err != nil {
			return mapvalues.ResumeCallHandlingErrors{}, err
		}
		return mapvalues.ResumeCallHandlingErrors{DataMissing: p}, nil
	default:
		return mapvalues.ResumeCallHandlingErrors{}, fmt.Errorf("%w: error code %d is not in resumeCallHandling ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeResumeCallHandlingError(value mapvalues.ResumeCallHandlingErrors, opts ...ber.EncodeOption) (mapvalues.EncodedError, error) {
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
		return mapvalues.EncodedError{}, fmt.Errorf("%w: exactly one resumeCallHandling error arm is required", ber.ErrInvalidBinding)
	}
	if value.ForwardingFailed != nil {
		return encodeMAPErrorMember(mapvalues.ForwardingFailed, value.ForwardingFailed, ForwardingFailedParamCodec(), opts...)
	}
	if value.OrNotAllowed != nil {
		return encodeMAPErrorMember(mapvalues.OrNotAllowed, value.OrNotAllowed, ORNotAllowedParamCodec(), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(mapvalues.UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	if value.DataMissing != nil {
		return encodeMAPErrorMember(mapvalues.DataMissing, value.DataMissing, DataMissingParamCodec(), opts...)
	}
	return mapvalues.EncodedError{}, fmt.Errorf("%w: no selected resumeCallHandling error", ber.ErrInvalidBinding)
}
func infoSendAuthenticationInfoOperation() mapvalues.OperationInfo {
	info, _ := mapvalues.LookupOperation(mapvalues.SendAuthenticationInfo)
	return info
}

// SendAuthenticationInfoOperation binds the formal object in TS 29.002 V19.1.0 §17.6.1 (X.880 §§8.2–8.3).
func SendAuthenticationInfoOperation() Operation[mapvalues.SendAuthenticationInfoArg, mapvalues.SendAuthenticationInfoRes, mapvalues.SendAuthenticationInfoErrors] {
	return Operation[mapvalues.SendAuthenticationInfoArg, mapvalues.SendAuthenticationInfoRes, mapvalues.SendAuthenticationInfoErrors]{code: mapvalues.SendAuthenticationInfo, info: infoSendAuthenticationInfoOperation, argument: SendAuthenticationInfoArgCodec(), result: SendAuthenticationInfoResCodec(), decode: decodeSendAuthenticationInfoError, encode: encodeSendAuthenticationInfoError}
}
func decodeSendAuthenticationInfoError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (mapvalues.SendAuthenticationInfoErrors, error) {
	switch code {
	case 34:
		p, err := decodeErrorParameter(data, present, SystemFailureParamCodec(), opts...)
		if err != nil {
			return mapvalues.SendAuthenticationInfoErrors{}, err
		}
		return mapvalues.SendAuthenticationInfoErrors{SystemFailure: p}, nil
	case 35:
		p, err := decodeErrorParameter(data, present, DataMissingParamCodec(), opts...)
		if err != nil {
			return mapvalues.SendAuthenticationInfoErrors{}, err
		}
		return mapvalues.SendAuthenticationInfoErrors{DataMissing: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return mapvalues.SendAuthenticationInfoErrors{}, err
		}
		return mapvalues.SendAuthenticationInfoErrors{UnexpectedDataValue: p}, nil
	case 1:
		p, err := decodeErrorParameter(data, present, UnknownSubscriberParamCodec(), opts...)
		if err != nil {
			return mapvalues.SendAuthenticationInfoErrors{}, err
		}
		return mapvalues.SendAuthenticationInfoErrors{UnknownSubscriber: p}, nil
	default:
		return mapvalues.SendAuthenticationInfoErrors{}, fmt.Errorf("%w: error code %d is not in sendAuthenticationInfo ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeSendAuthenticationInfoError(value mapvalues.SendAuthenticationInfoErrors, opts ...ber.EncodeOption) (mapvalues.EncodedError, error) {
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
		return mapvalues.EncodedError{}, fmt.Errorf("%w: exactly one sendAuthenticationInfo error arm is required", ber.ErrInvalidBinding)
	}
	if value.SystemFailure != nil {
		return encodeMAPErrorMember(mapvalues.SystemFailure, value.SystemFailure, SystemFailureParamCodec(), opts...)
	}
	if value.DataMissing != nil {
		return encodeMAPErrorMember(mapvalues.DataMissing, value.DataMissing, DataMissingParamCodec(), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(mapvalues.UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	if value.UnknownSubscriber != nil {
		return encodeMAPErrorMember(mapvalues.UnknownSubscriber, value.UnknownSubscriber, UnknownSubscriberParamCodec(), opts...)
	}
	return mapvalues.EncodedError{}, fmt.Errorf("%w: no selected sendAuthenticationInfo error", ber.ErrInvalidBinding)
}
func infoSendEndSignalOperation() mapvalues.OperationInfo {
	info, _ := mapvalues.LookupOperation(mapvalues.SendEndSignal)
	return info
}

// SendEndSignalOperation binds the formal object in TS 29.002 V19.1.0 §17.6.1 (X.880 §§8.2–8.3).
func SendEndSignalOperation() Operation[mapvalues.SendEndSignalArg, mapvalues.SendEndSignalRes, mapvalues.SendEndSignalErrors] {
	return Operation[mapvalues.SendEndSignalArg, mapvalues.SendEndSignalRes, mapvalues.SendEndSignalErrors]{code: mapvalues.SendEndSignal, info: infoSendEndSignalOperation, argument: SendEndSignalArgCodec(), result: SendEndSignalResCodec(), decode: decodeSendEndSignalError, encode: encodeSendEndSignalError}
}
func decodeSendEndSignalError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (mapvalues.SendEndSignalErrors, error) {
	switch code {
	default:
		return mapvalues.SendEndSignalErrors{}, fmt.Errorf("%w: error code %d is not in sendEndSignal ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeSendEndSignalError(value mapvalues.SendEndSignalErrors, opts ...ber.EncodeOption) (mapvalues.EncodedError, error) {
	return mapvalues.EncodedError{}, fmt.Errorf("%w: no selected sendEndSignal error", ber.ErrInvalidBinding)
}
func infoSendGroupCallEndSignalOperation() mapvalues.OperationInfo {
	info, _ := mapvalues.LookupOperation(mapvalues.SendGroupCallEndSignal)
	return info
}

// SendGroupCallEndSignalOperation binds the formal object in TS 29.002 V19.1.0 §17.6.7 (X.880 §§8.2–8.3).
func SendGroupCallEndSignalOperation() Operation[mapvalues.SendGroupCallEndSignalArg, mapvalues.SendGroupCallEndSignalRes, mapvalues.SendGroupCallEndSignalErrors] {
	return Operation[mapvalues.SendGroupCallEndSignalArg, mapvalues.SendGroupCallEndSignalRes, mapvalues.SendGroupCallEndSignalErrors]{code: mapvalues.SendGroupCallEndSignal, info: infoSendGroupCallEndSignalOperation, argument: SendGroupCallEndSignalArgCodec(), result: SendGroupCallEndSignalResCodec(), decode: decodeSendGroupCallEndSignalError, encode: encodeSendGroupCallEndSignalError}
}
func decodeSendGroupCallEndSignalError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (mapvalues.SendGroupCallEndSignalErrors, error) {
	switch code {
	default:
		return mapvalues.SendGroupCallEndSignalErrors{}, fmt.Errorf("%w: error code %d is not in sendGroupCallEndSignal ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeSendGroupCallEndSignalError(value mapvalues.SendGroupCallEndSignalErrors, opts ...ber.EncodeOption) (mapvalues.EncodedError, error) {
	return mapvalues.EncodedError{}, fmt.Errorf("%w: no selected sendGroupCallEndSignal error", ber.ErrInvalidBinding)
}
func infoSendGroupCallInfoOperation() mapvalues.OperationInfo {
	info, _ := mapvalues.LookupOperation(mapvalues.SendGroupCallInfo)
	return info
}

// SendGroupCallInfoOperation binds the formal object in TS 29.002 V19.1.0 §17.6.7 (X.880 §§8.2–8.3).
func SendGroupCallInfoOperation() Operation[mapvalues.SendGroupCallInfoArg, mapvalues.SendGroupCallInfoRes, mapvalues.SendGroupCallInfoErrors] {
	return Operation[mapvalues.SendGroupCallInfoArg, mapvalues.SendGroupCallInfoRes, mapvalues.SendGroupCallInfoErrors]{code: mapvalues.SendGroupCallInfo, info: infoSendGroupCallInfoOperation, argument: SendGroupCallInfoArgCodec(), result: SendGroupCallInfoResCodec(), decode: decodeSendGroupCallInfoError, encode: encodeSendGroupCallInfoError}
}
func decodeSendGroupCallInfoError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (mapvalues.SendGroupCallInfoErrors, error) {
	switch code {
	case 34:
		p, err := decodeErrorParameter(data, present, SystemFailureParamCodec(), opts...)
		if err != nil {
			return mapvalues.SendGroupCallInfoErrors{}, err
		}
		return mapvalues.SendGroupCallInfoErrors{SystemFailure: p}, nil
	case 22:
		p, err := decodeErrorParameter(data, present, OngoingGroupCallParamCodec(), opts...)
		if err != nil {
			return mapvalues.SendGroupCallInfoErrors{}, err
		}
		return mapvalues.SendGroupCallInfoErrors{OngoingGroupCall: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return mapvalues.SendGroupCallInfoErrors{}, err
		}
		return mapvalues.SendGroupCallInfoErrors{UnexpectedDataValue: p}, nil
	case 35:
		p, err := decodeErrorParameter(data, present, DataMissingParamCodec(), opts...)
		if err != nil {
			return mapvalues.SendGroupCallInfoErrors{}, err
		}
		return mapvalues.SendGroupCallInfoErrors{DataMissing: p}, nil
	case 11:
		p, err := decodeErrorParameter(data, present, TeleservNotProvParamCodec(), opts...)
		if err != nil {
			return mapvalues.SendGroupCallInfoErrors{}, err
		}
		return mapvalues.SendGroupCallInfoErrors{TeleserviceNotProvisioned: p}, nil
	case 1:
		p, err := decodeErrorParameter(data, present, UnknownSubscriberParamCodec(), opts...)
		if err != nil {
			return mapvalues.SendGroupCallInfoErrors{}, err
		}
		return mapvalues.SendGroupCallInfoErrors{UnknownSubscriber: p}, nil
	default:
		return mapvalues.SendGroupCallInfoErrors{}, fmt.Errorf("%w: error code %d is not in sendGroupCallInfo ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeSendGroupCallInfoError(value mapvalues.SendGroupCallInfoErrors, opts ...ber.EncodeOption) (mapvalues.EncodedError, error) {
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
		return mapvalues.EncodedError{}, fmt.Errorf("%w: exactly one sendGroupCallInfo error arm is required", ber.ErrInvalidBinding)
	}
	if value.SystemFailure != nil {
		return encodeMAPErrorMember(mapvalues.SystemFailure, value.SystemFailure, SystemFailureParamCodec(), opts...)
	}
	if value.OngoingGroupCall != nil {
		return encodeMAPErrorMember(mapvalues.OngoingGroupCall, value.OngoingGroupCall, OngoingGroupCallParamCodec(), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(mapvalues.UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	if value.DataMissing != nil {
		return encodeMAPErrorMember(mapvalues.DataMissing, value.DataMissing, DataMissingParamCodec(), opts...)
	}
	if value.TeleserviceNotProvisioned != nil {
		return encodeMAPErrorMember(mapvalues.TeleserviceNotProvisioned, value.TeleserviceNotProvisioned, TeleservNotProvParamCodec(), opts...)
	}
	if value.UnknownSubscriber != nil {
		return encodeMAPErrorMember(mapvalues.UnknownSubscriber, value.UnknownSubscriber, UnknownSubscriberParamCodec(), opts...)
	}
	return mapvalues.EncodedError{}, fmt.Errorf("%w: no selected sendGroupCallInfo error", ber.ErrInvalidBinding)
}
func infoSendIMSIOperation() mapvalues.OperationInfo {
	info, _ := mapvalues.LookupOperation(mapvalues.SendIMSI)
	return info
}

// SendIMSIOperation binds the formal object in TS 29.002 V19.1.0 §17.6.2 (X.880 §§8.2–8.3).
func SendIMSIOperation() Operation[mapvalues.BERValue[mapvalues.ISDNAddressString], mapvalues.BERValue[mapvalues.IMSI], mapvalues.SendIMSIErrors] {
	return Operation[mapvalues.BERValue[mapvalues.ISDNAddressString], mapvalues.BERValue[mapvalues.IMSI], mapvalues.SendIMSIErrors]{code: mapvalues.SendIMSI, info: infoSendIMSIOperation, argument: ISDNAddressStringCodec(), result: IMSICodec(), decode: decodeSendIMSIError, encode: encodeSendIMSIError}
}
func decodeSendIMSIError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (mapvalues.SendIMSIErrors, error) {
	switch code {
	case 35:
		p, err := decodeErrorParameter(data, present, DataMissingParamCodec(), opts...)
		if err != nil {
			return mapvalues.SendIMSIErrors{}, err
		}
		return mapvalues.SendIMSIErrors{DataMissing: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return mapvalues.SendIMSIErrors{}, err
		}
		return mapvalues.SendIMSIErrors{UnexpectedDataValue: p}, nil
	case 1:
		p, err := decodeErrorParameter(data, present, UnknownSubscriberParamCodec(), opts...)
		if err != nil {
			return mapvalues.SendIMSIErrors{}, err
		}
		return mapvalues.SendIMSIErrors{UnknownSubscriber: p}, nil
	default:
		return mapvalues.SendIMSIErrors{}, fmt.Errorf("%w: error code %d is not in sendIMSI ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeSendIMSIError(value mapvalues.SendIMSIErrors, opts ...ber.EncodeOption) (mapvalues.EncodedError, error) {
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
		return mapvalues.EncodedError{}, fmt.Errorf("%w: exactly one sendIMSI error arm is required", ber.ErrInvalidBinding)
	}
	if value.DataMissing != nil {
		return encodeMAPErrorMember(mapvalues.DataMissing, value.DataMissing, DataMissingParamCodec(), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(mapvalues.UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	if value.UnknownSubscriber != nil {
		return encodeMAPErrorMember(mapvalues.UnknownSubscriber, value.UnknownSubscriber, UnknownSubscriberParamCodec(), opts...)
	}
	return mapvalues.EncodedError{}, fmt.Errorf("%w: no selected sendIMSI error", ber.ErrInvalidBinding)
}
func infoSendIdentificationOperation() mapvalues.OperationInfo {
	info, _ := mapvalues.LookupOperation(mapvalues.SendIdentification)
	return info
}

// SendIdentificationOperation binds the formal object in TS 29.002 V19.1.0 §17.6.1 (X.880 §§8.2–8.3).
func SendIdentificationOperation() Operation[mapvalues.SendIdentificationArg, mapvalues.SendIdentificationRes, mapvalues.SendIdentificationErrors] {
	return Operation[mapvalues.SendIdentificationArg, mapvalues.SendIdentificationRes, mapvalues.SendIdentificationErrors]{code: mapvalues.SendIdentification, info: infoSendIdentificationOperation, argument: SendIdentificationArgCodec(), result: SendIdentificationResCodec(), decode: decodeSendIdentificationError, encode: encodeSendIdentificationError}
}
func decodeSendIdentificationError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (mapvalues.SendIdentificationErrors, error) {
	switch code {
	case 35:
		p, err := decodeErrorParameter(data, present, DataMissingParamCodec(), opts...)
		if err != nil {
			return mapvalues.SendIdentificationErrors{}, err
		}
		return mapvalues.SendIdentificationErrors{DataMissing: p}, nil
	case 5:
		p, err := decodeErrorParameter(data, present, UnidentifiedSubParamCodec(), opts...)
		if err != nil {
			return mapvalues.SendIdentificationErrors{}, err
		}
		return mapvalues.SendIdentificationErrors{UnidentifiedSubscriber: p}, nil
	default:
		return mapvalues.SendIdentificationErrors{}, fmt.Errorf("%w: error code %d is not in sendIdentification ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeSendIdentificationError(value mapvalues.SendIdentificationErrors, opts ...ber.EncodeOption) (mapvalues.EncodedError, error) {
	selected := 0
	if value.DataMissing != nil {
		selected++
	}
	if value.UnidentifiedSubscriber != nil {
		selected++
	}
	if selected != 1 {
		return mapvalues.EncodedError{}, fmt.Errorf("%w: exactly one sendIdentification error arm is required", ber.ErrInvalidBinding)
	}
	if value.DataMissing != nil {
		return encodeMAPErrorMember(mapvalues.DataMissing, value.DataMissing, DataMissingParamCodec(), opts...)
	}
	if value.UnidentifiedSubscriber != nil {
		return encodeMAPErrorMember(mapvalues.UnidentifiedSubscriber, value.UnidentifiedSubscriber, UnidentifiedSubParamCodec(), opts...)
	}
	return mapvalues.EncodedError{}, fmt.Errorf("%w: no selected sendIdentification error", ber.ErrInvalidBinding)
}
func infoSendRoutingInfoOperation() mapvalues.OperationInfo {
	info, _ := mapvalues.LookupOperation(mapvalues.SendRoutingInfo)
	return info
}

// SendRoutingInfoOperation binds the formal object in TS 29.002 V19.1.0 §17.6.3 (X.880 §§8.2–8.3).
func SendRoutingInfoOperation() Operation[mapvalues.SendRoutingInfoArg, mapvalues.SendRoutingInfoRes, mapvalues.SendRoutingInfoErrors] {
	return Operation[mapvalues.SendRoutingInfoArg, mapvalues.SendRoutingInfoRes, mapvalues.SendRoutingInfoErrors]{code: mapvalues.SendRoutingInfo, info: infoSendRoutingInfoOperation, argument: SendRoutingInfoArgCodec(), result: SendRoutingInfoResCodec(), decode: decodeSendRoutingInfoError, encode: encodeSendRoutingInfoError}
}
func decodeSendRoutingInfoError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (mapvalues.SendRoutingInfoErrors, error) {
	switch code {
	case 34:
		p, err := decodeErrorParameter(data, present, SystemFailureParamCodec(), opts...)
		if err != nil {
			return mapvalues.SendRoutingInfoErrors{}, err
		}
		return mapvalues.SendRoutingInfoErrors{SystemFailure: p}, nil
	case 35:
		p, err := decodeErrorParameter(data, present, DataMissingParamCodec(), opts...)
		if err != nil {
			return mapvalues.SendRoutingInfoErrors{}, err
		}
		return mapvalues.SendRoutingInfoErrors{DataMissing: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return mapvalues.SendRoutingInfoErrors{}, err
		}
		return mapvalues.SendRoutingInfoErrors{UnexpectedDataValue: p}, nil
	case 21:
		p, err := decodeErrorParameter(data, present, FacilityNotSupParamCodec(), opts...)
		if err != nil {
			return mapvalues.SendRoutingInfoErrors{}, err
		}
		return mapvalues.SendRoutingInfoErrors{FacilityNotSupported: p}, nil
	case 48:
		p, err := decodeErrorParameter(data, present, ORNotAllowedParamCodec(), opts...)
		if err != nil {
			return mapvalues.SendRoutingInfoErrors{}, err
		}
		return mapvalues.SendRoutingInfoErrors{OrNotAllowed: p}, nil
	case 1:
		p, err := decodeErrorParameter(data, present, UnknownSubscriberParamCodec(), opts...)
		if err != nil {
			return mapvalues.SendRoutingInfoErrors{}, err
		}
		return mapvalues.SendRoutingInfoErrors{UnknownSubscriber: p}, nil
	case 44:
		p, err := decodeErrorParameter(data, present, NumberChangedParamCodec(), opts...)
		if err != nil {
			return mapvalues.SendRoutingInfoErrors{}, err
		}
		return mapvalues.SendRoutingInfoErrors{NumberChanged: p}, nil
	case 10:
		p, err := decodeErrorParameter(data, present, BearerServNotProvParamCodec(), opts...)
		if err != nil {
			return mapvalues.SendRoutingInfoErrors{}, err
		}
		return mapvalues.SendRoutingInfoErrors{BearerServiceNotProvisioned: p}, nil
	case 11:
		p, err := decodeErrorParameter(data, present, TeleservNotProvParamCodec(), opts...)
		if err != nil {
			return mapvalues.SendRoutingInfoErrors{}, err
		}
		return mapvalues.SendRoutingInfoErrors{TeleserviceNotProvisioned: p}, nil
	case 27:
		p, err := decodeErrorParameter(data, present, AbsentSubscriberParamCodec(), opts...)
		if err != nil {
			return mapvalues.SendRoutingInfoErrors{}, err
		}
		return mapvalues.SendRoutingInfoErrors{AbsentSubscriber: p}, nil
	case 45:
		p, err := decodeErrorParameter(data, present, BusySubscriberParamCodec(), opts...)
		if err != nil {
			return mapvalues.SendRoutingInfoErrors{}, err
		}
		return mapvalues.SendRoutingInfoErrors{BusySubscriber: p}, nil
	case 46:
		p, err := decodeErrorParameter(data, present, NoSubscriberReplyParamCodec(), opts...)
		if err != nil {
			return mapvalues.SendRoutingInfoErrors{}, err
		}
		return mapvalues.SendRoutingInfoErrors{NoSubscriberReply: p}, nil
	case 13:
		p, err := decodeErrorParameter(data, present, CallBarredParamCodec(), opts...)
		if err != nil {
			return mapvalues.SendRoutingInfoErrors{}, err
		}
		return mapvalues.SendRoutingInfoErrors{CallBarred: p}, nil
	case 15:
		p, err := decodeErrorParameter(data, present, CUGRejectParamCodec(), opts...)
		if err != nil {
			return mapvalues.SendRoutingInfoErrors{}, err
		}
		return mapvalues.SendRoutingInfoErrors{CugReject: p}, nil
	case 14:
		p, err := decodeErrorParameter(data, present, ForwardingViolationParamCodec(), opts...)
		if err != nil {
			return mapvalues.SendRoutingInfoErrors{}, err
		}
		return mapvalues.SendRoutingInfoErrors{ForwardingViolation: p}, nil
	default:
		return mapvalues.SendRoutingInfoErrors{}, fmt.Errorf("%w: error code %d is not in sendRoutingInfo ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeSendRoutingInfoError(value mapvalues.SendRoutingInfoErrors, opts ...ber.EncodeOption) (mapvalues.EncodedError, error) {
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
		return mapvalues.EncodedError{}, fmt.Errorf("%w: exactly one sendRoutingInfo error arm is required", ber.ErrInvalidBinding)
	}
	if value.SystemFailure != nil {
		return encodeMAPErrorMember(mapvalues.SystemFailure, value.SystemFailure, SystemFailureParamCodec(), opts...)
	}
	if value.DataMissing != nil {
		return encodeMAPErrorMember(mapvalues.DataMissing, value.DataMissing, DataMissingParamCodec(), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(mapvalues.UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	if value.FacilityNotSupported != nil {
		return encodeMAPErrorMember(mapvalues.FacilityNotSupported, value.FacilityNotSupported, FacilityNotSupParamCodec(), opts...)
	}
	if value.OrNotAllowed != nil {
		return encodeMAPErrorMember(mapvalues.OrNotAllowed, value.OrNotAllowed, ORNotAllowedParamCodec(), opts...)
	}
	if value.UnknownSubscriber != nil {
		return encodeMAPErrorMember(mapvalues.UnknownSubscriber, value.UnknownSubscriber, UnknownSubscriberParamCodec(), opts...)
	}
	if value.NumberChanged != nil {
		return encodeMAPErrorMember(mapvalues.NumberChanged, value.NumberChanged, NumberChangedParamCodec(), opts...)
	}
	if value.BearerServiceNotProvisioned != nil {
		return encodeMAPErrorMember(mapvalues.BearerServiceNotProvisioned, value.BearerServiceNotProvisioned, BearerServNotProvParamCodec(), opts...)
	}
	if value.TeleserviceNotProvisioned != nil {
		return encodeMAPErrorMember(mapvalues.TeleserviceNotProvisioned, value.TeleserviceNotProvisioned, TeleservNotProvParamCodec(), opts...)
	}
	if value.AbsentSubscriber != nil {
		return encodeMAPErrorMember(mapvalues.AbsentSubscriber, value.AbsentSubscriber, AbsentSubscriberParamCodec(), opts...)
	}
	if value.BusySubscriber != nil {
		return encodeMAPErrorMember(mapvalues.BusySubscriber, value.BusySubscriber, BusySubscriberParamCodec(), opts...)
	}
	if value.NoSubscriberReply != nil {
		return encodeMAPErrorMember(mapvalues.NoSubscriberReply, value.NoSubscriberReply, NoSubscriberReplyParamCodec(), opts...)
	}
	if value.CallBarred != nil {
		return encodeMAPErrorMember(mapvalues.CallBarred, value.CallBarred, CallBarredParamCodec(), opts...)
	}
	if value.CugReject != nil {
		return encodeMAPErrorMember(mapvalues.CugReject, value.CugReject, CUGRejectParamCodec(), opts...)
	}
	if value.ForwardingViolation != nil {
		return encodeMAPErrorMember(mapvalues.ForwardingViolation, value.ForwardingViolation, ForwardingViolationParamCodec(), opts...)
	}
	return mapvalues.EncodedError{}, fmt.Errorf("%w: no selected sendRoutingInfo error", ber.ErrInvalidBinding)
}
func infoSendRoutingInfoForGprsOperation() mapvalues.OperationInfo {
	info, _ := mapvalues.LookupOperation(mapvalues.SendRoutingInfoForGprs)
	return info
}

// SendRoutingInfoForGprsOperation binds the formal object in TS 29.002 V19.1.0 §17.6.1 (X.880 §§8.2–8.3).
func SendRoutingInfoForGprsOperation() Operation[mapvalues.SendRoutingInfoForGprsArg, mapvalues.SendRoutingInfoForGprsRes, mapvalues.SendRoutingInfoForGprsErrors] {
	return Operation[mapvalues.SendRoutingInfoForGprsArg, mapvalues.SendRoutingInfoForGprsRes, mapvalues.SendRoutingInfoForGprsErrors]{code: mapvalues.SendRoutingInfoForGprs, info: infoSendRoutingInfoForGprsOperation, argument: SendRoutingInfoForGprsArgCodec(), result: SendRoutingInfoForGprsResCodec(), decode: decodeSendRoutingInfoForGprsError, encode: encodeSendRoutingInfoForGprsError}
}
func decodeSendRoutingInfoForGprsError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (mapvalues.SendRoutingInfoForGprsErrors, error) {
	switch code {
	case 27:
		p, err := decodeErrorParameter(data, present, AbsentSubscriberParamCodec(), opts...)
		if err != nil {
			return mapvalues.SendRoutingInfoForGprsErrors{}, err
		}
		return mapvalues.SendRoutingInfoForGprsErrors{AbsentSubscriber: p}, nil
	case 34:
		p, err := decodeErrorParameter(data, present, SystemFailureParamCodec(), opts...)
		if err != nil {
			return mapvalues.SendRoutingInfoForGprsErrors{}, err
		}
		return mapvalues.SendRoutingInfoForGprsErrors{SystemFailure: p}, nil
	case 35:
		p, err := decodeErrorParameter(data, present, DataMissingParamCodec(), opts...)
		if err != nil {
			return mapvalues.SendRoutingInfoForGprsErrors{}, err
		}
		return mapvalues.SendRoutingInfoForGprsErrors{DataMissing: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return mapvalues.SendRoutingInfoForGprsErrors{}, err
		}
		return mapvalues.SendRoutingInfoForGprsErrors{UnexpectedDataValue: p}, nil
	case 1:
		p, err := decodeErrorParameter(data, present, UnknownSubscriberParamCodec(), opts...)
		if err != nil {
			return mapvalues.SendRoutingInfoForGprsErrors{}, err
		}
		return mapvalues.SendRoutingInfoForGprsErrors{UnknownSubscriber: p}, nil
	case 13:
		p, err := decodeErrorParameter(data, present, CallBarredParamCodec(), opts...)
		if err != nil {
			return mapvalues.SendRoutingInfoForGprsErrors{}, err
		}
		return mapvalues.SendRoutingInfoForGprsErrors{CallBarred: p}, nil
	default:
		return mapvalues.SendRoutingInfoForGprsErrors{}, fmt.Errorf("%w: error code %d is not in sendRoutingInfoForGprs ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeSendRoutingInfoForGprsError(value mapvalues.SendRoutingInfoForGprsErrors, opts ...ber.EncodeOption) (mapvalues.EncodedError, error) {
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
		return mapvalues.EncodedError{}, fmt.Errorf("%w: exactly one sendRoutingInfoForGprs error arm is required", ber.ErrInvalidBinding)
	}
	if value.AbsentSubscriber != nil {
		return encodeMAPErrorMember(mapvalues.AbsentSubscriber, value.AbsentSubscriber, AbsentSubscriberParamCodec(), opts...)
	}
	if value.SystemFailure != nil {
		return encodeMAPErrorMember(mapvalues.SystemFailure, value.SystemFailure, SystemFailureParamCodec(), opts...)
	}
	if value.DataMissing != nil {
		return encodeMAPErrorMember(mapvalues.DataMissing, value.DataMissing, DataMissingParamCodec(), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(mapvalues.UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	if value.UnknownSubscriber != nil {
		return encodeMAPErrorMember(mapvalues.UnknownSubscriber, value.UnknownSubscriber, UnknownSubscriberParamCodec(), opts...)
	}
	if value.CallBarred != nil {
		return encodeMAPErrorMember(mapvalues.CallBarred, value.CallBarred, CallBarredParamCodec(), opts...)
	}
	return mapvalues.EncodedError{}, fmt.Errorf("%w: no selected sendRoutingInfoForGprs error", ber.ErrInvalidBinding)
}
func infoSendRoutingInfoForLCSOperation() mapvalues.OperationInfo {
	info, _ := mapvalues.LookupOperation(mapvalues.SendRoutingInfoForLCS)
	return info
}

// SendRoutingInfoForLCSOperation binds the formal object in TS 29.002 V19.1.0 §17.6.8 (X.880 §§8.2–8.3).
func SendRoutingInfoForLCSOperation() Operation[mapvalues.RoutingInfoForLCSArg, mapvalues.RoutingInfoForLCSRes, mapvalues.SendRoutingInfoForLCSErrors] {
	return Operation[mapvalues.RoutingInfoForLCSArg, mapvalues.RoutingInfoForLCSRes, mapvalues.SendRoutingInfoForLCSErrors]{code: mapvalues.SendRoutingInfoForLCS, info: infoSendRoutingInfoForLCSOperation, argument: RoutingInfoForLCSArgCodec(), result: RoutingInfoForLCSResCodec(), decode: decodeSendRoutingInfoForLCSError, encode: encodeSendRoutingInfoForLCSError}
}
func decodeSendRoutingInfoForLCSError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (mapvalues.SendRoutingInfoForLCSErrors, error) {
	switch code {
	case 34:
		p, err := decodeErrorParameter(data, present, SystemFailureParamCodec(), opts...)
		if err != nil {
			return mapvalues.SendRoutingInfoForLCSErrors{}, err
		}
		return mapvalues.SendRoutingInfoForLCSErrors{SystemFailure: p}, nil
	case 35:
		p, err := decodeErrorParameter(data, present, DataMissingParamCodec(), opts...)
		if err != nil {
			return mapvalues.SendRoutingInfoForLCSErrors{}, err
		}
		return mapvalues.SendRoutingInfoForLCSErrors{DataMissing: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return mapvalues.SendRoutingInfoForLCSErrors{}, err
		}
		return mapvalues.SendRoutingInfoForLCSErrors{UnexpectedDataValue: p}, nil
	case 21:
		p, err := decodeErrorParameter(data, present, FacilityNotSupParamCodec(), opts...)
		if err != nil {
			return mapvalues.SendRoutingInfoForLCSErrors{}, err
		}
		return mapvalues.SendRoutingInfoForLCSErrors{FacilityNotSupported: p}, nil
	case 1:
		p, err := decodeErrorParameter(data, present, UnknownSubscriberParamCodec(), opts...)
		if err != nil {
			return mapvalues.SendRoutingInfoForLCSErrors{}, err
		}
		return mapvalues.SendRoutingInfoForLCSErrors{UnknownSubscriber: p}, nil
	case 27:
		p, err := decodeErrorParameter(data, present, AbsentSubscriberParamCodec(), opts...)
		if err != nil {
			return mapvalues.SendRoutingInfoForLCSErrors{}, err
		}
		return mapvalues.SendRoutingInfoForLCSErrors{AbsentSubscriber: p}, nil
	case 52:
		p, err := decodeErrorParameter(data, present, UnauthorizedRequestingNetworkParamCodec(), opts...)
		if err != nil {
			return mapvalues.SendRoutingInfoForLCSErrors{}, err
		}
		return mapvalues.SendRoutingInfoForLCSErrors{UnauthorizedRequestingNetwork: p}, nil
	default:
		return mapvalues.SendRoutingInfoForLCSErrors{}, fmt.Errorf("%w: error code %d is not in sendRoutingInfoForLCS ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeSendRoutingInfoForLCSError(value mapvalues.SendRoutingInfoForLCSErrors, opts ...ber.EncodeOption) (mapvalues.EncodedError, error) {
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
		return mapvalues.EncodedError{}, fmt.Errorf("%w: exactly one sendRoutingInfoForLCS error arm is required", ber.ErrInvalidBinding)
	}
	if value.SystemFailure != nil {
		return encodeMAPErrorMember(mapvalues.SystemFailure, value.SystemFailure, SystemFailureParamCodec(), opts...)
	}
	if value.DataMissing != nil {
		return encodeMAPErrorMember(mapvalues.DataMissing, value.DataMissing, DataMissingParamCodec(), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(mapvalues.UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	if value.FacilityNotSupported != nil {
		return encodeMAPErrorMember(mapvalues.FacilityNotSupported, value.FacilityNotSupported, FacilityNotSupParamCodec(), opts...)
	}
	if value.UnknownSubscriber != nil {
		return encodeMAPErrorMember(mapvalues.UnknownSubscriber, value.UnknownSubscriber, UnknownSubscriberParamCodec(), opts...)
	}
	if value.AbsentSubscriber != nil {
		return encodeMAPErrorMember(mapvalues.AbsentSubscriber, value.AbsentSubscriber, AbsentSubscriberParamCodec(), opts...)
	}
	if value.UnauthorizedRequestingNetwork != nil {
		return encodeMAPErrorMember(mapvalues.UnauthorizedRequestingNetwork, value.UnauthorizedRequestingNetwork, UnauthorizedRequestingNetworkParamCodec(), opts...)
	}
	return mapvalues.EncodedError{}, fmt.Errorf("%w: no selected sendRoutingInfoForLCS error", ber.ErrInvalidBinding)
}
func infoSendRoutingInfoForSMOperation() mapvalues.OperationInfo {
	info, _ := mapvalues.LookupOperation(mapvalues.SendRoutingInfoForSM)
	return info
}

// SendRoutingInfoForSMOperation binds the formal object in TS 29.002 V19.1.0 §17.6.5 (X.880 §§8.2–8.3).
func SendRoutingInfoForSMOperation() Operation[mapvalues.RoutingInfoForSMArg, mapvalues.RoutingInfoForSMRes, mapvalues.SendRoutingInfoForSMErrors] {
	return Operation[mapvalues.RoutingInfoForSMArg, mapvalues.RoutingInfoForSMRes, mapvalues.SendRoutingInfoForSMErrors]{code: mapvalues.SendRoutingInfoForSM, info: infoSendRoutingInfoForSMOperation, argument: RoutingInfoForSMArgCodec(), result: RoutingInfoForSMResCodec(), decode: decodeSendRoutingInfoForSMError, encode: encodeSendRoutingInfoForSMError}
}
func decodeSendRoutingInfoForSMError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (mapvalues.SendRoutingInfoForSMErrors, error) {
	switch code {
	case 34:
		p, err := decodeErrorParameter(data, present, SystemFailureParamCodec(), opts...)
		if err != nil {
			return mapvalues.SendRoutingInfoForSMErrors{}, err
		}
		return mapvalues.SendRoutingInfoForSMErrors{SystemFailure: p}, nil
	case 35:
		p, err := decodeErrorParameter(data, present, DataMissingParamCodec(), opts...)
		if err != nil {
			return mapvalues.SendRoutingInfoForSMErrors{}, err
		}
		return mapvalues.SendRoutingInfoForSMErrors{DataMissing: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return mapvalues.SendRoutingInfoForSMErrors{}, err
		}
		return mapvalues.SendRoutingInfoForSMErrors{UnexpectedDataValue: p}, nil
	case 21:
		p, err := decodeErrorParameter(data, present, FacilityNotSupParamCodec(), opts...)
		if err != nil {
			return mapvalues.SendRoutingInfoForSMErrors{}, err
		}
		return mapvalues.SendRoutingInfoForSMErrors{FacilityNotSupported: p}, nil
	case 1:
		p, err := decodeErrorParameter(data, present, UnknownSubscriberParamCodec(), opts...)
		if err != nil {
			return mapvalues.SendRoutingInfoForSMErrors{}, err
		}
		return mapvalues.SendRoutingInfoForSMErrors{UnknownSubscriber: p}, nil
	case 11:
		p, err := decodeErrorParameter(data, present, TeleservNotProvParamCodec(), opts...)
		if err != nil {
			return mapvalues.SendRoutingInfoForSMErrors{}, err
		}
		return mapvalues.SendRoutingInfoForSMErrors{TeleserviceNotProvisioned: p}, nil
	case 13:
		p, err := decodeErrorParameter(data, present, CallBarredParamCodec(), opts...)
		if err != nil {
			return mapvalues.SendRoutingInfoForSMErrors{}, err
		}
		return mapvalues.SendRoutingInfoForSMErrors{CallBarred: p}, nil
	case 6:
		p, err := decodeErrorParameter(data, present, AbsentSubscriberSMParamCodec(), opts...)
		if err != nil {
			return mapvalues.SendRoutingInfoForSMErrors{}, err
		}
		return mapvalues.SendRoutingInfoForSMErrors{AbsentSubscriberSM: p}, nil
	default:
		return mapvalues.SendRoutingInfoForSMErrors{}, fmt.Errorf("%w: error code %d is not in sendRoutingInfoForSM ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeSendRoutingInfoForSMError(value mapvalues.SendRoutingInfoForSMErrors, opts ...ber.EncodeOption) (mapvalues.EncodedError, error) {
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
		return mapvalues.EncodedError{}, fmt.Errorf("%w: exactly one sendRoutingInfoForSM error arm is required", ber.ErrInvalidBinding)
	}
	if value.SystemFailure != nil {
		return encodeMAPErrorMember(mapvalues.SystemFailure, value.SystemFailure, SystemFailureParamCodec(), opts...)
	}
	if value.DataMissing != nil {
		return encodeMAPErrorMember(mapvalues.DataMissing, value.DataMissing, DataMissingParamCodec(), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(mapvalues.UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	if value.FacilityNotSupported != nil {
		return encodeMAPErrorMember(mapvalues.FacilityNotSupported, value.FacilityNotSupported, FacilityNotSupParamCodec(), opts...)
	}
	if value.UnknownSubscriber != nil {
		return encodeMAPErrorMember(mapvalues.UnknownSubscriber, value.UnknownSubscriber, UnknownSubscriberParamCodec(), opts...)
	}
	if value.TeleserviceNotProvisioned != nil {
		return encodeMAPErrorMember(mapvalues.TeleserviceNotProvisioned, value.TeleserviceNotProvisioned, TeleservNotProvParamCodec(), opts...)
	}
	if value.CallBarred != nil {
		return encodeMAPErrorMember(mapvalues.CallBarred, value.CallBarred, CallBarredParamCodec(), opts...)
	}
	if value.AbsentSubscriberSM != nil {
		return encodeMAPErrorMember(mapvalues.AbsentSubscriberSM, value.AbsentSubscriberSM, AbsentSubscriberSMParamCodec(), opts...)
	}
	return mapvalues.EncodedError{}, fmt.Errorf("%w: no selected sendRoutingInfoForSM error", ber.ErrInvalidBinding)
}
func infoSetReportingStateOperation() mapvalues.OperationInfo {
	info, _ := mapvalues.LookupOperation(mapvalues.SetReportingState)
	return info
}

// SetReportingStateOperation binds the formal object in TS 29.002 V19.1.0 §17.6.3 (X.880 §§8.2–8.3).
func SetReportingStateOperation() Operation[mapvalues.SetReportingStateArg, mapvalues.SetReportingStateRes, mapvalues.SetReportingStateErrors] {
	return Operation[mapvalues.SetReportingStateArg, mapvalues.SetReportingStateRes, mapvalues.SetReportingStateErrors]{code: mapvalues.SetReportingState, info: infoSetReportingStateOperation, argument: SetReportingStateArgCodec(), result: SetReportingStateResCodec(), decode: decodeSetReportingStateError, encode: encodeSetReportingStateError}
}
func decodeSetReportingStateError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (mapvalues.SetReportingStateErrors, error) {
	switch code {
	case 34:
		p, err := decodeErrorParameter(data, present, SystemFailureParamCodec(), opts...)
		if err != nil {
			return mapvalues.SetReportingStateErrors{}, err
		}
		return mapvalues.SetReportingStateErrors{SystemFailure: p}, nil
	case 5:
		p, err := decodeErrorParameter(data, present, UnidentifiedSubParamCodec(), opts...)
		if err != nil {
			return mapvalues.SetReportingStateErrors{}, err
		}
		return mapvalues.SetReportingStateErrors{UnidentifiedSubscriber: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return mapvalues.SetReportingStateErrors{}, err
		}
		return mapvalues.SetReportingStateErrors{UnexpectedDataValue: p}, nil
	case 35:
		p, err := decodeErrorParameter(data, present, DataMissingParamCodec(), opts...)
		if err != nil {
			return mapvalues.SetReportingStateErrors{}, err
		}
		return mapvalues.SetReportingStateErrors{DataMissing: p}, nil
	case 51:
		p, err := decodeErrorParameter(data, present, ResourceLimitationParamCodec(), opts...)
		if err != nil {
			return mapvalues.SetReportingStateErrors{}, err
		}
		return mapvalues.SetReportingStateErrors{ResourceLimitation: p}, nil
	case 21:
		p, err := decodeErrorParameter(data, present, FacilityNotSupParamCodec(), opts...)
		if err != nil {
			return mapvalues.SetReportingStateErrors{}, err
		}
		return mapvalues.SetReportingStateErrors{FacilityNotSupported: p}, nil
	default:
		return mapvalues.SetReportingStateErrors{}, fmt.Errorf("%w: error code %d is not in setReportingState ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeSetReportingStateError(value mapvalues.SetReportingStateErrors, opts ...ber.EncodeOption) (mapvalues.EncodedError, error) {
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
		return mapvalues.EncodedError{}, fmt.Errorf("%w: exactly one setReportingState error arm is required", ber.ErrInvalidBinding)
	}
	if value.SystemFailure != nil {
		return encodeMAPErrorMember(mapvalues.SystemFailure, value.SystemFailure, SystemFailureParamCodec(), opts...)
	}
	if value.UnidentifiedSubscriber != nil {
		return encodeMAPErrorMember(mapvalues.UnidentifiedSubscriber, value.UnidentifiedSubscriber, UnidentifiedSubParamCodec(), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(mapvalues.UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	if value.DataMissing != nil {
		return encodeMAPErrorMember(mapvalues.DataMissing, value.DataMissing, DataMissingParamCodec(), opts...)
	}
	if value.ResourceLimitation != nil {
		return encodeMAPErrorMember(mapvalues.ResourceLimitation, value.ResourceLimitation, ResourceLimitationParamCodec(), opts...)
	}
	if value.FacilityNotSupported != nil {
		return encodeMAPErrorMember(mapvalues.FacilityNotSupported, value.FacilityNotSupported, FacilityNotSupParamCodec(), opts...)
	}
	return mapvalues.EncodedError{}, fmt.Errorf("%w: no selected setReportingState error", ber.ErrInvalidBinding)
}
func infoSsInvocationNotificationOperation() mapvalues.OperationInfo {
	info, _ := mapvalues.LookupOperation(mapvalues.SsInvocationNotification)
	return info
}

// SsInvocationNotificationOperation binds the formal object in TS 29.002 V19.1.0 §17.6.4 (X.880 §§8.2–8.3).
func SsInvocationNotificationOperation() Operation[mapvalues.SSInvocationNotificationArg, mapvalues.SSInvocationNotificationRes, mapvalues.SsInvocationNotificationErrors] {
	return Operation[mapvalues.SSInvocationNotificationArg, mapvalues.SSInvocationNotificationRes, mapvalues.SsInvocationNotificationErrors]{code: mapvalues.SsInvocationNotification, info: infoSsInvocationNotificationOperation, argument: SSInvocationNotificationArgCodec(), result: SSInvocationNotificationResCodec(), decode: decodeSsInvocationNotificationError, encode: encodeSsInvocationNotificationError}
}
func decodeSsInvocationNotificationError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (mapvalues.SsInvocationNotificationErrors, error) {
	switch code {
	case 35:
		p, err := decodeErrorParameter(data, present, DataMissingParamCodec(), opts...)
		if err != nil {
			return mapvalues.SsInvocationNotificationErrors{}, err
		}
		return mapvalues.SsInvocationNotificationErrors{DataMissing: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return mapvalues.SsInvocationNotificationErrors{}, err
		}
		return mapvalues.SsInvocationNotificationErrors{UnexpectedDataValue: p}, nil
	case 1:
		p, err := decodeErrorParameter(data, present, UnknownSubscriberParamCodec(), opts...)
		if err != nil {
			return mapvalues.SsInvocationNotificationErrors{}, err
		}
		return mapvalues.SsInvocationNotificationErrors{UnknownSubscriber: p}, nil
	default:
		return mapvalues.SsInvocationNotificationErrors{}, fmt.Errorf("%w: error code %d is not in ss-InvocationNotification ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeSsInvocationNotificationError(value mapvalues.SsInvocationNotificationErrors, opts ...ber.EncodeOption) (mapvalues.EncodedError, error) {
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
		return mapvalues.EncodedError{}, fmt.Errorf("%w: exactly one ss-InvocationNotification error arm is required", ber.ErrInvalidBinding)
	}
	if value.DataMissing != nil {
		return encodeMAPErrorMember(mapvalues.DataMissing, value.DataMissing, DataMissingParamCodec(), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(mapvalues.UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	if value.UnknownSubscriber != nil {
		return encodeMAPErrorMember(mapvalues.UnknownSubscriber, value.UnknownSubscriber, UnknownSubscriberParamCodec(), opts...)
	}
	return mapvalues.EncodedError{}, fmt.Errorf("%w: no selected ss-InvocationNotification error", ber.ErrInvalidBinding)
}
func infoStatusReportOperation() mapvalues.OperationInfo {
	info, _ := mapvalues.LookupOperation(mapvalues.StatusReport)
	return info
}

// StatusReportOperation binds the formal object in TS 29.002 V19.1.0 §17.6.3 (X.880 §§8.2–8.3).
func StatusReportOperation() Operation[mapvalues.StatusReportArg, mapvalues.StatusReportRes, mapvalues.StatusReportErrors] {
	return Operation[mapvalues.StatusReportArg, mapvalues.StatusReportRes, mapvalues.StatusReportErrors]{code: mapvalues.StatusReport, info: infoStatusReportOperation, argument: StatusReportArgCodec(), result: StatusReportResCodec(), decode: decodeStatusReportError, encode: encodeStatusReportError}
}
func decodeStatusReportError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (mapvalues.StatusReportErrors, error) {
	switch code {
	case 1:
		p, err := decodeErrorParameter(data, present, UnknownSubscriberParamCodec(), opts...)
		if err != nil {
			return mapvalues.StatusReportErrors{}, err
		}
		return mapvalues.StatusReportErrors{UnknownSubscriber: p}, nil
	case 34:
		p, err := decodeErrorParameter(data, present, SystemFailureParamCodec(), opts...)
		if err != nil {
			return mapvalues.StatusReportErrors{}, err
		}
		return mapvalues.StatusReportErrors{SystemFailure: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return mapvalues.StatusReportErrors{}, err
		}
		return mapvalues.StatusReportErrors{UnexpectedDataValue: p}, nil
	case 35:
		p, err := decodeErrorParameter(data, present, DataMissingParamCodec(), opts...)
		if err != nil {
			return mapvalues.StatusReportErrors{}, err
		}
		return mapvalues.StatusReportErrors{DataMissing: p}, nil
	default:
		return mapvalues.StatusReportErrors{}, fmt.Errorf("%w: error code %d is not in statusReport ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeStatusReportError(value mapvalues.StatusReportErrors, opts ...ber.EncodeOption) (mapvalues.EncodedError, error) {
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
		return mapvalues.EncodedError{}, fmt.Errorf("%w: exactly one statusReport error arm is required", ber.ErrInvalidBinding)
	}
	if value.UnknownSubscriber != nil {
		return encodeMAPErrorMember(mapvalues.UnknownSubscriber, value.UnknownSubscriber, UnknownSubscriberParamCodec(), opts...)
	}
	if value.SystemFailure != nil {
		return encodeMAPErrorMember(mapvalues.SystemFailure, value.SystemFailure, SystemFailureParamCodec(), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(mapvalues.UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	if value.DataMissing != nil {
		return encodeMAPErrorMember(mapvalues.DataMissing, value.DataMissing, DataMissingParamCodec(), opts...)
	}
	return mapvalues.EncodedError{}, fmt.Errorf("%w: no selected statusReport error", ber.ErrInvalidBinding)
}
func infoSubscriberLocationReportOperation() mapvalues.OperationInfo {
	info, _ := mapvalues.LookupOperation(mapvalues.SubscriberLocationReport)
	return info
}

// SubscriberLocationReportOperation binds the formal object in TS 29.002 V19.1.0 §17.6.8 (X.880 §§8.2–8.3).
func SubscriberLocationReportOperation() Operation[mapvalues.SubscriberLocationReportArg, mapvalues.SubscriberLocationReportRes, mapvalues.SubscriberLocationReportErrors] {
	return Operation[mapvalues.SubscriberLocationReportArg, mapvalues.SubscriberLocationReportRes, mapvalues.SubscriberLocationReportErrors]{code: mapvalues.SubscriberLocationReport, info: infoSubscriberLocationReportOperation, argument: SubscriberLocationReportArgCodec(), result: SubscriberLocationReportResCodec(), decode: decodeSubscriberLocationReportError, encode: encodeSubscriberLocationReportError}
}
func decodeSubscriberLocationReportError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (mapvalues.SubscriberLocationReportErrors, error) {
	switch code {
	case 34:
		p, err := decodeErrorParameter(data, present, SystemFailureParamCodec(), opts...)
		if err != nil {
			return mapvalues.SubscriberLocationReportErrors{}, err
		}
		return mapvalues.SubscriberLocationReportErrors{SystemFailure: p}, nil
	case 35:
		p, err := decodeErrorParameter(data, present, DataMissingParamCodec(), opts...)
		if err != nil {
			return mapvalues.SubscriberLocationReportErrors{}, err
		}
		return mapvalues.SubscriberLocationReportErrors{DataMissing: p}, nil
	case 51:
		p, err := decodeErrorParameter(data, present, ResourceLimitationParamCodec(), opts...)
		if err != nil {
			return mapvalues.SubscriberLocationReportErrors{}, err
		}
		return mapvalues.SubscriberLocationReportErrors{ResourceLimitation: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return mapvalues.SubscriberLocationReportErrors{}, err
		}
		return mapvalues.SubscriberLocationReportErrors{UnexpectedDataValue: p}, nil
	case 1:
		p, err := decodeErrorParameter(data, present, UnknownSubscriberParamCodec(), opts...)
		if err != nil {
			return mapvalues.SubscriberLocationReportErrors{}, err
		}
		return mapvalues.SubscriberLocationReportErrors{UnknownSubscriber: p}, nil
	case 52:
		p, err := decodeErrorParameter(data, present, UnauthorizedRequestingNetworkParamCodec(), opts...)
		if err != nil {
			return mapvalues.SubscriberLocationReportErrors{}, err
		}
		return mapvalues.SubscriberLocationReportErrors{UnauthorizedRequestingNetwork: p}, nil
	case 58:
		p, err := decodeErrorParameter(data, present, UnknownOrUnreachableLCSClientParamCodec(), opts...)
		if err != nil {
			return mapvalues.SubscriberLocationReportErrors{}, err
		}
		return mapvalues.SubscriberLocationReportErrors{UnknownOrUnreachableLCSClient: p}, nil
	default:
		return mapvalues.SubscriberLocationReportErrors{}, fmt.Errorf("%w: error code %d is not in subscriberLocationReport ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeSubscriberLocationReportError(value mapvalues.SubscriberLocationReportErrors, opts ...ber.EncodeOption) (mapvalues.EncodedError, error) {
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
		return mapvalues.EncodedError{}, fmt.Errorf("%w: exactly one subscriberLocationReport error arm is required", ber.ErrInvalidBinding)
	}
	if value.SystemFailure != nil {
		return encodeMAPErrorMember(mapvalues.SystemFailure, value.SystemFailure, SystemFailureParamCodec(), opts...)
	}
	if value.DataMissing != nil {
		return encodeMAPErrorMember(mapvalues.DataMissing, value.DataMissing, DataMissingParamCodec(), opts...)
	}
	if value.ResourceLimitation != nil {
		return encodeMAPErrorMember(mapvalues.ResourceLimitation, value.ResourceLimitation, ResourceLimitationParamCodec(), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(mapvalues.UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	if value.UnknownSubscriber != nil {
		return encodeMAPErrorMember(mapvalues.UnknownSubscriber, value.UnknownSubscriber, UnknownSubscriberParamCodec(), opts...)
	}
	if value.UnauthorizedRequestingNetwork != nil {
		return encodeMAPErrorMember(mapvalues.UnauthorizedRequestingNetwork, value.UnauthorizedRequestingNetwork, UnauthorizedRequestingNetworkParamCodec(), opts...)
	}
	if value.UnknownOrUnreachableLCSClient != nil {
		return encodeMAPErrorMember(mapvalues.UnknownOrUnreachableLCSClient, value.UnknownOrUnreachableLCSClient, UnknownOrUnreachableLCSClientParamCodec(), opts...)
	}
	return mapvalues.EncodedError{}, fmt.Errorf("%w: no selected subscriberLocationReport error", ber.ErrInvalidBinding)
}
func infoUnstructuredSSNotifyOperation() mapvalues.OperationInfo {
	info, _ := mapvalues.LookupOperation(mapvalues.UnstructuredSSNotify)
	return info
}

// UnstructuredSSNotifyOperation binds the formal object in TS 29.002 V19.1.0 §17.6.4 (X.880 §§8.2–8.3).
func UnstructuredSSNotifyOperation() Operation[mapvalues.USSDArg, mapvalues.NoParameter, mapvalues.UnstructuredSSNotifyErrors] {
	return Operation[mapvalues.USSDArg, mapvalues.NoParameter, mapvalues.UnstructuredSSNotifyErrors]{code: mapvalues.UnstructuredSSNotify, info: infoUnstructuredSSNotifyOperation, argument: USSDArgCodec(), result: mapvalues.ValueCodec[mapvalues.NoParameter]{}, decode: decodeUnstructuredSSNotifyError, encode: encodeUnstructuredSSNotifyError}
}
func decodeUnstructuredSSNotifyError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (mapvalues.UnstructuredSSNotifyErrors, error) {
	switch code {
	case 34:
		p, err := decodeErrorParameter(data, present, SystemFailureParamCodec(), opts...)
		if err != nil {
			return mapvalues.UnstructuredSSNotifyErrors{}, err
		}
		return mapvalues.UnstructuredSSNotifyErrors{SystemFailure: p}, nil
	case 35:
		p, err := decodeErrorParameter(data, present, DataMissingParamCodec(), opts...)
		if err != nil {
			return mapvalues.UnstructuredSSNotifyErrors{}, err
		}
		return mapvalues.UnstructuredSSNotifyErrors{DataMissing: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return mapvalues.UnstructuredSSNotifyErrors{}, err
		}
		return mapvalues.UnstructuredSSNotifyErrors{UnexpectedDataValue: p}, nil
	case 27:
		p, err := decodeErrorParameter(data, present, AbsentSubscriberParamCodec(), opts...)
		if err != nil {
			return mapvalues.UnstructuredSSNotifyErrors{}, err
		}
		return mapvalues.UnstructuredSSNotifyErrors{AbsentSubscriber: p}, nil
	case 9:
		p, err := decodeErrorParameter(data, present, IllegalSubscriberParamCodec(), opts...)
		if err != nil {
			return mapvalues.UnstructuredSSNotifyErrors{}, err
		}
		return mapvalues.UnstructuredSSNotifyErrors{IllegalSubscriber: p}, nil
	case 12:
		p, err := decodeErrorParameter(data, present, IllegalEquipmentParamCodec(), opts...)
		if err != nil {
			return mapvalues.UnstructuredSSNotifyErrors{}, err
		}
		return mapvalues.UnstructuredSSNotifyErrors{IllegalEquipment: p}, nil
	case 71:
		p, err := decodeErrorParameter(data, present, mapvalues.ValueCodec[mapvalues.NoParameter]{}, opts...)
		if err != nil {
			return mapvalues.UnstructuredSSNotifyErrors{}, err
		}
		return mapvalues.UnstructuredSSNotifyErrors{UnknownAlphabet: p}, nil
	case 72:
		p, err := decodeErrorParameter(data, present, mapvalues.ValueCodec[mapvalues.NoParameter]{}, opts...)
		if err != nil {
			return mapvalues.UnstructuredSSNotifyErrors{}, err
		}
		return mapvalues.UnstructuredSSNotifyErrors{UssdBusy: p}, nil
	default:
		return mapvalues.UnstructuredSSNotifyErrors{}, fmt.Errorf("%w: error code %d is not in unstructuredSS-Notify ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeUnstructuredSSNotifyError(value mapvalues.UnstructuredSSNotifyErrors, opts ...ber.EncodeOption) (mapvalues.EncodedError, error) {
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
		return mapvalues.EncodedError{}, fmt.Errorf("%w: exactly one unstructuredSS-Notify error arm is required", ber.ErrInvalidBinding)
	}
	if value.SystemFailure != nil {
		return encodeMAPErrorMember(mapvalues.SystemFailure, value.SystemFailure, SystemFailureParamCodec(), opts...)
	}
	if value.DataMissing != nil {
		return encodeMAPErrorMember(mapvalues.DataMissing, value.DataMissing, DataMissingParamCodec(), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(mapvalues.UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	if value.AbsentSubscriber != nil {
		return encodeMAPErrorMember(mapvalues.AbsentSubscriber, value.AbsentSubscriber, AbsentSubscriberParamCodec(), opts...)
	}
	if value.IllegalSubscriber != nil {
		return encodeMAPErrorMember(mapvalues.IllegalSubscriber, value.IllegalSubscriber, IllegalSubscriberParamCodec(), opts...)
	}
	if value.IllegalEquipment != nil {
		return encodeMAPErrorMember(mapvalues.IllegalEquipment, value.IllegalEquipment, IllegalEquipmentParamCodec(), opts...)
	}
	if value.UnknownAlphabet != nil {
		return encodeMAPErrorMember(mapvalues.UnknownAlphabet, value.UnknownAlphabet, mapvalues.ValueCodec[mapvalues.NoParameter]{}, opts...)
	}
	if value.UssdBusy != nil {
		return encodeMAPErrorMember(mapvalues.UssdBusy, value.UssdBusy, mapvalues.ValueCodec[mapvalues.NoParameter]{}, opts...)
	}
	return mapvalues.EncodedError{}, fmt.Errorf("%w: no selected unstructuredSS-Notify error", ber.ErrInvalidBinding)
}
func infoUnstructuredSSRequestOperation() mapvalues.OperationInfo {
	info, _ := mapvalues.LookupOperation(mapvalues.UnstructuredSSRequest)
	return info
}

// UnstructuredSSRequestOperation binds the formal object in TS 29.002 V19.1.0 §17.6.4 (X.880 §§8.2–8.3).
func UnstructuredSSRequestOperation() Operation[mapvalues.USSDArg, mapvalues.USSDRes, mapvalues.UnstructuredSSRequestErrors] {
	return Operation[mapvalues.USSDArg, mapvalues.USSDRes, mapvalues.UnstructuredSSRequestErrors]{code: mapvalues.UnstructuredSSRequest, info: infoUnstructuredSSRequestOperation, argument: USSDArgCodec(), result: USSDResCodec(), decode: decodeUnstructuredSSRequestError, encode: encodeUnstructuredSSRequestError}
}
func decodeUnstructuredSSRequestError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (mapvalues.UnstructuredSSRequestErrors, error) {
	switch code {
	case 34:
		p, err := decodeErrorParameter(data, present, SystemFailureParamCodec(), opts...)
		if err != nil {
			return mapvalues.UnstructuredSSRequestErrors{}, err
		}
		return mapvalues.UnstructuredSSRequestErrors{SystemFailure: p}, nil
	case 35:
		p, err := decodeErrorParameter(data, present, DataMissingParamCodec(), opts...)
		if err != nil {
			return mapvalues.UnstructuredSSRequestErrors{}, err
		}
		return mapvalues.UnstructuredSSRequestErrors{DataMissing: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return mapvalues.UnstructuredSSRequestErrors{}, err
		}
		return mapvalues.UnstructuredSSRequestErrors{UnexpectedDataValue: p}, nil
	case 27:
		p, err := decodeErrorParameter(data, present, AbsentSubscriberParamCodec(), opts...)
		if err != nil {
			return mapvalues.UnstructuredSSRequestErrors{}, err
		}
		return mapvalues.UnstructuredSSRequestErrors{AbsentSubscriber: p}, nil
	case 9:
		p, err := decodeErrorParameter(data, present, IllegalSubscriberParamCodec(), opts...)
		if err != nil {
			return mapvalues.UnstructuredSSRequestErrors{}, err
		}
		return mapvalues.UnstructuredSSRequestErrors{IllegalSubscriber: p}, nil
	case 12:
		p, err := decodeErrorParameter(data, present, IllegalEquipmentParamCodec(), opts...)
		if err != nil {
			return mapvalues.UnstructuredSSRequestErrors{}, err
		}
		return mapvalues.UnstructuredSSRequestErrors{IllegalEquipment: p}, nil
	case 71:
		p, err := decodeErrorParameter(data, present, mapvalues.ValueCodec[mapvalues.NoParameter]{}, opts...)
		if err != nil {
			return mapvalues.UnstructuredSSRequestErrors{}, err
		}
		return mapvalues.UnstructuredSSRequestErrors{UnknownAlphabet: p}, nil
	case 72:
		p, err := decodeErrorParameter(data, present, mapvalues.ValueCodec[mapvalues.NoParameter]{}, opts...)
		if err != nil {
			return mapvalues.UnstructuredSSRequestErrors{}, err
		}
		return mapvalues.UnstructuredSSRequestErrors{UssdBusy: p}, nil
	default:
		return mapvalues.UnstructuredSSRequestErrors{}, fmt.Errorf("%w: error code %d is not in unstructuredSS-Request ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeUnstructuredSSRequestError(value mapvalues.UnstructuredSSRequestErrors, opts ...ber.EncodeOption) (mapvalues.EncodedError, error) {
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
		return mapvalues.EncodedError{}, fmt.Errorf("%w: exactly one unstructuredSS-Request error arm is required", ber.ErrInvalidBinding)
	}
	if value.SystemFailure != nil {
		return encodeMAPErrorMember(mapvalues.SystemFailure, value.SystemFailure, SystemFailureParamCodec(), opts...)
	}
	if value.DataMissing != nil {
		return encodeMAPErrorMember(mapvalues.DataMissing, value.DataMissing, DataMissingParamCodec(), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(mapvalues.UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	if value.AbsentSubscriber != nil {
		return encodeMAPErrorMember(mapvalues.AbsentSubscriber, value.AbsentSubscriber, AbsentSubscriberParamCodec(), opts...)
	}
	if value.IllegalSubscriber != nil {
		return encodeMAPErrorMember(mapvalues.IllegalSubscriber, value.IllegalSubscriber, IllegalSubscriberParamCodec(), opts...)
	}
	if value.IllegalEquipment != nil {
		return encodeMAPErrorMember(mapvalues.IllegalEquipment, value.IllegalEquipment, IllegalEquipmentParamCodec(), opts...)
	}
	if value.UnknownAlphabet != nil {
		return encodeMAPErrorMember(mapvalues.UnknownAlphabet, value.UnknownAlphabet, mapvalues.ValueCodec[mapvalues.NoParameter]{}, opts...)
	}
	if value.UssdBusy != nil {
		return encodeMAPErrorMember(mapvalues.UssdBusy, value.UssdBusy, mapvalues.ValueCodec[mapvalues.NoParameter]{}, opts...)
	}
	return mapvalues.EncodedError{}, fmt.Errorf("%w: no selected unstructuredSS-Request error", ber.ErrInvalidBinding)
}
func infoUpdateGprsLocationOperation() mapvalues.OperationInfo {
	info, _ := mapvalues.LookupOperation(mapvalues.UpdateGprsLocation)
	return info
}

// UpdateGprsLocationOperation binds the formal object in TS 29.002 V19.1.0 §17.6.1 (X.880 §§8.2–8.3).
func UpdateGprsLocationOperation() Operation[mapvalues.UpdateGprsLocationArg, mapvalues.UpdateGprsLocationRes, mapvalues.UpdateGprsLocationErrors] {
	return Operation[mapvalues.UpdateGprsLocationArg, mapvalues.UpdateGprsLocationRes, mapvalues.UpdateGprsLocationErrors]{code: mapvalues.UpdateGprsLocation, info: infoUpdateGprsLocationOperation, argument: UpdateGprsLocationArgCodec(), result: UpdateGprsLocationResCodec(), decode: decodeUpdateGprsLocationError, encode: encodeUpdateGprsLocationError}
}
func decodeUpdateGprsLocationError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (mapvalues.UpdateGprsLocationErrors, error) {
	switch code {
	case 34:
		p, err := decodeErrorParameter(data, present, SystemFailureParamCodec(), opts...)
		if err != nil {
			return mapvalues.UpdateGprsLocationErrors{}, err
		}
		return mapvalues.UpdateGprsLocationErrors{SystemFailure: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return mapvalues.UpdateGprsLocationErrors{}, err
		}
		return mapvalues.UpdateGprsLocationErrors{UnexpectedDataValue: p}, nil
	case 1:
		p, err := decodeErrorParameter(data, present, UnknownSubscriberParamCodec(), opts...)
		if err != nil {
			return mapvalues.UpdateGprsLocationErrors{}, err
		}
		return mapvalues.UpdateGprsLocationErrors{UnknownSubscriber: p}, nil
	case 8:
		p, err := decodeErrorParameter(data, present, RoamingNotAllowedParamCodec(), opts...)
		if err != nil {
			return mapvalues.UpdateGprsLocationErrors{}, err
		}
		return mapvalues.UpdateGprsLocationErrors{RoamingNotAllowed: p}, nil
	default:
		return mapvalues.UpdateGprsLocationErrors{}, fmt.Errorf("%w: error code %d is not in updateGprsLocation ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeUpdateGprsLocationError(value mapvalues.UpdateGprsLocationErrors, opts ...ber.EncodeOption) (mapvalues.EncodedError, error) {
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
		return mapvalues.EncodedError{}, fmt.Errorf("%w: exactly one updateGprsLocation error arm is required", ber.ErrInvalidBinding)
	}
	if value.SystemFailure != nil {
		return encodeMAPErrorMember(mapvalues.SystemFailure, value.SystemFailure, SystemFailureParamCodec(), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(mapvalues.UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	if value.UnknownSubscriber != nil {
		return encodeMAPErrorMember(mapvalues.UnknownSubscriber, value.UnknownSubscriber, UnknownSubscriberParamCodec(), opts...)
	}
	if value.RoamingNotAllowed != nil {
		return encodeMAPErrorMember(mapvalues.RoamingNotAllowed, value.RoamingNotAllowed, RoamingNotAllowedParamCodec(), opts...)
	}
	return mapvalues.EncodedError{}, fmt.Errorf("%w: no selected updateGprsLocation error", ber.ErrInvalidBinding)
}
func infoUpdateLocationOperation() mapvalues.OperationInfo {
	info, _ := mapvalues.LookupOperation(mapvalues.UpdateLocation)
	return info
}

// UpdateLocationOperation binds the formal object in TS 29.002 V19.1.0 §17.6.1 (X.880 §§8.2–8.3).
func UpdateLocationOperation() Operation[mapvalues.UpdateLocationArg, mapvalues.UpdateLocationRes, mapvalues.UpdateLocationErrors] {
	return Operation[mapvalues.UpdateLocationArg, mapvalues.UpdateLocationRes, mapvalues.UpdateLocationErrors]{code: mapvalues.UpdateLocation, info: infoUpdateLocationOperation, argument: UpdateLocationArgCodec(), result: UpdateLocationResCodec(), decode: decodeUpdateLocationError, encode: encodeUpdateLocationError}
}
func decodeUpdateLocationError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (mapvalues.UpdateLocationErrors, error) {
	switch code {
	case 34:
		p, err := decodeErrorParameter(data, present, SystemFailureParamCodec(), opts...)
		if err != nil {
			return mapvalues.UpdateLocationErrors{}, err
		}
		return mapvalues.UpdateLocationErrors{SystemFailure: p}, nil
	case 35:
		p, err := decodeErrorParameter(data, present, DataMissingParamCodec(), opts...)
		if err != nil {
			return mapvalues.UpdateLocationErrors{}, err
		}
		return mapvalues.UpdateLocationErrors{DataMissing: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return mapvalues.UpdateLocationErrors{}, err
		}
		return mapvalues.UpdateLocationErrors{UnexpectedDataValue: p}, nil
	case 1:
		p, err := decodeErrorParameter(data, present, UnknownSubscriberParamCodec(), opts...)
		if err != nil {
			return mapvalues.UpdateLocationErrors{}, err
		}
		return mapvalues.UpdateLocationErrors{UnknownSubscriber: p}, nil
	case 8:
		p, err := decodeErrorParameter(data, present, RoamingNotAllowedParamCodec(), opts...)
		if err != nil {
			return mapvalues.UpdateLocationErrors{}, err
		}
		return mapvalues.UpdateLocationErrors{RoamingNotAllowed: p}, nil
	default:
		return mapvalues.UpdateLocationErrors{}, fmt.Errorf("%w: error code %d is not in updateLocation ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeUpdateLocationError(value mapvalues.UpdateLocationErrors, opts ...ber.EncodeOption) (mapvalues.EncodedError, error) {
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
		return mapvalues.EncodedError{}, fmt.Errorf("%w: exactly one updateLocation error arm is required", ber.ErrInvalidBinding)
	}
	if value.SystemFailure != nil {
		return encodeMAPErrorMember(mapvalues.SystemFailure, value.SystemFailure, SystemFailureParamCodec(), opts...)
	}
	if value.DataMissing != nil {
		return encodeMAPErrorMember(mapvalues.DataMissing, value.DataMissing, DataMissingParamCodec(), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(mapvalues.UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	if value.UnknownSubscriber != nil {
		return encodeMAPErrorMember(mapvalues.UnknownSubscriber, value.UnknownSubscriber, UnknownSubscriberParamCodec(), opts...)
	}
	if value.RoamingNotAllowed != nil {
		return encodeMAPErrorMember(mapvalues.RoamingNotAllowed, value.RoamingNotAllowed, RoamingNotAllowedParamCodec(), opts...)
	}
	return mapvalues.EncodedError{}, fmt.Errorf("%w: no selected updateLocation error", ber.ErrInvalidBinding)
}
func infoUpdateVcsgLocationOperation() mapvalues.OperationInfo {
	info, _ := mapvalues.LookupOperation(mapvalues.UpdateVcsgLocation)
	return info
}

// UpdateVcsgLocationOperation binds the formal object in TS 29.002 V19.1.0 §17.6.1 (X.880 §§8.2–8.3).
func UpdateVcsgLocationOperation() Operation[mapvalues.UpdateVcsgLocationArg, mapvalues.UpdateVcsgLocationRes, mapvalues.UpdateVcsgLocationErrors] {
	return Operation[mapvalues.UpdateVcsgLocationArg, mapvalues.UpdateVcsgLocationRes, mapvalues.UpdateVcsgLocationErrors]{code: mapvalues.UpdateVcsgLocation, info: infoUpdateVcsgLocationOperation, argument: UpdateVcsgLocationArgCodec(), result: UpdateVcsgLocationResCodec(), decode: decodeUpdateVcsgLocationError, encode: encodeUpdateVcsgLocationError}
}
func decodeUpdateVcsgLocationError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (mapvalues.UpdateVcsgLocationErrors, error) {
	switch code {
	case 34:
		p, err := decodeErrorParameter(data, present, SystemFailureParamCodec(), opts...)
		if err != nil {
			return mapvalues.UpdateVcsgLocationErrors{}, err
		}
		return mapvalues.UpdateVcsgLocationErrors{SystemFailure: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, UnexpectedDataParamCodec(), opts...)
		if err != nil {
			return mapvalues.UpdateVcsgLocationErrors{}, err
		}
		return mapvalues.UpdateVcsgLocationErrors{UnexpectedDataValue: p}, nil
	case 1:
		p, err := decodeErrorParameter(data, present, UnknownSubscriberParamCodec(), opts...)
		if err != nil {
			return mapvalues.UpdateVcsgLocationErrors{}, err
		}
		return mapvalues.UpdateVcsgLocationErrors{UnknownSubscriber: p}, nil
	default:
		return mapvalues.UpdateVcsgLocationErrors{}, fmt.Errorf("%w: error code %d is not in updateVcsgLocation ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeUpdateVcsgLocationError(value mapvalues.UpdateVcsgLocationErrors, opts ...ber.EncodeOption) (mapvalues.EncodedError, error) {
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
		return mapvalues.EncodedError{}, fmt.Errorf("%w: exactly one updateVcsgLocation error arm is required", ber.ErrInvalidBinding)
	}
	if value.SystemFailure != nil {
		return encodeMAPErrorMember(mapvalues.SystemFailure, value.SystemFailure, SystemFailureParamCodec(), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeMAPErrorMember(mapvalues.UnexpectedDataValue, value.UnexpectedDataValue, UnexpectedDataParamCodec(), opts...)
	}
	if value.UnknownSubscriber != nil {
		return encodeMAPErrorMember(mapvalues.UnknownSubscriber, value.UnknownSubscriber, UnknownSubscriberParamCodec(), opts...)
	}
	return mapvalues.EncodedError{}, fmt.Errorf("%w: no selected updateVcsgLocation error", ber.ErrInvalidBinding)
}

type SSErrorDescriptor[P any] struct {
	errorBinding[P, mapvalues.SSErrorInfo, mapvalues.SSErrorCode]
}

// SSDeflectionToServedSubscriberErrorDescriptor binds the formal ERROR object SS-Errors.deflectionToServedSubscriber (X.880 §8.3).
func SSDeflectionToServedSubscriberErrorDescriptor() SSErrorDescriptor[mapvalues.NoParameter] {
	return SSErrorDescriptor[mapvalues.NoParameter]{errorBinding[mapvalues.NoParameter, mapvalues.SSErrorInfo, mapvalues.SSErrorCode]{code: mapvalues.SSDeflectionToServedSubscriber, info: infoSSDeflectionToServedSubscriberError, parameter: mapvalues.ValueCodec[mapvalues.NoParameter]{}}}
}
func infoSSDeflectionToServedSubscriberError() mapvalues.SSErrorInfo {
	info, _ := mapvalues.LookupSSError(mapvalues.SSDeflectionToServedSubscriber)
	return info
}

// SSInvalidDeflectedToNumberErrorDescriptor binds the formal ERROR object SS-Errors.invalidDeflectedToNumber (X.880 §8.3).
func SSInvalidDeflectedToNumberErrorDescriptor() SSErrorDescriptor[mapvalues.NoParameter] {
	return SSErrorDescriptor[mapvalues.NoParameter]{errorBinding[mapvalues.NoParameter, mapvalues.SSErrorInfo, mapvalues.SSErrorCode]{code: mapvalues.SSInvalidDeflectedToNumber, info: infoSSInvalidDeflectedToNumberError, parameter: mapvalues.ValueCodec[mapvalues.NoParameter]{}}}
}
func infoSSInvalidDeflectedToNumberError() mapvalues.SSErrorInfo {
	info, _ := mapvalues.LookupSSError(mapvalues.SSInvalidDeflectedToNumber)
	return info
}

// SSLcsInvalidPruErrorDescriptor binds the formal ERROR object SS-Errors.lcs-invalidPru (X.880 §8.3).
func SSLcsInvalidPruErrorDescriptor() SSErrorDescriptor[mapvalues.NoParameter] {
	return SSErrorDescriptor[mapvalues.NoParameter]{errorBinding[mapvalues.NoParameter, mapvalues.SSErrorInfo, mapvalues.SSErrorCode]{code: mapvalues.SSLcsInvalidPru, info: infoSSLcsInvalidPruError, parameter: mapvalues.ValueCodec[mapvalues.NoParameter]{}}}
}
func infoSSLcsInvalidPruError() mapvalues.SSErrorInfo {
	info, _ := mapvalues.LookupSSError(mapvalues.SSLcsInvalidPru)
	return info
}

// SSLcsPruAssociationRejErrorDescriptor binds the formal ERROR object SS-Errors.lcs-PruAssociationRej (X.880 §8.3).
func SSLcsPruAssociationRejErrorDescriptor() SSErrorDescriptor[mapvalues.PruAssociationRejParam] {
	return SSErrorDescriptor[mapvalues.PruAssociationRejParam]{errorBinding[mapvalues.PruAssociationRejParam, mapvalues.SSErrorInfo, mapvalues.SSErrorCode]{code: mapvalues.SSLcsPruAssociationRej, info: infoSSLcsPruAssociationRejError, parameter: PruAssociationRejParamCodec()}}
}
func infoSSLcsPruAssociationRejError() mapvalues.SSErrorInfo {
	info, _ := mapvalues.LookupSSError(mapvalues.SSLcsPruAssociationRej)
	return info
}

// SSMaxNumberOfMPTYParticipantsExceededErrorDescriptor binds the formal ERROR object SS-Errors.maxNumberOfMPTY-ParticipantsExceeded (X.880 §8.3).
func SSMaxNumberOfMPTYParticipantsExceededErrorDescriptor() SSErrorDescriptor[mapvalues.NoParameter] {
	return SSErrorDescriptor[mapvalues.NoParameter]{errorBinding[mapvalues.NoParameter, mapvalues.SSErrorInfo, mapvalues.SSErrorCode]{code: mapvalues.SSMaxNumberOfMPTYParticipantsExceeded, info: infoSSMaxNumberOfMPTYParticipantsExceededError, parameter: mapvalues.ValueCodec[mapvalues.NoParameter]{}}}
}
func infoSSMaxNumberOfMPTYParticipantsExceededError() mapvalues.SSErrorInfo {
	info, _ := mapvalues.LookupSSError(mapvalues.SSMaxNumberOfMPTYParticipantsExceeded)
	return info
}

// SSRejectedByNetworkErrorDescriptor binds the formal ERROR object SS-Errors.rejectedByNetwork (X.880 §8.3).
func SSRejectedByNetworkErrorDescriptor() SSErrorDescriptor[mapvalues.NoParameter] {
	return SSErrorDescriptor[mapvalues.NoParameter]{errorBinding[mapvalues.NoParameter, mapvalues.SSErrorInfo, mapvalues.SSErrorCode]{code: mapvalues.SSRejectedByNetwork, info: infoSSRejectedByNetworkError, parameter: mapvalues.ValueCodec[mapvalues.NoParameter]{}}}
}
func infoSSRejectedByNetworkError() mapvalues.SSErrorInfo {
	info, _ := mapvalues.LookupSSError(mapvalues.SSRejectedByNetwork)
	return info
}

// SSRejectedByUserErrorDescriptor binds the formal ERROR object SS-Errors.rejectedByUser (X.880 §8.3).
func SSRejectedByUserErrorDescriptor() SSErrorDescriptor[mapvalues.NoParameter] {
	return SSErrorDescriptor[mapvalues.NoParameter]{errorBinding[mapvalues.NoParameter, mapvalues.SSErrorInfo, mapvalues.SSErrorCode]{code: mapvalues.SSRejectedByUser, info: infoSSRejectedByUserError, parameter: mapvalues.ValueCodec[mapvalues.NoParameter]{}}}
}
func infoSSRejectedByUserError() mapvalues.SSErrorInfo {
	info, _ := mapvalues.LookupSSError(mapvalues.SSRejectedByUser)
	return info
}

// SSResourcesNotAvailableErrorDescriptor binds the formal ERROR object SS-Errors.resourcesNotAvailable (X.880 §8.3).
func SSResourcesNotAvailableErrorDescriptor() SSErrorDescriptor[mapvalues.NoParameter] {
	return SSErrorDescriptor[mapvalues.NoParameter]{errorBinding[mapvalues.NoParameter, mapvalues.SSErrorInfo, mapvalues.SSErrorCode]{code: mapvalues.SSResourcesNotAvailable, info: infoSSResourcesNotAvailableError, parameter: mapvalues.ValueCodec[mapvalues.NoParameter]{}}}
}
func infoSSResourcesNotAvailableError() mapvalues.SSErrorInfo {
	info, _ := mapvalues.LookupSSError(mapvalues.SSResourcesNotAvailable)
	return info
}

// SSSpecialServiceCodeErrorDescriptor binds the formal ERROR object SS-Errors.specialServiceCode (X.880 §8.3).
func SSSpecialServiceCodeErrorDescriptor() SSErrorDescriptor[mapvalues.NoParameter] {
	return SSErrorDescriptor[mapvalues.NoParameter]{errorBinding[mapvalues.NoParameter, mapvalues.SSErrorInfo, mapvalues.SSErrorCode]{code: mapvalues.SSSpecialServiceCode, info: infoSSSpecialServiceCodeError, parameter: mapvalues.ValueCodec[mapvalues.NoParameter]{}}}
}
func infoSSSpecialServiceCodeError() mapvalues.SSErrorInfo {
	info, _ := mapvalues.LookupSSError(mapvalues.SSSpecialServiceCode)
	return info
}
func encodeSSErrorMember[P any](code int64, source mapvalues.SourceRef, value *mapvalues.ErrorValue[P], codec mapvalues.ValueCodec[P], opts ...ber.EncodeOption) (mapvalues.SSErrorEncoding, error) {
	data, present, err := encodeErrorParameter(value, codec, opts...)
	if err != nil {
		return mapvalues.SSErrorEncoding{}, err
	}
	return mapvalues.SSErrorEncoding{LocalCode: code, Source: source, Parameter: data, HasParameter: present}, nil
}

type SSOperation[A, R, E any] struct {
	code     mapvalues.SSOperationCode
	info     func() mapvalues.SSOperationInfo
	argument mapvalues.ValueCodec[A]
	result   mapvalues.ValueCodec[R]
	decode   func(int64, []byte, bool, ...ber.DecodeOption) (E, error)
	encode   func(E, ...ber.EncodeOption) (mapvalues.SSErrorEncoding, error)
}

func (d SSOperation[A, R, E]) Code() mapvalues.SSOperationCode { return d.code }
func (d SSOperation[A, R, E]) Info() mapvalues.SSOperationInfo {
	if d.info == nil {
		return mapvalues.SSOperationInfo{}
	}
	return d.info()
}
func (d SSOperation[A, R, E]) Argument() (mapvalues.ValueCodec[A], bool) {
	return d.argument, d.argument.Valid()
}
func (d SSOperation[A, R, E]) Result() (mapvalues.ValueCodec[R], bool) {
	return d.result, d.result.Valid()
}
func (d SSOperation[A, R, E]) DecodeError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (E, error) {
	if d.decode == nil {
		var zero E
		return zero, ber.ErrInvalidBinding
	}
	return d.decode(int64(code), data, present, opts...)
}
func (d SSOperation[A, R, E]) EncodeError(v E, opts ...ber.EncodeOption) (mapvalues.SSErrorEncoding, error) {
	if d.encode == nil {
		return mapvalues.SSErrorEncoding{}, ber.ErrInvalidBinding
	}
	return d.encode(v, opts...)
}
func (d SSOperation[A, R, E]) Errors() []mapvalues.SSErrorMemberInfo { return d.Info().Errors }
func infoSSAccessRegisterCCEntryOperation() mapvalues.SSOperationInfo {
	info, _ := mapvalues.LookupSSOperation(mapvalues.SSAccessRegisterCCEntry)
	return info
}

// SSAccessRegisterCCEntryOperation binds the formal object in TS 24.080 V19.4.0 §4.2 (X.880 §§8.2–8.3).
func SSAccessRegisterCCEntryOperation() SSOperation[mapvalues.AccessRegisterCCEntryArg, __asn1pkg_v21_map_ss_datatypes.SSRegisterCCEntryRes, mapvalues.SSAccessRegisterCCEntryErrors] {
	return SSOperation[mapvalues.AccessRegisterCCEntryArg, __asn1pkg_v21_map_ss_datatypes.SSRegisterCCEntryRes, mapvalues.SSAccessRegisterCCEntryErrors]{code: mapvalues.SSAccessRegisterCCEntry, info: infoSSAccessRegisterCCEntryOperation, argument: AccessRegisterCCEntryArgCodec(), result: adaptValueCodec[__asn1pkg_v21_map_ss_datatypes.SSRegisterCCEntryRes](__asn1pkg_v21_map_ss_datatypes.SSRegisterCCEntryResCodec()), decode: decodeSSAccessRegisterCCEntryError, encode: encodeSSAccessRegisterCCEntryError}
}
func decodeSSAccessRegisterCCEntryError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (mapvalues.SSAccessRegisterCCEntryErrors, error) {
	switch code {
	case 34:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam](__asn1pkg_v21_map_er_datatypes.ERSystemFailureParamCodec()), opts...)
		if err != nil {
			return mapvalues.SSAccessRegisterCCEntryErrors{}, err
		}
		return mapvalues.SSAccessRegisterCCEntryErrors{SystemFailure: p}, nil
	case 35:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERDataMissingParam](__asn1pkg_v21_map_er_datatypes.ERDataMissingParamCodec()), opts...)
		if err != nil {
			return mapvalues.SSAccessRegisterCCEntryErrors{}, err
		}
		return mapvalues.SSAccessRegisterCCEntryErrors{DataMissing: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParam](__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParamCodec()), opts...)
		if err != nil {
			return mapvalues.SSAccessRegisterCCEntryErrors{}, err
		}
		return mapvalues.SSAccessRegisterCCEntryErrors{UnexpectedDataValue: p}, nil
	case 13:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERCallBarredParam](__asn1pkg_v21_map_er_datatypes.ERCallBarredParamCodec()), opts...)
		if err != nil {
			return mapvalues.SSAccessRegisterCCEntryErrors{}, err
		}
		return mapvalues.SSAccessRegisterCCEntryErrors{CallBarred: p}, nil
	case 16:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERIllegalSSOperationParam](__asn1pkg_v21_map_er_datatypes.ERIllegalSSOperationParamCodec()), opts...)
		if err != nil {
			return mapvalues.SSAccessRegisterCCEntryErrors{}, err
		}
		return mapvalues.SSAccessRegisterCCEntryErrors{IllegalSSOperation: p}, nil
	case 17:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_ss_datatypes.BERValue[__asn1pkg_v21_map_ss_datatypes.SSSSStatus]](__asn1pkg_v21_map_ss_datatypes.SSSSStatusCodec()), opts...)
		if err != nil {
			return mapvalues.SSAccessRegisterCCEntryErrors{}, err
		}
		return mapvalues.SSAccessRegisterCCEntryErrors{SsErrorStatus: p}, nil
	case 20:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSSIncompatibilityCause](__asn1pkg_v21_map_er_datatypes.ERSSIncompatibilityCauseCodec()), opts...)
		if err != nil {
			return mapvalues.SSAccessRegisterCCEntryErrors{}, err
		}
		return mapvalues.SSAccessRegisterCCEntryErrors{SsIncompatibility: p}, nil
	case 29:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERShortTermDenialParam](__asn1pkg_v21_map_er_datatypes.ERShortTermDenialParamCodec()), opts...)
		if err != nil {
			return mapvalues.SSAccessRegisterCCEntryErrors{}, err
		}
		return mapvalues.SSAccessRegisterCCEntryErrors{ShortTermDenial: p}, nil
	case 30:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERLongTermDenialParam](__asn1pkg_v21_map_er_datatypes.ERLongTermDenialParamCodec()), opts...)
		if err != nil {
			return mapvalues.SSAccessRegisterCCEntryErrors{}, err
		}
		return mapvalues.SSAccessRegisterCCEntryErrors{LongTermDenial: p}, nil
	case 21:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParam](__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParamCodec()), opts...)
		if err != nil {
			return mapvalues.SSAccessRegisterCCEntryErrors{}, err
		}
		return mapvalues.SSAccessRegisterCCEntryErrors{FacilityNotSupported: p}, nil
	default:
		return mapvalues.SSAccessRegisterCCEntryErrors{}, fmt.Errorf("%w: error code %d is not in accessRegisterCCEntry ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeSSAccessRegisterCCEntryError(value mapvalues.SSAccessRegisterCCEntryErrors, opts ...ber.EncodeOption) (mapvalues.SSErrorEncoding, error) {
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
		return mapvalues.SSErrorEncoding{}, fmt.Errorf("%w: exactly one accessRegisterCCEntry error arm is required", ber.ErrInvalidBinding)
	}
	if value.SystemFailure != nil {
		return encodeSSErrorMember(34, mapvalues.SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: "17.6.6", Module: "MAP-Errors", Assignment: "systemFailure", SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}, value.SystemFailure, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam](__asn1pkg_v21_map_er_datatypes.ERSystemFailureParamCodec()), opts...)
	}
	if value.DataMissing != nil {
		return encodeSSErrorMember(35, mapvalues.SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: "17.6.6", Module: "MAP-Errors", Assignment: "dataMissing", SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}, value.DataMissing, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERDataMissingParam](__asn1pkg_v21_map_er_datatypes.ERDataMissingParamCodec()), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeSSErrorMember(36, mapvalues.SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: "17.6.6", Module: "MAP-Errors", Assignment: "unexpectedDataValue", SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}, value.UnexpectedDataValue, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParam](__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParamCodec()), opts...)
	}
	if value.CallBarred != nil {
		return encodeSSErrorMember(13, mapvalues.SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: "17.6.6", Module: "MAP-Errors", Assignment: "callBarred", SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}, value.CallBarred, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERCallBarredParam](__asn1pkg_v21_map_er_datatypes.ERCallBarredParamCodec()), opts...)
	}
	if value.IllegalSSOperation != nil {
		return encodeSSErrorMember(16, mapvalues.SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: "17.6.6", Module: "MAP-Errors", Assignment: "illegalSS-Operation", SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}, value.IllegalSSOperation, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERIllegalSSOperationParam](__asn1pkg_v21_map_er_datatypes.ERIllegalSSOperationParamCodec()), opts...)
	}
	if value.SsErrorStatus != nil {
		return encodeSSErrorMember(17, mapvalues.SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: "17.6.6", Module: "MAP-Errors", Assignment: "ss-ErrorStatus", SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}, value.SsErrorStatus, adaptValueCodec[__asn1pkg_v21_map_ss_datatypes.BERValue[__asn1pkg_v21_map_ss_datatypes.SSSSStatus]](__asn1pkg_v21_map_ss_datatypes.SSSSStatusCodec()), opts...)
	}
	if value.SsIncompatibility != nil {
		return encodeSSErrorMember(20, mapvalues.SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: "17.6.6", Module: "MAP-Errors", Assignment: "ss-Incompatibility", SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}, value.SsIncompatibility, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSSIncompatibilityCause](__asn1pkg_v21_map_er_datatypes.ERSSIncompatibilityCauseCodec()), opts...)
	}
	if value.ShortTermDenial != nil {
		return encodeSSErrorMember(29, mapvalues.SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: "17.6.6", Module: "MAP-Errors", Assignment: "shortTermDenial", SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}, value.ShortTermDenial, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERShortTermDenialParam](__asn1pkg_v21_map_er_datatypes.ERShortTermDenialParamCodec()), opts...)
	}
	if value.LongTermDenial != nil {
		return encodeSSErrorMember(30, mapvalues.SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: "17.6.6", Module: "MAP-Errors", Assignment: "longTermDenial", SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}, value.LongTermDenial, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERLongTermDenialParam](__asn1pkg_v21_map_er_datatypes.ERLongTermDenialParamCodec()), opts...)
	}
	if value.FacilityNotSupported != nil {
		return encodeSSErrorMember(21, mapvalues.SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: "17.6.6", Module: "MAP-Errors", Assignment: "facilityNotSupported", SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}, value.FacilityNotSupported, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParam](__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParamCodec()), opts...)
	}
	return mapvalues.SSErrorEncoding{}, fmt.Errorf("%w: no selected accessRegisterCCEntry error", ber.ErrInvalidBinding)
}
func infoSSBuildMPTYOperation() mapvalues.SSOperationInfo {
	info, _ := mapvalues.LookupSSOperation(mapvalues.SSBuildMPTY)
	return info
}

// SSBuildMPTYOperation binds the formal object in TS 24.080 V19.4.0 §4.2 (X.880 §§8.2–8.3).
func SSBuildMPTYOperation() SSOperation[mapvalues.NoParameter, mapvalues.NoParameter, mapvalues.SSBuildMPTYErrors] {
	return SSOperation[mapvalues.NoParameter, mapvalues.NoParameter, mapvalues.SSBuildMPTYErrors]{code: mapvalues.SSBuildMPTY, info: infoSSBuildMPTYOperation, argument: mapvalues.ValueCodec[mapvalues.NoParameter]{}, result: mapvalues.ValueCodec[mapvalues.NoParameter]{}, decode: decodeSSBuildMPTYError, encode: encodeSSBuildMPTYError}
}
func decodeSSBuildMPTYError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (mapvalues.SSBuildMPTYErrors, error) {
	switch code {
	case 16:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERIllegalSSOperationParam](__asn1pkg_v21_map_er_datatypes.ERIllegalSSOperationParamCodec()), opts...)
		if err != nil {
			return mapvalues.SSBuildMPTYErrors{}, err
		}
		return mapvalues.SSBuildMPTYErrors{IllegalSSOperation: p}, nil
	case 17:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_ss_datatypes.BERValue[__asn1pkg_v21_map_ss_datatypes.SSSSStatus]](__asn1pkg_v21_map_ss_datatypes.SSSSStatusCodec()), opts...)
		if err != nil {
			return mapvalues.SSBuildMPTYErrors{}, err
		}
		return mapvalues.SSBuildMPTYErrors{SsErrorStatus: p}, nil
	case 18:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSSNotAvailableParam](__asn1pkg_v21_map_er_datatypes.ERSSNotAvailableParamCodec()), opts...)
		if err != nil {
			return mapvalues.SSBuildMPTYErrors{}, err
		}
		return mapvalues.SSBuildMPTYErrors{SsNotAvailable: p}, nil
	case 20:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSSIncompatibilityCause](__asn1pkg_v21_map_er_datatypes.ERSSIncompatibilityCauseCodec()), opts...)
		if err != nil {
			return mapvalues.SSBuildMPTYErrors{}, err
		}
		return mapvalues.SSBuildMPTYErrors{SsIncompatibility: p}, nil
	case 34:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam](__asn1pkg_v21_map_er_datatypes.ERSystemFailureParamCodec()), opts...)
		if err != nil {
			return mapvalues.SSBuildMPTYErrors{}, err
		}
		return mapvalues.SSBuildMPTYErrors{SystemFailure: p}, nil
	case 127:
		p, err := decodeErrorParameter(data, present, mapvalues.ValueCodec[mapvalues.NoParameter]{}, opts...)
		if err != nil {
			return mapvalues.SSBuildMPTYErrors{}, err
		}
		return mapvalues.SSBuildMPTYErrors{ResourcesNotAvailable: p}, nil
	case 126:
		p, err := decodeErrorParameter(data, present, mapvalues.ValueCodec[mapvalues.NoParameter]{}, opts...)
		if err != nil {
			return mapvalues.SSBuildMPTYErrors{}, err
		}
		return mapvalues.SSBuildMPTYErrors{MaxNumberOfMPTYParticipantsExceeded: p}, nil
	default:
		return mapvalues.SSBuildMPTYErrors{}, fmt.Errorf("%w: error code %d is not in buildMPTY ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeSSBuildMPTYError(value mapvalues.SSBuildMPTYErrors, opts ...ber.EncodeOption) (mapvalues.SSErrorEncoding, error) {
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
		return mapvalues.SSErrorEncoding{}, fmt.Errorf("%w: exactly one buildMPTY error arm is required", ber.ErrInvalidBinding)
	}
	if value.IllegalSSOperation != nil {
		return encodeSSErrorMember(16, mapvalues.SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: "17.6.6", Module: "MAP-Errors", Assignment: "illegalSS-Operation", SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}, value.IllegalSSOperation, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERIllegalSSOperationParam](__asn1pkg_v21_map_er_datatypes.ERIllegalSSOperationParamCodec()), opts...)
	}
	if value.SsErrorStatus != nil {
		return encodeSSErrorMember(17, mapvalues.SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: "17.6.6", Module: "MAP-Errors", Assignment: "ss-ErrorStatus", SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}, value.SsErrorStatus, adaptValueCodec[__asn1pkg_v21_map_ss_datatypes.BERValue[__asn1pkg_v21_map_ss_datatypes.SSSSStatus]](__asn1pkg_v21_map_ss_datatypes.SSSSStatusCodec()), opts...)
	}
	if value.SsNotAvailable != nil {
		return encodeSSErrorMember(18, mapvalues.SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: "17.6.6", Module: "MAP-Errors", Assignment: "ss-NotAvailable", SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}, value.SsNotAvailable, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSSNotAvailableParam](__asn1pkg_v21_map_er_datatypes.ERSSNotAvailableParamCodec()), opts...)
	}
	if value.SsIncompatibility != nil {
		return encodeSSErrorMember(20, mapvalues.SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: "17.6.6", Module: "MAP-Errors", Assignment: "ss-Incompatibility", SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}, value.SsIncompatibility, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSSIncompatibilityCause](__asn1pkg_v21_map_er_datatypes.ERSSIncompatibilityCauseCodec()), opts...)
	}
	if value.SystemFailure != nil {
		return encodeSSErrorMember(34, mapvalues.SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: "17.6.6", Module: "MAP-Errors", Assignment: "systemFailure", SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}, value.SystemFailure, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam](__asn1pkg_v21_map_er_datatypes.ERSystemFailureParamCodec()), opts...)
	}
	if value.ResourcesNotAvailable != nil {
		return encodeSSErrorMember(127, mapvalues.SourceRef{Document: "3GPP TS 24.080", Edition: "19.4.0", Clause: "4.3", Module: "SS-Errors", Assignment: "resourcesNotAvailable", SHA256: "b81d2a668e33702414eec4d9210bd4922f1104ccc4384cb6d8d3301ce8fa129e"}, value.ResourcesNotAvailable, mapvalues.ValueCodec[mapvalues.NoParameter]{}, opts...)
	}
	if value.MaxNumberOfMPTYParticipantsExceeded != nil {
		return encodeSSErrorMember(126, mapvalues.SourceRef{Document: "3GPP TS 24.080", Edition: "19.4.0", Clause: "4.3", Module: "SS-Errors", Assignment: "maxNumberOfMPTY-ParticipantsExceeded", SHA256: "b81d2a668e33702414eec4d9210bd4922f1104ccc4384cb6d8d3301ce8fa129e"}, value.MaxNumberOfMPTYParticipantsExceeded, mapvalues.ValueCodec[mapvalues.NoParameter]{}, opts...)
	}
	return mapvalues.SSErrorEncoding{}, fmt.Errorf("%w: no selected buildMPTY error", ber.ErrInvalidBinding)
}
func infoSSCallDeflectionOperation() mapvalues.SSOperationInfo {
	info, _ := mapvalues.LookupSSOperation(mapvalues.SSCallDeflection)
	return info
}

// SSCallDeflectionOperation binds the formal object in TS 24.080 V19.4.0 §4.2 (X.880 §§8.2–8.3).
func SSCallDeflectionOperation() SSOperation[mapvalues.CallDeflectionArg, mapvalues.NoParameter, mapvalues.SSCallDeflectionErrors] {
	return SSOperation[mapvalues.CallDeflectionArg, mapvalues.NoParameter, mapvalues.SSCallDeflectionErrors]{code: mapvalues.SSCallDeflection, info: infoSSCallDeflectionOperation, argument: CallDeflectionArgCodec(), result: mapvalues.ValueCodec[mapvalues.NoParameter]{}, decode: decodeSSCallDeflectionError, encode: encodeSSCallDeflectionError}
}
func decodeSSCallDeflectionError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (mapvalues.SSCallDeflectionErrors, error) {
	switch code {
	case 16:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERIllegalSSOperationParam](__asn1pkg_v21_map_er_datatypes.ERIllegalSSOperationParamCodec()), opts...)
		if err != nil {
			return mapvalues.SSCallDeflectionErrors{}, err
		}
		return mapvalues.SSCallDeflectionErrors{IllegalSSOperation: p}, nil
	case 17:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_ss_datatypes.BERValue[__asn1pkg_v21_map_ss_datatypes.SSSSStatus]](__asn1pkg_v21_map_ss_datatypes.SSSSStatusCodec()), opts...)
		if err != nil {
			return mapvalues.SSCallDeflectionErrors{}, err
		}
		return mapvalues.SSCallDeflectionErrors{SsErrorStatus: p}, nil
	case 18:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSSNotAvailableParam](__asn1pkg_v21_map_er_datatypes.ERSSNotAvailableParamCodec()), opts...)
		if err != nil {
			return mapvalues.SSCallDeflectionErrors{}, err
		}
		return mapvalues.SSCallDeflectionErrors{SsNotAvailable: p}, nil
	case 20:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSSIncompatibilityCause](__asn1pkg_v21_map_er_datatypes.ERSSIncompatibilityCauseCodec()), opts...)
		if err != nil {
			return mapvalues.SSCallDeflectionErrors{}, err
		}
		return mapvalues.SSCallDeflectionErrors{SsIncompatibility: p}, nil
	case 21:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParam](__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParamCodec()), opts...)
		if err != nil {
			return mapvalues.SSCallDeflectionErrors{}, err
		}
		return mapvalues.SSCallDeflectionErrors{FacilityNotSupported: p}, nil
	case 34:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam](__asn1pkg_v21_map_er_datatypes.ERSystemFailureParamCodec()), opts...)
		if err != nil {
			return mapvalues.SSCallDeflectionErrors{}, err
		}
		return mapvalues.SSCallDeflectionErrors{SystemFailure: p}, nil
	case 127:
		p, err := decodeErrorParameter(data, present, mapvalues.ValueCodec[mapvalues.NoParameter]{}, opts...)
		if err != nil {
			return mapvalues.SSCallDeflectionErrors{}, err
		}
		return mapvalues.SSCallDeflectionErrors{ResourcesNotAvailable: p}, nil
	case 14:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERForwardingViolationParam](__asn1pkg_v21_map_er_datatypes.ERForwardingViolationParamCodec()), opts...)
		if err != nil {
			return mapvalues.SSCallDeflectionErrors{}, err
		}
		return mapvalues.SSCallDeflectionErrors{ForwardingViolation: p}, nil
	case 13:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERCallBarredParam](__asn1pkg_v21_map_er_datatypes.ERCallBarredParamCodec()), opts...)
		if err != nil {
			return mapvalues.SSCallDeflectionErrors{}, err
		}
		return mapvalues.SSCallDeflectionErrors{CallBarred: p}, nil
	case 123:
		p, err := decodeErrorParameter(data, present, mapvalues.ValueCodec[mapvalues.NoParameter]{}, opts...)
		if err != nil {
			return mapvalues.SSCallDeflectionErrors{}, err
		}
		return mapvalues.SSCallDeflectionErrors{DeflectionToServedSubscriber: p}, nil
	case 125:
		p, err := decodeErrorParameter(data, present, mapvalues.ValueCodec[mapvalues.NoParameter]{}, opts...)
		if err != nil {
			return mapvalues.SSCallDeflectionErrors{}, err
		}
		return mapvalues.SSCallDeflectionErrors{InvalidDeflectedToNumber: p}, nil
	case 124:
		p, err := decodeErrorParameter(data, present, mapvalues.ValueCodec[mapvalues.NoParameter]{}, opts...)
		if err != nil {
			return mapvalues.SSCallDeflectionErrors{}, err
		}
		return mapvalues.SSCallDeflectionErrors{SpecialServiceCode: p}, nil
	case 47:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERForwardingFailedParam](__asn1pkg_v21_map_er_datatypes.ERForwardingFailedParamCodec()), opts...)
		if err != nil {
			return mapvalues.SSCallDeflectionErrors{}, err
		}
		return mapvalues.SSCallDeflectionErrors{ForwardingFailed: p}, nil
	default:
		return mapvalues.SSCallDeflectionErrors{}, fmt.Errorf("%w: error code %d is not in callDeflection ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeSSCallDeflectionError(value mapvalues.SSCallDeflectionErrors, opts ...ber.EncodeOption) (mapvalues.SSErrorEncoding, error) {
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
		return mapvalues.SSErrorEncoding{}, fmt.Errorf("%w: exactly one callDeflection error arm is required", ber.ErrInvalidBinding)
	}
	if value.IllegalSSOperation != nil {
		return encodeSSErrorMember(16, mapvalues.SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: "17.6.6", Module: "MAP-Errors", Assignment: "illegalSS-Operation", SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}, value.IllegalSSOperation, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERIllegalSSOperationParam](__asn1pkg_v21_map_er_datatypes.ERIllegalSSOperationParamCodec()), opts...)
	}
	if value.SsErrorStatus != nil {
		return encodeSSErrorMember(17, mapvalues.SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: "17.6.6", Module: "MAP-Errors", Assignment: "ss-ErrorStatus", SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}, value.SsErrorStatus, adaptValueCodec[__asn1pkg_v21_map_ss_datatypes.BERValue[__asn1pkg_v21_map_ss_datatypes.SSSSStatus]](__asn1pkg_v21_map_ss_datatypes.SSSSStatusCodec()), opts...)
	}
	if value.SsNotAvailable != nil {
		return encodeSSErrorMember(18, mapvalues.SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: "17.6.6", Module: "MAP-Errors", Assignment: "ss-NotAvailable", SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}, value.SsNotAvailable, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSSNotAvailableParam](__asn1pkg_v21_map_er_datatypes.ERSSNotAvailableParamCodec()), opts...)
	}
	if value.SsIncompatibility != nil {
		return encodeSSErrorMember(20, mapvalues.SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: "17.6.6", Module: "MAP-Errors", Assignment: "ss-Incompatibility", SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}, value.SsIncompatibility, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSSIncompatibilityCause](__asn1pkg_v21_map_er_datatypes.ERSSIncompatibilityCauseCodec()), opts...)
	}
	if value.FacilityNotSupported != nil {
		return encodeSSErrorMember(21, mapvalues.SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: "17.6.6", Module: "MAP-Errors", Assignment: "facilityNotSupported", SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}, value.FacilityNotSupported, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParam](__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParamCodec()), opts...)
	}
	if value.SystemFailure != nil {
		return encodeSSErrorMember(34, mapvalues.SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: "17.6.6", Module: "MAP-Errors", Assignment: "systemFailure", SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}, value.SystemFailure, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam](__asn1pkg_v21_map_er_datatypes.ERSystemFailureParamCodec()), opts...)
	}
	if value.ResourcesNotAvailable != nil {
		return encodeSSErrorMember(127, mapvalues.SourceRef{Document: "3GPP TS 24.080", Edition: "19.4.0", Clause: "4.3", Module: "SS-Errors", Assignment: "resourcesNotAvailable", SHA256: "b81d2a668e33702414eec4d9210bd4922f1104ccc4384cb6d8d3301ce8fa129e"}, value.ResourcesNotAvailable, mapvalues.ValueCodec[mapvalues.NoParameter]{}, opts...)
	}
	if value.ForwardingViolation != nil {
		return encodeSSErrorMember(14, mapvalues.SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: "17.6.6", Module: "MAP-Errors", Assignment: "forwardingViolation", SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}, value.ForwardingViolation, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERForwardingViolationParam](__asn1pkg_v21_map_er_datatypes.ERForwardingViolationParamCodec()), opts...)
	}
	if value.CallBarred != nil {
		return encodeSSErrorMember(13, mapvalues.SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: "17.6.6", Module: "MAP-Errors", Assignment: "callBarred", SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}, value.CallBarred, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERCallBarredParam](__asn1pkg_v21_map_er_datatypes.ERCallBarredParamCodec()), opts...)
	}
	if value.DeflectionToServedSubscriber != nil {
		return encodeSSErrorMember(123, mapvalues.SourceRef{Document: "3GPP TS 24.080", Edition: "19.4.0", Clause: "4.3", Module: "SS-Errors", Assignment: "deflectionToServedSubscriber", SHA256: "b81d2a668e33702414eec4d9210bd4922f1104ccc4384cb6d8d3301ce8fa129e"}, value.DeflectionToServedSubscriber, mapvalues.ValueCodec[mapvalues.NoParameter]{}, opts...)
	}
	if value.InvalidDeflectedToNumber != nil {
		return encodeSSErrorMember(125, mapvalues.SourceRef{Document: "3GPP TS 24.080", Edition: "19.4.0", Clause: "4.3", Module: "SS-Errors", Assignment: "invalidDeflectedToNumber", SHA256: "b81d2a668e33702414eec4d9210bd4922f1104ccc4384cb6d8d3301ce8fa129e"}, value.InvalidDeflectedToNumber, mapvalues.ValueCodec[mapvalues.NoParameter]{}, opts...)
	}
	if value.SpecialServiceCode != nil {
		return encodeSSErrorMember(124, mapvalues.SourceRef{Document: "3GPP TS 24.080", Edition: "19.4.0", Clause: "4.3", Module: "SS-Errors", Assignment: "specialServiceCode", SHA256: "b81d2a668e33702414eec4d9210bd4922f1104ccc4384cb6d8d3301ce8fa129e"}, value.SpecialServiceCode, mapvalues.ValueCodec[mapvalues.NoParameter]{}, opts...)
	}
	if value.ForwardingFailed != nil {
		return encodeSSErrorMember(47, mapvalues.SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: "17.6.6", Module: "MAP-Errors", Assignment: "forwardingFailed", SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}, value.ForwardingFailed, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERForwardingFailedParam](__asn1pkg_v21_map_er_datatypes.ERForwardingFailedParamCodec()), opts...)
	}
	return mapvalues.SSErrorEncoding{}, fmt.Errorf("%w: no selected callDeflection error", ber.ErrInvalidBinding)
}
func infoSSExplicitCTOperation() mapvalues.SSOperationInfo {
	info, _ := mapvalues.LookupSSOperation(mapvalues.SSExplicitCT)
	return info
}

// SSExplicitCTOperation binds the formal object in TS 24.080 V19.4.0 §4.2 (X.880 §§8.2–8.3).
func SSExplicitCTOperation() SSOperation[mapvalues.NoParameter, mapvalues.NoParameter, mapvalues.SSExplicitCTErrors] {
	return SSOperation[mapvalues.NoParameter, mapvalues.NoParameter, mapvalues.SSExplicitCTErrors]{code: mapvalues.SSExplicitCT, info: infoSSExplicitCTOperation, argument: mapvalues.ValueCodec[mapvalues.NoParameter]{}, result: mapvalues.ValueCodec[mapvalues.NoParameter]{}, decode: decodeSSExplicitCTError, encode: encodeSSExplicitCTError}
}
func decodeSSExplicitCTError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (mapvalues.SSExplicitCTErrors, error) {
	switch code {
	case 16:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERIllegalSSOperationParam](__asn1pkg_v21_map_er_datatypes.ERIllegalSSOperationParamCodec()), opts...)
		if err != nil {
			return mapvalues.SSExplicitCTErrors{}, err
		}
		return mapvalues.SSExplicitCTErrors{IllegalSSOperation: p}, nil
	case 17:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_ss_datatypes.BERValue[__asn1pkg_v21_map_ss_datatypes.SSSSStatus]](__asn1pkg_v21_map_ss_datatypes.SSSSStatusCodec()), opts...)
		if err != nil {
			return mapvalues.SSExplicitCTErrors{}, err
		}
		return mapvalues.SSExplicitCTErrors{SsErrorStatus: p}, nil
	case 18:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSSNotAvailableParam](__asn1pkg_v21_map_er_datatypes.ERSSNotAvailableParamCodec()), opts...)
		if err != nil {
			return mapvalues.SSExplicitCTErrors{}, err
		}
		return mapvalues.SSExplicitCTErrors{SsNotAvailable: p}, nil
	case 20:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSSIncompatibilityCause](__asn1pkg_v21_map_er_datatypes.ERSSIncompatibilityCauseCodec()), opts...)
		if err != nil {
			return mapvalues.SSExplicitCTErrors{}, err
		}
		return mapvalues.SSExplicitCTErrors{SsIncompatibility: p}, nil
	case 21:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParam](__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParamCodec()), opts...)
		if err != nil {
			return mapvalues.SSExplicitCTErrors{}, err
		}
		return mapvalues.SSExplicitCTErrors{FacilityNotSupported: p}, nil
	case 34:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam](__asn1pkg_v21_map_er_datatypes.ERSystemFailureParamCodec()), opts...)
		if err != nil {
			return mapvalues.SSExplicitCTErrors{}, err
		}
		return mapvalues.SSExplicitCTErrors{SystemFailure: p}, nil
	case 127:
		p, err := decodeErrorParameter(data, present, mapvalues.ValueCodec[mapvalues.NoParameter]{}, opts...)
		if err != nil {
			return mapvalues.SSExplicitCTErrors{}, err
		}
		return mapvalues.SSExplicitCTErrors{ResourcesNotAvailable: p}, nil
	case 13:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERCallBarredParam](__asn1pkg_v21_map_er_datatypes.ERCallBarredParamCodec()), opts...)
		if err != nil {
			return mapvalues.SSExplicitCTErrors{}, err
		}
		return mapvalues.SSExplicitCTErrors{CallBarred: p}, nil
	default:
		return mapvalues.SSExplicitCTErrors{}, fmt.Errorf("%w: error code %d is not in explicitCT ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeSSExplicitCTError(value mapvalues.SSExplicitCTErrors, opts ...ber.EncodeOption) (mapvalues.SSErrorEncoding, error) {
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
		return mapvalues.SSErrorEncoding{}, fmt.Errorf("%w: exactly one explicitCT error arm is required", ber.ErrInvalidBinding)
	}
	if value.IllegalSSOperation != nil {
		return encodeSSErrorMember(16, mapvalues.SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: "17.6.6", Module: "MAP-Errors", Assignment: "illegalSS-Operation", SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}, value.IllegalSSOperation, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERIllegalSSOperationParam](__asn1pkg_v21_map_er_datatypes.ERIllegalSSOperationParamCodec()), opts...)
	}
	if value.SsErrorStatus != nil {
		return encodeSSErrorMember(17, mapvalues.SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: "17.6.6", Module: "MAP-Errors", Assignment: "ss-ErrorStatus", SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}, value.SsErrorStatus, adaptValueCodec[__asn1pkg_v21_map_ss_datatypes.BERValue[__asn1pkg_v21_map_ss_datatypes.SSSSStatus]](__asn1pkg_v21_map_ss_datatypes.SSSSStatusCodec()), opts...)
	}
	if value.SsNotAvailable != nil {
		return encodeSSErrorMember(18, mapvalues.SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: "17.6.6", Module: "MAP-Errors", Assignment: "ss-NotAvailable", SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}, value.SsNotAvailable, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSSNotAvailableParam](__asn1pkg_v21_map_er_datatypes.ERSSNotAvailableParamCodec()), opts...)
	}
	if value.SsIncompatibility != nil {
		return encodeSSErrorMember(20, mapvalues.SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: "17.6.6", Module: "MAP-Errors", Assignment: "ss-Incompatibility", SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}, value.SsIncompatibility, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSSIncompatibilityCause](__asn1pkg_v21_map_er_datatypes.ERSSIncompatibilityCauseCodec()), opts...)
	}
	if value.FacilityNotSupported != nil {
		return encodeSSErrorMember(21, mapvalues.SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: "17.6.6", Module: "MAP-Errors", Assignment: "facilityNotSupported", SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}, value.FacilityNotSupported, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParam](__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParamCodec()), opts...)
	}
	if value.SystemFailure != nil {
		return encodeSSErrorMember(34, mapvalues.SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: "17.6.6", Module: "MAP-Errors", Assignment: "systemFailure", SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}, value.SystemFailure, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam](__asn1pkg_v21_map_er_datatypes.ERSystemFailureParamCodec()), opts...)
	}
	if value.ResourcesNotAvailable != nil {
		return encodeSSErrorMember(127, mapvalues.SourceRef{Document: "3GPP TS 24.080", Edition: "19.4.0", Clause: "4.3", Module: "SS-Errors", Assignment: "resourcesNotAvailable", SHA256: "b81d2a668e33702414eec4d9210bd4922f1104ccc4384cb6d8d3301ce8fa129e"}, value.ResourcesNotAvailable, mapvalues.ValueCodec[mapvalues.NoParameter]{}, opts...)
	}
	if value.CallBarred != nil {
		return encodeSSErrorMember(13, mapvalues.SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: "17.6.6", Module: "MAP-Errors", Assignment: "callBarred", SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}, value.CallBarred, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERCallBarredParam](__asn1pkg_v21_map_er_datatypes.ERCallBarredParamCodec()), opts...)
	}
	return mapvalues.SSErrorEncoding{}, fmt.Errorf("%w: no selected explicitCT error", ber.ErrInvalidBinding)
}
func infoSSForwardCUGInfoOperation() mapvalues.SSOperationInfo {
	info, _ := mapvalues.LookupSSOperation(mapvalues.SSForwardCUGInfo)
	return info
}

// SSForwardCUGInfoOperation binds the formal object in TS 24.080 V19.4.0 §4.2 (X.880 §§8.2–8.3).
func SSForwardCUGInfoOperation() SSOperation[mapvalues.ForwardCUGInfoArg, mapvalues.NoParameter, mapvalues.SSForwardCUGInfoErrors] {
	return SSOperation[mapvalues.ForwardCUGInfoArg, mapvalues.NoParameter, mapvalues.SSForwardCUGInfoErrors]{code: mapvalues.SSForwardCUGInfo, info: infoSSForwardCUGInfoOperation, argument: ForwardCUGInfoArgCodec(), result: mapvalues.ValueCodec[mapvalues.NoParameter]{}, decode: decodeSSForwardCUGInfoError, encode: encodeSSForwardCUGInfoError}
}
func decodeSSForwardCUGInfoError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (mapvalues.SSForwardCUGInfoErrors, error) {
	switch code {
	default:
		return mapvalues.SSForwardCUGInfoErrors{}, fmt.Errorf("%w: error code %d is not in forwardCUG-Info ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeSSForwardCUGInfoError(value mapvalues.SSForwardCUGInfoErrors, opts ...ber.EncodeOption) (mapvalues.SSErrorEncoding, error) {
	return mapvalues.SSErrorEncoding{}, fmt.Errorf("%w: no selected forwardCUG-Info error", ber.ErrInvalidBinding)
}
func infoSSForwardChargeAdviceOperation() mapvalues.SSOperationInfo {
	info, _ := mapvalues.LookupSSOperation(mapvalues.SSForwardChargeAdvice)
	return info
}

// SSForwardChargeAdviceOperation binds the formal object in TS 24.080 V19.4.0 §4.2 (X.880 §§8.2–8.3).
func SSForwardChargeAdviceOperation() SSOperation[mapvalues.ForwardChargeAdviceArg, mapvalues.NoParameter, mapvalues.SSForwardChargeAdviceErrors] {
	return SSOperation[mapvalues.ForwardChargeAdviceArg, mapvalues.NoParameter, mapvalues.SSForwardChargeAdviceErrors]{code: mapvalues.SSForwardChargeAdvice, info: infoSSForwardChargeAdviceOperation, argument: ForwardChargeAdviceArgCodec(), result: mapvalues.ValueCodec[mapvalues.NoParameter]{}, decode: decodeSSForwardChargeAdviceError, encode: encodeSSForwardChargeAdviceError}
}
func decodeSSForwardChargeAdviceError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (mapvalues.SSForwardChargeAdviceErrors, error) {
	switch code {
	default:
		return mapvalues.SSForwardChargeAdviceErrors{}, fmt.Errorf("%w: error code %d is not in forwardChargeAdvice ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeSSForwardChargeAdviceError(value mapvalues.SSForwardChargeAdviceErrors, opts ...ber.EncodeOption) (mapvalues.SSErrorEncoding, error) {
	return mapvalues.SSErrorEncoding{}, fmt.Errorf("%w: no selected forwardChargeAdvice error", ber.ErrInvalidBinding)
}
func infoSSHoldMPTYOperation() mapvalues.SSOperationInfo {
	info, _ := mapvalues.LookupSSOperation(mapvalues.SSHoldMPTY)
	return info
}

// SSHoldMPTYOperation binds the formal object in TS 24.080 V19.4.0 §4.2 (X.880 §§8.2–8.3).
func SSHoldMPTYOperation() SSOperation[mapvalues.NoParameter, mapvalues.NoParameter, mapvalues.SSHoldMPTYErrors] {
	return SSOperation[mapvalues.NoParameter, mapvalues.NoParameter, mapvalues.SSHoldMPTYErrors]{code: mapvalues.SSHoldMPTY, info: infoSSHoldMPTYOperation, argument: mapvalues.ValueCodec[mapvalues.NoParameter]{}, result: mapvalues.ValueCodec[mapvalues.NoParameter]{}, decode: decodeSSHoldMPTYError, encode: encodeSSHoldMPTYError}
}
func decodeSSHoldMPTYError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (mapvalues.SSHoldMPTYErrors, error) {
	switch code {
	case 16:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERIllegalSSOperationParam](__asn1pkg_v21_map_er_datatypes.ERIllegalSSOperationParamCodec()), opts...)
		if err != nil {
			return mapvalues.SSHoldMPTYErrors{}, err
		}
		return mapvalues.SSHoldMPTYErrors{IllegalSSOperation: p}, nil
	case 17:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_ss_datatypes.BERValue[__asn1pkg_v21_map_ss_datatypes.SSSSStatus]](__asn1pkg_v21_map_ss_datatypes.SSSSStatusCodec()), opts...)
		if err != nil {
			return mapvalues.SSHoldMPTYErrors{}, err
		}
		return mapvalues.SSHoldMPTYErrors{SsErrorStatus: p}, nil
	case 20:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSSIncompatibilityCause](__asn1pkg_v21_map_er_datatypes.ERSSIncompatibilityCauseCodec()), opts...)
		if err != nil {
			return mapvalues.SSHoldMPTYErrors{}, err
		}
		return mapvalues.SSHoldMPTYErrors{SsIncompatibility: p}, nil
	case 21:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParam](__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParamCodec()), opts...)
		if err != nil {
			return mapvalues.SSHoldMPTYErrors{}, err
		}
		return mapvalues.SSHoldMPTYErrors{FacilityNotSupported: p}, nil
	case 34:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam](__asn1pkg_v21_map_er_datatypes.ERSystemFailureParamCodec()), opts...)
		if err != nil {
			return mapvalues.SSHoldMPTYErrors{}, err
		}
		return mapvalues.SSHoldMPTYErrors{SystemFailure: p}, nil
	default:
		return mapvalues.SSHoldMPTYErrors{}, fmt.Errorf("%w: error code %d is not in holdMPTY ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeSSHoldMPTYError(value mapvalues.SSHoldMPTYErrors, opts ...ber.EncodeOption) (mapvalues.SSErrorEncoding, error) {
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
		return mapvalues.SSErrorEncoding{}, fmt.Errorf("%w: exactly one holdMPTY error arm is required", ber.ErrInvalidBinding)
	}
	if value.IllegalSSOperation != nil {
		return encodeSSErrorMember(16, mapvalues.SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: "17.6.6", Module: "MAP-Errors", Assignment: "illegalSS-Operation", SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}, value.IllegalSSOperation, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERIllegalSSOperationParam](__asn1pkg_v21_map_er_datatypes.ERIllegalSSOperationParamCodec()), opts...)
	}
	if value.SsErrorStatus != nil {
		return encodeSSErrorMember(17, mapvalues.SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: "17.6.6", Module: "MAP-Errors", Assignment: "ss-ErrorStatus", SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}, value.SsErrorStatus, adaptValueCodec[__asn1pkg_v21_map_ss_datatypes.BERValue[__asn1pkg_v21_map_ss_datatypes.SSSSStatus]](__asn1pkg_v21_map_ss_datatypes.SSSSStatusCodec()), opts...)
	}
	if value.SsIncompatibility != nil {
		return encodeSSErrorMember(20, mapvalues.SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: "17.6.6", Module: "MAP-Errors", Assignment: "ss-Incompatibility", SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}, value.SsIncompatibility, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSSIncompatibilityCause](__asn1pkg_v21_map_er_datatypes.ERSSIncompatibilityCauseCodec()), opts...)
	}
	if value.FacilityNotSupported != nil {
		return encodeSSErrorMember(21, mapvalues.SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: "17.6.6", Module: "MAP-Errors", Assignment: "facilityNotSupported", SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}, value.FacilityNotSupported, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParam](__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParamCodec()), opts...)
	}
	if value.SystemFailure != nil {
		return encodeSSErrorMember(34, mapvalues.SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: "17.6.6", Module: "MAP-Errors", Assignment: "systemFailure", SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}, value.SystemFailure, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam](__asn1pkg_v21_map_er_datatypes.ERSystemFailureParamCodec()), opts...)
	}
	return mapvalues.SSErrorEncoding{}, fmt.Errorf("%w: no selected holdMPTY error", ber.ErrInvalidBinding)
}
func infoSSLcsAreaEventCancellationOperation() mapvalues.SSOperationInfo {
	info, _ := mapvalues.LookupSSOperation(mapvalues.SSLcsAreaEventCancellation)
	return info
}

// SSLcsAreaEventCancellationOperation binds the formal object in TS 24.080 V19.4.0 §4.2 (X.880 §§8.2–8.3).
func SSLcsAreaEventCancellationOperation() SSOperation[mapvalues.LCSAreaEventCancellationArg, mapvalues.NoParameter, mapvalues.SSLcsAreaEventCancellationErrors] {
	return SSOperation[mapvalues.LCSAreaEventCancellationArg, mapvalues.NoParameter, mapvalues.SSLcsAreaEventCancellationErrors]{code: mapvalues.SSLcsAreaEventCancellation, info: infoSSLcsAreaEventCancellationOperation, argument: LCSAreaEventCancellationArgCodec(), result: mapvalues.ValueCodec[mapvalues.NoParameter]{}, decode: decodeSSLcsAreaEventCancellationError, encode: encodeSSLcsAreaEventCancellationError}
}
func decodeSSLcsAreaEventCancellationError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (mapvalues.SSLcsAreaEventCancellationErrors, error) {
	switch code {
	case 34:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam](__asn1pkg_v21_map_er_datatypes.ERSystemFailureParamCodec()), opts...)
		if err != nil {
			return mapvalues.SSLcsAreaEventCancellationErrors{}, err
		}
		return mapvalues.SSLcsAreaEventCancellationErrors{SystemFailure: p}, nil
	case 21:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParam](__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParamCodec()), opts...)
		if err != nil {
			return mapvalues.SSLcsAreaEventCancellationErrors{}, err
		}
		return mapvalues.SSLcsAreaEventCancellationErrors{FacilityNotSupported: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParam](__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParamCodec()), opts...)
		if err != nil {
			return mapvalues.SSLcsAreaEventCancellationErrors{}, err
		}
		return mapvalues.SSLcsAreaEventCancellationErrors{UnexpectedDataValue: p}, nil
	default:
		return mapvalues.SSLcsAreaEventCancellationErrors{}, fmt.Errorf("%w: error code %d is not in lcs-AreaEventCancellation ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeSSLcsAreaEventCancellationError(value mapvalues.SSLcsAreaEventCancellationErrors, opts ...ber.EncodeOption) (mapvalues.SSErrorEncoding, error) {
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
		return mapvalues.SSErrorEncoding{}, fmt.Errorf("%w: exactly one lcs-AreaEventCancellation error arm is required", ber.ErrInvalidBinding)
	}
	if value.SystemFailure != nil {
		return encodeSSErrorMember(34, mapvalues.SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: "17.6.6", Module: "MAP-Errors", Assignment: "systemFailure", SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}, value.SystemFailure, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam](__asn1pkg_v21_map_er_datatypes.ERSystemFailureParamCodec()), opts...)
	}
	if value.FacilityNotSupported != nil {
		return encodeSSErrorMember(21, mapvalues.SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: "17.6.6", Module: "MAP-Errors", Assignment: "facilityNotSupported", SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}, value.FacilityNotSupported, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParam](__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParamCodec()), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeSSErrorMember(36, mapvalues.SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: "17.6.6", Module: "MAP-Errors", Assignment: "unexpectedDataValue", SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}, value.UnexpectedDataValue, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParam](__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParamCodec()), opts...)
	}
	return mapvalues.SSErrorEncoding{}, fmt.Errorf("%w: no selected lcs-AreaEventCancellation error", ber.ErrInvalidBinding)
}
func infoSSLcsAreaEventReportOperation() mapvalues.SSOperationInfo {
	info, _ := mapvalues.LookupSSOperation(mapvalues.SSLcsAreaEventReport)
	return info
}

// SSLcsAreaEventReportOperation binds the formal object in TS 24.080 V19.4.0 §4.2 (X.880 §§8.2–8.3).
func SSLcsAreaEventReportOperation() SSOperation[mapvalues.LCSAreaEventReportArg, mapvalues.NoParameter, mapvalues.SSLcsAreaEventReportErrors] {
	return SSOperation[mapvalues.LCSAreaEventReportArg, mapvalues.NoParameter, mapvalues.SSLcsAreaEventReportErrors]{code: mapvalues.SSLcsAreaEventReport, info: infoSSLcsAreaEventReportOperation, argument: LCSAreaEventReportArgCodec(), result: mapvalues.ValueCodec[mapvalues.NoParameter]{}, decode: decodeSSLcsAreaEventReportError, encode: encodeSSLcsAreaEventReportError}
}
func decodeSSLcsAreaEventReportError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (mapvalues.SSLcsAreaEventReportErrors, error) {
	switch code {
	case 34:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam](__asn1pkg_v21_map_er_datatypes.ERSystemFailureParamCodec()), opts...)
		if err != nil {
			return mapvalues.SSLcsAreaEventReportErrors{}, err
		}
		return mapvalues.SSLcsAreaEventReportErrors{SystemFailure: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParam](__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParamCodec()), opts...)
		if err != nil {
			return mapvalues.SSLcsAreaEventReportErrors{}, err
		}
		return mapvalues.SSLcsAreaEventReportErrors{UnexpectedDataValue: p}, nil
	case 21:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParam](__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParamCodec()), opts...)
		if err != nil {
			return mapvalues.SSLcsAreaEventReportErrors{}, err
		}
		return mapvalues.SSLcsAreaEventReportErrors{FacilityNotSupported: p}, nil
	default:
		return mapvalues.SSLcsAreaEventReportErrors{}, fmt.Errorf("%w: error code %d is not in lcs-AreaEventReport ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeSSLcsAreaEventReportError(value mapvalues.SSLcsAreaEventReportErrors, opts ...ber.EncodeOption) (mapvalues.SSErrorEncoding, error) {
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
		return mapvalues.SSErrorEncoding{}, fmt.Errorf("%w: exactly one lcs-AreaEventReport error arm is required", ber.ErrInvalidBinding)
	}
	if value.SystemFailure != nil {
		return encodeSSErrorMember(34, mapvalues.SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: "17.6.6", Module: "MAP-Errors", Assignment: "systemFailure", SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}, value.SystemFailure, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam](__asn1pkg_v21_map_er_datatypes.ERSystemFailureParamCodec()), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeSSErrorMember(36, mapvalues.SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: "17.6.6", Module: "MAP-Errors", Assignment: "unexpectedDataValue", SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}, value.UnexpectedDataValue, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParam](__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParamCodec()), opts...)
	}
	if value.FacilityNotSupported != nil {
		return encodeSSErrorMember(21, mapvalues.SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: "17.6.6", Module: "MAP-Errors", Assignment: "facilityNotSupported", SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}, value.FacilityNotSupported, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParam](__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParamCodec()), opts...)
	}
	return mapvalues.SSErrorEncoding{}, fmt.Errorf("%w: no selected lcs-AreaEventReport error", ber.ErrInvalidBinding)
}
func infoSSLcsAreaEventRequestOperation() mapvalues.SSOperationInfo {
	info, _ := mapvalues.LookupSSOperation(mapvalues.SSLcsAreaEventRequest)
	return info
}

// SSLcsAreaEventRequestOperation binds the formal object in TS 24.080 V19.4.0 §4.2 (X.880 §§8.2–8.3).
func SSLcsAreaEventRequestOperation() SSOperation[mapvalues.LCSAreaEventRequestArg, mapvalues.NoParameter, mapvalues.SSLcsAreaEventRequestErrors] {
	return SSOperation[mapvalues.LCSAreaEventRequestArg, mapvalues.NoParameter, mapvalues.SSLcsAreaEventRequestErrors]{code: mapvalues.SSLcsAreaEventRequest, info: infoSSLcsAreaEventRequestOperation, argument: LCSAreaEventRequestArgCodec(), result: mapvalues.ValueCodec[mapvalues.NoParameter]{}, decode: decodeSSLcsAreaEventRequestError, encode: encodeSSLcsAreaEventRequestError}
}
func decodeSSLcsAreaEventRequestError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (mapvalues.SSLcsAreaEventRequestErrors, error) {
	switch code {
	case 34:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam](__asn1pkg_v21_map_er_datatypes.ERSystemFailureParamCodec()), opts...)
		if err != nil {
			return mapvalues.SSLcsAreaEventRequestErrors{}, err
		}
		return mapvalues.SSLcsAreaEventRequestErrors{SystemFailure: p}, nil
	case 21:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParam](__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParamCodec()), opts...)
		if err != nil {
			return mapvalues.SSLcsAreaEventRequestErrors{}, err
		}
		return mapvalues.SSLcsAreaEventRequestErrors{FacilityNotSupported: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParam](__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParamCodec()), opts...)
		if err != nil {
			return mapvalues.SSLcsAreaEventRequestErrors{}, err
		}
		return mapvalues.SSLcsAreaEventRequestErrors{UnexpectedDataValue: p}, nil
	default:
		return mapvalues.SSLcsAreaEventRequestErrors{}, fmt.Errorf("%w: error code %d is not in lcs-AreaEventRequest ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeSSLcsAreaEventRequestError(value mapvalues.SSLcsAreaEventRequestErrors, opts ...ber.EncodeOption) (mapvalues.SSErrorEncoding, error) {
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
		return mapvalues.SSErrorEncoding{}, fmt.Errorf("%w: exactly one lcs-AreaEventRequest error arm is required", ber.ErrInvalidBinding)
	}
	if value.SystemFailure != nil {
		return encodeSSErrorMember(34, mapvalues.SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: "17.6.6", Module: "MAP-Errors", Assignment: "systemFailure", SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}, value.SystemFailure, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam](__asn1pkg_v21_map_er_datatypes.ERSystemFailureParamCodec()), opts...)
	}
	if value.FacilityNotSupported != nil {
		return encodeSSErrorMember(21, mapvalues.SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: "17.6.6", Module: "MAP-Errors", Assignment: "facilityNotSupported", SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}, value.FacilityNotSupported, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParam](__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParamCodec()), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeSSErrorMember(36, mapvalues.SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: "17.6.6", Module: "MAP-Errors", Assignment: "unexpectedDataValue", SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}, value.UnexpectedDataValue, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParam](__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParamCodec()), opts...)
	}
	return mapvalues.SSErrorEncoding{}, fmt.Errorf("%w: no selected lcs-AreaEventRequest error", ber.ErrInvalidBinding)
}
func infoSSLcsCancelDeferredLocationOperation() mapvalues.SSOperationInfo {
	info, _ := mapvalues.LookupSSOperation(mapvalues.SSLcsCancelDeferredLocation)
	return info
}

// SSLcsCancelDeferredLocationOperation binds the formal object in TS 24.080 V19.4.0 §4.2 (X.880 §§8.2–8.3).
func SSLcsCancelDeferredLocationOperation() SSOperation[mapvalues.LCSCancelDeferredLocationArg, mapvalues.NoParameter, mapvalues.SSLcsCancelDeferredLocationErrors] {
	return SSOperation[mapvalues.LCSCancelDeferredLocationArg, mapvalues.NoParameter, mapvalues.SSLcsCancelDeferredLocationErrors]{code: mapvalues.SSLcsCancelDeferredLocation, info: infoSSLcsCancelDeferredLocationOperation, argument: LCSCancelDeferredLocationArgCodec(), result: mapvalues.ValueCodec[mapvalues.NoParameter]{}, decode: decodeSSLcsCancelDeferredLocationError, encode: encodeSSLcsCancelDeferredLocationError}
}
func decodeSSLcsCancelDeferredLocationError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (mapvalues.SSLcsCancelDeferredLocationErrors, error) {
	switch code {
	case 34:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam](__asn1pkg_v21_map_er_datatypes.ERSystemFailureParamCodec()), opts...)
		if err != nil {
			return mapvalues.SSLcsCancelDeferredLocationErrors{}, err
		}
		return mapvalues.SSLcsCancelDeferredLocationErrors{SystemFailure: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParam](__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParamCodec()), opts...)
		if err != nil {
			return mapvalues.SSLcsCancelDeferredLocationErrors{}, err
		}
		return mapvalues.SSLcsCancelDeferredLocationErrors{UnexpectedDataValue: p}, nil
	default:
		return mapvalues.SSLcsCancelDeferredLocationErrors{}, fmt.Errorf("%w: error code %d is not in lcs-CancelDeferredLocation ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeSSLcsCancelDeferredLocationError(value mapvalues.SSLcsCancelDeferredLocationErrors, opts ...ber.EncodeOption) (mapvalues.SSErrorEncoding, error) {
	selected := 0
	if value.SystemFailure != nil {
		selected++
	}
	if value.UnexpectedDataValue != nil {
		selected++
	}
	if selected != 1 {
		return mapvalues.SSErrorEncoding{}, fmt.Errorf("%w: exactly one lcs-CancelDeferredLocation error arm is required", ber.ErrInvalidBinding)
	}
	if value.SystemFailure != nil {
		return encodeSSErrorMember(34, mapvalues.SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: "17.6.6", Module: "MAP-Errors", Assignment: "systemFailure", SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}, value.SystemFailure, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam](__asn1pkg_v21_map_er_datatypes.ERSystemFailureParamCodec()), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeSSErrorMember(36, mapvalues.SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: "17.6.6", Module: "MAP-Errors", Assignment: "unexpectedDataValue", SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}, value.UnexpectedDataValue, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParam](__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParamCodec()), opts...)
	}
	return mapvalues.SSErrorEncoding{}, fmt.Errorf("%w: no selected lcs-CancelDeferredLocation error", ber.ErrInvalidBinding)
}
func infoSSLcsDLRSPPTransportOperation() mapvalues.SSOperationInfo {
	info, _ := mapvalues.LookupSSOperation(mapvalues.SSLcsDLRSPPTransport)
	return info
}

// SSLcsDLRSPPTransportOperation binds the formal object in TS 24.080 V19.4.0 §4.2 (X.880 §§8.2–8.3).
func SSLcsDLRSPPTransportOperation() SSOperation[mapvalues.LCSDLRSPPTransportArg, mapvalues.LCSDLRSPPTransportRes, mapvalues.SSLcsDLRSPPTransportErrors] {
	return SSOperation[mapvalues.LCSDLRSPPTransportArg, mapvalues.LCSDLRSPPTransportRes, mapvalues.SSLcsDLRSPPTransportErrors]{code: mapvalues.SSLcsDLRSPPTransport, info: infoSSLcsDLRSPPTransportOperation, argument: LCSDLRSPPTransportArgCodec(), result: LCSDLRSPPTransportResCodec(), decode: decodeSSLcsDLRSPPTransportError, encode: encodeSSLcsDLRSPPTransportError}
}
func decodeSSLcsDLRSPPTransportError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (mapvalues.SSLcsDLRSPPTransportErrors, error) {
	switch code {
	case 34:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam](__asn1pkg_v21_map_er_datatypes.ERSystemFailureParamCodec()), opts...)
		if err != nil {
			return mapvalues.SSLcsDLRSPPTransportErrors{}, err
		}
		return mapvalues.SSLcsDLRSPPTransportErrors{SystemFailure: p}, nil
	case 21:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParam](__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParamCodec()), opts...)
		if err != nil {
			return mapvalues.SSLcsDLRSPPTransportErrors{}, err
		}
		return mapvalues.SSLcsDLRSPPTransportErrors{FacilityNotSupported: p}, nil
	default:
		return mapvalues.SSLcsDLRSPPTransportErrors{}, fmt.Errorf("%w: error code %d is not in lcs-DLRSPPTransport ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeSSLcsDLRSPPTransportError(value mapvalues.SSLcsDLRSPPTransportErrors, opts ...ber.EncodeOption) (mapvalues.SSErrorEncoding, error) {
	selected := 0
	if value.SystemFailure != nil {
		selected++
	}
	if value.FacilityNotSupported != nil {
		selected++
	}
	if selected != 1 {
		return mapvalues.SSErrorEncoding{}, fmt.Errorf("%w: exactly one lcs-DLRSPPTransport error arm is required", ber.ErrInvalidBinding)
	}
	if value.SystemFailure != nil {
		return encodeSSErrorMember(34, mapvalues.SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: "17.6.6", Module: "MAP-Errors", Assignment: "systemFailure", SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}, value.SystemFailure, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam](__asn1pkg_v21_map_er_datatypes.ERSystemFailureParamCodec()), opts...)
	}
	if value.FacilityNotSupported != nil {
		return encodeSSErrorMember(21, mapvalues.SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: "17.6.6", Module: "MAP-Errors", Assignment: "facilityNotSupported", SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}, value.FacilityNotSupported, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParam](__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParamCodec()), opts...)
	}
	return mapvalues.SSErrorEncoding{}, fmt.Errorf("%w: no selected lcs-DLRSPPTransport error", ber.ErrInvalidBinding)
}
func infoSSLcsEventReportOperation() mapvalues.SSOperationInfo {
	info, _ := mapvalues.LookupSSOperation(mapvalues.SSLcsEventReport)
	return info
}

// SSLcsEventReportOperation binds the formal object in TS 24.080 V19.4.0 §4.2 (X.880 §§8.2–8.3).
func SSLcsEventReportOperation() SSOperation[mapvalues.LCSEventReportArg, mapvalues.LCSEventReportRes, mapvalues.SSLcsEventReportErrors] {
	return SSOperation[mapvalues.LCSEventReportArg, mapvalues.LCSEventReportRes, mapvalues.SSLcsEventReportErrors]{code: mapvalues.SSLcsEventReport, info: infoSSLcsEventReportOperation, argument: LCSEventReportArgCodec(), result: LCSEventReportResCodec(), decode: decodeSSLcsEventReportError, encode: encodeSSLcsEventReportError}
}
func decodeSSLcsEventReportError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (mapvalues.SSLcsEventReportErrors, error) {
	switch code {
	case 34:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam](__asn1pkg_v21_map_er_datatypes.ERSystemFailureParamCodec()), opts...)
		if err != nil {
			return mapvalues.SSLcsEventReportErrors{}, err
		}
		return mapvalues.SSLcsEventReportErrors{SystemFailure: p}, nil
	case 21:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParam](__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParamCodec()), opts...)
		if err != nil {
			return mapvalues.SSLcsEventReportErrors{}, err
		}
		return mapvalues.SSLcsEventReportErrors{FacilityNotSupported: p}, nil
	case 19:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSSSubscriptionViolationParam](__asn1pkg_v21_map_er_datatypes.ERSSSubscriptionViolationParamCodec()), opts...)
		if err != nil {
			return mapvalues.SSLcsEventReportErrors{}, err
		}
		return mapvalues.SSLcsEventReportErrors{SsSubscriptionViolation: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParam](__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParamCodec()), opts...)
		if err != nil {
			return mapvalues.SSLcsEventReportErrors{}, err
		}
		return mapvalues.SSLcsEventReportErrors{UnexpectedDataValue: p}, nil
	case 35:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERDataMissingParam](__asn1pkg_v21_map_er_datatypes.ERDataMissingParamCodec()), opts...)
		if err != nil {
			return mapvalues.SSLcsEventReportErrors{}, err
		}
		return mapvalues.SSLcsEventReportErrors{DataMissing: p}, nil
	case 51:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERResourceLimitationParam](__asn1pkg_v21_map_er_datatypes.ERResourceLimitationParamCodec()), opts...)
		if err != nil {
			return mapvalues.SSLcsEventReportErrors{}, err
		}
		return mapvalues.SSLcsEventReportErrors{ResourceLimitation: p}, nil
	default:
		return mapvalues.SSLcsEventReportErrors{}, fmt.Errorf("%w: error code %d is not in lcs-EventReport ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeSSLcsEventReportError(value mapvalues.SSLcsEventReportErrors, opts ...ber.EncodeOption) (mapvalues.SSErrorEncoding, error) {
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
		return mapvalues.SSErrorEncoding{}, fmt.Errorf("%w: exactly one lcs-EventReport error arm is required", ber.ErrInvalidBinding)
	}
	if value.SystemFailure != nil {
		return encodeSSErrorMember(34, mapvalues.SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: "17.6.6", Module: "MAP-Errors", Assignment: "systemFailure", SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}, value.SystemFailure, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam](__asn1pkg_v21_map_er_datatypes.ERSystemFailureParamCodec()), opts...)
	}
	if value.FacilityNotSupported != nil {
		return encodeSSErrorMember(21, mapvalues.SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: "17.6.6", Module: "MAP-Errors", Assignment: "facilityNotSupported", SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}, value.FacilityNotSupported, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParam](__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParamCodec()), opts...)
	}
	if value.SsSubscriptionViolation != nil {
		return encodeSSErrorMember(19, mapvalues.SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: "17.6.6", Module: "MAP-Errors", Assignment: "ss-SubscriptionViolation", SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}, value.SsSubscriptionViolation, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSSSubscriptionViolationParam](__asn1pkg_v21_map_er_datatypes.ERSSSubscriptionViolationParamCodec()), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeSSErrorMember(36, mapvalues.SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: "17.6.6", Module: "MAP-Errors", Assignment: "unexpectedDataValue", SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}, value.UnexpectedDataValue, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParam](__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParamCodec()), opts...)
	}
	if value.DataMissing != nil {
		return encodeSSErrorMember(35, mapvalues.SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: "17.6.6", Module: "MAP-Errors", Assignment: "dataMissing", SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}, value.DataMissing, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERDataMissingParam](__asn1pkg_v21_map_er_datatypes.ERDataMissingParamCodec()), opts...)
	}
	if value.ResourceLimitation != nil {
		return encodeSSErrorMember(51, mapvalues.SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: "17.6.6", Module: "MAP-Errors", Assignment: "resourceLimitation", SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}, value.ResourceLimitation, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERResourceLimitationParam](__asn1pkg_v21_map_er_datatypes.ERResourceLimitationParamCodec()), opts...)
	}
	return mapvalues.SSErrorEncoding{}, fmt.Errorf("%w: no selected lcs-EventReport error", ber.ErrInvalidBinding)
}
func infoSSLcsLocationNotificationOperation() mapvalues.SSOperationInfo {
	info, _ := mapvalues.LookupSSOperation(mapvalues.SSLcsLocationNotification)
	return info
}

// SSLcsLocationNotificationOperation binds the formal object in TS 24.080 V19.4.0 §4.2 (X.880 §§8.2–8.3).
func SSLcsLocationNotificationOperation() SSOperation[mapvalues.LocationNotificationArg, mapvalues.LocationNotificationRes, mapvalues.SSLcsLocationNotificationErrors] {
	return SSOperation[mapvalues.LocationNotificationArg, mapvalues.LocationNotificationRes, mapvalues.SSLcsLocationNotificationErrors]{code: mapvalues.SSLcsLocationNotification, info: infoSSLcsLocationNotificationOperation, argument: LocationNotificationArgCodec(), result: LocationNotificationResCodec(), decode: decodeSSLcsLocationNotificationError, encode: encodeSSLcsLocationNotificationError}
}
func decodeSSLcsLocationNotificationError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (mapvalues.SSLcsLocationNotificationErrors, error) {
	switch code {
	case 34:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam](__asn1pkg_v21_map_er_datatypes.ERSystemFailureParamCodec()), opts...)
		if err != nil {
			return mapvalues.SSLcsLocationNotificationErrors{}, err
		}
		return mapvalues.SSLcsLocationNotificationErrors{SystemFailure: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParam](__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParamCodec()), opts...)
		if err != nil {
			return mapvalues.SSLcsLocationNotificationErrors{}, err
		}
		return mapvalues.SSLcsLocationNotificationErrors{UnexpectedDataValue: p}, nil
	default:
		return mapvalues.SSLcsLocationNotificationErrors{}, fmt.Errorf("%w: error code %d is not in lcs-LocationNotification ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeSSLcsLocationNotificationError(value mapvalues.SSLcsLocationNotificationErrors, opts ...ber.EncodeOption) (mapvalues.SSErrorEncoding, error) {
	selected := 0
	if value.SystemFailure != nil {
		selected++
	}
	if value.UnexpectedDataValue != nil {
		selected++
	}
	if selected != 1 {
		return mapvalues.SSErrorEncoding{}, fmt.Errorf("%w: exactly one lcs-LocationNotification error arm is required", ber.ErrInvalidBinding)
	}
	if value.SystemFailure != nil {
		return encodeSSErrorMember(34, mapvalues.SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: "17.6.6", Module: "MAP-Errors", Assignment: "systemFailure", SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}, value.SystemFailure, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam](__asn1pkg_v21_map_er_datatypes.ERSystemFailureParamCodec()), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeSSErrorMember(36, mapvalues.SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: "17.6.6", Module: "MAP-Errors", Assignment: "unexpectedDataValue", SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}, value.UnexpectedDataValue, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParam](__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParamCodec()), opts...)
	}
	return mapvalues.SSErrorEncoding{}, fmt.Errorf("%w: no selected lcs-LocationNotification error", ber.ErrInvalidBinding)
}
func infoSSLcsLocationPrivacySettingOperation() mapvalues.SSOperationInfo {
	info, _ := mapvalues.LookupSSOperation(mapvalues.SSLcsLocationPrivacySetting)
	return info
}

// SSLcsLocationPrivacySettingOperation binds the formal object in TS 24.080 V19.4.0 §4.2 (X.880 §§8.2–8.3).
func SSLcsLocationPrivacySettingOperation() SSOperation[mapvalues.LCSLocationPrivacySettingArg, mapvalues.NoParameter, mapvalues.SSLcsLocationPrivacySettingErrors] {
	return SSOperation[mapvalues.LCSLocationPrivacySettingArg, mapvalues.NoParameter, mapvalues.SSLcsLocationPrivacySettingErrors]{code: mapvalues.SSLcsLocationPrivacySetting, info: infoSSLcsLocationPrivacySettingOperation, argument: LCSLocationPrivacySettingArgCodec(), result: mapvalues.ValueCodec[mapvalues.NoParameter]{}, decode: decodeSSLcsLocationPrivacySettingError, encode: encodeSSLcsLocationPrivacySettingError}
}
func decodeSSLcsLocationPrivacySettingError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (mapvalues.SSLcsLocationPrivacySettingErrors, error) {
	switch code {
	case 34:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam](__asn1pkg_v21_map_er_datatypes.ERSystemFailureParamCodec()), opts...)
		if err != nil {
			return mapvalues.SSLcsLocationPrivacySettingErrors{}, err
		}
		return mapvalues.SSLcsLocationPrivacySettingErrors{SystemFailure: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParam](__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParamCodec()), opts...)
		if err != nil {
			return mapvalues.SSLcsLocationPrivacySettingErrors{}, err
		}
		return mapvalues.SSLcsLocationPrivacySettingErrors{UnexpectedDataValue: p}, nil
	default:
		return mapvalues.SSLcsLocationPrivacySettingErrors{}, fmt.Errorf("%w: error code %d is not in lcs-LocationPrivacySetting ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeSSLcsLocationPrivacySettingError(value mapvalues.SSLcsLocationPrivacySettingErrors, opts ...ber.EncodeOption) (mapvalues.SSErrorEncoding, error) {
	selected := 0
	if value.SystemFailure != nil {
		selected++
	}
	if value.UnexpectedDataValue != nil {
		selected++
	}
	if selected != 1 {
		return mapvalues.SSErrorEncoding{}, fmt.Errorf("%w: exactly one lcs-LocationPrivacySetting error arm is required", ber.ErrInvalidBinding)
	}
	if value.SystemFailure != nil {
		return encodeSSErrorMember(34, mapvalues.SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: "17.6.6", Module: "MAP-Errors", Assignment: "systemFailure", SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}, value.SystemFailure, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam](__asn1pkg_v21_map_er_datatypes.ERSystemFailureParamCodec()), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeSSErrorMember(36, mapvalues.SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: "17.6.6", Module: "MAP-Errors", Assignment: "unexpectedDataValue", SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}, value.UnexpectedDataValue, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParam](__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParamCodec()), opts...)
	}
	return mapvalues.SSErrorEncoding{}, fmt.Errorf("%w: no selected lcs-LocationPrivacySetting error", ber.ErrInvalidBinding)
}
func infoSSLcsLocationUpdateOperation() mapvalues.SSOperationInfo {
	info, _ := mapvalues.LookupSSOperation(mapvalues.SSLcsLocationUpdate)
	return info
}

// SSLcsLocationUpdateOperation binds the formal object in TS 24.080 V19.4.0 §4.2 (X.880 §§8.2–8.3).
func SSLcsLocationUpdateOperation() SSOperation[mapvalues.LCSLocationUpdateArg, mapvalues.LCSLocationUpdateRes, mapvalues.SSLcsLocationUpdateErrors] {
	return SSOperation[mapvalues.LCSLocationUpdateArg, mapvalues.LCSLocationUpdateRes, mapvalues.SSLcsLocationUpdateErrors]{code: mapvalues.SSLcsLocationUpdate, info: infoSSLcsLocationUpdateOperation, argument: LCSLocationUpdateArgCodec(), result: LCSLocationUpdateResCodec(), decode: decodeSSLcsLocationUpdateError, encode: encodeSSLcsLocationUpdateError}
}
func decodeSSLcsLocationUpdateError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (mapvalues.SSLcsLocationUpdateErrors, error) {
	switch code {
	case 34:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam](__asn1pkg_v21_map_er_datatypes.ERSystemFailureParamCodec()), opts...)
		if err != nil {
			return mapvalues.SSLcsLocationUpdateErrors{}, err
		}
		return mapvalues.SSLcsLocationUpdateErrors{SystemFailure: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParam](__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParamCodec()), opts...)
		if err != nil {
			return mapvalues.SSLcsLocationUpdateErrors{}, err
		}
		return mapvalues.SSLcsLocationUpdateErrors{UnexpectedDataValue: p}, nil
	default:
		return mapvalues.SSLcsLocationUpdateErrors{}, fmt.Errorf("%w: error code %d is not in lcs-LocationUpdate ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeSSLcsLocationUpdateError(value mapvalues.SSLcsLocationUpdateErrors, opts ...ber.EncodeOption) (mapvalues.SSErrorEncoding, error) {
	selected := 0
	if value.SystemFailure != nil {
		selected++
	}
	if value.UnexpectedDataValue != nil {
		selected++
	}
	if selected != 1 {
		return mapvalues.SSErrorEncoding{}, fmt.Errorf("%w: exactly one lcs-LocationUpdate error arm is required", ber.ErrInvalidBinding)
	}
	if value.SystemFailure != nil {
		return encodeSSErrorMember(34, mapvalues.SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: "17.6.6", Module: "MAP-Errors", Assignment: "systemFailure", SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}, value.SystemFailure, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam](__asn1pkg_v21_map_er_datatypes.ERSystemFailureParamCodec()), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeSSErrorMember(36, mapvalues.SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: "17.6.6", Module: "MAP-Errors", Assignment: "unexpectedDataValue", SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}, value.UnexpectedDataValue, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParam](__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParamCodec()), opts...)
	}
	return mapvalues.SSErrorEncoding{}, fmt.Errorf("%w: no selected lcs-LocationUpdate error", ber.ErrInvalidBinding)
}
func infoSSLcsMOLROperation() mapvalues.SSOperationInfo {
	info, _ := mapvalues.LookupSSOperation(mapvalues.SSLcsMOLR)
	return info
}

// SSLcsMOLROperation binds the formal object in TS 24.080 V19.4.0 §4.2 (X.880 §§8.2–8.3).
func SSLcsMOLROperation() SSOperation[mapvalues.LCSMOLRArg, mapvalues.LCSMOLRRes, mapvalues.SSLcsMOLRErrors] {
	return SSOperation[mapvalues.LCSMOLRArg, mapvalues.LCSMOLRRes, mapvalues.SSLcsMOLRErrors]{code: mapvalues.SSLcsMOLR, info: infoSSLcsMOLROperation, argument: LCSMOLRArgCodec(), result: LCSMOLRResCodec(), decode: decodeSSLcsMOLRError, encode: encodeSSLcsMOLRError}
}
func decodeSSLcsMOLRError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (mapvalues.SSLcsMOLRErrors, error) {
	switch code {
	case 34:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam](__asn1pkg_v21_map_er_datatypes.ERSystemFailureParamCodec()), opts...)
		if err != nil {
			return mapvalues.SSLcsMOLRErrors{}, err
		}
		return mapvalues.SSLcsMOLRErrors{SystemFailure: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParam](__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParamCodec()), opts...)
		if err != nil {
			return mapvalues.SSLcsMOLRErrors{}, err
		}
		return mapvalues.SSLcsMOLRErrors{UnexpectedDataValue: p}, nil
	case 35:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERDataMissingParam](__asn1pkg_v21_map_er_datatypes.ERDataMissingParamCodec()), opts...)
		if err != nil {
			return mapvalues.SSLcsMOLRErrors{}, err
		}
		return mapvalues.SSLcsMOLRErrors{DataMissing: p}, nil
	case 21:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParam](__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParamCodec()), opts...)
		if err != nil {
			return mapvalues.SSLcsMOLRErrors{}, err
		}
		return mapvalues.SSLcsMOLRErrors{FacilityNotSupported: p}, nil
	case 19:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSSSubscriptionViolationParam](__asn1pkg_v21_map_er_datatypes.ERSSSubscriptionViolationParamCodec()), opts...)
		if err != nil {
			return mapvalues.SSLcsMOLRErrors{}, err
		}
		return mapvalues.SSLcsMOLRErrors{SsSubscriptionViolation: p}, nil
	case 54:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERPositionMethodFailureParam](__asn1pkg_v21_map_er_datatypes.ERPositionMethodFailureParamCodec()), opts...)
		if err != nil {
			return mapvalues.SSLcsMOLRErrors{}, err
		}
		return mapvalues.SSLcsMOLRErrors{PositionMethodFailure: p}, nil
	default:
		return mapvalues.SSLcsMOLRErrors{}, fmt.Errorf("%w: error code %d is not in lcs-MOLR ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeSSLcsMOLRError(value mapvalues.SSLcsMOLRErrors, opts ...ber.EncodeOption) (mapvalues.SSErrorEncoding, error) {
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
		return mapvalues.SSErrorEncoding{}, fmt.Errorf("%w: exactly one lcs-MOLR error arm is required", ber.ErrInvalidBinding)
	}
	if value.SystemFailure != nil {
		return encodeSSErrorMember(34, mapvalues.SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: "17.6.6", Module: "MAP-Errors", Assignment: "systemFailure", SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}, value.SystemFailure, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam](__asn1pkg_v21_map_er_datatypes.ERSystemFailureParamCodec()), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeSSErrorMember(36, mapvalues.SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: "17.6.6", Module: "MAP-Errors", Assignment: "unexpectedDataValue", SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}, value.UnexpectedDataValue, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParam](__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParamCodec()), opts...)
	}
	if value.DataMissing != nil {
		return encodeSSErrorMember(35, mapvalues.SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: "17.6.6", Module: "MAP-Errors", Assignment: "dataMissing", SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}, value.DataMissing, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERDataMissingParam](__asn1pkg_v21_map_er_datatypes.ERDataMissingParamCodec()), opts...)
	}
	if value.FacilityNotSupported != nil {
		return encodeSSErrorMember(21, mapvalues.SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: "17.6.6", Module: "MAP-Errors", Assignment: "facilityNotSupported", SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}, value.FacilityNotSupported, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParam](__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParamCodec()), opts...)
	}
	if value.SsSubscriptionViolation != nil {
		return encodeSSErrorMember(19, mapvalues.SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: "17.6.6", Module: "MAP-Errors", Assignment: "ss-SubscriptionViolation", SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}, value.SsSubscriptionViolation, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSSSubscriptionViolationParam](__asn1pkg_v21_map_er_datatypes.ERSSSubscriptionViolationParamCodec()), opts...)
	}
	if value.PositionMethodFailure != nil {
		return encodeSSErrorMember(54, mapvalues.SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: "17.6.6", Module: "MAP-Errors", Assignment: "positionMethodFailure", SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}, value.PositionMethodFailure, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERPositionMethodFailureParam](__asn1pkg_v21_map_er_datatypes.ERPositionMethodFailureParamCodec()), opts...)
	}
	return mapvalues.SSErrorEncoding{}, fmt.Errorf("%w: no selected lcs-MOLR error", ber.ErrInvalidBinding)
}
func infoSSLcsMSCancelDeferredLocationOperation() mapvalues.SSOperationInfo {
	info, _ := mapvalues.LookupSSOperation(mapvalues.SSLcsMSCancelDeferredLocation)
	return info
}

// SSLcsMSCancelDeferredLocationOperation binds the formal object in TS 24.080 V19.4.0 §4.2 (X.880 §§8.2–8.3).
func SSLcsMSCancelDeferredLocationOperation() SSOperation[mapvalues.LCSCancelDeferredLocationArg, mapvalues.NoParameter, mapvalues.SSLcsMSCancelDeferredLocationErrors] {
	return SSOperation[mapvalues.LCSCancelDeferredLocationArg, mapvalues.NoParameter, mapvalues.SSLcsMSCancelDeferredLocationErrors]{code: mapvalues.SSLcsMSCancelDeferredLocation, info: infoSSLcsMSCancelDeferredLocationOperation, argument: LCSCancelDeferredLocationArgCodec(), result: mapvalues.ValueCodec[mapvalues.NoParameter]{}, decode: decodeSSLcsMSCancelDeferredLocationError, encode: encodeSSLcsMSCancelDeferredLocationError}
}
func decodeSSLcsMSCancelDeferredLocationError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (mapvalues.SSLcsMSCancelDeferredLocationErrors, error) {
	switch code {
	case 34:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam](__asn1pkg_v21_map_er_datatypes.ERSystemFailureParamCodec()), opts...)
		if err != nil {
			return mapvalues.SSLcsMSCancelDeferredLocationErrors{}, err
		}
		return mapvalues.SSLcsMSCancelDeferredLocationErrors{SystemFailure: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParam](__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParamCodec()), opts...)
		if err != nil {
			return mapvalues.SSLcsMSCancelDeferredLocationErrors{}, err
		}
		return mapvalues.SSLcsMSCancelDeferredLocationErrors{UnexpectedDataValue: p}, nil
	default:
		return mapvalues.SSLcsMSCancelDeferredLocationErrors{}, fmt.Errorf("%w: error code %d is not in lcs-MSCancelDeferredLocation ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeSSLcsMSCancelDeferredLocationError(value mapvalues.SSLcsMSCancelDeferredLocationErrors, opts ...ber.EncodeOption) (mapvalues.SSErrorEncoding, error) {
	selected := 0
	if value.SystemFailure != nil {
		selected++
	}
	if value.UnexpectedDataValue != nil {
		selected++
	}
	if selected != 1 {
		return mapvalues.SSErrorEncoding{}, fmt.Errorf("%w: exactly one lcs-MSCancelDeferredLocation error arm is required", ber.ErrInvalidBinding)
	}
	if value.SystemFailure != nil {
		return encodeSSErrorMember(34, mapvalues.SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: "17.6.6", Module: "MAP-Errors", Assignment: "systemFailure", SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}, value.SystemFailure, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam](__asn1pkg_v21_map_er_datatypes.ERSystemFailureParamCodec()), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeSSErrorMember(36, mapvalues.SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: "17.6.6", Module: "MAP-Errors", Assignment: "unexpectedDataValue", SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}, value.UnexpectedDataValue, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParam](__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParamCodec()), opts...)
	}
	return mapvalues.SSErrorEncoding{}, fmt.Errorf("%w: no selected lcs-MSCancelDeferredLocation error", ber.ErrInvalidBinding)
}
func infoSSLcsPeriodicLocationCancellationOperation() mapvalues.SSOperationInfo {
	info, _ := mapvalues.LookupSSOperation(mapvalues.SSLcsPeriodicLocationCancellation)
	return info
}

// SSLcsPeriodicLocationCancellationOperation binds the formal object in TS 24.080 V19.4.0 §4.2 (X.880 §§8.2–8.3).
func SSLcsPeriodicLocationCancellationOperation() SSOperation[mapvalues.LCSPeriodicLocationCancellationArg, mapvalues.NoParameter, mapvalues.SSLcsPeriodicLocationCancellationErrors] {
	return SSOperation[mapvalues.LCSPeriodicLocationCancellationArg, mapvalues.NoParameter, mapvalues.SSLcsPeriodicLocationCancellationErrors]{code: mapvalues.SSLcsPeriodicLocationCancellation, info: infoSSLcsPeriodicLocationCancellationOperation, argument: LCSPeriodicLocationCancellationArgCodec(), result: mapvalues.ValueCodec[mapvalues.NoParameter]{}, decode: decodeSSLcsPeriodicLocationCancellationError, encode: encodeSSLcsPeriodicLocationCancellationError}
}
func decodeSSLcsPeriodicLocationCancellationError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (mapvalues.SSLcsPeriodicLocationCancellationErrors, error) {
	switch code {
	case 34:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam](__asn1pkg_v21_map_er_datatypes.ERSystemFailureParamCodec()), opts...)
		if err != nil {
			return mapvalues.SSLcsPeriodicLocationCancellationErrors{}, err
		}
		return mapvalues.SSLcsPeriodicLocationCancellationErrors{SystemFailure: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParam](__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParamCodec()), opts...)
		if err != nil {
			return mapvalues.SSLcsPeriodicLocationCancellationErrors{}, err
		}
		return mapvalues.SSLcsPeriodicLocationCancellationErrors{UnexpectedDataValue: p}, nil
	default:
		return mapvalues.SSLcsPeriodicLocationCancellationErrors{}, fmt.Errorf("%w: error code %d is not in lcs-PeriodicLocationCancellation ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeSSLcsPeriodicLocationCancellationError(value mapvalues.SSLcsPeriodicLocationCancellationErrors, opts ...ber.EncodeOption) (mapvalues.SSErrorEncoding, error) {
	selected := 0
	if value.SystemFailure != nil {
		selected++
	}
	if value.UnexpectedDataValue != nil {
		selected++
	}
	if selected != 1 {
		return mapvalues.SSErrorEncoding{}, fmt.Errorf("%w: exactly one lcs-PeriodicLocationCancellation error arm is required", ber.ErrInvalidBinding)
	}
	if value.SystemFailure != nil {
		return encodeSSErrorMember(34, mapvalues.SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: "17.6.6", Module: "MAP-Errors", Assignment: "systemFailure", SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}, value.SystemFailure, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam](__asn1pkg_v21_map_er_datatypes.ERSystemFailureParamCodec()), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeSSErrorMember(36, mapvalues.SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: "17.6.6", Module: "MAP-Errors", Assignment: "unexpectedDataValue", SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}, value.UnexpectedDataValue, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParam](__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParamCodec()), opts...)
	}
	return mapvalues.SSErrorEncoding{}, fmt.Errorf("%w: no selected lcs-PeriodicLocationCancellation error", ber.ErrInvalidBinding)
}
func infoSSLcsPeriodicLocationRequestOperation() mapvalues.SSOperationInfo {
	info, _ := mapvalues.LookupSSOperation(mapvalues.SSLcsPeriodicLocationRequest)
	return info
}

// SSLcsPeriodicLocationRequestOperation binds the formal object in TS 24.080 V19.4.0 §4.2 (X.880 §§8.2–8.3).
func SSLcsPeriodicLocationRequestOperation() SSOperation[mapvalues.LCSPeriodicLocationRequestArg, mapvalues.LCSPeriodicLocationRequestRes, mapvalues.SSLcsPeriodicLocationRequestErrors] {
	return SSOperation[mapvalues.LCSPeriodicLocationRequestArg, mapvalues.LCSPeriodicLocationRequestRes, mapvalues.SSLcsPeriodicLocationRequestErrors]{code: mapvalues.SSLcsPeriodicLocationRequest, info: infoSSLcsPeriodicLocationRequestOperation, argument: LCSPeriodicLocationRequestArgCodec(), result: LCSPeriodicLocationRequestResCodec(), decode: decodeSSLcsPeriodicLocationRequestError, encode: encodeSSLcsPeriodicLocationRequestError}
}
func decodeSSLcsPeriodicLocationRequestError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (mapvalues.SSLcsPeriodicLocationRequestErrors, error) {
	switch code {
	case 34:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam](__asn1pkg_v21_map_er_datatypes.ERSystemFailureParamCodec()), opts...)
		if err != nil {
			return mapvalues.SSLcsPeriodicLocationRequestErrors{}, err
		}
		return mapvalues.SSLcsPeriodicLocationRequestErrors{SystemFailure: p}, nil
	case 21:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParam](__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParamCodec()), opts...)
		if err != nil {
			return mapvalues.SSLcsPeriodicLocationRequestErrors{}, err
		}
		return mapvalues.SSLcsPeriodicLocationRequestErrors{FacilityNotSupported: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParam](__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParamCodec()), opts...)
		if err != nil {
			return mapvalues.SSLcsPeriodicLocationRequestErrors{}, err
		}
		return mapvalues.SSLcsPeriodicLocationRequestErrors{UnexpectedDataValue: p}, nil
	case 35:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERDataMissingParam](__asn1pkg_v21_map_er_datatypes.ERDataMissingParamCodec()), opts...)
		if err != nil {
			return mapvalues.SSLcsPeriodicLocationRequestErrors{}, err
		}
		return mapvalues.SSLcsPeriodicLocationRequestErrors{DataMissing: p}, nil
	default:
		return mapvalues.SSLcsPeriodicLocationRequestErrors{}, fmt.Errorf("%w: error code %d is not in lcs-PeriodicLocationRequest ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeSSLcsPeriodicLocationRequestError(value mapvalues.SSLcsPeriodicLocationRequestErrors, opts ...ber.EncodeOption) (mapvalues.SSErrorEncoding, error) {
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
		return mapvalues.SSErrorEncoding{}, fmt.Errorf("%w: exactly one lcs-PeriodicLocationRequest error arm is required", ber.ErrInvalidBinding)
	}
	if value.SystemFailure != nil {
		return encodeSSErrorMember(34, mapvalues.SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: "17.6.6", Module: "MAP-Errors", Assignment: "systemFailure", SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}, value.SystemFailure, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam](__asn1pkg_v21_map_er_datatypes.ERSystemFailureParamCodec()), opts...)
	}
	if value.FacilityNotSupported != nil {
		return encodeSSErrorMember(21, mapvalues.SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: "17.6.6", Module: "MAP-Errors", Assignment: "facilityNotSupported", SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}, value.FacilityNotSupported, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParam](__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParamCodec()), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeSSErrorMember(36, mapvalues.SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: "17.6.6", Module: "MAP-Errors", Assignment: "unexpectedDataValue", SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}, value.UnexpectedDataValue, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParam](__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParamCodec()), opts...)
	}
	if value.DataMissing != nil {
		return encodeSSErrorMember(35, mapvalues.SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: "17.6.6", Module: "MAP-Errors", Assignment: "dataMissing", SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}, value.DataMissing, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERDataMissingParam](__asn1pkg_v21_map_er_datatypes.ERDataMissingParamCodec()), opts...)
	}
	return mapvalues.SSErrorEncoding{}, fmt.Errorf("%w: no selected lcs-PeriodicLocationRequest error", ber.ErrInvalidBinding)
}
func infoSSLcsPeriodicTriggeredInvokeOperation() mapvalues.SSOperationInfo {
	info, _ := mapvalues.LookupSSOperation(mapvalues.SSLcsPeriodicTriggeredInvoke)
	return info
}

// SSLcsPeriodicTriggeredInvokeOperation binds the formal object in TS 24.080 V19.4.0 §4.2 (X.880 §§8.2–8.3).
func SSLcsPeriodicTriggeredInvokeOperation() SSOperation[mapvalues.LCSPeriodicTriggeredInvokeArg, mapvalues.LCSPeriodicTriggeredInvokeRes, mapvalues.SSLcsPeriodicTriggeredInvokeErrors] {
	return SSOperation[mapvalues.LCSPeriodicTriggeredInvokeArg, mapvalues.LCSPeriodicTriggeredInvokeRes, mapvalues.SSLcsPeriodicTriggeredInvokeErrors]{code: mapvalues.SSLcsPeriodicTriggeredInvoke, info: infoSSLcsPeriodicTriggeredInvokeOperation, argument: LCSPeriodicTriggeredInvokeArgCodec(), result: LCSPeriodicTriggeredInvokeResCodec(), decode: decodeSSLcsPeriodicTriggeredInvokeError, encode: encodeSSLcsPeriodicTriggeredInvokeError}
}
func decodeSSLcsPeriodicTriggeredInvokeError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (mapvalues.SSLcsPeriodicTriggeredInvokeErrors, error) {
	switch code {
	case 34:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam](__asn1pkg_v21_map_er_datatypes.ERSystemFailureParamCodec()), opts...)
		if err != nil {
			return mapvalues.SSLcsPeriodicTriggeredInvokeErrors{}, err
		}
		return mapvalues.SSLcsPeriodicTriggeredInvokeErrors{SystemFailure: p}, nil
	case 21:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParam](__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParamCodec()), opts...)
		if err != nil {
			return mapvalues.SSLcsPeriodicTriggeredInvokeErrors{}, err
		}
		return mapvalues.SSLcsPeriodicTriggeredInvokeErrors{FacilityNotSupported: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParam](__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParamCodec()), opts...)
		if err != nil {
			return mapvalues.SSLcsPeriodicTriggeredInvokeErrors{}, err
		}
		return mapvalues.SSLcsPeriodicTriggeredInvokeErrors{UnexpectedDataValue: p}, nil
	case 35:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERDataMissingParam](__asn1pkg_v21_map_er_datatypes.ERDataMissingParamCodec()), opts...)
		if err != nil {
			return mapvalues.SSLcsPeriodicTriggeredInvokeErrors{}, err
		}
		return mapvalues.SSLcsPeriodicTriggeredInvokeErrors{DataMissing: p}, nil
	case 51:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERResourceLimitationParam](__asn1pkg_v21_map_er_datatypes.ERResourceLimitationParamCodec()), opts...)
		if err != nil {
			return mapvalues.SSLcsPeriodicTriggeredInvokeErrors{}, err
		}
		return mapvalues.SSLcsPeriodicTriggeredInvokeErrors{ResourceLimitation: p}, nil
	default:
		return mapvalues.SSLcsPeriodicTriggeredInvokeErrors{}, fmt.Errorf("%w: error code %d is not in lcs-PeriodicTriggeredInvoke ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeSSLcsPeriodicTriggeredInvokeError(value mapvalues.SSLcsPeriodicTriggeredInvokeErrors, opts ...ber.EncodeOption) (mapvalues.SSErrorEncoding, error) {
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
		return mapvalues.SSErrorEncoding{}, fmt.Errorf("%w: exactly one lcs-PeriodicTriggeredInvoke error arm is required", ber.ErrInvalidBinding)
	}
	if value.SystemFailure != nil {
		return encodeSSErrorMember(34, mapvalues.SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: "17.6.6", Module: "MAP-Errors", Assignment: "systemFailure", SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}, value.SystemFailure, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam](__asn1pkg_v21_map_er_datatypes.ERSystemFailureParamCodec()), opts...)
	}
	if value.FacilityNotSupported != nil {
		return encodeSSErrorMember(21, mapvalues.SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: "17.6.6", Module: "MAP-Errors", Assignment: "facilityNotSupported", SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}, value.FacilityNotSupported, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParam](__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParamCodec()), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeSSErrorMember(36, mapvalues.SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: "17.6.6", Module: "MAP-Errors", Assignment: "unexpectedDataValue", SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}, value.UnexpectedDataValue, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParam](__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParamCodec()), opts...)
	}
	if value.DataMissing != nil {
		return encodeSSErrorMember(35, mapvalues.SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: "17.6.6", Module: "MAP-Errors", Assignment: "dataMissing", SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}, value.DataMissing, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERDataMissingParam](__asn1pkg_v21_map_er_datatypes.ERDataMissingParamCodec()), opts...)
	}
	if value.ResourceLimitation != nil {
		return encodeSSErrorMember(51, mapvalues.SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: "17.6.6", Module: "MAP-Errors", Assignment: "resourceLimitation", SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}, value.ResourceLimitation, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERResourceLimitationParam](__asn1pkg_v21_map_er_datatypes.ERResourceLimitationParamCodec()), opts...)
	}
	return mapvalues.SSErrorEncoding{}, fmt.Errorf("%w: no selected lcs-PeriodicTriggeredInvoke error", ber.ErrInvalidBinding)
}
func infoSSLcsPruAssociationOperation() mapvalues.SSOperationInfo {
	info, _ := mapvalues.LookupSSOperation(mapvalues.SSLcsPruAssociation)
	return info
}

// SSLcsPruAssociationOperation binds the formal object in TS 24.080 V19.4.0 §4.2 (X.880 §§8.2–8.3).
func SSLcsPruAssociationOperation() SSOperation[mapvalues.LCSPruAssociationArg, mapvalues.LCSPruAssociationRes, mapvalues.SSLcsPruAssociationErrors] {
	return SSOperation[mapvalues.LCSPruAssociationArg, mapvalues.LCSPruAssociationRes, mapvalues.SSLcsPruAssociationErrors]{code: mapvalues.SSLcsPruAssociation, info: infoSSLcsPruAssociationOperation, argument: LCSPruAssociationArgCodec(), result: LCSPruAssociationResCodec(), decode: decodeSSLcsPruAssociationError, encode: encodeSSLcsPruAssociationError}
}
func decodeSSLcsPruAssociationError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (mapvalues.SSLcsPruAssociationErrors, error) {
	switch code {
	case 120:
		p, err := decodeErrorParameter(data, present, mapvalues.ValueCodec[mapvalues.NoParameter]{}, opts...)
		if err != nil {
			return mapvalues.SSLcsPruAssociationErrors{}, err
		}
		return mapvalues.SSLcsPruAssociationErrors{LcsInvalidPru: p}, nil
	case 119:
		p, err := decodeErrorParameter(data, present, PruAssociationRejParamCodec(), opts...)
		if err != nil {
			return mapvalues.SSLcsPruAssociationErrors{}, err
		}
		return mapvalues.SSLcsPruAssociationErrors{LcsPruAssociationRej: p}, nil
	case 34:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam](__asn1pkg_v21_map_er_datatypes.ERSystemFailureParamCodec()), opts...)
		if err != nil {
			return mapvalues.SSLcsPruAssociationErrors{}, err
		}
		return mapvalues.SSLcsPruAssociationErrors{SystemFailure: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParam](__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParamCodec()), opts...)
		if err != nil {
			return mapvalues.SSLcsPruAssociationErrors{}, err
		}
		return mapvalues.SSLcsPruAssociationErrors{UnexpectedDataValue: p}, nil
	default:
		return mapvalues.SSLcsPruAssociationErrors{}, fmt.Errorf("%w: error code %d is not in lcs-PruAssociation ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeSSLcsPruAssociationError(value mapvalues.SSLcsPruAssociationErrors, opts ...ber.EncodeOption) (mapvalues.SSErrorEncoding, error) {
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
		return mapvalues.SSErrorEncoding{}, fmt.Errorf("%w: exactly one lcs-PruAssociation error arm is required", ber.ErrInvalidBinding)
	}
	if value.LcsInvalidPru != nil {
		return encodeSSErrorMember(120, mapvalues.SourceRef{Document: "3GPP TS 24.080", Edition: "19.4.0", Clause: "4.3", Module: "SS-Errors", Assignment: "lcs-invalidPru", SHA256: "b81d2a668e33702414eec4d9210bd4922f1104ccc4384cb6d8d3301ce8fa129e"}, value.LcsInvalidPru, mapvalues.ValueCodec[mapvalues.NoParameter]{}, opts...)
	}
	if value.LcsPruAssociationRej != nil {
		return encodeSSErrorMember(119, mapvalues.SourceRef{Document: "3GPP TS 24.080", Edition: "19.4.0", Clause: "4.3", Module: "SS-Errors", Assignment: "lcs-PruAssociationRej", SHA256: "b81d2a668e33702414eec4d9210bd4922f1104ccc4384cb6d8d3301ce8fa129e"}, value.LcsPruAssociationRej, PruAssociationRejParamCodec(), opts...)
	}
	if value.SystemFailure != nil {
		return encodeSSErrorMember(34, mapvalues.SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: "17.6.6", Module: "MAP-Errors", Assignment: "systemFailure", SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}, value.SystemFailure, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam](__asn1pkg_v21_map_er_datatypes.ERSystemFailureParamCodec()), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeSSErrorMember(36, mapvalues.SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: "17.6.6", Module: "MAP-Errors", Assignment: "unexpectedDataValue", SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}, value.UnexpectedDataValue, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParam](__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParamCodec()), opts...)
	}
	return mapvalues.SSErrorEncoding{}, fmt.Errorf("%w: no selected lcs-PruAssociation error", ber.ErrInvalidBinding)
}
func infoSSLcsPruDisassociationOperation() mapvalues.SSOperationInfo {
	info, _ := mapvalues.LookupSSOperation(mapvalues.SSLcsPruDisassociation)
	return info
}

// SSLcsPruDisassociationOperation binds the formal object in TS 24.080 V19.4.0 §4.2 (X.880 §§8.2–8.3).
func SSLcsPruDisassociationOperation() SSOperation[mapvalues.LCSPruDisassociationArg, mapvalues.NoParameter, mapvalues.SSLcsPruDisassociationErrors] {
	return SSOperation[mapvalues.LCSPruDisassociationArg, mapvalues.NoParameter, mapvalues.SSLcsPruDisassociationErrors]{code: mapvalues.SSLcsPruDisassociation, info: infoSSLcsPruDisassociationOperation, argument: LCSPruDisassociationArgCodec(), result: mapvalues.ValueCodec[mapvalues.NoParameter]{}, decode: decodeSSLcsPruDisassociationError, encode: encodeSSLcsPruDisassociationError}
}
func decodeSSLcsPruDisassociationError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (mapvalues.SSLcsPruDisassociationErrors, error) {
	switch code {
	case 34:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam](__asn1pkg_v21_map_er_datatypes.ERSystemFailureParamCodec()), opts...)
		if err != nil {
			return mapvalues.SSLcsPruDisassociationErrors{}, err
		}
		return mapvalues.SSLcsPruDisassociationErrors{SystemFailure: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParam](__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParamCodec()), opts...)
		if err != nil {
			return mapvalues.SSLcsPruDisassociationErrors{}, err
		}
		return mapvalues.SSLcsPruDisassociationErrors{UnexpectedDataValue: p}, nil
	default:
		return mapvalues.SSLcsPruDisassociationErrors{}, fmt.Errorf("%w: error code %d is not in lcs-PruDisassociation ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeSSLcsPruDisassociationError(value mapvalues.SSLcsPruDisassociationErrors, opts ...ber.EncodeOption) (mapvalues.SSErrorEncoding, error) {
	selected := 0
	if value.SystemFailure != nil {
		selected++
	}
	if value.UnexpectedDataValue != nil {
		selected++
	}
	if selected != 1 {
		return mapvalues.SSErrorEncoding{}, fmt.Errorf("%w: exactly one lcs-PruDisassociation error arm is required", ber.ErrInvalidBinding)
	}
	if value.SystemFailure != nil {
		return encodeSSErrorMember(34, mapvalues.SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: "17.6.6", Module: "MAP-Errors", Assignment: "systemFailure", SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}, value.SystemFailure, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam](__asn1pkg_v21_map_er_datatypes.ERSystemFailureParamCodec()), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeSSErrorMember(36, mapvalues.SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: "17.6.6", Module: "MAP-Errors", Assignment: "unexpectedDataValue", SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}, value.UnexpectedDataValue, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParam](__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParamCodec()), opts...)
	}
	return mapvalues.SSErrorEncoding{}, fmt.Errorf("%w: no selected lcs-PruDisassociation error", ber.ErrInvalidBinding)
}
func infoSSLcsSLMOLROperation() mapvalues.SSOperationInfo {
	info, _ := mapvalues.LookupSSOperation(mapvalues.SSLcsSLMOLR)
	return info
}

// SSLcsSLMOLROperation binds the formal object in TS 24.080 V19.4.0 §4.2 (X.880 §§8.2–8.3).
func SSLcsSLMOLROperation() SSOperation[mapvalues.LCSSLMOLRArg, mapvalues.LCSSLMOLRRes, mapvalues.SSLcsSLMOLRErrors] {
	return SSOperation[mapvalues.LCSSLMOLRArg, mapvalues.LCSSLMOLRRes, mapvalues.SSLcsSLMOLRErrors]{code: mapvalues.SSLcsSLMOLR, info: infoSSLcsSLMOLROperation, argument: LCSSLMOLRArgCodec(), result: LCSSLMOLRResCodec(), decode: decodeSSLcsSLMOLRError, encode: encodeSSLcsSLMOLRError}
}
func decodeSSLcsSLMOLRError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (mapvalues.SSLcsSLMOLRErrors, error) {
	switch code {
	case 34:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam](__asn1pkg_v21_map_er_datatypes.ERSystemFailureParamCodec()), opts...)
		if err != nil {
			return mapvalues.SSLcsSLMOLRErrors{}, err
		}
		return mapvalues.SSLcsSLMOLRErrors{SystemFailure: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParam](__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParamCodec()), opts...)
		if err != nil {
			return mapvalues.SSLcsSLMOLRErrors{}, err
		}
		return mapvalues.SSLcsSLMOLRErrors{UnexpectedDataValue: p}, nil
	case 35:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERDataMissingParam](__asn1pkg_v21_map_er_datatypes.ERDataMissingParamCodec()), opts...)
		if err != nil {
			return mapvalues.SSLcsSLMOLRErrors{}, err
		}
		return mapvalues.SSLcsSLMOLRErrors{DataMissing: p}, nil
	case 21:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParam](__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParamCodec()), opts...)
		if err != nil {
			return mapvalues.SSLcsSLMOLRErrors{}, err
		}
		return mapvalues.SSLcsSLMOLRErrors{FacilityNotSupported: p}, nil
	case 19:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSSSubscriptionViolationParam](__asn1pkg_v21_map_er_datatypes.ERSSSubscriptionViolationParamCodec()), opts...)
		if err != nil {
			return mapvalues.SSLcsSLMOLRErrors{}, err
		}
		return mapvalues.SSLcsSLMOLRErrors{SsSubscriptionViolation: p}, nil
	case 54:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERPositionMethodFailureParam](__asn1pkg_v21_map_er_datatypes.ERPositionMethodFailureParamCodec()), opts...)
		if err != nil {
			return mapvalues.SSLcsSLMOLRErrors{}, err
		}
		return mapvalues.SSLcsSLMOLRErrors{PositionMethodFailure: p}, nil
	default:
		return mapvalues.SSLcsSLMOLRErrors{}, fmt.Errorf("%w: error code %d is not in lcs-SLMOLR ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeSSLcsSLMOLRError(value mapvalues.SSLcsSLMOLRErrors, opts ...ber.EncodeOption) (mapvalues.SSErrorEncoding, error) {
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
		return mapvalues.SSErrorEncoding{}, fmt.Errorf("%w: exactly one lcs-SLMOLR error arm is required", ber.ErrInvalidBinding)
	}
	if value.SystemFailure != nil {
		return encodeSSErrorMember(34, mapvalues.SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: "17.6.6", Module: "MAP-Errors", Assignment: "systemFailure", SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}, value.SystemFailure, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam](__asn1pkg_v21_map_er_datatypes.ERSystemFailureParamCodec()), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeSSErrorMember(36, mapvalues.SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: "17.6.6", Module: "MAP-Errors", Assignment: "unexpectedDataValue", SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}, value.UnexpectedDataValue, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParam](__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParamCodec()), opts...)
	}
	if value.DataMissing != nil {
		return encodeSSErrorMember(35, mapvalues.SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: "17.6.6", Module: "MAP-Errors", Assignment: "dataMissing", SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}, value.DataMissing, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERDataMissingParam](__asn1pkg_v21_map_er_datatypes.ERDataMissingParamCodec()), opts...)
	}
	if value.FacilityNotSupported != nil {
		return encodeSSErrorMember(21, mapvalues.SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: "17.6.6", Module: "MAP-Errors", Assignment: "facilityNotSupported", SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}, value.FacilityNotSupported, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParam](__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParamCodec()), opts...)
	}
	if value.SsSubscriptionViolation != nil {
		return encodeSSErrorMember(19, mapvalues.SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: "17.6.6", Module: "MAP-Errors", Assignment: "ss-SubscriptionViolation", SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}, value.SsSubscriptionViolation, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSSSubscriptionViolationParam](__asn1pkg_v21_map_er_datatypes.ERSSSubscriptionViolationParamCodec()), opts...)
	}
	if value.PositionMethodFailure != nil {
		return encodeSSErrorMember(54, mapvalues.SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: "17.6.6", Module: "MAP-Errors", Assignment: "positionMethodFailure", SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}, value.PositionMethodFailure, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERPositionMethodFailureParam](__asn1pkg_v21_map_er_datatypes.ERPositionMethodFailureParamCodec()), opts...)
	}
	return mapvalues.SSErrorEncoding{}, fmt.Errorf("%w: no selected lcs-SLMOLR error", ber.ErrInvalidBinding)
}
func infoSSLcsSLMTLROperation() mapvalues.SSOperationInfo {
	info, _ := mapvalues.LookupSSOperation(mapvalues.SSLcsSLMTLR)
	return info
}

// SSLcsSLMTLROperation binds the formal object in TS 24.080 V19.4.0 §4.2 (X.880 §§8.2–8.3).
func SSLcsSLMTLROperation() SSOperation[mapvalues.LCSSLMTLRArg, mapvalues.LCSSLMTLRRes, mapvalues.SSLcsSLMTLRErrors] {
	return SSOperation[mapvalues.LCSSLMTLRArg, mapvalues.LCSSLMTLRRes, mapvalues.SSLcsSLMTLRErrors]{code: mapvalues.SSLcsSLMTLR, info: infoSSLcsSLMTLROperation, argument: LCSSLMTLRArgCodec(), result: LCSSLMTLRResCodec(), decode: decodeSSLcsSLMTLRError, encode: encodeSSLcsSLMTLRError}
}
func decodeSSLcsSLMTLRError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (mapvalues.SSLcsSLMTLRErrors, error) {
	switch code {
	case 34:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam](__asn1pkg_v21_map_er_datatypes.ERSystemFailureParamCodec()), opts...)
		if err != nil {
			return mapvalues.SSLcsSLMTLRErrors{}, err
		}
		return mapvalues.SSLcsSLMTLRErrors{SystemFailure: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParam](__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParamCodec()), opts...)
		if err != nil {
			return mapvalues.SSLcsSLMTLRErrors{}, err
		}
		return mapvalues.SSLcsSLMTLRErrors{UnexpectedDataValue: p}, nil
	case 35:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERDataMissingParam](__asn1pkg_v21_map_er_datatypes.ERDataMissingParamCodec()), opts...)
		if err != nil {
			return mapvalues.SSLcsSLMTLRErrors{}, err
		}
		return mapvalues.SSLcsSLMTLRErrors{DataMissing: p}, nil
	case 21:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParam](__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParamCodec()), opts...)
		if err != nil {
			return mapvalues.SSLcsSLMTLRErrors{}, err
		}
		return mapvalues.SSLcsSLMTLRErrors{FacilityNotSupported: p}, nil
	default:
		return mapvalues.SSLcsSLMTLRErrors{}, fmt.Errorf("%w: error code %d is not in lcs-SLMTLR ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeSSLcsSLMTLRError(value mapvalues.SSLcsSLMTLRErrors, opts ...ber.EncodeOption) (mapvalues.SSErrorEncoding, error) {
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
		return mapvalues.SSErrorEncoding{}, fmt.Errorf("%w: exactly one lcs-SLMTLR error arm is required", ber.ErrInvalidBinding)
	}
	if value.SystemFailure != nil {
		return encodeSSErrorMember(34, mapvalues.SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: "17.6.6", Module: "MAP-Errors", Assignment: "systemFailure", SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}, value.SystemFailure, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam](__asn1pkg_v21_map_er_datatypes.ERSystemFailureParamCodec()), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeSSErrorMember(36, mapvalues.SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: "17.6.6", Module: "MAP-Errors", Assignment: "unexpectedDataValue", SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}, value.UnexpectedDataValue, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParam](__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParamCodec()), opts...)
	}
	if value.DataMissing != nil {
		return encodeSSErrorMember(35, mapvalues.SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: "17.6.6", Module: "MAP-Errors", Assignment: "dataMissing", SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}, value.DataMissing, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERDataMissingParam](__asn1pkg_v21_map_er_datatypes.ERDataMissingParamCodec()), opts...)
	}
	if value.FacilityNotSupported != nil {
		return encodeSSErrorMember(21, mapvalues.SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: "17.6.6", Module: "MAP-Errors", Assignment: "facilityNotSupported", SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}, value.FacilityNotSupported, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParam](__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParamCodec()), opts...)
	}
	return mapvalues.SSErrorEncoding{}, fmt.Errorf("%w: no selected lcs-SLMTLR error", ber.ErrInvalidBinding)
}
func infoSSLcsULRSPPTransportOperation() mapvalues.SSOperationInfo {
	info, _ := mapvalues.LookupSSOperation(mapvalues.SSLcsULRSPPTransport)
	return info
}

// SSLcsULRSPPTransportOperation binds the formal object in TS 24.080 V19.4.0 §4.2 (X.880 §§8.2–8.3).
func SSLcsULRSPPTransportOperation() SSOperation[mapvalues.LCSULRSPPTransportArg, mapvalues.LCSULRSPPTransportRes, mapvalues.SSLcsULRSPPTransportErrors] {
	return SSOperation[mapvalues.LCSULRSPPTransportArg, mapvalues.LCSULRSPPTransportRes, mapvalues.SSLcsULRSPPTransportErrors]{code: mapvalues.SSLcsULRSPPTransport, info: infoSSLcsULRSPPTransportOperation, argument: LCSULRSPPTransportArgCodec(), result: LCSULRSPPTransportResCodec(), decode: decodeSSLcsULRSPPTransportError, encode: encodeSSLcsULRSPPTransportError}
}
func decodeSSLcsULRSPPTransportError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (mapvalues.SSLcsULRSPPTransportErrors, error) {
	switch code {
	case 34:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam](__asn1pkg_v21_map_er_datatypes.ERSystemFailureParamCodec()), opts...)
		if err != nil {
			return mapvalues.SSLcsULRSPPTransportErrors{}, err
		}
		return mapvalues.SSLcsULRSPPTransportErrors{SystemFailure: p}, nil
	case 21:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParam](__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParamCodec()), opts...)
		if err != nil {
			return mapvalues.SSLcsULRSPPTransportErrors{}, err
		}
		return mapvalues.SSLcsULRSPPTransportErrors{FacilityNotSupported: p}, nil
	default:
		return mapvalues.SSLcsULRSPPTransportErrors{}, fmt.Errorf("%w: error code %d is not in lcs-ULRSPPTransport ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeSSLcsULRSPPTransportError(value mapvalues.SSLcsULRSPPTransportErrors, opts ...ber.EncodeOption) (mapvalues.SSErrorEncoding, error) {
	selected := 0
	if value.SystemFailure != nil {
		selected++
	}
	if value.FacilityNotSupported != nil {
		selected++
	}
	if selected != 1 {
		return mapvalues.SSErrorEncoding{}, fmt.Errorf("%w: exactly one lcs-ULRSPPTransport error arm is required", ber.ErrInvalidBinding)
	}
	if value.SystemFailure != nil {
		return encodeSSErrorMember(34, mapvalues.SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: "17.6.6", Module: "MAP-Errors", Assignment: "systemFailure", SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}, value.SystemFailure, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam](__asn1pkg_v21_map_er_datatypes.ERSystemFailureParamCodec()), opts...)
	}
	if value.FacilityNotSupported != nil {
		return encodeSSErrorMember(21, mapvalues.SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: "17.6.6", Module: "MAP-Errors", Assignment: "facilityNotSupported", SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}, value.FacilityNotSupported, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParam](__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParamCodec()), opts...)
	}
	return mapvalues.SSErrorEncoding{}, fmt.Errorf("%w: no selected lcs-ULRSPPTransport error", ber.ErrInvalidBinding)
}
func infoSSNotifySSOperation() mapvalues.SSOperationInfo {
	info, _ := mapvalues.LookupSSOperation(mapvalues.SSNotifySS)
	return info
}

// SSNotifySSOperation binds the formal object in TS 24.080 V19.4.0 §4.2 (X.880 §§8.2–8.3).
func SSNotifySSOperation() SSOperation[mapvalues.NotifySSArg, mapvalues.NoParameter, mapvalues.SSNotifySSErrors] {
	return SSOperation[mapvalues.NotifySSArg, mapvalues.NoParameter, mapvalues.SSNotifySSErrors]{code: mapvalues.SSNotifySS, info: infoSSNotifySSOperation, argument: NotifySSArgCodec(), result: mapvalues.ValueCodec[mapvalues.NoParameter]{}, decode: decodeSSNotifySSError, encode: encodeSSNotifySSError}
}
func decodeSSNotifySSError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (mapvalues.SSNotifySSErrors, error) {
	switch code {
	default:
		return mapvalues.SSNotifySSErrors{}, fmt.Errorf("%w: error code %d is not in notifySS ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeSSNotifySSError(value mapvalues.SSNotifySSErrors, opts ...ber.EncodeOption) (mapvalues.SSErrorEncoding, error) {
	return mapvalues.SSErrorEncoding{}, fmt.Errorf("%w: no selected notifySS error", ber.ErrInvalidBinding)
}
func infoSSProcessUnstructuredSSDataOperation() mapvalues.SSOperationInfo {
	info, _ := mapvalues.LookupSSOperation(mapvalues.SSProcessUnstructuredSSData)
	return info
}

// SSProcessUnstructuredSSDataOperation binds the formal object in TS 24.080 V19.4.0 §4.2 (X.880 §§8.2–8.3).
func SSProcessUnstructuredSSDataOperation() SSOperation[mapvalues.BERValue[mapvalues.SSUserData], mapvalues.BERValue[mapvalues.SSUserData], mapvalues.SSProcessUnstructuredSSDataErrors] {
	return SSOperation[mapvalues.BERValue[mapvalues.SSUserData], mapvalues.BERValue[mapvalues.SSUserData], mapvalues.SSProcessUnstructuredSSDataErrors]{code: mapvalues.SSProcessUnstructuredSSData, info: infoSSProcessUnstructuredSSDataOperation, argument: SSUserDataCodec(), result: SSUserDataCodec(), decode: decodeSSProcessUnstructuredSSDataError, encode: encodeSSProcessUnstructuredSSDataError}
}
func decodeSSProcessUnstructuredSSDataError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (mapvalues.SSProcessUnstructuredSSDataErrors, error) {
	switch code {
	case 34:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam](__asn1pkg_v21_map_er_datatypes.ERSystemFailureParamCodec()), opts...)
		if err != nil {
			return mapvalues.SSProcessUnstructuredSSDataErrors{}, err
		}
		return mapvalues.SSProcessUnstructuredSSDataErrors{SystemFailure: p}, nil
	case 36:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParam](__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParamCodec()), opts...)
		if err != nil {
			return mapvalues.SSProcessUnstructuredSSDataErrors{}, err
		}
		return mapvalues.SSProcessUnstructuredSSDataErrors{UnexpectedDataValue: p}, nil
	default:
		return mapvalues.SSProcessUnstructuredSSDataErrors{}, fmt.Errorf("%w: error code %d is not in processUnstructuredSS-Data ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeSSProcessUnstructuredSSDataError(value mapvalues.SSProcessUnstructuredSSDataErrors, opts ...ber.EncodeOption) (mapvalues.SSErrorEncoding, error) {
	selected := 0
	if value.SystemFailure != nil {
		selected++
	}
	if value.UnexpectedDataValue != nil {
		selected++
	}
	if selected != 1 {
		return mapvalues.SSErrorEncoding{}, fmt.Errorf("%w: exactly one processUnstructuredSS-Data error arm is required", ber.ErrInvalidBinding)
	}
	if value.SystemFailure != nil {
		return encodeSSErrorMember(34, mapvalues.SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: "17.6.6", Module: "MAP-Errors", Assignment: "systemFailure", SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}, value.SystemFailure, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam](__asn1pkg_v21_map_er_datatypes.ERSystemFailureParamCodec()), opts...)
	}
	if value.UnexpectedDataValue != nil {
		return encodeSSErrorMember(36, mapvalues.SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: "17.6.6", Module: "MAP-Errors", Assignment: "unexpectedDataValue", SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}, value.UnexpectedDataValue, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParam](__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParamCodec()), opts...)
	}
	return mapvalues.SSErrorEncoding{}, fmt.Errorf("%w: no selected processUnstructuredSS-Data error", ber.ErrInvalidBinding)
}
func infoSSRetrieveMPTYOperation() mapvalues.SSOperationInfo {
	info, _ := mapvalues.LookupSSOperation(mapvalues.SSRetrieveMPTY)
	return info
}

// SSRetrieveMPTYOperation binds the formal object in TS 24.080 V19.4.0 §4.2 (X.880 §§8.2–8.3).
func SSRetrieveMPTYOperation() SSOperation[mapvalues.NoParameter, mapvalues.NoParameter, mapvalues.SSRetrieveMPTYErrors] {
	return SSOperation[mapvalues.NoParameter, mapvalues.NoParameter, mapvalues.SSRetrieveMPTYErrors]{code: mapvalues.SSRetrieveMPTY, info: infoSSRetrieveMPTYOperation, argument: mapvalues.ValueCodec[mapvalues.NoParameter]{}, result: mapvalues.ValueCodec[mapvalues.NoParameter]{}, decode: decodeSSRetrieveMPTYError, encode: encodeSSRetrieveMPTYError}
}
func decodeSSRetrieveMPTYError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (mapvalues.SSRetrieveMPTYErrors, error) {
	switch code {
	case 16:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERIllegalSSOperationParam](__asn1pkg_v21_map_er_datatypes.ERIllegalSSOperationParamCodec()), opts...)
		if err != nil {
			return mapvalues.SSRetrieveMPTYErrors{}, err
		}
		return mapvalues.SSRetrieveMPTYErrors{IllegalSSOperation: p}, nil
	case 17:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_ss_datatypes.BERValue[__asn1pkg_v21_map_ss_datatypes.SSSSStatus]](__asn1pkg_v21_map_ss_datatypes.SSSSStatusCodec()), opts...)
		if err != nil {
			return mapvalues.SSRetrieveMPTYErrors{}, err
		}
		return mapvalues.SSRetrieveMPTYErrors{SsErrorStatus: p}, nil
	case 20:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSSIncompatibilityCause](__asn1pkg_v21_map_er_datatypes.ERSSIncompatibilityCauseCodec()), opts...)
		if err != nil {
			return mapvalues.SSRetrieveMPTYErrors{}, err
		}
		return mapvalues.SSRetrieveMPTYErrors{SsIncompatibility: p}, nil
	case 21:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParam](__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParamCodec()), opts...)
		if err != nil {
			return mapvalues.SSRetrieveMPTYErrors{}, err
		}
		return mapvalues.SSRetrieveMPTYErrors{FacilityNotSupported: p}, nil
	case 34:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam](__asn1pkg_v21_map_er_datatypes.ERSystemFailureParamCodec()), opts...)
		if err != nil {
			return mapvalues.SSRetrieveMPTYErrors{}, err
		}
		return mapvalues.SSRetrieveMPTYErrors{SystemFailure: p}, nil
	default:
		return mapvalues.SSRetrieveMPTYErrors{}, fmt.Errorf("%w: error code %d is not in retrieveMPTY ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeSSRetrieveMPTYError(value mapvalues.SSRetrieveMPTYErrors, opts ...ber.EncodeOption) (mapvalues.SSErrorEncoding, error) {
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
		return mapvalues.SSErrorEncoding{}, fmt.Errorf("%w: exactly one retrieveMPTY error arm is required", ber.ErrInvalidBinding)
	}
	if value.IllegalSSOperation != nil {
		return encodeSSErrorMember(16, mapvalues.SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: "17.6.6", Module: "MAP-Errors", Assignment: "illegalSS-Operation", SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}, value.IllegalSSOperation, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERIllegalSSOperationParam](__asn1pkg_v21_map_er_datatypes.ERIllegalSSOperationParamCodec()), opts...)
	}
	if value.SsErrorStatus != nil {
		return encodeSSErrorMember(17, mapvalues.SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: "17.6.6", Module: "MAP-Errors", Assignment: "ss-ErrorStatus", SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}, value.SsErrorStatus, adaptValueCodec[__asn1pkg_v21_map_ss_datatypes.BERValue[__asn1pkg_v21_map_ss_datatypes.SSSSStatus]](__asn1pkg_v21_map_ss_datatypes.SSSSStatusCodec()), opts...)
	}
	if value.SsIncompatibility != nil {
		return encodeSSErrorMember(20, mapvalues.SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: "17.6.6", Module: "MAP-Errors", Assignment: "ss-Incompatibility", SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}, value.SsIncompatibility, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSSIncompatibilityCause](__asn1pkg_v21_map_er_datatypes.ERSSIncompatibilityCauseCodec()), opts...)
	}
	if value.FacilityNotSupported != nil {
		return encodeSSErrorMember(21, mapvalues.SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: "17.6.6", Module: "MAP-Errors", Assignment: "facilityNotSupported", SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}, value.FacilityNotSupported, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParam](__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParamCodec()), opts...)
	}
	if value.SystemFailure != nil {
		return encodeSSErrorMember(34, mapvalues.SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: "17.6.6", Module: "MAP-Errors", Assignment: "systemFailure", SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}, value.SystemFailure, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam](__asn1pkg_v21_map_er_datatypes.ERSystemFailureParamCodec()), opts...)
	}
	return mapvalues.SSErrorEncoding{}, fmt.Errorf("%w: no selected retrieveMPTY error", ber.ErrInvalidBinding)
}
func infoSSSplitMPTYOperation() mapvalues.SSOperationInfo {
	info, _ := mapvalues.LookupSSOperation(mapvalues.SSSplitMPTY)
	return info
}

// SSSplitMPTYOperation binds the formal object in TS 24.080 V19.4.0 §4.2 (X.880 §§8.2–8.3).
func SSSplitMPTYOperation() SSOperation[mapvalues.NoParameter, mapvalues.NoParameter, mapvalues.SSSplitMPTYErrors] {
	return SSOperation[mapvalues.NoParameter, mapvalues.NoParameter, mapvalues.SSSplitMPTYErrors]{code: mapvalues.SSSplitMPTY, info: infoSSSplitMPTYOperation, argument: mapvalues.ValueCodec[mapvalues.NoParameter]{}, result: mapvalues.ValueCodec[mapvalues.NoParameter]{}, decode: decodeSSSplitMPTYError, encode: encodeSSSplitMPTYError}
}
func decodeSSSplitMPTYError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (mapvalues.SSSplitMPTYErrors, error) {
	switch code {
	case 16:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERIllegalSSOperationParam](__asn1pkg_v21_map_er_datatypes.ERIllegalSSOperationParamCodec()), opts...)
		if err != nil {
			return mapvalues.SSSplitMPTYErrors{}, err
		}
		return mapvalues.SSSplitMPTYErrors{IllegalSSOperation: p}, nil
	case 17:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_ss_datatypes.BERValue[__asn1pkg_v21_map_ss_datatypes.SSSSStatus]](__asn1pkg_v21_map_ss_datatypes.SSSSStatusCodec()), opts...)
		if err != nil {
			return mapvalues.SSSplitMPTYErrors{}, err
		}
		return mapvalues.SSSplitMPTYErrors{SsErrorStatus: p}, nil
	case 20:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSSIncompatibilityCause](__asn1pkg_v21_map_er_datatypes.ERSSIncompatibilityCauseCodec()), opts...)
		if err != nil {
			return mapvalues.SSSplitMPTYErrors{}, err
		}
		return mapvalues.SSSplitMPTYErrors{SsIncompatibility: p}, nil
	case 21:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParam](__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParamCodec()), opts...)
		if err != nil {
			return mapvalues.SSSplitMPTYErrors{}, err
		}
		return mapvalues.SSSplitMPTYErrors{FacilityNotSupported: p}, nil
	case 34:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam](__asn1pkg_v21_map_er_datatypes.ERSystemFailureParamCodec()), opts...)
		if err != nil {
			return mapvalues.SSSplitMPTYErrors{}, err
		}
		return mapvalues.SSSplitMPTYErrors{SystemFailure: p}, nil
	default:
		return mapvalues.SSSplitMPTYErrors{}, fmt.Errorf("%w: error code %d is not in splitMPTY ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeSSSplitMPTYError(value mapvalues.SSSplitMPTYErrors, opts ...ber.EncodeOption) (mapvalues.SSErrorEncoding, error) {
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
		return mapvalues.SSErrorEncoding{}, fmt.Errorf("%w: exactly one splitMPTY error arm is required", ber.ErrInvalidBinding)
	}
	if value.IllegalSSOperation != nil {
		return encodeSSErrorMember(16, mapvalues.SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: "17.6.6", Module: "MAP-Errors", Assignment: "illegalSS-Operation", SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}, value.IllegalSSOperation, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERIllegalSSOperationParam](__asn1pkg_v21_map_er_datatypes.ERIllegalSSOperationParamCodec()), opts...)
	}
	if value.SsErrorStatus != nil {
		return encodeSSErrorMember(17, mapvalues.SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: "17.6.6", Module: "MAP-Errors", Assignment: "ss-ErrorStatus", SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}, value.SsErrorStatus, adaptValueCodec[__asn1pkg_v21_map_ss_datatypes.BERValue[__asn1pkg_v21_map_ss_datatypes.SSSSStatus]](__asn1pkg_v21_map_ss_datatypes.SSSSStatusCodec()), opts...)
	}
	if value.SsIncompatibility != nil {
		return encodeSSErrorMember(20, mapvalues.SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: "17.6.6", Module: "MAP-Errors", Assignment: "ss-Incompatibility", SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}, value.SsIncompatibility, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSSIncompatibilityCause](__asn1pkg_v21_map_er_datatypes.ERSSIncompatibilityCauseCodec()), opts...)
	}
	if value.FacilityNotSupported != nil {
		return encodeSSErrorMember(21, mapvalues.SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: "17.6.6", Module: "MAP-Errors", Assignment: "facilityNotSupported", SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}, value.FacilityNotSupported, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParam](__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParamCodec()), opts...)
	}
	if value.SystemFailure != nil {
		return encodeSSErrorMember(34, mapvalues.SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: "17.6.6", Module: "MAP-Errors", Assignment: "systemFailure", SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}, value.SystemFailure, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam](__asn1pkg_v21_map_er_datatypes.ERSystemFailureParamCodec()), opts...)
	}
	return mapvalues.SSErrorEncoding{}, fmt.Errorf("%w: no selected splitMPTY error", ber.ErrInvalidBinding)
}
func infoSSUserUserServiceOperation() mapvalues.SSOperationInfo {
	info, _ := mapvalues.LookupSSOperation(mapvalues.SSUserUserService)
	return info
}

// SSUserUserServiceOperation binds the formal object in TS 24.080 V19.4.0 §4.2 (X.880 §§8.2–8.3).
func SSUserUserServiceOperation() SSOperation[mapvalues.UserUserServiceArg, mapvalues.NoParameter, mapvalues.SSUserUserServiceErrors] {
	return SSOperation[mapvalues.UserUserServiceArg, mapvalues.NoParameter, mapvalues.SSUserUserServiceErrors]{code: mapvalues.SSUserUserService, info: infoSSUserUserServiceOperation, argument: UserUserServiceArgCodec(), result: mapvalues.ValueCodec[mapvalues.NoParameter]{}, decode: decodeSSUserUserServiceError, encode: encodeSSUserUserServiceError}
}
func decodeSSUserUserServiceError(code int64, data []byte, present bool, opts ...ber.DecodeOption) (mapvalues.SSUserUserServiceErrors, error) {
	switch code {
	case 16:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERIllegalSSOperationParam](__asn1pkg_v21_map_er_datatypes.ERIllegalSSOperationParamCodec()), opts...)
		if err != nil {
			return mapvalues.SSUserUserServiceErrors{}, err
		}
		return mapvalues.SSUserUserServiceErrors{IllegalSSOperation: p}, nil
	case 17:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_ss_datatypes.BERValue[__asn1pkg_v21_map_ss_datatypes.SSSSStatus]](__asn1pkg_v21_map_ss_datatypes.SSSSStatusCodec()), opts...)
		if err != nil {
			return mapvalues.SSUserUserServiceErrors{}, err
		}
		return mapvalues.SSUserUserServiceErrors{SsErrorStatus: p}, nil
	case 18:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSSNotAvailableParam](__asn1pkg_v21_map_er_datatypes.ERSSNotAvailableParamCodec()), opts...)
		if err != nil {
			return mapvalues.SSUserUserServiceErrors{}, err
		}
		return mapvalues.SSUserUserServiceErrors{SsNotAvailable: p}, nil
	case 20:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSSIncompatibilityCause](__asn1pkg_v21_map_er_datatypes.ERSSIncompatibilityCauseCodec()), opts...)
		if err != nil {
			return mapvalues.SSUserUserServiceErrors{}, err
		}
		return mapvalues.SSUserUserServiceErrors{SsIncompatibility: p}, nil
	case 21:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParam](__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParamCodec()), opts...)
		if err != nil {
			return mapvalues.SSUserUserServiceErrors{}, err
		}
		return mapvalues.SSUserUserServiceErrors{FacilityNotSupported: p}, nil
	case 34:
		p, err := decodeErrorParameter(data, present, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam](__asn1pkg_v21_map_er_datatypes.ERSystemFailureParamCodec()), opts...)
		if err != nil {
			return mapvalues.SSUserUserServiceErrors{}, err
		}
		return mapvalues.SSUserUserServiceErrors{SystemFailure: p}, nil
	case 127:
		p, err := decodeErrorParameter(data, present, mapvalues.ValueCodec[mapvalues.NoParameter]{}, opts...)
		if err != nil {
			return mapvalues.SSUserUserServiceErrors{}, err
		}
		return mapvalues.SSUserUserServiceErrors{ResourcesNotAvailable: p}, nil
	case 122:
		p, err := decodeErrorParameter(data, present, mapvalues.ValueCodec[mapvalues.NoParameter]{}, opts...)
		if err != nil {
			return mapvalues.SSUserUserServiceErrors{}, err
		}
		return mapvalues.SSUserUserServiceErrors{RejectedByNetwork: p}, nil
	case 121:
		p, err := decodeErrorParameter(data, present, mapvalues.ValueCodec[mapvalues.NoParameter]{}, opts...)
		if err != nil {
			return mapvalues.SSUserUserServiceErrors{}, err
		}
		return mapvalues.SSUserUserServiceErrors{RejectedByUser: p}, nil
	default:
		return mapvalues.SSUserUserServiceErrors{}, fmt.Errorf("%w: error code %d is not in userUserService ERRORS", ber.ErrInvalidBinding, code)
	}
}
func encodeSSUserUserServiceError(value mapvalues.SSUserUserServiceErrors, opts ...ber.EncodeOption) (mapvalues.SSErrorEncoding, error) {
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
		return mapvalues.SSErrorEncoding{}, fmt.Errorf("%w: exactly one userUserService error arm is required", ber.ErrInvalidBinding)
	}
	if value.IllegalSSOperation != nil {
		return encodeSSErrorMember(16, mapvalues.SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: "17.6.6", Module: "MAP-Errors", Assignment: "illegalSS-Operation", SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}, value.IllegalSSOperation, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERIllegalSSOperationParam](__asn1pkg_v21_map_er_datatypes.ERIllegalSSOperationParamCodec()), opts...)
	}
	if value.SsErrorStatus != nil {
		return encodeSSErrorMember(17, mapvalues.SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: "17.6.6", Module: "MAP-Errors", Assignment: "ss-ErrorStatus", SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}, value.SsErrorStatus, adaptValueCodec[__asn1pkg_v21_map_ss_datatypes.BERValue[__asn1pkg_v21_map_ss_datatypes.SSSSStatus]](__asn1pkg_v21_map_ss_datatypes.SSSSStatusCodec()), opts...)
	}
	if value.SsNotAvailable != nil {
		return encodeSSErrorMember(18, mapvalues.SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: "17.6.6", Module: "MAP-Errors", Assignment: "ss-NotAvailable", SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}, value.SsNotAvailable, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSSNotAvailableParam](__asn1pkg_v21_map_er_datatypes.ERSSNotAvailableParamCodec()), opts...)
	}
	if value.SsIncompatibility != nil {
		return encodeSSErrorMember(20, mapvalues.SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: "17.6.6", Module: "MAP-Errors", Assignment: "ss-Incompatibility", SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}, value.SsIncompatibility, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSSIncompatibilityCause](__asn1pkg_v21_map_er_datatypes.ERSSIncompatibilityCauseCodec()), opts...)
	}
	if value.FacilityNotSupported != nil {
		return encodeSSErrorMember(21, mapvalues.SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: "17.6.6", Module: "MAP-Errors", Assignment: "facilityNotSupported", SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}, value.FacilityNotSupported, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParam](__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParamCodec()), opts...)
	}
	if value.SystemFailure != nil {
		return encodeSSErrorMember(34, mapvalues.SourceRef{Document: "3GPP TS 29.002", Edition: "18.0.0", Clause: "17.6.6", Module: "MAP-Errors", Assignment: "systemFailure", SHA256: "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054"}, value.SystemFailure, adaptValueCodec[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam](__asn1pkg_v21_map_er_datatypes.ERSystemFailureParamCodec()), opts...)
	}
	if value.ResourcesNotAvailable != nil {
		return encodeSSErrorMember(127, mapvalues.SourceRef{Document: "3GPP TS 24.080", Edition: "19.4.0", Clause: "4.3", Module: "SS-Errors", Assignment: "resourcesNotAvailable", SHA256: "b81d2a668e33702414eec4d9210bd4922f1104ccc4384cb6d8d3301ce8fa129e"}, value.ResourcesNotAvailable, mapvalues.ValueCodec[mapvalues.NoParameter]{}, opts...)
	}
	if value.RejectedByNetwork != nil {
		return encodeSSErrorMember(122, mapvalues.SourceRef{Document: "3GPP TS 24.080", Edition: "19.4.0", Clause: "4.3", Module: "SS-Errors", Assignment: "rejectedByNetwork", SHA256: "b81d2a668e33702414eec4d9210bd4922f1104ccc4384cb6d8d3301ce8fa129e"}, value.RejectedByNetwork, mapvalues.ValueCodec[mapvalues.NoParameter]{}, opts...)
	}
	if value.RejectedByUser != nil {
		return encodeSSErrorMember(121, mapvalues.SourceRef{Document: "3GPP TS 24.080", Edition: "19.4.0", Clause: "4.3", Module: "SS-Errors", Assignment: "rejectedByUser", SHA256: "b81d2a668e33702414eec4d9210bd4922f1104ccc4384cb6d8d3301ce8fa129e"}, value.RejectedByUser, mapvalues.ValueCodec[mapvalues.NoParameter]{}, opts...)
	}
	return mapvalues.SSErrorEncoding{}, fmt.Errorf("%w: no selected userUserService error", ber.ErrInvalidBinding)
}
