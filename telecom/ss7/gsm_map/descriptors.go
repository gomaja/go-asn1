// Code generated from formal ASN.1 objects and values. DO NOT EDIT.

package gsm_map

import (
	runtime "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime"

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

func apiBool(v bool) *bool { return &v }

type ErrorInfo struct {
	Name              string
	Code              MAPErrorCode
	Parameter         *TypeRef
	ParameterOptional *bool
	Source            SourceRef
}

func infoAbsentSubscriberError() ErrorInfo {
	return ErrorInfo{Name: "absentSubscriber", Code: AbsentSubscriber, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.22", ASN1Name: "AbsentSubscriberParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "AbsentSubscriberParam"}, ParameterOptional: nil, Source: sourceInfo0("absentSubscriber", "17.6.6")}
}
func infoAbsentSubscriberSMError() ErrorInfo {
	return ErrorInfo{Name: "absentSubscriberSM", Code: AbsentSubscriberSM, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.22", ASN1Name: "AbsentSubscriberSM-Param", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "AbsentSubscriberSMParam"}, ParameterOptional: nil, Source: sourceInfo0("absentSubscriberSM", "17.6.6")}
}
func infoAtiNotAllowedError() ErrorInfo {
	return ErrorInfo{Name: "ati-NotAllowed", Code: AtiNotAllowed, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.22", ASN1Name: "ATI-NotAllowedParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "ATINotAllowedParam"}, ParameterOptional: nil, Source: sourceInfo0("ati-NotAllowed", "17.6.6")}
}
func infoAtmNotAllowedError() ErrorInfo {
	return ErrorInfo{Name: "atm-NotAllowed", Code: AtmNotAllowed, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.22", ASN1Name: "ATM-NotAllowedParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "ATMNotAllowedParam"}, ParameterOptional: nil, Source: sourceInfo0("atm-NotAllowed", "17.6.6")}
}
func infoAtsiNotAllowedError() ErrorInfo {
	return ErrorInfo{Name: "atsi-NotAllowed", Code: AtsiNotAllowed, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.22", ASN1Name: "ATSI-NotAllowedParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "ATSINotAllowedParam"}, ParameterOptional: nil, Source: sourceInfo0("atsi-NotAllowed", "17.6.6")}
}
func infoBearerServiceNotProvisionedError() ErrorInfo {
	return ErrorInfo{Name: "bearerServiceNotProvisioned", Code: BearerServiceNotProvisioned, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.22", ASN1Name: "BearerServNotProvParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "BearerServNotProvParam"}, ParameterOptional: nil, Source: sourceInfo0("bearerServiceNotProvisioned", "17.6.6")}
}
func infoBusySubscriberError() ErrorInfo {
	return ErrorInfo{Name: "busySubscriber", Code: BusySubscriber, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.22", ASN1Name: "BusySubscriberParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "BusySubscriberParam"}, ParameterOptional: nil, Source: sourceInfo0("busySubscriber", "17.6.6")}
}
func infoCallBarredError() ErrorInfo {
	return ErrorInfo{Name: "callBarred", Code: CallBarred, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.22", ASN1Name: "CallBarredParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "CallBarredParam"}, ParameterOptional: nil, Source: sourceInfo0("callBarred", "17.6.6")}
}
func infoCugRejectError() ErrorInfo {
	return ErrorInfo{Name: "cug-Reject", Code: CugReject, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.22", ASN1Name: "CUG-RejectParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "CUGRejectParam"}, ParameterOptional: nil, Source: sourceInfo0("cug-Reject", "17.6.6")}
}
func infoDataMissingError() ErrorInfo {
	return ErrorInfo{Name: "dataMissing", Code: DataMissing, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.22", ASN1Name: "DataMissingParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "DataMissingParam"}, ParameterOptional: nil, Source: sourceInfo0("dataMissing", "17.6.6")}
}
func infoFacilityNotSupportedError() ErrorInfo {
	return ErrorInfo{Name: "facilityNotSupported", Code: FacilityNotSupported, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.22", ASN1Name: "FacilityNotSupParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "FacilityNotSupParam"}, ParameterOptional: nil, Source: sourceInfo0("facilityNotSupported", "17.6.6")}
}
func infoForwardingFailedError() ErrorInfo {
	return ErrorInfo{Name: "forwardingFailed", Code: ForwardingFailed, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.22", ASN1Name: "ForwardingFailedParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "ForwardingFailedParam"}, ParameterOptional: nil, Source: sourceInfo0("forwardingFailed", "17.6.6")}
}
func infoForwardingViolationError() ErrorInfo {
	return ErrorInfo{Name: "forwardingViolation", Code: ForwardingViolation, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.22", ASN1Name: "ForwardingViolationParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "ForwardingViolationParam"}, ParameterOptional: nil, Source: sourceInfo0("forwardingViolation", "17.6.6")}
}
func infoIllegalEquipmentError() ErrorInfo {
	return ErrorInfo{Name: "illegalEquipment", Code: IllegalEquipment, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.22", ASN1Name: "IllegalEquipmentParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "IllegalEquipmentParam"}, ParameterOptional: nil, Source: sourceInfo0("illegalEquipment", "17.6.6")}
}
func infoIllegalSSOperationError() ErrorInfo {
	return ErrorInfo{Name: "illegalSS-Operation", Code: IllegalSSOperation, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.22", ASN1Name: "IllegalSS-OperationParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "IllegalSSOperationParam"}, ParameterOptional: nil, Source: sourceInfo0("illegalSS-Operation", "17.6.6")}
}
func infoIllegalSubscriberError() ErrorInfo {
	return ErrorInfo{Name: "illegalSubscriber", Code: IllegalSubscriber, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.22", ASN1Name: "IllegalSubscriberParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "IllegalSubscriberParam"}, ParameterOptional: nil, Source: sourceInfo0("illegalSubscriber", "17.6.6")}
}
func infoIncompatibleTerminalError() ErrorInfo {
	return ErrorInfo{Name: "incompatibleTerminal", Code: IncompatibleTerminal, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.22", ASN1Name: "IncompatibleTerminalParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "IncompatibleTerminalParam"}, ParameterOptional: nil, Source: sourceInfo0("incompatibleTerminal", "17.6.6")}
}
func infoInformationNotAvailableError() ErrorInfo {
	return ErrorInfo{Name: "informationNotAvailable", Code: InformationNotAvailable, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.22", ASN1Name: "InformationNotAvailableParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "InformationNotAvailableParam"}, ParameterOptional: nil, Source: sourceInfo0("informationNotAvailable", "17.6.6")}
}
func infoLongTermDenialError() ErrorInfo {
	return ErrorInfo{Name: "longTermDenial", Code: LongTermDenial, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.22", ASN1Name: "LongTermDenialParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "LongTermDenialParam"}, ParameterOptional: nil, Source: sourceInfo0("longTermDenial", "17.6.6")}
}
func infoMessageWaitingListFullError() ErrorInfo {
	return ErrorInfo{Name: "messageWaitingListFull", Code: MessageWaitingListFull, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.22", ASN1Name: "MessageWaitListFullParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "MessageWaitListFullParam"}, ParameterOptional: nil, Source: sourceInfo0("messageWaitingListFull", "17.6.6")}
}
func infoMmEventNotSupportedError() ErrorInfo {
	return ErrorInfo{Name: "mm-EventNotSupported", Code: MmEventNotSupported, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.22", ASN1Name: "MM-EventNotSupported-Param", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "MMEventNotSupportedParam"}, ParameterOptional: nil, Source: sourceInfo0("mm-EventNotSupported", "17.6.6")}
}
func infoNegativePWCheckError() ErrorInfo {
	return ErrorInfo{Name: "negativePW-Check", Code: NegativePWCheck, Parameter: nil, ParameterOptional: nil, Source: sourceInfo0("negativePW-Check", "17.6.6")}
}
func infoNoGroupCallNumberAvailableError() ErrorInfo {
	return ErrorInfo{Name: "noGroupCallNumberAvailable", Code: NoGroupCallNumberAvailable, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.22", ASN1Name: "NoGroupCallNbParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "NoGroupCallNbParam"}, ParameterOptional: nil, Source: sourceInfo0("noGroupCallNumberAvailable", "17.6.6")}
}
func infoNoHandoverNumberAvailableError() ErrorInfo {
	return ErrorInfo{Name: "noHandoverNumberAvailable", Code: NoHandoverNumberAvailable, Parameter: nil, ParameterOptional: nil, Source: sourceInfo0("noHandoverNumberAvailable", "17.6.6")}
}
func infoNoRoamingNumberAvailableError() ErrorInfo {
	return ErrorInfo{Name: "noRoamingNumberAvailable", Code: NoRoamingNumberAvailable, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.22", ASN1Name: "NoRoamingNbParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "NoRoamingNbParam"}, ParameterOptional: nil, Source: sourceInfo0("noRoamingNumberAvailable", "17.6.6")}
}
func infoNoSubscriberReplyError() ErrorInfo {
	return ErrorInfo{Name: "noSubscriberReply", Code: NoSubscriberReply, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.22", ASN1Name: "NoSubscriberReplyParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "NoSubscriberReplyParam"}, ParameterOptional: nil, Source: sourceInfo0("noSubscriberReply", "17.6.6")}
}
func infoNumberChangedError() ErrorInfo {
	return ErrorInfo{Name: "numberChanged", Code: NumberChanged, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.22", ASN1Name: "NumberChangedParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "NumberChangedParam"}, ParameterOptional: nil, Source: sourceInfo0("numberChanged", "17.6.6")}
}
func infoNumberOfPWAttemptsViolationError() ErrorInfo {
	return ErrorInfo{Name: "numberOfPW-AttemptsViolation", Code: NumberOfPWAttemptsViolation, Parameter: nil, ParameterOptional: nil, Source: sourceInfo0("numberOfPW-AttemptsViolation", "17.6.6")}
}
func infoOngoingGroupCallError() ErrorInfo {
	return ErrorInfo{Name: "ongoingGroupCall", Code: OngoingGroupCall, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.22", ASN1Name: "OngoingGroupCallParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "OngoingGroupCallParam"}, ParameterOptional: nil, Source: sourceInfo0("ongoingGroupCall", "17.6.6")}
}
func infoOrNotAllowedError() ErrorInfo {
	return ErrorInfo{Name: "or-NotAllowed", Code: OrNotAllowed, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.22", ASN1Name: "OR-NotAllowedParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "ORNotAllowedParam"}, ParameterOptional: nil, Source: sourceInfo0("or-NotAllowed", "17.6.6")}
}
func infoPositionMethodFailureError() ErrorInfo {
	return ErrorInfo{Name: "positionMethodFailure", Code: PositionMethodFailure, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.22", ASN1Name: "PositionMethodFailure-Param", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "PositionMethodFailureParam"}, ParameterOptional: nil, Source: sourceInfo0("positionMethodFailure", "17.6.6")}
}
func infoPwRegistrationFailureError() ErrorInfo {
	return ErrorInfo{Name: "pw-RegistrationFailure", Code: PwRegistrationFailure, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.22", ASN1Name: "PW-RegistrationFailureCause", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "PWRegistrationFailureCause"}, ParameterOptional: nil, Source: sourceInfo0("pw-RegistrationFailure", "17.6.6")}
}
func infoResourceLimitationError() ErrorInfo {
	return ErrorInfo{Name: "resourceLimitation", Code: ResourceLimitation, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.22", ASN1Name: "ResourceLimitationParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "ResourceLimitationParam"}, ParameterOptional: nil, Source: sourceInfo0("resourceLimitation", "17.6.6")}
}
func infoRoamingNotAllowedError() ErrorInfo {
	return ErrorInfo{Name: "roamingNotAllowed", Code: RoamingNotAllowed, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.22", ASN1Name: "RoamingNotAllowedParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "RoamingNotAllowedParam"}, ParameterOptional: nil, Source: sourceInfo0("roamingNotAllowed", "17.6.6")}
}
func infoShortTermDenialError() ErrorInfo {
	return ErrorInfo{Name: "shortTermDenial", Code: ShortTermDenial, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.22", ASN1Name: "ShortTermDenialParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "ShortTermDenialParam"}, ParameterOptional: nil, Source: sourceInfo0("shortTermDenial", "17.6.6")}
}
func infoSmDeliveryFailureError() ErrorInfo {
	return ErrorInfo{Name: "sm-DeliveryFailure", Code: SmDeliveryFailure, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.22", ASN1Name: "SM-DeliveryFailureCause", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "SMDeliveryFailureCause"}, ParameterOptional: nil, Source: sourceInfo0("sm-DeliveryFailure", "17.6.6")}
}
func infoSsErrorStatusError() ErrorInfo {
	return ErrorInfo{Name: "ss-ErrorStatus", Code: SsErrorStatus, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.14.22", ASN1Name: "SS-Status", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "SSStatus"}, ParameterOptional: nil, Source: sourceInfo0("ss-ErrorStatus", "17.6.6")}
}
func infoSsIncompatibilityError() ErrorInfo {
	return ErrorInfo{Name: "ss-Incompatibility", Code: SsIncompatibility, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.22", ASN1Name: "SS-IncompatibilityCause", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "SSIncompatibilityCause"}, ParameterOptional: nil, Source: sourceInfo0("ss-Incompatibility", "17.6.6")}
}
func infoSsNotAvailableError() ErrorInfo {
	return ErrorInfo{Name: "ss-NotAvailable", Code: SsNotAvailable, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.22", ASN1Name: "SS-NotAvailableParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "SSNotAvailableParam"}, ParameterOptional: nil, Source: sourceInfo0("ss-NotAvailable", "17.6.6")}
}
func infoSsSubscriptionViolationError() ErrorInfo {
	return ErrorInfo{Name: "ss-SubscriptionViolation", Code: SsSubscriptionViolation, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.22", ASN1Name: "SS-SubscriptionViolationParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "SSSubscriptionViolationParam"}, ParameterOptional: nil, Source: sourceInfo0("ss-SubscriptionViolation", "17.6.6")}
}
func infoSubscriberBusyForMTSMSError() ErrorInfo {
	return ErrorInfo{Name: "subscriberBusyForMT-SMS", Code: SubscriberBusyForMTSMS, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.22", ASN1Name: "SubBusyForMT-SMS-Param", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "SubBusyForMTSMSParam"}, ParameterOptional: nil, Source: sourceInfo0("subscriberBusyForMT-SMS", "17.6.6")}
}
func infoSubsequentHandoverFailureError() ErrorInfo {
	return ErrorInfo{Name: "subsequentHandoverFailure", Code: SubsequentHandoverFailure, Parameter: nil, ParameterOptional: nil, Source: sourceInfo0("subsequentHandoverFailure", "17.6.6")}
}
func infoSystemFailureError() ErrorInfo {
	return ErrorInfo{Name: "systemFailure", Code: SystemFailure, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.22", ASN1Name: "SystemFailureParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "SystemFailureParam"}, ParameterOptional: nil, Source: sourceInfo0("systemFailure", "17.6.6")}
}
func infoTargetCellOutsideGroupCallAreaError() ErrorInfo {
	return ErrorInfo{Name: "targetCellOutsideGroupCallArea", Code: TargetCellOutsideGroupCallArea, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.22", ASN1Name: "TargetCellOutsideGCA-Param", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "TargetCellOutsideGCAParam"}, ParameterOptional: nil, Source: sourceInfo0("targetCellOutsideGroupCallArea", "17.6.6")}
}
func infoTeleserviceNotProvisionedError() ErrorInfo {
	return ErrorInfo{Name: "teleserviceNotProvisioned", Code: TeleserviceNotProvisioned, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.22", ASN1Name: "TeleservNotProvParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "TeleservNotProvParam"}, ParameterOptional: nil, Source: sourceInfo0("teleserviceNotProvisioned", "17.6.6")}
}
func infoTracingBufferFullError() ErrorInfo {
	return ErrorInfo{Name: "tracingBufferFull", Code: TracingBufferFull, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.22", ASN1Name: "TracingBufferFullParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "TracingBufferFullParam"}, ParameterOptional: nil, Source: sourceInfo0("tracingBufferFull", "17.6.6")}
}
func infoUnauthorizedLCSClientError() ErrorInfo {
	return ErrorInfo{Name: "unauthorizedLCSClient", Code: UnauthorizedLCSClient, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.22", ASN1Name: "UnauthorizedLCSClient-Param", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "UnauthorizedLCSClientParam"}, ParameterOptional: nil, Source: sourceInfo0("unauthorizedLCSClient", "17.6.6")}
}
func infoUnauthorizedRequestingNetworkError() ErrorInfo {
	return ErrorInfo{Name: "unauthorizedRequestingNetwork", Code: UnauthorizedRequestingNetwork, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.22", ASN1Name: "UnauthorizedRequestingNetwork-Param", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "UnauthorizedRequestingNetworkParam"}, ParameterOptional: nil, Source: sourceInfo0("unauthorizedRequestingNetwork", "17.6.6")}
}
func infoUnexpectedDataValueError() ErrorInfo {
	return ErrorInfo{Name: "unexpectedDataValue", Code: UnexpectedDataValue, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.22", ASN1Name: "UnexpectedDataParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "UnexpectedDataParam"}, ParameterOptional: nil, Source: sourceInfo0("unexpectedDataValue", "17.6.6")}
}
func infoUnidentifiedSubscriberError() ErrorInfo {
	return ErrorInfo{Name: "unidentifiedSubscriber", Code: UnidentifiedSubscriber, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.22", ASN1Name: "UnidentifiedSubParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "UnidentifiedSubParam"}, ParameterOptional: nil, Source: sourceInfo0("unidentifiedSubscriber", "17.6.6")}
}
func infoUnknownAlphabetError() ErrorInfo {
	return ErrorInfo{Name: "unknownAlphabet", Code: UnknownAlphabet, Parameter: nil, ParameterOptional: nil, Source: sourceInfo0("unknownAlphabet", "17.6.6")}
}
func infoUnknownEquipmentError() ErrorInfo {
	return ErrorInfo{Name: "unknownEquipment", Code: UnknownEquipment, Parameter: nil, ParameterOptional: nil, Source: sourceInfo0("unknownEquipment", "17.6.6")}
}
func infoUnknownMSCError() ErrorInfo {
	return ErrorInfo{Name: "unknownMSC", Code: UnknownMSC, Parameter: nil, ParameterOptional: nil, Source: sourceInfo0("unknownMSC", "17.6.6")}
}
func infoUnknownOrUnreachableLCSClientError() ErrorInfo {
	return ErrorInfo{Name: "unknownOrUnreachableLCSClient", Code: UnknownOrUnreachableLCSClient, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.22", ASN1Name: "UnknownOrUnreachableLCSClient-Param", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "UnknownOrUnreachableLCSClientParam"}, ParameterOptional: nil, Source: sourceInfo0("unknownOrUnreachableLCSClient", "17.6.6")}
}
func infoUnknownSubscriberError() ErrorInfo {
	return ErrorInfo{Name: "unknownSubscriber", Code: UnknownSubscriber, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.22", ASN1Name: "UnknownSubscriberParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "UnknownSubscriberParam"}, ParameterOptional: nil, Source: sourceInfo0("unknownSubscriber", "17.6.6")}
}
func infoUssdBusyError() ErrorInfo {
	return ErrorInfo{Name: "ussd-Busy", Code: UssdBusy, Parameter: nil, ParameterOptional: nil, Source: sourceInfo0("ussd-Busy", "17.6.6")}
}

// Errors returns detached metadata snapshots of the source error catalogue.
func Errors() []ErrorInfo {
	return []ErrorInfo{infoAbsentSubscriberError(), infoAbsentSubscriberSMError(), infoAtiNotAllowedError(), infoAtmNotAllowedError(), infoAtsiNotAllowedError(), infoBearerServiceNotProvisionedError(), infoBusySubscriberError(), infoCallBarredError(), infoCugRejectError(), infoDataMissingError(), infoFacilityNotSupportedError(), infoForwardingFailedError(), infoForwardingViolationError(), infoIllegalEquipmentError(), infoIllegalSSOperationError(), infoIllegalSubscriberError(), infoIncompatibleTerminalError(), infoInformationNotAvailableError(), infoLongTermDenialError(), infoMessageWaitingListFullError(), infoMmEventNotSupportedError(), infoNegativePWCheckError(), infoNoGroupCallNumberAvailableError(), infoNoHandoverNumberAvailableError(), infoNoRoamingNumberAvailableError(), infoNoSubscriberReplyError(), infoNumberChangedError(), infoNumberOfPWAttemptsViolationError(), infoOngoingGroupCallError(), infoOrNotAllowedError(), infoPositionMethodFailureError(), infoPwRegistrationFailureError(), infoResourceLimitationError(), infoRoamingNotAllowedError(), infoShortTermDenialError(), infoSmDeliveryFailureError(), infoSsErrorStatusError(), infoSsIncompatibilityError(), infoSsNotAvailableError(), infoSsSubscriptionViolationError(), infoSubscriberBusyForMTSMSError(), infoSubsequentHandoverFailureError(), infoSystemFailureError(), infoTargetCellOutsideGroupCallAreaError(), infoTeleserviceNotProvisionedError(), infoTracingBufferFullError(), infoUnauthorizedLCSClientError(), infoUnauthorizedRequestingNetworkError(), infoUnexpectedDataValueError(), infoUnidentifiedSubscriberError(), infoUnknownAlphabetError(), infoUnknownEquipmentError(), infoUnknownMSCError(), infoUnknownOrUnreachableLCSClientError(), infoUnknownSubscriberError(), infoUssdBusyError()}
}

// LookupError returns detached metadata for code, or zero metadata and false if absent.
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

// AlertServiceCentreErrors selects exactly the formal ERRORS set of MAP-ShortMessageServiceOperations.alertServiceCentre.
type AlertServiceCentreErrors struct {
	SystemFailure       *ErrorValue[SystemFailureParam]
	DataMissing         *ErrorValue[DataMissingParam]
	UnexpectedDataValue *ErrorValue[UnexpectedDataParam]
}

func infoAlertServiceCentreOperation() OperationInfo {
	return OperationInfo{Name: "alertServiceCentre", Code: AlertServiceCentre, Argument: &TypeRef{ModuleOID: "0.4.0.0.1.3.16.22", ASN1Name: "AlertServiceCentreArg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "AlertServiceCentreArg"}, Result: nil, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: true, Source: sourceInfo3("alertServiceCentre", "17.6.5"), Errors: []ErrorInfo{infoSystemFailureError(), infoDataMissingError(), infoUnexpectedDataValueError()}, Linked: []MAPOperationCode{}}
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

// AuthenticationFailureReportErrors selects exactly the formal ERRORS set of MAP-MobileServiceOperations.authenticationFailureReport.
type AuthenticationFailureReportErrors struct {
	SystemFailure       *ErrorValue[SystemFailureParam]
	UnexpectedDataValue *ErrorValue[UnexpectedDataParam]
	UnknownSubscriber   *ErrorValue[UnknownSubscriberParam]
}

func infoAuthenticationFailureReportOperation() OperationInfo {
	return OperationInfo{Name: "authenticationFailureReport", Code: AuthenticationFailureReport, Argument: &TypeRef{ModuleOID: "0.4.0.0.1.3.11.22", ASN1Name: "AuthenticationFailureReportArg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "AuthenticationFailureReportArg"}, Result: &TypeRef{ModuleOID: "0.4.0.0.1.3.11.22", ASN1Name: "AuthenticationFailureReportRes", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "AuthenticationFailureReportRes"}, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: false, Source: sourceInfo4("authenticationFailureReport", "17.6.1"), Errors: []ErrorInfo{infoSystemFailureError(), infoUnexpectedDataValueError(), infoUnknownSubscriberError()}, Linked: []MAPOperationCode{}}
}

// CancelLocationErrors selects exactly the formal ERRORS set of MAP-MobileServiceOperations.cancelLocation.
type CancelLocationErrors struct {
	DataMissing         *ErrorValue[DataMissingParam]
	UnexpectedDataValue *ErrorValue[UnexpectedDataParam]
}

func infoCancelLocationOperation() OperationInfo {
	return OperationInfo{Name: "cancelLocation", Code: CancelLocation, Argument: &TypeRef{ModuleOID: "0.4.0.0.1.3.11.22", ASN1Name: "CancelLocationArg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "CancelLocationArg"}, Result: &TypeRef{ModuleOID: "0.4.0.0.1.3.11.22", ASN1Name: "CancelLocationRes", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "CancelLocationRes"}, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: false, Source: sourceInfo4("cancelLocation", "17.6.1"), Errors: []ErrorInfo{infoDataMissingError(), infoUnexpectedDataValueError()}, Linked: []MAPOperationCode{}}
}

// CancelVcsgLocationErrors selects exactly the formal ERRORS set of MAP-MobileServiceOperations.cancelVcsgLocation.
type CancelVcsgLocationErrors struct {
	DataMissing         *ErrorValue[DataMissingParam]
	UnexpectedDataValue *ErrorValue[UnexpectedDataParam]
}

func infoCancelVcsgLocationOperation() OperationInfo {
	return OperationInfo{Name: "cancelVcsgLocation", Code: CancelVcsgLocation, Argument: &TypeRef{ModuleOID: "0.4.0.0.1.3.11.22", ASN1Name: "CancelVcsgLocationArg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "CancelVcsgLocationArg"}, Result: &TypeRef{ModuleOID: "0.4.0.0.1.3.11.22", ASN1Name: "CancelVcsgLocationRes", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "CancelVcsgLocationRes"}, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: false, Source: sourceInfo4("cancelVcsgLocation", "17.6.1"), Errors: []ErrorInfo{infoDataMissingError(), infoUnexpectedDataValueError()}, Linked: []MAPOperationCode{}}
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

// DeleteSubscriberDataErrors selects exactly the formal ERRORS set of MAP-MobileServiceOperations.deleteSubscriberData.
type DeleteSubscriberDataErrors struct {
	DataMissing            *ErrorValue[DataMissingParam]
	UnexpectedDataValue    *ErrorValue[UnexpectedDataParam]
	UnidentifiedSubscriber *ErrorValue[UnidentifiedSubParam]
}

func infoDeleteSubscriberDataOperation() OperationInfo {
	return OperationInfo{Name: "deleteSubscriberData", Code: DeleteSubscriberData, Argument: &TypeRef{ModuleOID: "0.4.0.0.1.3.11.22", ASN1Name: "DeleteSubscriberDataArg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "DeleteSubscriberDataArg"}, Result: &TypeRef{ModuleOID: "0.4.0.0.1.3.11.22", ASN1Name: "DeleteSubscriberDataRes", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "DeleteSubscriberDataRes"}, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: false, Source: sourceInfo4("deleteSubscriberData", "17.6.1"), Errors: []ErrorInfo{infoDataMissingError(), infoUnexpectedDataValueError(), infoUnidentifiedSubscriberError()}, Linked: []MAPOperationCode{}}
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

// ForwardAccessSignallingErrors selects exactly the formal ERRORS set of MAP-MobileServiceOperations.forwardAccessSignalling.
type ForwardAccessSignallingErrors struct {
}

func infoForwardAccessSignallingOperation() OperationInfo {
	return OperationInfo{Name: "forwardAccessSignalling", Code: ForwardAccessSignalling, Argument: &TypeRef{ModuleOID: "0.4.0.0.1.3.11.22", ASN1Name: "ForwardAccessSignalling-Arg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "ForwardAccessSignallingArg"}, Result: nil, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: false, Source: sourceInfo4("forwardAccessSignalling", "17.6.1"), Errors: []ErrorInfo{}, Linked: []MAPOperationCode{}}
}

// ForwardCheckSSIndicationErrors selects exactly the formal ERRORS set of MAP-MobileServiceOperations.forwardCheckSS-Indication.
type ForwardCheckSSIndicationErrors struct {
}

func infoForwardCheckSSIndicationOperation() OperationInfo {
	return OperationInfo{Name: "forwardCheckSS-Indication", Code: ForwardCheckSSIndication, Argument: nil, Result: nil, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: false, Source: sourceInfo4("forwardCheckSS-Indication", "17.6.1"), Errors: []ErrorInfo{}, Linked: []MAPOperationCode{}}
}

// ForwardGroupCallSignallingErrors selects exactly the formal ERRORS set of MAP-Group-Call-Operations.forwardGroupCallSignalling.
type ForwardGroupCallSignallingErrors struct {
}

func infoForwardGroupCallSignallingOperation() OperationInfo {
	return OperationInfo{Name: "forwardGroupCallSignalling", Code: ForwardGroupCallSignalling, Argument: &TypeRef{ModuleOID: "0.4.0.0.1.3.23.22", ASN1Name: "ForwardGroupCallSignallingArg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "ForwardGroupCallSignallingArg"}, Result: nil, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: false, Source: sourceInfo5("forwardGroupCallSignalling", "17.6.7"), Errors: []ErrorInfo{}, Linked: []MAPOperationCode{}}
}

// GetPasswordErrors selects exactly the formal ERRORS set of MAP-SupplementaryServiceOperations.getPassword.
type GetPasswordErrors struct {
}

func infoGetPasswordOperation() OperationInfo {
	return OperationInfo{Name: "getPassword", Code: GetPassword, Argument: &TypeRef{ModuleOID: "0.4.0.0.1.3.14.22", ASN1Name: "GuidanceInfo", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "GuidanceInfo"}, Result: &TypeRef{ModuleOID: "0.4.0.0.1.3.14.22", ASN1Name: "Password", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "Password"}, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: false, Source: sourceInfo1("getPassword", "17.6.4"), Errors: []ErrorInfo{}, Linked: []MAPOperationCode{}}
}

// InformServiceCentreErrors selects exactly the formal ERRORS set of MAP-ShortMessageServiceOperations.informServiceCentre.
type InformServiceCentreErrors struct {
}

func infoInformServiceCentreOperation() OperationInfo {
	return OperationInfo{Name: "informServiceCentre", Code: InformServiceCentre, Argument: &TypeRef{ModuleOID: "0.4.0.0.1.3.16.22", ASN1Name: "InformServiceCentreArg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "InformServiceCentreArg"}, Result: nil, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: false, Source: sourceInfo3("informServiceCentre", "17.6.5"), Errors: []ErrorInfo{}, Linked: []MAPOperationCode{}}
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

// MtForwardSMVGCSErrors selects exactly the formal ERRORS set of MAP-ShortMessageServiceOperations.mt-ForwardSM-VGCS.
type MtForwardSMVGCSErrors struct {
	SystemFailure       *ErrorValue[SystemFailureParam]
	UnexpectedDataValue *ErrorValue[UnexpectedDataParam]
}

func infoMtForwardSMVGCSOperation() OperationInfo {
	return OperationInfo{Name: "mt-ForwardSM-VGCS", Code: MtForwardSMVGCS, Argument: &TypeRef{ModuleOID: "0.4.0.0.1.3.16.22", ASN1Name: "MT-ForwardSM-VGCS-Arg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "MTForwardSMVGCSArg"}, Result: &TypeRef{ModuleOID: "0.4.0.0.1.3.16.22", ASN1Name: "MT-ForwardSM-VGCS-Res", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "MTForwardSMVGCSRes"}, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: false, Source: sourceInfo3("mt-ForwardSM-VGCS", "17.6.5"), Errors: []ErrorInfo{infoSystemFailureError(), infoUnexpectedDataValueError()}, Linked: []MAPOperationCode{}}
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

// NoteSubscriberDataModifiedErrors selects exactly the formal ERRORS set of MAP-MobileServiceOperations.noteSubscriberDataModified.
type NoteSubscriberDataModifiedErrors struct {
	DataMissing         *ErrorValue[DataMissingParam]
	UnexpectedDataValue *ErrorValue[UnexpectedDataParam]
	UnknownSubscriber   *ErrorValue[UnknownSubscriberParam]
}

func infoNoteSubscriberDataModifiedOperation() OperationInfo {
	return OperationInfo{Name: "noteSubscriberDataModified", Code: NoteSubscriberDataModified, Argument: &TypeRef{ModuleOID: "0.4.0.0.1.3.11.22", ASN1Name: "NoteSubscriberDataModifiedArg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "NoteSubscriberDataModifiedArg"}, Result: &TypeRef{ModuleOID: "0.4.0.0.1.3.11.22", ASN1Name: "NoteSubscriberDataModifiedRes", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "NoteSubscriberDataModifiedRes"}, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: false, Source: sourceInfo4("noteSubscriberDataModified", "17.6.1"), Errors: []ErrorInfo{infoDataMissingError(), infoUnexpectedDataValueError(), infoUnknownSubscriberError()}, Linked: []MAPOperationCode{}}
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

// ProcessAccessSignallingErrors selects exactly the formal ERRORS set of MAP-MobileServiceOperations.processAccessSignalling.
type ProcessAccessSignallingErrors struct {
}

func infoProcessAccessSignallingOperation() OperationInfo {
	return OperationInfo{Name: "processAccessSignalling", Code: ProcessAccessSignalling, Argument: &TypeRef{ModuleOID: "0.4.0.0.1.3.11.22", ASN1Name: "ProcessAccessSignalling-Arg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "ProcessAccessSignallingArg"}, Result: nil, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: false, Source: sourceInfo4("processAccessSignalling", "17.6.1"), Errors: []ErrorInfo{}, Linked: []MAPOperationCode{}}
}

// ProcessGroupCallSignallingErrors selects exactly the formal ERRORS set of MAP-Group-Call-Operations.processGroupCallSignalling.
type ProcessGroupCallSignallingErrors struct {
}

func infoProcessGroupCallSignallingOperation() OperationInfo {
	return OperationInfo{Name: "processGroupCallSignalling", Code: ProcessGroupCallSignalling, Argument: &TypeRef{ModuleOID: "0.4.0.0.1.3.23.22", ASN1Name: "ProcessGroupCallSignallingArg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "ProcessGroupCallSignallingArg"}, Result: nil, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: false, Source: sourceInfo5("processGroupCallSignalling", "17.6.7"), Errors: []ErrorInfo{}, Linked: []MAPOperationCode{}}
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

// ProvideSubscriberInfoErrors selects exactly the formal ERRORS set of MAP-MobileServiceOperations.provideSubscriberInfo.
type ProvideSubscriberInfoErrors struct {
	DataMissing         *ErrorValue[DataMissingParam]
	UnexpectedDataValue *ErrorValue[UnexpectedDataParam]
}

func infoProvideSubscriberInfoOperation() OperationInfo {
	return OperationInfo{Name: "provideSubscriberInfo", Code: ProvideSubscriberInfo, Argument: &TypeRef{ModuleOID: "0.4.0.0.1.3.11.22", ASN1Name: "ProvideSubscriberInfoArg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "ProvideSubscriberInfoArg"}, Result: &TypeRef{ModuleOID: "0.4.0.0.1.3.11.22", ASN1Name: "ProvideSubscriberInfoRes", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "ProvideSubscriberInfoRes"}, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: false, Source: sourceInfo4("provideSubscriberInfo", "17.6.1"), Errors: []ErrorInfo{infoDataMissingError(), infoUnexpectedDataValueError()}, Linked: []MAPOperationCode{}}
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

// PurgeMSErrors selects exactly the formal ERRORS set of MAP-MobileServiceOperations.purgeMS.
type PurgeMSErrors struct {
	DataMissing         *ErrorValue[DataMissingParam]
	UnexpectedDataValue *ErrorValue[UnexpectedDataParam]
	UnknownSubscriber   *ErrorValue[UnknownSubscriberParam]
}

func infoPurgeMSOperation() OperationInfo {
	return OperationInfo{Name: "purgeMS", Code: PurgeMS, Argument: &TypeRef{ModuleOID: "0.4.0.0.1.3.11.22", ASN1Name: "PurgeMS-Arg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "PurgeMSArg"}, Result: &TypeRef{ModuleOID: "0.4.0.0.1.3.11.22", ASN1Name: "PurgeMS-Res", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "PurgeMSRes"}, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: false, Source: sourceInfo4("purgeMS", "17.6.1"), Errors: []ErrorInfo{infoDataMissingError(), infoUnexpectedDataValueError(), infoUnknownSubscriberError()}, Linked: []MAPOperationCode{}}
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

// ReleaseResourcesErrors selects exactly the formal ERRORS set of MAP-CallHandlingOperations.releaseResources.
type ReleaseResourcesErrors struct {
	UnexpectedDataValue *ErrorValue[UnexpectedDataParam]
	SystemFailure       *ErrorValue[SystemFailureParam]
}

func infoReleaseResourcesOperation() OperationInfo {
	return OperationInfo{Name: "releaseResources", Code: ReleaseResources, Argument: &TypeRef{ModuleOID: "0.4.0.0.1.3.13.22", ASN1Name: "ReleaseResourcesArg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "ReleaseResourcesArg"}, Result: &TypeRef{ModuleOID: "0.4.0.0.1.3.13.22", ASN1Name: "ReleaseResourcesRes", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "ReleaseResourcesRes"}, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: false, Source: sourceInfo6("releaseResources", "17.6.3"), Errors: []ErrorInfo{infoUnexpectedDataValueError(), infoSystemFailureError()}, Linked: []MAPOperationCode{}}
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

// ResetErrors selects exactly the formal ERRORS set of MAP-MobileServiceOperations.reset.
type ResetErrors struct {
}

func infoResetOperation() OperationInfo {
	return OperationInfo{Name: "reset", Code: Reset, Argument: &TypeRef{ModuleOID: "0.4.0.0.1.3.11.22", ASN1Name: "ResetArg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "ResetArg"}, Result: nil, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: false, Source: sourceInfo4("reset", "17.6.1"), Errors: []ErrorInfo{}, Linked: []MAPOperationCode{}}
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

// SendEndSignalErrors selects exactly the formal ERRORS set of MAP-MobileServiceOperations.sendEndSignal.
type SendEndSignalErrors struct {
}

func infoSendEndSignalOperation() OperationInfo {
	return OperationInfo{Name: "sendEndSignal", Code: SendEndSignal, Argument: &TypeRef{ModuleOID: "0.4.0.0.1.3.11.22", ASN1Name: "SendEndSignal-Arg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "SendEndSignalArg"}, Result: &TypeRef{ModuleOID: "0.4.0.0.1.3.11.22", ASN1Name: "SendEndSignal-Res", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "SendEndSignalRes"}, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: false, Source: sourceInfo4("sendEndSignal", "17.6.1"), Errors: []ErrorInfo{}, Linked: []MAPOperationCode{}}
}

// SendGroupCallEndSignalErrors selects exactly the formal ERRORS set of MAP-Group-Call-Operations.sendGroupCallEndSignal.
type SendGroupCallEndSignalErrors struct {
}

func infoSendGroupCallEndSignalOperation() OperationInfo {
	return OperationInfo{Name: "sendGroupCallEndSignal", Code: SendGroupCallEndSignal, Argument: &TypeRef{ModuleOID: "0.4.0.0.1.3.23.22", ASN1Name: "SendGroupCallEndSignalArg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "SendGroupCallEndSignalArg"}, Result: &TypeRef{ModuleOID: "0.4.0.0.1.3.23.22", ASN1Name: "SendGroupCallEndSignalRes", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "SendGroupCallEndSignalRes"}, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: false, Source: sourceInfo5("sendGroupCallEndSignal", "17.6.7"), Errors: []ErrorInfo{}, Linked: []MAPOperationCode{}}
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

// SendIMSIErrors selects exactly the formal ERRORS set of MAP-OperationAndMaintenanceOperations.sendIMSI.
type SendIMSIErrors struct {
	DataMissing         *ErrorValue[DataMissingParam]
	UnexpectedDataValue *ErrorValue[UnexpectedDataParam]
	UnknownSubscriber   *ErrorValue[UnknownSubscriberParam]
}

func infoSendIMSIOperation() OperationInfo {
	return OperationInfo{Name: "sendIMSI", Code: SendIMSI, Argument: &TypeRef{ModuleOID: "0.4.0.0.1.3.18.22", ASN1Name: "ISDN-AddressString", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "ISDNAddressString"}, Result: &TypeRef{ModuleOID: "0.4.0.0.1.3.18.22", ASN1Name: "IMSI", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "IMSI"}, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: false, Source: sourceInfo2("sendIMSI", "17.6.2"), Errors: []ErrorInfo{infoDataMissingError(), infoUnexpectedDataValueError(), infoUnknownSubscriberError()}, Linked: []MAPOperationCode{}}
}

// SendIdentificationErrors selects exactly the formal ERRORS set of MAP-MobileServiceOperations.sendIdentification.
type SendIdentificationErrors struct {
	DataMissing            *ErrorValue[DataMissingParam]
	UnidentifiedSubscriber *ErrorValue[UnidentifiedSubParam]
}

func infoSendIdentificationOperation() OperationInfo {
	return OperationInfo{Name: "sendIdentification", Code: SendIdentification, Argument: &TypeRef{ModuleOID: "0.4.0.0.1.3.11.22", ASN1Name: "SendIdentificationArg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "SendIdentificationArg"}, Result: &TypeRef{ModuleOID: "0.4.0.0.1.3.11.22", ASN1Name: "SendIdentificationRes", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "SendIdentificationRes"}, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: false, Source: sourceInfo4("sendIdentification", "17.6.1"), Errors: []ErrorInfo{infoDataMissingError(), infoUnidentifiedSubscriberError()}, Linked: []MAPOperationCode{}}
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

// SsInvocationNotificationErrors selects exactly the formal ERRORS set of MAP-SupplementaryServiceOperations.ss-InvocationNotification.
type SsInvocationNotificationErrors struct {
	DataMissing         *ErrorValue[DataMissingParam]
	UnexpectedDataValue *ErrorValue[UnexpectedDataParam]
	UnknownSubscriber   *ErrorValue[UnknownSubscriberParam]
}

func infoSsInvocationNotificationOperation() OperationInfo {
	return OperationInfo{Name: "ss-InvocationNotification", Code: SsInvocationNotification, Argument: &TypeRef{ModuleOID: "0.4.0.0.1.3.14.22", ASN1Name: "SS-InvocationNotificationArg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "SSInvocationNotificationArg"}, Result: &TypeRef{ModuleOID: "0.4.0.0.1.3.14.22", ASN1Name: "SS-InvocationNotificationRes", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "SSInvocationNotificationRes"}, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: false, Source: sourceInfo1("ss-InvocationNotification", "17.6.4"), Errors: []ErrorInfo{infoDataMissingError(), infoUnexpectedDataValueError(), infoUnknownSubscriberError()}, Linked: []MAPOperationCode{}}
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

// UpdateVcsgLocationErrors selects exactly the formal ERRORS set of MAP-MobileServiceOperations.updateVcsgLocation.
type UpdateVcsgLocationErrors struct {
	SystemFailure       *ErrorValue[SystemFailureParam]
	UnexpectedDataValue *ErrorValue[UnexpectedDataParam]
	UnknownSubscriber   *ErrorValue[UnknownSubscriberParam]
}

func infoUpdateVcsgLocationOperation() OperationInfo {
	return OperationInfo{Name: "updateVcsgLocation", Code: UpdateVcsgLocation, Argument: &TypeRef{ModuleOID: "0.4.0.0.1.3.11.22", ASN1Name: "UpdateVcsgLocationArg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "UpdateVcsgLocationArg"}, Result: &TypeRef{ModuleOID: "0.4.0.0.1.3.11.22", ASN1Name: "UpdateVcsgLocationRes", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "UpdateVcsgLocationRes"}, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: false, Source: sourceInfo4("updateVcsgLocation", "17.6.1"), Errors: []ErrorInfo{infoSystemFailureError(), infoUnexpectedDataValueError(), infoUnknownSubscriberError()}, Linked: []MAPOperationCode{}}
}

// Operations returns detached metadata snapshots of the source operation catalogue.
func Operations() []OperationInfo {
	return []OperationInfo{infoActivateSSOperation(), infoActivateTraceModeOperation(), infoAlertServiceCentreOperation(), infoAnyTimeInterrogationOperation(), infoAnyTimeModificationOperation(), infoAnyTimeSubscriptionInterrogationOperation(), infoAuthenticationFailureReportOperation(), infoCancelLocationOperation(), infoCancelVcsgLocationOperation(), infoCheckIMEIOperation(), infoDeactivateSSOperation(), infoDeactivateTraceModeOperation(), infoDeleteSubscriberDataOperation(), infoEraseCCEntryOperation(), infoEraseSSOperation(), infoFailureReportOperation(), infoForwardAccessSignallingOperation(), infoForwardCheckSSIndicationOperation(), infoForwardGroupCallSignallingOperation(), infoGetPasswordOperation(), infoInformServiceCentreOperation(), infoInsertSubscriberDataOperation(), infoInterrogateSSOperation(), infoIstAlertOperation(), infoIstCommandOperation(), infoMoForwardSMOperation(), infoMtForwardSMOperation(), infoMtForwardSMVGCSOperation(), infoNoteMMEventOperation(), infoNoteMsPresentForGprsOperation(), infoNoteSubscriberDataModifiedOperation(), infoPrepareGroupCallOperation(), infoPrepareHandoverOperation(), infoPrepareSubsequentHandoverOperation(), infoProcessAccessSignallingOperation(), infoProcessGroupCallSignallingOperation(), infoProcessUnstructuredSSRequestOperation(), infoProvideRoamingNumberOperation(), infoProvideSubscriberInfoOperation(), infoProvideSubscriberLocationOperation(), infoPurgeMSOperation(), infoReadyForSMOperation(), infoRegisterCCEntryOperation(), infoRegisterPasswordOperation(), infoRegisterSSOperation(), infoReleaseResourcesOperation(), infoRemoteUserFreeOperation(), infoReportSMDeliveryStatusOperation(), infoResetOperation(), infoRestoreDataOperation(), infoResumeCallHandlingOperation(), infoSendAuthenticationInfoOperation(), infoSendEndSignalOperation(), infoSendGroupCallEndSignalOperation(), infoSendGroupCallInfoOperation(), infoSendIMSIOperation(), infoSendIdentificationOperation(), infoSendRoutingInfoOperation(), infoSendRoutingInfoForGprsOperation(), infoSendRoutingInfoForLCSOperation(), infoSendRoutingInfoForSMOperation(), infoSetReportingStateOperation(), infoSsInvocationNotificationOperation(), infoStatusReportOperation(), infoSubscriberLocationReportOperation(), infoUnstructuredSSNotifyOperation(), infoUnstructuredSSRequestOperation(), infoUpdateGprsLocationOperation(), infoUpdateLocationOperation(), infoUpdateVcsgLocationOperation()}
}

// LookupOperation returns detached metadata for code, or zero metadata and false if absent.
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

func infoSSDeflectionToServedSubscriberError() SSErrorInfo {
	return SSErrorInfo{Name: "deflectionToServedSubscriber", Code: SSDeflectionToServedSubscriber, Parameter: nil, ParameterOptional: nil, Source: sourceInfo8("deflectionToServedSubscriber", "4.3")}
}
func infoSSInvalidDeflectedToNumberError() SSErrorInfo {
	return SSErrorInfo{Name: "invalidDeflectedToNumber", Code: SSInvalidDeflectedToNumber, Parameter: nil, ParameterOptional: nil, Source: sourceInfo8("invalidDeflectedToNumber", "4.3")}
}
func infoSSLcsInvalidPruError() SSErrorInfo {
	return SSErrorInfo{Name: "lcs-invalidPru", Code: SSLcsInvalidPru, Parameter: nil, ParameterOptional: nil, Source: sourceInfo8("lcs-invalidPru", "4.3")}
}
func infoSSLcsPruAssociationRejError() SSErrorInfo {
	return SSErrorInfo{Name: "lcs-PruAssociationRej", Code: SSLcsPruAssociationRej, Parameter: &TypeRef{ModuleOID: "0.4.0.0.2.3.1.18", ASN1Name: "PruAssociationRejParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "PruAssociationRejParam"}, ParameterOptional: nil, Source: sourceInfo8("lcs-PruAssociationRej", "4.3")}
}
func infoSSMaxNumberOfMPTYParticipantsExceededError() SSErrorInfo {
	return SSErrorInfo{Name: "maxNumberOfMPTY-ParticipantsExceeded", Code: SSMaxNumberOfMPTYParticipantsExceeded, Parameter: nil, ParameterOptional: nil, Source: sourceInfo8("maxNumberOfMPTY-ParticipantsExceeded", "4.3")}
}
func infoSSRejectedByNetworkError() SSErrorInfo {
	return SSErrorInfo{Name: "rejectedByNetwork", Code: SSRejectedByNetwork, Parameter: nil, ParameterOptional: nil, Source: sourceInfo8("rejectedByNetwork", "4.3")}
}
func infoSSRejectedByUserError() SSErrorInfo {
	return SSErrorInfo{Name: "rejectedByUser", Code: SSRejectedByUser, Parameter: nil, ParameterOptional: nil, Source: sourceInfo8("rejectedByUser", "4.3")}
}
func infoSSResourcesNotAvailableError() SSErrorInfo {
	return SSErrorInfo{Name: "resourcesNotAvailable", Code: SSResourcesNotAvailable, Parameter: nil, ParameterOptional: nil, Source: sourceInfo8("resourcesNotAvailable", "4.3")}
}
func infoSSSpecialServiceCodeError() SSErrorInfo {
	return SSErrorInfo{Name: "specialServiceCode", Code: SSSpecialServiceCode, Parameter: nil, ParameterOptional: nil, Source: sourceInfo8("specialServiceCode", "4.3")}
}

// SSErrors returns detached metadata snapshots of the source error catalogue.
func SSErrors() []SSErrorInfo {
	return []SSErrorInfo{infoSSDeflectionToServedSubscriberError(), infoSSInvalidDeflectedToNumberError(), infoSSLcsInvalidPruError(), infoSSLcsPruAssociationRejError(), infoSSMaxNumberOfMPTYParticipantsExceededError(), infoSSRejectedByNetworkError(), infoSSRejectedByUserError(), infoSSResourcesNotAvailableError(), infoSSSpecialServiceCodeError()}
}

// LookupSSError returns detached metadata for code, or zero metadata and false if absent.
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
type SSOperationInfo struct {
	Name                               string
	Code                               SSOperationCode
	Argument, Result                   *TypeRef
	ArgumentOptional, ResultOptional   *bool
	ReturnResult, ReturnResultExplicit bool
	Errors                             []SSErrorMemberInfo
	Source                             SourceRef
}

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

// SSForwardCUGInfoErrors selects exactly the formal ERRORS set of SS-Operations.forwardCUG-Info.
type SSForwardCUGInfoErrors struct {
}

func infoSSForwardCUGInfoOperation() SSOperationInfo {
	return SSOperationInfo{Name: "forwardCUG-Info", Code: SSForwardCUGInfo, Argument: &TypeRef{ModuleOID: "0.4.0.0.2.3.2.18", ASN1Name: "ForwardCUG-InfoArg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "ForwardCUGInfoArg"}, Result: nil, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: false, Source: sourceInfo9("forwardCUG-Info", "4.2"), Errors: []SSErrorMemberInfo{}}
}

// SSForwardChargeAdviceErrors selects exactly the formal ERRORS set of SS-Operations.forwardChargeAdvice.
type SSForwardChargeAdviceErrors struct {
}

func infoSSForwardChargeAdviceOperation() SSOperationInfo {
	return SSOperationInfo{Name: "forwardChargeAdvice", Code: SSForwardChargeAdvice, Argument: &TypeRef{ModuleOID: "0.4.0.0.2.3.2.18", ASN1Name: "ForwardChargeAdviceArg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "ForwardChargeAdviceArg"}, Result: nil, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: true, Source: sourceInfo9("forwardChargeAdvice", "4.2"), Errors: []SSErrorMemberInfo{}}
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

// SSLcsAreaEventCancellationErrors selects exactly the formal ERRORS set of SS-Operations.lcs-AreaEventCancellation.
type SSLcsAreaEventCancellationErrors struct {
	SystemFailure        *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam]
	FacilityNotSupported *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParam]
	UnexpectedDataValue  *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParam]
}

func infoSSLcsAreaEventCancellationOperation() SSOperationInfo {
	return SSOperationInfo{Name: "lcs-AreaEventCancellation", Code: SSLcsAreaEventCancellation, Argument: &TypeRef{ModuleOID: "0.4.0.0.2.3.2.18", ASN1Name: "LCS-AreaEventCancellationArg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "LCSAreaEventCancellationArg"}, Result: nil, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: true, Source: sourceInfo9("lcs-AreaEventCancellation", "4.2"), Errors: []SSErrorMemberInfo{SSErrorMemberInfo{Name: "systemFailure", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 34, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "SystemFailureParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERSystemFailureParam"}, Source: sourceInfo10("systemFailure", "17.6.6")}, SSErrorMemberInfo{Name: "facilityNotSupported", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 21, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "FacilityNotSupParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERFacilityNotSupParam"}, Source: sourceInfo10("facilityNotSupported", "17.6.6")}, SSErrorMemberInfo{Name: "unexpectedDataValue", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 36, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "UnexpectedDataParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERUnexpectedDataParam"}, Source: sourceInfo10("unexpectedDataValue", "17.6.6")}}}
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

// SSLcsAreaEventRequestErrors selects exactly the formal ERRORS set of SS-Operations.lcs-AreaEventRequest.
type SSLcsAreaEventRequestErrors struct {
	SystemFailure        *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam]
	FacilityNotSupported *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParam]
	UnexpectedDataValue  *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParam]
}

func infoSSLcsAreaEventRequestOperation() SSOperationInfo {
	return SSOperationInfo{Name: "lcs-AreaEventRequest", Code: SSLcsAreaEventRequest, Argument: &TypeRef{ModuleOID: "0.4.0.0.2.3.2.18", ASN1Name: "LCS-AreaEventRequestArg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "LCSAreaEventRequestArg"}, Result: nil, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: true, Source: sourceInfo9("lcs-AreaEventRequest", "4.2"), Errors: []SSErrorMemberInfo{SSErrorMemberInfo{Name: "systemFailure", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 34, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "SystemFailureParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERSystemFailureParam"}, Source: sourceInfo10("systemFailure", "17.6.6")}, SSErrorMemberInfo{Name: "facilityNotSupported", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 21, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "FacilityNotSupParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERFacilityNotSupParam"}, Source: sourceInfo10("facilityNotSupported", "17.6.6")}, SSErrorMemberInfo{Name: "unexpectedDataValue", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 36, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "UnexpectedDataParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERUnexpectedDataParam"}, Source: sourceInfo10("unexpectedDataValue", "17.6.6")}}}
}

// SSLcsCancelDeferredLocationErrors selects exactly the formal ERRORS set of SS-Operations.lcs-CancelDeferredLocation.
type SSLcsCancelDeferredLocationErrors struct {
	SystemFailure       *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam]
	UnexpectedDataValue *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParam]
}

func infoSSLcsCancelDeferredLocationOperation() SSOperationInfo {
	return SSOperationInfo{Name: "lcs-CancelDeferredLocation", Code: SSLcsCancelDeferredLocation, Argument: &TypeRef{ModuleOID: "0.4.0.0.2.3.2.18", ASN1Name: "LCS-CancelDeferredLocationArg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "LCSCancelDeferredLocationArg"}, Result: nil, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: true, Source: sourceInfo9("lcs-CancelDeferredLocation", "4.2"), Errors: []SSErrorMemberInfo{SSErrorMemberInfo{Name: "systemFailure", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 34, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "SystemFailureParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERSystemFailureParam"}, Source: sourceInfo10("systemFailure", "17.6.6")}, SSErrorMemberInfo{Name: "unexpectedDataValue", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 36, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "UnexpectedDataParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERUnexpectedDataParam"}, Source: sourceInfo10("unexpectedDataValue", "17.6.6")}}}
}

// SSLcsDLRSPPTransportErrors selects exactly the formal ERRORS set of SS-Operations.lcs-DLRSPPTransport.
type SSLcsDLRSPPTransportErrors struct {
	SystemFailure        *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam]
	FacilityNotSupported *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParam]
}

func infoSSLcsDLRSPPTransportOperation() SSOperationInfo {
	return SSOperationInfo{Name: "lcs-DLRSPPTransport", Code: SSLcsDLRSPPTransport, Argument: &TypeRef{ModuleOID: "0.4.0.0.2.3.2.18", ASN1Name: "LCS-DLRSPPTransportArg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "LCSDLRSPPTransportArg"}, Result: &TypeRef{ModuleOID: "0.4.0.0.2.3.2.18", ASN1Name: "LCS-DLRSPPTransportRes", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "LCSDLRSPPTransportRes"}, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: false, Source: sourceInfo9("lcs-DLRSPPTransport", "4.2"), Errors: []SSErrorMemberInfo{SSErrorMemberInfo{Name: "systemFailure", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 34, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "SystemFailureParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERSystemFailureParam"}, Source: sourceInfo10("systemFailure", "17.6.6")}, SSErrorMemberInfo{Name: "facilityNotSupported", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 21, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "FacilityNotSupParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERFacilityNotSupParam"}, Source: sourceInfo10("facilityNotSupported", "17.6.6")}}}
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

// SSLcsLocationNotificationErrors selects exactly the formal ERRORS set of SS-Operations.lcs-LocationNotification.
type SSLcsLocationNotificationErrors struct {
	SystemFailure       *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam]
	UnexpectedDataValue *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParam]
}

func infoSSLcsLocationNotificationOperation() SSOperationInfo {
	return SSOperationInfo{Name: "lcs-LocationNotification", Code: SSLcsLocationNotification, Argument: &TypeRef{ModuleOID: "0.4.0.0.2.3.2.18", ASN1Name: "LocationNotificationArg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "LocationNotificationArg"}, Result: &TypeRef{ModuleOID: "0.4.0.0.2.3.2.18", ASN1Name: "LocationNotificationRes", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "LocationNotificationRes"}, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: false, Source: sourceInfo9("lcs-LocationNotification", "4.2"), Errors: []SSErrorMemberInfo{SSErrorMemberInfo{Name: "systemFailure", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 34, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "SystemFailureParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERSystemFailureParam"}, Source: sourceInfo10("systemFailure", "17.6.6")}, SSErrorMemberInfo{Name: "unexpectedDataValue", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 36, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "UnexpectedDataParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERUnexpectedDataParam"}, Source: sourceInfo10("unexpectedDataValue", "17.6.6")}}}
}

// SSLcsLocationPrivacySettingErrors selects exactly the formal ERRORS set of SS-Operations.lcs-LocationPrivacySetting.
type SSLcsLocationPrivacySettingErrors struct {
	SystemFailure       *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam]
	UnexpectedDataValue *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParam]
}

func infoSSLcsLocationPrivacySettingOperation() SSOperationInfo {
	return SSOperationInfo{Name: "lcs-LocationPrivacySetting", Code: SSLcsLocationPrivacySetting, Argument: &TypeRef{ModuleOID: "0.4.0.0.2.3.2.18", ASN1Name: "LCS-LocationPrivacySettingArg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "LCSLocationPrivacySettingArg"}, Result: nil, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: true, Source: sourceInfo9("lcs-LocationPrivacySetting", "4.2"), Errors: []SSErrorMemberInfo{SSErrorMemberInfo{Name: "systemFailure", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 34, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "SystemFailureParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERSystemFailureParam"}, Source: sourceInfo10("systemFailure", "17.6.6")}, SSErrorMemberInfo{Name: "unexpectedDataValue", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 36, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "UnexpectedDataParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERUnexpectedDataParam"}, Source: sourceInfo10("unexpectedDataValue", "17.6.6")}}}
}

// SSLcsLocationUpdateErrors selects exactly the formal ERRORS set of SS-Operations.lcs-LocationUpdate.
type SSLcsLocationUpdateErrors struct {
	SystemFailure       *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam]
	UnexpectedDataValue *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParam]
}

func infoSSLcsLocationUpdateOperation() SSOperationInfo {
	return SSOperationInfo{Name: "lcs-LocationUpdate", Code: SSLcsLocationUpdate, Argument: &TypeRef{ModuleOID: "0.4.0.0.2.3.2.18", ASN1Name: "LCS-LocationUpdateArg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "LCSLocationUpdateArg"}, Result: &TypeRef{ModuleOID: "0.4.0.0.2.3.2.18", ASN1Name: "LCS-LocationUpdateRes", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "LCSLocationUpdateRes"}, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: false, Source: sourceInfo9("lcs-LocationUpdate", "4.2"), Errors: []SSErrorMemberInfo{SSErrorMemberInfo{Name: "systemFailure", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 34, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "SystemFailureParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERSystemFailureParam"}, Source: sourceInfo10("systemFailure", "17.6.6")}, SSErrorMemberInfo{Name: "unexpectedDataValue", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 36, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "UnexpectedDataParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERUnexpectedDataParam"}, Source: sourceInfo10("unexpectedDataValue", "17.6.6")}}}
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

// SSLcsMSCancelDeferredLocationErrors selects exactly the formal ERRORS set of SS-Operations.lcs-MSCancelDeferredLocation.
type SSLcsMSCancelDeferredLocationErrors struct {
	SystemFailure       *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam]
	UnexpectedDataValue *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParam]
}

func infoSSLcsMSCancelDeferredLocationOperation() SSOperationInfo {
	return SSOperationInfo{Name: "lcs-MSCancelDeferredLocation", Code: SSLcsMSCancelDeferredLocation, Argument: &TypeRef{ModuleOID: "0.4.0.0.2.3.2.18", ASN1Name: "LCS-CancelDeferredLocationArg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "LCSCancelDeferredLocationArg"}, Result: nil, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: true, Source: sourceInfo9("lcs-MSCancelDeferredLocation", "4.2"), Errors: []SSErrorMemberInfo{SSErrorMemberInfo{Name: "systemFailure", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 34, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "SystemFailureParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERSystemFailureParam"}, Source: sourceInfo10("systemFailure", "17.6.6")}, SSErrorMemberInfo{Name: "unexpectedDataValue", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 36, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "UnexpectedDataParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERUnexpectedDataParam"}, Source: sourceInfo10("unexpectedDataValue", "17.6.6")}}}
}

// SSLcsPeriodicLocationCancellationErrors selects exactly the formal ERRORS set of SS-Operations.lcs-PeriodicLocationCancellation.
type SSLcsPeriodicLocationCancellationErrors struct {
	SystemFailure       *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam]
	UnexpectedDataValue *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParam]
}

func infoSSLcsPeriodicLocationCancellationOperation() SSOperationInfo {
	return SSOperationInfo{Name: "lcs-PeriodicLocationCancellation", Code: SSLcsPeriodicLocationCancellation, Argument: &TypeRef{ModuleOID: "0.4.0.0.2.3.2.18", ASN1Name: "LCS-PeriodicLocationCancellationArg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "LCSPeriodicLocationCancellationArg"}, Result: nil, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: true, Source: sourceInfo9("lcs-PeriodicLocationCancellation", "4.2"), Errors: []SSErrorMemberInfo{SSErrorMemberInfo{Name: "systemFailure", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 34, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "SystemFailureParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERSystemFailureParam"}, Source: sourceInfo10("systemFailure", "17.6.6")}, SSErrorMemberInfo{Name: "unexpectedDataValue", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 36, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "UnexpectedDataParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERUnexpectedDataParam"}, Source: sourceInfo10("unexpectedDataValue", "17.6.6")}}}
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

// SSLcsPruDisassociationErrors selects exactly the formal ERRORS set of SS-Operations.lcs-PruDisassociation.
type SSLcsPruDisassociationErrors struct {
	SystemFailure       *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam]
	UnexpectedDataValue *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParam]
}

func infoSSLcsPruDisassociationOperation() SSOperationInfo {
	return SSOperationInfo{Name: "lcs-PruDisassociation", Code: SSLcsPruDisassociation, Argument: &TypeRef{ModuleOID: "0.4.0.0.2.3.2.18", ASN1Name: "LCS-PruDisassociationArg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "LCSPruDisassociationArg"}, Result: nil, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: true, Source: sourceInfo9("lcs-PruDisassociation", "4.2"), Errors: []SSErrorMemberInfo{SSErrorMemberInfo{Name: "systemFailure", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 34, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "SystemFailureParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERSystemFailureParam"}, Source: sourceInfo10("systemFailure", "17.6.6")}, SSErrorMemberInfo{Name: "unexpectedDataValue", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 36, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "UnexpectedDataParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERUnexpectedDataParam"}, Source: sourceInfo10("unexpectedDataValue", "17.6.6")}}}
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

// SSLcsULRSPPTransportErrors selects exactly the formal ERRORS set of SS-Operations.lcs-ULRSPPTransport.
type SSLcsULRSPPTransportErrors struct {
	SystemFailure        *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam]
	FacilityNotSupported *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERFacilityNotSupParam]
}

func infoSSLcsULRSPPTransportOperation() SSOperationInfo {
	return SSOperationInfo{Name: "lcs-ULRSPPTransport", Code: SSLcsULRSPPTransport, Argument: &TypeRef{ModuleOID: "0.4.0.0.2.3.2.18", ASN1Name: "LCS-ULRSPPTransportArg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "LCSULRSPPTransportArg"}, Result: &TypeRef{ModuleOID: "0.4.0.0.2.3.2.18", ASN1Name: "LCS-ULRSPPTransportRes", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "LCSULRSPPTransportRes"}, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: false, Source: sourceInfo9("lcs-ULRSPPTransport", "4.2"), Errors: []SSErrorMemberInfo{SSErrorMemberInfo{Name: "systemFailure", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 34, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "SystemFailureParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERSystemFailureParam"}, Source: sourceInfo10("systemFailure", "17.6.6")}, SSErrorMemberInfo{Name: "facilityNotSupported", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 21, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "FacilityNotSupParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERFacilityNotSupParam"}, Source: sourceInfo10("facilityNotSupported", "17.6.6")}}}
}

// SSNotifySSErrors selects exactly the formal ERRORS set of SS-Operations.notifySS.
type SSNotifySSErrors struct {
}

func infoSSNotifySSOperation() SSOperationInfo {
	return SSOperationInfo{Name: "notifySS", Code: SSNotifySS, Argument: &TypeRef{ModuleOID: "0.4.0.0.2.3.2.18", ASN1Name: "NotifySS-Arg", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "NotifySSArg"}, Result: nil, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: false, Source: sourceInfo9("notifySS", "4.2"), Errors: []SSErrorMemberInfo{}}
}

// SSProcessUnstructuredSSDataErrors selects exactly the formal ERRORS set of SS-Operations.processUnstructuredSS-Data.
type SSProcessUnstructuredSSDataErrors struct {
	SystemFailure       *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERSystemFailureParam]
	UnexpectedDataValue *ErrorValue[__asn1pkg_v21_map_er_datatypes.ERUnexpectedDataParam]
}

func infoSSProcessUnstructuredSSDataOperation() SSOperationInfo {
	return SSOperationInfo{Name: "processUnstructuredSS-Data", Code: SSProcessUnstructuredSSData, Argument: &TypeRef{ModuleOID: "0.4.0.0.2.3.2.18", ASN1Name: "SS-UserData", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "SSUserData"}, Result: &TypeRef{ModuleOID: "0.4.0.0.2.3.2.18", ASN1Name: "SS-UserData", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map", GoName: "SSUserData"}, ArgumentOptional: nil, ResultOptional: nil, ReturnResult: true, ReturnResultExplicit: false, Source: sourceInfo9("processUnstructuredSS-Data", "4.2"), Errors: []SSErrorMemberInfo{SSErrorMemberInfo{Name: "systemFailure", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 34, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "SystemFailureParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERSystemFailureParam"}, Source: sourceInfo10("systemFailure", "17.6.6")}, SSErrorMemberInfo{Name: "unexpectedDataValue", DeclaringModuleOID: "{#0/#4/#0/#0/#1/#3/#10/#21}", LocalCode: 36, Parameter: &TypeRef{ModuleOID: "0.4.0.0.1.3.17.21", ASN1Name: "UnexpectedDataParam", GoPackage: "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes", GoName: "ERUnexpectedDataParam"}, Source: sourceInfo10("unexpectedDataValue", "17.6.6")}}}
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

// SSOperations returns detached metadata snapshots of the source operation catalogue.
func SSOperations() []SSOperationInfo {
	return []SSOperationInfo{infoSSAccessRegisterCCEntryOperation(), infoSSBuildMPTYOperation(), infoSSCallDeflectionOperation(), infoSSExplicitCTOperation(), infoSSForwardCUGInfoOperation(), infoSSForwardChargeAdviceOperation(), infoSSHoldMPTYOperation(), infoSSLcsAreaEventCancellationOperation(), infoSSLcsAreaEventReportOperation(), infoSSLcsAreaEventRequestOperation(), infoSSLcsCancelDeferredLocationOperation(), infoSSLcsDLRSPPTransportOperation(), infoSSLcsEventReportOperation(), infoSSLcsLocationNotificationOperation(), infoSSLcsLocationPrivacySettingOperation(), infoSSLcsLocationUpdateOperation(), infoSSLcsMOLROperation(), infoSSLcsMSCancelDeferredLocationOperation(), infoSSLcsPeriodicLocationCancellationOperation(), infoSSLcsPeriodicLocationRequestOperation(), infoSSLcsPeriodicTriggeredInvokeOperation(), infoSSLcsPruAssociationOperation(), infoSSLcsPruDisassociationOperation(), infoSSLcsSLMOLROperation(), infoSSLcsSLMTLROperation(), infoSSLcsULRSPPTransportOperation(), infoSSNotifySSOperation(), infoSSProcessUnstructuredSSDataOperation(), infoSSRetrieveMPTYOperation(), infoSSSplitMPTYOperation(), infoSSUserUserServiceOperation()}
}

// LookupSSOperation returns detached metadata for code, or zero metadata and false if absent.
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

// ApplicationContexts returns detached source OID and version metadata without negotiation policy.
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

// LookupApplicationContext returns detached metadata for oid, or a zero context and false if absent.
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
