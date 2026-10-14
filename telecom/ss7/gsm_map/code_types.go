// Code generated from ASN.1. DO NOT EDIT.

// Codes retain information-object provenance (X.880 §§8.2.13, 8.3.5, 8.8).
package gsm_map

import "fmt"

// MAPOperationCode and MAPErrorCode are derived from the authenticated
// TS 29.002 V19.1.0 modules, §§17.5, 17.6.1–17.6.8 (70 operations, 56 errors).
// SSOperationCode and SSErrorCode belong to TS 24.080 V19.4.0 §§4.2–4.3;
// their identifiers start with SS and their code space is independent of MAP.
// Code 38's current MAP name is forwardCheckSS-Indication.
// TS 29.002 §17.5 reserves operation numbers 9, 19, 28, 30, 31, 32, 35, 48,
// 49, 52, 54 and error numbers 2, 23, 24 for historical uses. They are not
// current MAP information objects. Historical protocol variants remain in
// their declaring modules.
// MAPsec operations are absent from the current MAP catalogue (CR 0806,
// C4-060705).

// MAPErrorCode is a local INTEGER code.
type MAPErrorCode int64

const (
	// SystemFailure identifies systemFailure. Source: map-29002-v22/modules/MAP-Errors.asn; SHA-256 fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346.
	SystemFailure MAPErrorCode = 34
	// DataMissing identifies dataMissing. Source: map-29002-v22/modules/MAP-Errors.asn; SHA-256 fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346.
	DataMissing MAPErrorCode = 35
	// UnexpectedDataValue identifies unexpectedDataValue. Source: map-29002-v22/modules/MAP-Errors.asn; SHA-256 fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346.
	UnexpectedDataValue MAPErrorCode = 36
	// FacilityNotSupported identifies facilityNotSupported. Source: map-29002-v22/modules/MAP-Errors.asn; SHA-256 fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346.
	FacilityNotSupported MAPErrorCode = 21
	// IncompatibleTerminal identifies incompatibleTerminal. Source: map-29002-v22/modules/MAP-Errors.asn; SHA-256 fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346.
	IncompatibleTerminal MAPErrorCode = 28
	// ResourceLimitation identifies resourceLimitation. Source: map-29002-v22/modules/MAP-Errors.asn; SHA-256 fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346.
	ResourceLimitation MAPErrorCode = 51
	// UnknownSubscriber identifies unknownSubscriber. Source: map-29002-v22/modules/MAP-Errors.asn; SHA-256 fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346.
	UnknownSubscriber MAPErrorCode = 1
	// NumberChanged identifies numberChanged. Source: map-29002-v22/modules/MAP-Errors.asn; SHA-256 fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346.
	NumberChanged MAPErrorCode = 44
	// UnknownMSC identifies unknownMSC. Source: map-29002-v22/modules/MAP-Errors.asn; SHA-256 fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346.
	UnknownMSC MAPErrorCode = 3
	// UnidentifiedSubscriber identifies unidentifiedSubscriber. Source: map-29002-v22/modules/MAP-Errors.asn; SHA-256 fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346.
	UnidentifiedSubscriber MAPErrorCode = 5
	// UnknownEquipment identifies unknownEquipment. Source: map-29002-v22/modules/MAP-Errors.asn; SHA-256 fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346.
	UnknownEquipment MAPErrorCode = 7
	// RoamingNotAllowed identifies roamingNotAllowed. Source: map-29002-v22/modules/MAP-Errors.asn; SHA-256 fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346.
	RoamingNotAllowed MAPErrorCode = 8
	// IllegalSubscriber identifies illegalSubscriber. Source: map-29002-v22/modules/MAP-Errors.asn; SHA-256 fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346.
	IllegalSubscriber MAPErrorCode = 9
	// IllegalEquipment identifies illegalEquipment. Source: map-29002-v22/modules/MAP-Errors.asn; SHA-256 fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346.
	IllegalEquipment MAPErrorCode = 12
	// BearerServiceNotProvisioned identifies bearerServiceNotProvisioned. Source: map-29002-v22/modules/MAP-Errors.asn; SHA-256 fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346.
	BearerServiceNotProvisioned MAPErrorCode = 10
	// TeleserviceNotProvisioned identifies teleserviceNotProvisioned. Source: map-29002-v22/modules/MAP-Errors.asn; SHA-256 fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346.
	TeleserviceNotProvisioned MAPErrorCode = 11
	// NoHandoverNumberAvailable identifies noHandoverNumberAvailable. Source: map-29002-v22/modules/MAP-Errors.asn; SHA-256 fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346.
	NoHandoverNumberAvailable MAPErrorCode = 25
	// SubsequentHandoverFailure identifies subsequentHandoverFailure. Source: map-29002-v22/modules/MAP-Errors.asn; SHA-256 fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346.
	SubsequentHandoverFailure MAPErrorCode = 26
	// TargetCellOutsideGroupCallArea identifies targetCellOutsideGroupCallArea. Source: map-29002-v22/modules/MAP-Errors.asn; SHA-256 fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346.
	TargetCellOutsideGroupCallArea MAPErrorCode = 42
	// TracingBufferFull identifies tracingBufferFull. Source: map-29002-v22/modules/MAP-Errors.asn; SHA-256 fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346.
	TracingBufferFull MAPErrorCode = 40
	// NoRoamingNumberAvailable identifies noRoamingNumberAvailable. Source: map-29002-v22/modules/MAP-Errors.asn; SHA-256 fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346.
	NoRoamingNumberAvailable MAPErrorCode = 39
	// AbsentSubscriber identifies absentSubscriber. Source: map-29002-v22/modules/MAP-Errors.asn; SHA-256 fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346.
	AbsentSubscriber MAPErrorCode = 27
	// BusySubscriber identifies busySubscriber. Source: map-29002-v22/modules/MAP-Errors.asn; SHA-256 fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346.
	BusySubscriber MAPErrorCode = 45
	// NoSubscriberReply identifies noSubscriberReply. Source: map-29002-v22/modules/MAP-Errors.asn; SHA-256 fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346.
	NoSubscriberReply MAPErrorCode = 46
	// CallBarred identifies callBarred. Source: map-29002-v22/modules/MAP-Errors.asn; SHA-256 fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346.
	CallBarred MAPErrorCode = 13
	// ForwardingViolation identifies forwardingViolation. Source: map-29002-v22/modules/MAP-Errors.asn; SHA-256 fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346.
	ForwardingViolation MAPErrorCode = 14
	// ForwardingFailed identifies forwardingFailed. Source: map-29002-v22/modules/MAP-Errors.asn; SHA-256 fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346.
	ForwardingFailed MAPErrorCode = 47
	// CugReject identifies cug-Reject. Source: map-29002-v22/modules/MAP-Errors.asn; SHA-256 fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346.
	CugReject MAPErrorCode = 15
	// OrNotAllowed identifies or-NotAllowed. Source: map-29002-v22/modules/MAP-Errors.asn; SHA-256 fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346.
	OrNotAllowed MAPErrorCode = 48
	// AtiNotAllowed identifies ati-NotAllowed. Source: map-29002-v22/modules/MAP-Errors.asn; SHA-256 fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346.
	AtiNotAllowed MAPErrorCode = 49
	// AtsiNotAllowed identifies atsi-NotAllowed. Source: map-29002-v22/modules/MAP-Errors.asn; SHA-256 fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346.
	AtsiNotAllowed MAPErrorCode = 60
	// AtmNotAllowed identifies atm-NotAllowed. Source: map-29002-v22/modules/MAP-Errors.asn; SHA-256 fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346.
	AtmNotAllowed MAPErrorCode = 61
	// InformationNotAvailable identifies informationNotAvailable. Source: map-29002-v22/modules/MAP-Errors.asn; SHA-256 fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346.
	InformationNotAvailable MAPErrorCode = 62
	// IllegalSSOperation identifies illegalSS-Operation. Source: map-29002-v22/modules/MAP-Errors.asn; SHA-256 fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346.
	IllegalSSOperation MAPErrorCode = 16
	// SsErrorStatus identifies ss-ErrorStatus. Source: map-29002-v22/modules/MAP-Errors.asn; SHA-256 fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346.
	SsErrorStatus MAPErrorCode = 17
	// SsNotAvailable identifies ss-NotAvailable. Source: map-29002-v22/modules/MAP-Errors.asn; SHA-256 fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346.
	SsNotAvailable MAPErrorCode = 18
	// SsSubscriptionViolation identifies ss-SubscriptionViolation. Source: map-29002-v22/modules/MAP-Errors.asn; SHA-256 fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346.
	SsSubscriptionViolation MAPErrorCode = 19
	// SsIncompatibility identifies ss-Incompatibility. Source: map-29002-v22/modules/MAP-Errors.asn; SHA-256 fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346.
	SsIncompatibility MAPErrorCode = 20
	// UnknownAlphabet identifies unknownAlphabet. Source: map-29002-v22/modules/MAP-Errors.asn; SHA-256 fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346.
	UnknownAlphabet MAPErrorCode = 71
	// UssdBusy identifies ussd-Busy. Source: map-29002-v22/modules/MAP-Errors.asn; SHA-256 fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346.
	UssdBusy MAPErrorCode = 72
	// PwRegistrationFailure identifies pw-RegistrationFailure. Source: map-29002-v22/modules/MAP-Errors.asn; SHA-256 fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346.
	PwRegistrationFailure MAPErrorCode = 37
	// NegativePWCheck identifies negativePW-Check. Source: map-29002-v22/modules/MAP-Errors.asn; SHA-256 fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346.
	NegativePWCheck MAPErrorCode = 38
	// NumberOfPWAttemptsViolation identifies numberOfPW-AttemptsViolation. Source: map-29002-v22/modules/MAP-Errors.asn; SHA-256 fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346.
	NumberOfPWAttemptsViolation MAPErrorCode = 43
	// ShortTermDenial identifies shortTermDenial. Source: map-29002-v22/modules/MAP-Errors.asn; SHA-256 fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346.
	ShortTermDenial MAPErrorCode = 29
	// LongTermDenial identifies longTermDenial. Source: map-29002-v22/modules/MAP-Errors.asn; SHA-256 fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346.
	LongTermDenial MAPErrorCode = 30
	// SubscriberBusyForMTSMS identifies subscriberBusyForMT-SMS. Source: map-29002-v22/modules/MAP-Errors.asn; SHA-256 fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346.
	SubscriberBusyForMTSMS MAPErrorCode = 31
	// SmDeliveryFailure identifies sm-DeliveryFailure. Source: map-29002-v22/modules/MAP-Errors.asn; SHA-256 fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346.
	SmDeliveryFailure MAPErrorCode = 32
	// MessageWaitingListFull identifies messageWaitingListFull. Source: map-29002-v22/modules/MAP-Errors.asn; SHA-256 fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346.
	MessageWaitingListFull MAPErrorCode = 33
	// AbsentSubscriberSM identifies absentSubscriberSM. Source: map-29002-v22/modules/MAP-Errors.asn; SHA-256 fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346.
	AbsentSubscriberSM MAPErrorCode = 6
	// NoGroupCallNumberAvailable identifies noGroupCallNumberAvailable. Source: map-29002-v22/modules/MAP-Errors.asn; SHA-256 fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346.
	NoGroupCallNumberAvailable MAPErrorCode = 50
	// OngoingGroupCall identifies ongoingGroupCall. Source: map-29002-v22/modules/MAP-Errors.asn; SHA-256 fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346.
	OngoingGroupCall MAPErrorCode = 22
	// UnauthorizedRequestingNetwork identifies unauthorizedRequestingNetwork. Source: map-29002-v22/modules/MAP-Errors.asn; SHA-256 fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346.
	UnauthorizedRequestingNetwork MAPErrorCode = 52
	// UnauthorizedLCSClient identifies unauthorizedLCSClient. Source: map-29002-v22/modules/MAP-Errors.asn; SHA-256 fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346.
	UnauthorizedLCSClient MAPErrorCode = 53
	// PositionMethodFailure identifies positionMethodFailure. Source: map-29002-v22/modules/MAP-Errors.asn; SHA-256 fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346.
	PositionMethodFailure MAPErrorCode = 54
	// UnknownOrUnreachableLCSClient identifies unknownOrUnreachableLCSClient. Source: map-29002-v22/modules/MAP-Errors.asn; SHA-256 fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346.
	UnknownOrUnreachableLCSClient MAPErrorCode = 58
	// MmEventNotSupported identifies mm-EventNotSupported. Source: map-29002-v22/modules/MAP-Errors.asn; SHA-256 fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346.
	MmEventNotSupported MAPErrorCode = 59
)

// String returns the first source name for this code.
func (c MAPErrorCode) String() string {
	switch c {
	case SystemFailure:
		return "systemFailure"
	case DataMissing:
		return "dataMissing"
	case UnexpectedDataValue:
		return "unexpectedDataValue"
	case FacilityNotSupported:
		return "facilityNotSupported"
	case IncompatibleTerminal:
		return "incompatibleTerminal"
	case ResourceLimitation:
		return "resourceLimitation"
	case UnknownSubscriber:
		return "unknownSubscriber"
	case NumberChanged:
		return "numberChanged"
	case UnknownMSC:
		return "unknownMSC"
	case UnidentifiedSubscriber:
		return "unidentifiedSubscriber"
	case UnknownEquipment:
		return "unknownEquipment"
	case RoamingNotAllowed:
		return "roamingNotAllowed"
	case IllegalSubscriber:
		return "illegalSubscriber"
	case IllegalEquipment:
		return "illegalEquipment"
	case BearerServiceNotProvisioned:
		return "bearerServiceNotProvisioned"
	case TeleserviceNotProvisioned:
		return "teleserviceNotProvisioned"
	case NoHandoverNumberAvailable:
		return "noHandoverNumberAvailable"
	case SubsequentHandoverFailure:
		return "subsequentHandoverFailure"
	case TargetCellOutsideGroupCallArea:
		return "targetCellOutsideGroupCallArea"
	case TracingBufferFull:
		return "tracingBufferFull"
	case NoRoamingNumberAvailable:
		return "noRoamingNumberAvailable"
	case AbsentSubscriber:
		return "absentSubscriber"
	case BusySubscriber:
		return "busySubscriber"
	case NoSubscriberReply:
		return "noSubscriberReply"
	case CallBarred:
		return "callBarred"
	case ForwardingViolation:
		return "forwardingViolation"
	case ForwardingFailed:
		return "forwardingFailed"
	case CugReject:
		return "cug-Reject"
	case OrNotAllowed:
		return "or-NotAllowed"
	case AtiNotAllowed:
		return "ati-NotAllowed"
	case AtsiNotAllowed:
		return "atsi-NotAllowed"
	case AtmNotAllowed:
		return "atm-NotAllowed"
	case InformationNotAvailable:
		return "informationNotAvailable"
	case IllegalSSOperation:
		return "illegalSS-Operation"
	case SsErrorStatus:
		return "ss-ErrorStatus"
	case SsNotAvailable:
		return "ss-NotAvailable"
	case SsSubscriptionViolation:
		return "ss-SubscriptionViolation"
	case SsIncompatibility:
		return "ss-Incompatibility"
	case UnknownAlphabet:
		return "unknownAlphabet"
	case UssdBusy:
		return "ussd-Busy"
	case PwRegistrationFailure:
		return "pw-RegistrationFailure"
	case NegativePWCheck:
		return "negativePW-Check"
	case NumberOfPWAttemptsViolation:
		return "numberOfPW-AttemptsViolation"
	case ShortTermDenial:
		return "shortTermDenial"
	case LongTermDenial:
		return "longTermDenial"
	case SubscriberBusyForMTSMS:
		return "subscriberBusyForMT-SMS"
	case SmDeliveryFailure:
		return "sm-DeliveryFailure"
	case MessageWaitingListFull:
		return "messageWaitingListFull"
	case AbsentSubscriberSM:
		return "absentSubscriberSM"
	case NoGroupCallNumberAvailable:
		return "noGroupCallNumberAvailable"
	case OngoingGroupCall:
		return "ongoingGroupCall"
	case UnauthorizedRequestingNetwork:
		return "unauthorizedRequestingNetwork"
	case UnauthorizedLCSClient:
		return "unauthorizedLCSClient"
	case PositionMethodFailure:
		return "positionMethodFailure"
	case UnknownOrUnreachableLCSClient:
		return "unknownOrUnreachableLCSClient"
	case MmEventNotSupported:
		return "mm-EventNotSupported"
	default:
		return fmt.Sprintf("MAPErrorCode(%d)", int64(c))
	}
}

// MAPOperationCode is a local INTEGER code.
type MAPOperationCode int64

const (
	// SendRoutingInfo identifies sendRoutingInfo. Source: map-29002-v22/modules/MAP-CallHandlingOperations.asn; SHA-256 c61f10b3a81b1206acd7d36318c56a7cb3e0a212a4de53d2f5f705bf7cde4a1d.
	SendRoutingInfo MAPOperationCode = 22
	// ProvideRoamingNumber identifies provideRoamingNumber. Source: map-29002-v22/modules/MAP-CallHandlingOperations.asn; SHA-256 c61f10b3a81b1206acd7d36318c56a7cb3e0a212a4de53d2f5f705bf7cde4a1d.
	ProvideRoamingNumber MAPOperationCode = 4
	// ResumeCallHandling identifies resumeCallHandling. Source: map-29002-v22/modules/MAP-CallHandlingOperations.asn; SHA-256 c61f10b3a81b1206acd7d36318c56a7cb3e0a212a4de53d2f5f705bf7cde4a1d.
	ResumeCallHandling MAPOperationCode = 6
	// SetReportingState identifies setReportingState. Source: map-29002-v22/modules/MAP-CallHandlingOperations.asn; SHA-256 c61f10b3a81b1206acd7d36318c56a7cb3e0a212a4de53d2f5f705bf7cde4a1d.
	SetReportingState MAPOperationCode = 73
	// StatusReport identifies statusReport. Source: map-29002-v22/modules/MAP-CallHandlingOperations.asn; SHA-256 c61f10b3a81b1206acd7d36318c56a7cb3e0a212a4de53d2f5f705bf7cde4a1d.
	StatusReport MAPOperationCode = 74
	// RemoteUserFree identifies remoteUserFree. Source: map-29002-v22/modules/MAP-CallHandlingOperations.asn; SHA-256 c61f10b3a81b1206acd7d36318c56a7cb3e0a212a4de53d2f5f705bf7cde4a1d.
	RemoteUserFree MAPOperationCode = 75
	// IstAlert identifies ist-Alert. Source: map-29002-v22/modules/MAP-CallHandlingOperations.asn; SHA-256 c61f10b3a81b1206acd7d36318c56a7cb3e0a212a4de53d2f5f705bf7cde4a1d.
	IstAlert MAPOperationCode = 87
	// IstCommand identifies ist-Command. Source: map-29002-v22/modules/MAP-CallHandlingOperations.asn; SHA-256 c61f10b3a81b1206acd7d36318c56a7cb3e0a212a4de53d2f5f705bf7cde4a1d.
	IstCommand MAPOperationCode = 88
	// ReleaseResources identifies releaseResources. Source: map-29002-v22/modules/MAP-CallHandlingOperations.asn; SHA-256 c61f10b3a81b1206acd7d36318c56a7cb3e0a212a4de53d2f5f705bf7cde4a1d.
	ReleaseResources MAPOperationCode = 20
	// PrepareGroupCall identifies prepareGroupCall. Source: map-29002-v22/modules/MAP-Group-Call-Operations.asn; SHA-256 2047261424cb7e0de50d6507e142ce3c4439a628ad5a273efc8e4ddefe1087f6.
	PrepareGroupCall MAPOperationCode = 39
	// SendGroupCallEndSignal identifies sendGroupCallEndSignal. Source: map-29002-v22/modules/MAP-Group-Call-Operations.asn; SHA-256 2047261424cb7e0de50d6507e142ce3c4439a628ad5a273efc8e4ddefe1087f6.
	SendGroupCallEndSignal MAPOperationCode = 40
	// ProcessGroupCallSignalling identifies processGroupCallSignalling. Source: map-29002-v22/modules/MAP-Group-Call-Operations.asn; SHA-256 2047261424cb7e0de50d6507e142ce3c4439a628ad5a273efc8e4ddefe1087f6.
	ProcessGroupCallSignalling MAPOperationCode = 41
	// ForwardGroupCallSignalling identifies forwardGroupCallSignalling. Source: map-29002-v22/modules/MAP-Group-Call-Operations.asn; SHA-256 2047261424cb7e0de50d6507e142ce3c4439a628ad5a273efc8e4ddefe1087f6.
	ForwardGroupCallSignalling MAPOperationCode = 42
	// SendGroupCallInfo identifies sendGroupCallInfo. Source: map-29002-v22/modules/MAP-Group-Call-Operations.asn; SHA-256 2047261424cb7e0de50d6507e142ce3c4439a628ad5a273efc8e4ddefe1087f6.
	SendGroupCallInfo MAPOperationCode = 84
	// SendRoutingInfoForLCS identifies sendRoutingInfoForLCS. Source: map-29002-v22/modules/MAP-LocationServiceOperations.asn; SHA-256 280414f331b25e83c672dc7ce1773e9e4f1585f1d0f3f374bd98637e11ad6b0a.
	SendRoutingInfoForLCS MAPOperationCode = 85
	// ProvideSubscriberLocation identifies provideSubscriberLocation. Source: map-29002-v22/modules/MAP-LocationServiceOperations.asn; SHA-256 280414f331b25e83c672dc7ce1773e9e4f1585f1d0f3f374bd98637e11ad6b0a.
	ProvideSubscriberLocation MAPOperationCode = 83
	// SubscriberLocationReport identifies subscriberLocationReport. Source: map-29002-v22/modules/MAP-LocationServiceOperations.asn; SHA-256 280414f331b25e83c672dc7ce1773e9e4f1585f1d0f3f374bd98637e11ad6b0a.
	SubscriberLocationReport MAPOperationCode = 86
	// UpdateLocation identifies updateLocation. Source: map-29002-v22/modules/MAP-MobileServiceOperations.asn; SHA-256 1ff741e4cfa8e39efd9585cd08d7c5196d14b483dc2776ebc4e8c6e07babc496.
	UpdateLocation MAPOperationCode = 2
	// CancelLocation identifies cancelLocation. Source: map-29002-v22/modules/MAP-MobileServiceOperations.asn; SHA-256 1ff741e4cfa8e39efd9585cd08d7c5196d14b483dc2776ebc4e8c6e07babc496.
	CancelLocation MAPOperationCode = 3
	// PurgeMS identifies purgeMS. Source: map-29002-v22/modules/MAP-MobileServiceOperations.asn; SHA-256 1ff741e4cfa8e39efd9585cd08d7c5196d14b483dc2776ebc4e8c6e07babc496.
	PurgeMS MAPOperationCode = 67
	// SendIdentification identifies sendIdentification. Source: map-29002-v22/modules/MAP-MobileServiceOperations.asn; SHA-256 1ff741e4cfa8e39efd9585cd08d7c5196d14b483dc2776ebc4e8c6e07babc496.
	SendIdentification MAPOperationCode = 55
	// UpdateGprsLocation identifies updateGprsLocation. Source: map-29002-v22/modules/MAP-MobileServiceOperations.asn; SHA-256 1ff741e4cfa8e39efd9585cd08d7c5196d14b483dc2776ebc4e8c6e07babc496.
	UpdateGprsLocation MAPOperationCode = 23
	// ProvideSubscriberInfo identifies provideSubscriberInfo. Source: map-29002-v22/modules/MAP-MobileServiceOperations.asn; SHA-256 1ff741e4cfa8e39efd9585cd08d7c5196d14b483dc2776ebc4e8c6e07babc496.
	ProvideSubscriberInfo MAPOperationCode = 70
	// AnyTimeInterrogation identifies anyTimeInterrogation. Source: map-29002-v22/modules/MAP-MobileServiceOperations.asn; SHA-256 1ff741e4cfa8e39efd9585cd08d7c5196d14b483dc2776ebc4e8c6e07babc496.
	AnyTimeInterrogation MAPOperationCode = 71
	// AnyTimeSubscriptionInterrogation identifies anyTimeSubscriptionInterrogation. Source: map-29002-v22/modules/MAP-MobileServiceOperations.asn; SHA-256 1ff741e4cfa8e39efd9585cd08d7c5196d14b483dc2776ebc4e8c6e07babc496.
	AnyTimeSubscriptionInterrogation MAPOperationCode = 62
	// AnyTimeModification identifies anyTimeModification. Source: map-29002-v22/modules/MAP-MobileServiceOperations.asn; SHA-256 1ff741e4cfa8e39efd9585cd08d7c5196d14b483dc2776ebc4e8c6e07babc496.
	AnyTimeModification MAPOperationCode = 65
	// NoteSubscriberDataModified identifies noteSubscriberDataModified. Source: map-29002-v22/modules/MAP-MobileServiceOperations.asn; SHA-256 1ff741e4cfa8e39efd9585cd08d7c5196d14b483dc2776ebc4e8c6e07babc496.
	NoteSubscriberDataModified MAPOperationCode = 5
	// PrepareHandover identifies prepareHandover. Source: map-29002-v22/modules/MAP-MobileServiceOperations.asn; SHA-256 1ff741e4cfa8e39efd9585cd08d7c5196d14b483dc2776ebc4e8c6e07babc496.
	PrepareHandover MAPOperationCode = 68
	// SendEndSignal identifies sendEndSignal. Source: map-29002-v22/modules/MAP-MobileServiceOperations.asn; SHA-256 1ff741e4cfa8e39efd9585cd08d7c5196d14b483dc2776ebc4e8c6e07babc496.
	SendEndSignal MAPOperationCode = 29
	// ProcessAccessSignalling identifies processAccessSignalling. Source: map-29002-v22/modules/MAP-MobileServiceOperations.asn; SHA-256 1ff741e4cfa8e39efd9585cd08d7c5196d14b483dc2776ebc4e8c6e07babc496.
	ProcessAccessSignalling MAPOperationCode = 33
	// ForwardAccessSignalling identifies forwardAccessSignalling. Source: map-29002-v22/modules/MAP-MobileServiceOperations.asn; SHA-256 1ff741e4cfa8e39efd9585cd08d7c5196d14b483dc2776ebc4e8c6e07babc496.
	ForwardAccessSignalling MAPOperationCode = 34
	// PrepareSubsequentHandover identifies prepareSubsequentHandover. Source: map-29002-v22/modules/MAP-MobileServiceOperations.asn; SHA-256 1ff741e4cfa8e39efd9585cd08d7c5196d14b483dc2776ebc4e8c6e07babc496.
	PrepareSubsequentHandover MAPOperationCode = 69
	// SendAuthenticationInfo identifies sendAuthenticationInfo. Source: map-29002-v22/modules/MAP-MobileServiceOperations.asn; SHA-256 1ff741e4cfa8e39efd9585cd08d7c5196d14b483dc2776ebc4e8c6e07babc496.
	SendAuthenticationInfo MAPOperationCode = 56
	// AuthenticationFailureReport identifies authenticationFailureReport. Source: map-29002-v22/modules/MAP-MobileServiceOperations.asn; SHA-256 1ff741e4cfa8e39efd9585cd08d7c5196d14b483dc2776ebc4e8c6e07babc496.
	AuthenticationFailureReport MAPOperationCode = 15
	// CheckIMEI identifies checkIMEI. Source: map-29002-v22/modules/MAP-MobileServiceOperations.asn; SHA-256 1ff741e4cfa8e39efd9585cd08d7c5196d14b483dc2776ebc4e8c6e07babc496.
	CheckIMEI MAPOperationCode = 43
	// InsertSubscriberData identifies insertSubscriberData. Source: map-29002-v22/modules/MAP-MobileServiceOperations.asn; SHA-256 1ff741e4cfa8e39efd9585cd08d7c5196d14b483dc2776ebc4e8c6e07babc496.
	InsertSubscriberData MAPOperationCode = 7
	// DeleteSubscriberData identifies deleteSubscriberData. Source: map-29002-v22/modules/MAP-MobileServiceOperations.asn; SHA-256 1ff741e4cfa8e39efd9585cd08d7c5196d14b483dc2776ebc4e8c6e07babc496.
	DeleteSubscriberData MAPOperationCode = 8
	// Reset identifies reset. Source: map-29002-v22/modules/MAP-MobileServiceOperations.asn; SHA-256 1ff741e4cfa8e39efd9585cd08d7c5196d14b483dc2776ebc4e8c6e07babc496.
	Reset MAPOperationCode = 37
	// ForwardCheckSSIndication identifies forwardCheckSS-Indication. Source: map-29002-v22/modules/MAP-MobileServiceOperations.asn; SHA-256 1ff741e4cfa8e39efd9585cd08d7c5196d14b483dc2776ebc4e8c6e07babc496.
	ForwardCheckSSIndication MAPOperationCode = 38
	// RestoreData identifies restoreData. Source: map-29002-v22/modules/MAP-MobileServiceOperations.asn; SHA-256 1ff741e4cfa8e39efd9585cd08d7c5196d14b483dc2776ebc4e8c6e07babc496.
	RestoreData MAPOperationCode = 57
	// SendRoutingInfoForGprs identifies sendRoutingInfoForGprs. Source: map-29002-v22/modules/MAP-MobileServiceOperations.asn; SHA-256 1ff741e4cfa8e39efd9585cd08d7c5196d14b483dc2776ebc4e8c6e07babc496.
	SendRoutingInfoForGprs MAPOperationCode = 24
	// FailureReport identifies failureReport. Source: map-29002-v22/modules/MAP-MobileServiceOperations.asn; SHA-256 1ff741e4cfa8e39efd9585cd08d7c5196d14b483dc2776ebc4e8c6e07babc496.
	FailureReport MAPOperationCode = 25
	// NoteMsPresentForGprs identifies noteMsPresentForGprs. Source: map-29002-v22/modules/MAP-MobileServiceOperations.asn; SHA-256 1ff741e4cfa8e39efd9585cd08d7c5196d14b483dc2776ebc4e8c6e07babc496.
	NoteMsPresentForGprs MAPOperationCode = 26
	// NoteMMEvent identifies noteMM-Event. Source: map-29002-v22/modules/MAP-MobileServiceOperations.asn; SHA-256 1ff741e4cfa8e39efd9585cd08d7c5196d14b483dc2776ebc4e8c6e07babc496.
	NoteMMEvent MAPOperationCode = 89
	// UpdateVcsgLocation identifies updateVcsgLocation. Source: map-29002-v22/modules/MAP-MobileServiceOperations.asn; SHA-256 1ff741e4cfa8e39efd9585cd08d7c5196d14b483dc2776ebc4e8c6e07babc496.
	UpdateVcsgLocation MAPOperationCode = 53
	// CancelVcsgLocation identifies cancelVcsgLocation. Source: map-29002-v22/modules/MAP-MobileServiceOperations.asn; SHA-256 1ff741e4cfa8e39efd9585cd08d7c5196d14b483dc2776ebc4e8c6e07babc496.
	CancelVcsgLocation MAPOperationCode = 36
	// ActivateTraceMode identifies activateTraceMode. Source: map-29002-v22/modules/MAP-OperationAndMaintenanceOperations.asn; SHA-256 7f706f72645f72d54c8add36cc083c7d20ccbc42f5bdbae5e3cfaf765e369845.
	ActivateTraceMode MAPOperationCode = 50
	// DeactivateTraceMode identifies deactivateTraceMode. Source: map-29002-v22/modules/MAP-OperationAndMaintenanceOperations.asn; SHA-256 7f706f72645f72d54c8add36cc083c7d20ccbc42f5bdbae5e3cfaf765e369845.
	DeactivateTraceMode MAPOperationCode = 51
	// SendIMSI identifies sendIMSI. Source: map-29002-v22/modules/MAP-OperationAndMaintenanceOperations.asn; SHA-256 7f706f72645f72d54c8add36cc083c7d20ccbc42f5bdbae5e3cfaf765e369845.
	SendIMSI MAPOperationCode = 58
	// SendRoutingInfoForSM identifies sendRoutingInfoForSM. Source: map-29002-v22/modules/MAP-ShortMessageServiceOperations.asn; SHA-256 6c8edebb3afbfa8e662db4adfd2da590323343c6df8c82f686761e779ed297bb.
	SendRoutingInfoForSM MAPOperationCode = 45
	// MoForwardSM identifies mo-ForwardSM. Source: map-29002-v22/modules/MAP-ShortMessageServiceOperations.asn; SHA-256 6c8edebb3afbfa8e662db4adfd2da590323343c6df8c82f686761e779ed297bb.
	MoForwardSM MAPOperationCode = 46
	// MtForwardSM identifies mt-ForwardSM. Source: map-29002-v22/modules/MAP-ShortMessageServiceOperations.asn; SHA-256 6c8edebb3afbfa8e662db4adfd2da590323343c6df8c82f686761e779ed297bb.
	MtForwardSM MAPOperationCode = 44
	// ReportSMDeliveryStatus identifies reportSM-DeliveryStatus. Source: map-29002-v22/modules/MAP-ShortMessageServiceOperations.asn; SHA-256 6c8edebb3afbfa8e662db4adfd2da590323343c6df8c82f686761e779ed297bb.
	ReportSMDeliveryStatus MAPOperationCode = 47
	// AlertServiceCentre identifies alertServiceCentre. Source: map-29002-v22/modules/MAP-ShortMessageServiceOperations.asn; SHA-256 6c8edebb3afbfa8e662db4adfd2da590323343c6df8c82f686761e779ed297bb.
	AlertServiceCentre MAPOperationCode = 64
	// InformServiceCentre identifies informServiceCentre. Source: map-29002-v22/modules/MAP-ShortMessageServiceOperations.asn; SHA-256 6c8edebb3afbfa8e662db4adfd2da590323343c6df8c82f686761e779ed297bb.
	InformServiceCentre MAPOperationCode = 63
	// ReadyForSM identifies readyForSM. Source: map-29002-v22/modules/MAP-ShortMessageServiceOperations.asn; SHA-256 6c8edebb3afbfa8e662db4adfd2da590323343c6df8c82f686761e779ed297bb.
	ReadyForSM MAPOperationCode = 66
	// MtForwardSMVGCS identifies mt-ForwardSM-VGCS. Source: map-29002-v22/modules/MAP-ShortMessageServiceOperations.asn; SHA-256 6c8edebb3afbfa8e662db4adfd2da590323343c6df8c82f686761e779ed297bb.
	MtForwardSMVGCS MAPOperationCode = 21
	// RegisterSS identifies registerSS. Source: map-29002-v22/modules/MAP-SupplementaryServiceOperations.asn; SHA-256 b257f83655d74e8ed13f747c0ddc858178308c9689f5c4544b9a70c8076e494f.
	RegisterSS MAPOperationCode = 10
	// EraseSS identifies eraseSS. Source: map-29002-v22/modules/MAP-SupplementaryServiceOperations.asn; SHA-256 b257f83655d74e8ed13f747c0ddc858178308c9689f5c4544b9a70c8076e494f.
	EraseSS MAPOperationCode = 11
	// ActivateSS identifies activateSS. Source: map-29002-v22/modules/MAP-SupplementaryServiceOperations.asn; SHA-256 b257f83655d74e8ed13f747c0ddc858178308c9689f5c4544b9a70c8076e494f.
	ActivateSS MAPOperationCode = 12
	// DeactivateSS identifies deactivateSS. Source: map-29002-v22/modules/MAP-SupplementaryServiceOperations.asn; SHA-256 b257f83655d74e8ed13f747c0ddc858178308c9689f5c4544b9a70c8076e494f.
	DeactivateSS MAPOperationCode = 13
	// InterrogateSS identifies interrogateSS. Source: map-29002-v22/modules/MAP-SupplementaryServiceOperations.asn; SHA-256 b257f83655d74e8ed13f747c0ddc858178308c9689f5c4544b9a70c8076e494f.
	InterrogateSS MAPOperationCode = 14
	// ProcessUnstructuredSSRequest identifies processUnstructuredSS-Request. Source: map-29002-v22/modules/MAP-SupplementaryServiceOperations.asn; SHA-256 b257f83655d74e8ed13f747c0ddc858178308c9689f5c4544b9a70c8076e494f.
	ProcessUnstructuredSSRequest MAPOperationCode = 59
	// UnstructuredSSRequest identifies unstructuredSS-Request. Source: map-29002-v22/modules/MAP-SupplementaryServiceOperations.asn; SHA-256 b257f83655d74e8ed13f747c0ddc858178308c9689f5c4544b9a70c8076e494f.
	UnstructuredSSRequest MAPOperationCode = 60
	// UnstructuredSSNotify identifies unstructuredSS-Notify. Source: map-29002-v22/modules/MAP-SupplementaryServiceOperations.asn; SHA-256 b257f83655d74e8ed13f747c0ddc858178308c9689f5c4544b9a70c8076e494f.
	UnstructuredSSNotify MAPOperationCode = 61
	// RegisterPassword identifies registerPassword. Source: map-29002-v22/modules/MAP-SupplementaryServiceOperations.asn; SHA-256 b257f83655d74e8ed13f747c0ddc858178308c9689f5c4544b9a70c8076e494f.
	RegisterPassword MAPOperationCode = 17
	// GetPassword identifies getPassword. Source: map-29002-v22/modules/MAP-SupplementaryServiceOperations.asn; SHA-256 b257f83655d74e8ed13f747c0ddc858178308c9689f5c4544b9a70c8076e494f.
	GetPassword MAPOperationCode = 18
	// SsInvocationNotification identifies ss-InvocationNotification. Source: map-29002-v22/modules/MAP-SupplementaryServiceOperations.asn; SHA-256 b257f83655d74e8ed13f747c0ddc858178308c9689f5c4544b9a70c8076e494f.
	SsInvocationNotification MAPOperationCode = 72
	// RegisterCCEntry identifies registerCC-Entry. Source: map-29002-v22/modules/MAP-SupplementaryServiceOperations.asn; SHA-256 b257f83655d74e8ed13f747c0ddc858178308c9689f5c4544b9a70c8076e494f.
	RegisterCCEntry MAPOperationCode = 76
	// EraseCCEntry identifies eraseCC-Entry. Source: map-29002-v22/modules/MAP-SupplementaryServiceOperations.asn; SHA-256 b257f83655d74e8ed13f747c0ddc858178308c9689f5c4544b9a70c8076e494f.
	EraseCCEntry MAPOperationCode = 77
)

// String returns the first source name for this code.
func (c MAPOperationCode) String() string {
	switch c {
	case SendRoutingInfo:
		return "sendRoutingInfo"
	case ProvideRoamingNumber:
		return "provideRoamingNumber"
	case ResumeCallHandling:
		return "resumeCallHandling"
	case SetReportingState:
		return "setReportingState"
	case StatusReport:
		return "statusReport"
	case RemoteUserFree:
		return "remoteUserFree"
	case IstAlert:
		return "ist-Alert"
	case IstCommand:
		return "ist-Command"
	case ReleaseResources:
		return "releaseResources"
	case PrepareGroupCall:
		return "prepareGroupCall"
	case SendGroupCallEndSignal:
		return "sendGroupCallEndSignal"
	case ProcessGroupCallSignalling:
		return "processGroupCallSignalling"
	case ForwardGroupCallSignalling:
		return "forwardGroupCallSignalling"
	case SendGroupCallInfo:
		return "sendGroupCallInfo"
	case SendRoutingInfoForLCS:
		return "sendRoutingInfoForLCS"
	case ProvideSubscriberLocation:
		return "provideSubscriberLocation"
	case SubscriberLocationReport:
		return "subscriberLocationReport"
	case UpdateLocation:
		return "updateLocation"
	case CancelLocation:
		return "cancelLocation"
	case PurgeMS:
		return "purgeMS"
	case SendIdentification:
		return "sendIdentification"
	case UpdateGprsLocation:
		return "updateGprsLocation"
	case ProvideSubscriberInfo:
		return "provideSubscriberInfo"
	case AnyTimeInterrogation:
		return "anyTimeInterrogation"
	case AnyTimeSubscriptionInterrogation:
		return "anyTimeSubscriptionInterrogation"
	case AnyTimeModification:
		return "anyTimeModification"
	case NoteSubscriberDataModified:
		return "noteSubscriberDataModified"
	case PrepareHandover:
		return "prepareHandover"
	case SendEndSignal:
		return "sendEndSignal"
	case ProcessAccessSignalling:
		return "processAccessSignalling"
	case ForwardAccessSignalling:
		return "forwardAccessSignalling"
	case PrepareSubsequentHandover:
		return "prepareSubsequentHandover"
	case SendAuthenticationInfo:
		return "sendAuthenticationInfo"
	case AuthenticationFailureReport:
		return "authenticationFailureReport"
	case CheckIMEI:
		return "checkIMEI"
	case InsertSubscriberData:
		return "insertSubscriberData"
	case DeleteSubscriberData:
		return "deleteSubscriberData"
	case Reset:
		return "reset"
	case ForwardCheckSSIndication:
		return "forwardCheckSS-Indication"
	case RestoreData:
		return "restoreData"
	case SendRoutingInfoForGprs:
		return "sendRoutingInfoForGprs"
	case FailureReport:
		return "failureReport"
	case NoteMsPresentForGprs:
		return "noteMsPresentForGprs"
	case NoteMMEvent:
		return "noteMM-Event"
	case UpdateVcsgLocation:
		return "updateVcsgLocation"
	case CancelVcsgLocation:
		return "cancelVcsgLocation"
	case ActivateTraceMode:
		return "activateTraceMode"
	case DeactivateTraceMode:
		return "deactivateTraceMode"
	case SendIMSI:
		return "sendIMSI"
	case SendRoutingInfoForSM:
		return "sendRoutingInfoForSM"
	case MoForwardSM:
		return "mo-ForwardSM"
	case MtForwardSM:
		return "mt-ForwardSM"
	case ReportSMDeliveryStatus:
		return "reportSM-DeliveryStatus"
	case AlertServiceCentre:
		return "alertServiceCentre"
	case InformServiceCentre:
		return "informServiceCentre"
	case ReadyForSM:
		return "readyForSM"
	case MtForwardSMVGCS:
		return "mt-ForwardSM-VGCS"
	case RegisterSS:
		return "registerSS"
	case EraseSS:
		return "eraseSS"
	case ActivateSS:
		return "activateSS"
	case DeactivateSS:
		return "deactivateSS"
	case InterrogateSS:
		return "interrogateSS"
	case ProcessUnstructuredSSRequest:
		return "processUnstructuredSS-Request"
	case UnstructuredSSRequest:
		return "unstructuredSS-Request"
	case UnstructuredSSNotify:
		return "unstructuredSS-Notify"
	case RegisterPassword:
		return "registerPassword"
	case GetPassword:
		return "getPassword"
	case SsInvocationNotification:
		return "ss-InvocationNotification"
	case RegisterCCEntry:
		return "registerCC-Entry"
	case EraseCCEntry:
		return "eraseCC-Entry"
	default:
		return fmt.Sprintf("MAPOperationCode(%d)", int64(c))
	}
}

// SSErrorCode is a local INTEGER code.
type SSErrorCode int64

const (
	// SSResourcesNotAvailable identifies resourcesNotAvailable. Source: ss-24080-v19/modules/SS-Errors.asn; SHA-256 b81d2a668e33702414eec4d9210bd4922f1104ccc4384cb6d8d3301ce8fa129e.
	SSResourcesNotAvailable SSErrorCode = 127
	// SSMaxNumberOfMPTYParticipantsExceeded identifies maxNumberOfMPTY-ParticipantsExceeded. Source: ss-24080-v19/modules/SS-Errors.asn; SHA-256 b81d2a668e33702414eec4d9210bd4922f1104ccc4384cb6d8d3301ce8fa129e.
	SSMaxNumberOfMPTYParticipantsExceeded SSErrorCode = 126
	// SSInvalidDeflectedToNumber identifies invalidDeflectedToNumber. Source: ss-24080-v19/modules/SS-Errors.asn; SHA-256 b81d2a668e33702414eec4d9210bd4922f1104ccc4384cb6d8d3301ce8fa129e.
	SSInvalidDeflectedToNumber SSErrorCode = 125
	// SSSpecialServiceCode identifies specialServiceCode. Source: ss-24080-v19/modules/SS-Errors.asn; SHA-256 b81d2a668e33702414eec4d9210bd4922f1104ccc4384cb6d8d3301ce8fa129e.
	SSSpecialServiceCode SSErrorCode = 124
	// SSDeflectionToServedSubscriber identifies deflectionToServedSubscriber. Source: ss-24080-v19/modules/SS-Errors.asn; SHA-256 b81d2a668e33702414eec4d9210bd4922f1104ccc4384cb6d8d3301ce8fa129e.
	SSDeflectionToServedSubscriber SSErrorCode = 123
	// SSRejectedByNetwork identifies rejectedByNetwork. Source: ss-24080-v19/modules/SS-Errors.asn; SHA-256 b81d2a668e33702414eec4d9210bd4922f1104ccc4384cb6d8d3301ce8fa129e.
	SSRejectedByNetwork SSErrorCode = 122
	// SSRejectedByUser identifies rejectedByUser. Source: ss-24080-v19/modules/SS-Errors.asn; SHA-256 b81d2a668e33702414eec4d9210bd4922f1104ccc4384cb6d8d3301ce8fa129e.
	SSRejectedByUser SSErrorCode = 121
	// SSLcsInvalidPru identifies lcs-invalidPru. Source: ss-24080-v19/modules/SS-Errors.asn; SHA-256 b81d2a668e33702414eec4d9210bd4922f1104ccc4384cb6d8d3301ce8fa129e.
	SSLcsInvalidPru SSErrorCode = 120
	// SSLcsPruAssociationRej identifies lcs-PruAssociationRej. Source: ss-24080-v19/modules/SS-Errors.asn; SHA-256 b81d2a668e33702414eec4d9210bd4922f1104ccc4384cb6d8d3301ce8fa129e.
	SSLcsPruAssociationRej SSErrorCode = 119
)

// String returns the first source name for this code.
func (c SSErrorCode) String() string {
	switch c {
	case SSResourcesNotAvailable:
		return "resourcesNotAvailable"
	case SSMaxNumberOfMPTYParticipantsExceeded:
		return "maxNumberOfMPTY-ParticipantsExceeded"
	case SSInvalidDeflectedToNumber:
		return "invalidDeflectedToNumber"
	case SSSpecialServiceCode:
		return "specialServiceCode"
	case SSDeflectionToServedSubscriber:
		return "deflectionToServedSubscriber"
	case SSRejectedByNetwork:
		return "rejectedByNetwork"
	case SSRejectedByUser:
		return "rejectedByUser"
	case SSLcsInvalidPru:
		return "lcs-invalidPru"
	case SSLcsPruAssociationRej:
		return "lcs-PruAssociationRej"
	default:
		return fmt.Sprintf("SSErrorCode(%d)", int64(c))
	}
}

// SSOperationCode is a local INTEGER code.
type SSOperationCode int64

const (
	// SSProcessUnstructuredSSData identifies processUnstructuredSS-Data. Source: ss-24080-v19/modules/SS-Operations.asn; SHA-256 d3eba960d95875df7ffb757f3e944ee68d3172f407fb27cdeebec4e6e1317673.
	SSProcessUnstructuredSSData SSOperationCode = 19
	// SSNotifySS identifies notifySS. Source: ss-24080-v19/modules/SS-Operations.asn; SHA-256 d3eba960d95875df7ffb757f3e944ee68d3172f407fb27cdeebec4e6e1317673.
	SSNotifySS SSOperationCode = 16
	// SSForwardChargeAdvice identifies forwardChargeAdvice. Source: ss-24080-v19/modules/SS-Operations.asn; SHA-256 d3eba960d95875df7ffb757f3e944ee68d3172f407fb27cdeebec4e6e1317673.
	SSForwardChargeAdvice SSOperationCode = 125
	// SSForwardCUGInfo identifies forwardCUG-Info. Source: ss-24080-v19/modules/SS-Operations.asn; SHA-256 d3eba960d95875df7ffb757f3e944ee68d3172f407fb27cdeebec4e6e1317673.
	SSForwardCUGInfo SSOperationCode = 120
	// SSBuildMPTY identifies buildMPTY. Source: ss-24080-v19/modules/SS-Operations.asn; SHA-256 d3eba960d95875df7ffb757f3e944ee68d3172f407fb27cdeebec4e6e1317673.
	SSBuildMPTY SSOperationCode = 124
	// SSHoldMPTY identifies holdMPTY. Source: ss-24080-v19/modules/SS-Operations.asn; SHA-256 d3eba960d95875df7ffb757f3e944ee68d3172f407fb27cdeebec4e6e1317673.
	SSHoldMPTY SSOperationCode = 123
	// SSRetrieveMPTY identifies retrieveMPTY. Source: ss-24080-v19/modules/SS-Operations.asn; SHA-256 d3eba960d95875df7ffb757f3e944ee68d3172f407fb27cdeebec4e6e1317673.
	SSRetrieveMPTY SSOperationCode = 122
	// SSSplitMPTY identifies splitMPTY. Source: ss-24080-v19/modules/SS-Operations.asn; SHA-256 d3eba960d95875df7ffb757f3e944ee68d3172f407fb27cdeebec4e6e1317673.
	SSSplitMPTY SSOperationCode = 121
	// SSExplicitCT identifies explicitCT. Source: ss-24080-v19/modules/SS-Operations.asn; SHA-256 d3eba960d95875df7ffb757f3e944ee68d3172f407fb27cdeebec4e6e1317673.
	SSExplicitCT SSOperationCode = 126
	// SSAccessRegisterCCEntry identifies accessRegisterCCEntry. Source: ss-24080-v19/modules/SS-Operations.asn; SHA-256 d3eba960d95875df7ffb757f3e944ee68d3172f407fb27cdeebec4e6e1317673.
	SSAccessRegisterCCEntry SSOperationCode = 119
	// SSCallDeflection identifies callDeflection. Source: ss-24080-v19/modules/SS-Operations.asn; SHA-256 d3eba960d95875df7ffb757f3e944ee68d3172f407fb27cdeebec4e6e1317673.
	SSCallDeflection SSOperationCode = 117
	// SSUserUserService identifies userUserService. Source: ss-24080-v19/modules/SS-Operations.asn; SHA-256 d3eba960d95875df7ffb757f3e944ee68d3172f407fb27cdeebec4e6e1317673.
	SSUserUserService SSOperationCode = 118
	// SSLcsLocationNotification identifies lcs-LocationNotification. Source: ss-24080-v19/modules/SS-Operations.asn; SHA-256 d3eba960d95875df7ffb757f3e944ee68d3172f407fb27cdeebec4e6e1317673.
	SSLcsLocationNotification SSOperationCode = 116
	// SSLcsMOLR identifies lcs-MOLR. Source: ss-24080-v19/modules/SS-Operations.asn; SHA-256 d3eba960d95875df7ffb757f3e944ee68d3172f407fb27cdeebec4e6e1317673.
	SSLcsMOLR SSOperationCode = 115
	// SSLcsAreaEventRequest identifies lcs-AreaEventRequest. Source: ss-24080-v19/modules/SS-Operations.asn; SHA-256 d3eba960d95875df7ffb757f3e944ee68d3172f407fb27cdeebec4e6e1317673.
	SSLcsAreaEventRequest SSOperationCode = 114
	// SSLcsAreaEventReport identifies lcs-AreaEventReport. Source: ss-24080-v19/modules/SS-Operations.asn; SHA-256 d3eba960d95875df7ffb757f3e944ee68d3172f407fb27cdeebec4e6e1317673.
	SSLcsAreaEventReport SSOperationCode = 113
	// SSLcsAreaEventCancellation identifies lcs-AreaEventCancellation. Source: ss-24080-v19/modules/SS-Operations.asn; SHA-256 d3eba960d95875df7ffb757f3e944ee68d3172f407fb27cdeebec4e6e1317673.
	SSLcsAreaEventCancellation SSOperationCode = 112
	// SSLcsPeriodicLocationRequest identifies lcs-PeriodicLocationRequest. Source: ss-24080-v19/modules/SS-Operations.asn; SHA-256 d3eba960d95875df7ffb757f3e944ee68d3172f407fb27cdeebec4e6e1317673.
	SSLcsPeriodicLocationRequest SSOperationCode = 111
	// SSLcsLocationUpdate identifies lcs-LocationUpdate. Source: ss-24080-v19/modules/SS-Operations.asn; SHA-256 d3eba960d95875df7ffb757f3e944ee68d3172f407fb27cdeebec4e6e1317673.
	SSLcsLocationUpdate SSOperationCode = 110
	// SSLcsPeriodicLocationCancellation identifies lcs-PeriodicLocationCancellation. Source: ss-24080-v19/modules/SS-Operations.asn; SHA-256 d3eba960d95875df7ffb757f3e944ee68d3172f407fb27cdeebec4e6e1317673.
	SSLcsPeriodicLocationCancellation SSOperationCode = 109
	// SSLcsPeriodicTriggeredInvoke identifies lcs-PeriodicTriggeredInvoke. Source: ss-24080-v19/modules/SS-Operations.asn; SHA-256 d3eba960d95875df7ffb757f3e944ee68d3172f407fb27cdeebec4e6e1317673.
	SSLcsPeriodicTriggeredInvoke SSOperationCode = 108
	// SSLcsEventReport identifies lcs-EventReport. Source: ss-24080-v19/modules/SS-Operations.asn; SHA-256 d3eba960d95875df7ffb757f3e944ee68d3172f407fb27cdeebec4e6e1317673.
	SSLcsEventReport SSOperationCode = 107
	// SSLcsCancelDeferredLocation identifies lcs-CancelDeferredLocation. Source: ss-24080-v19/modules/SS-Operations.asn; SHA-256 d3eba960d95875df7ffb757f3e944ee68d3172f407fb27cdeebec4e6e1317673.
	SSLcsCancelDeferredLocation SSOperationCode = 106
	// SSLcsMSCancelDeferredLocation identifies lcs-MSCancelDeferredLocation. Source: ss-24080-v19/modules/SS-Operations.asn; SHA-256 d3eba960d95875df7ffb757f3e944ee68d3172f407fb27cdeebec4e6e1317673.
	SSLcsMSCancelDeferredLocation SSOperationCode = 105
	// SSLcsLocationPrivacySetting identifies lcs-LocationPrivacySetting. Source: ss-24080-v19/modules/SS-Operations.asn; SHA-256 d3eba960d95875df7ffb757f3e944ee68d3172f407fb27cdeebec4e6e1317673.
	SSLcsLocationPrivacySetting SSOperationCode = 104
	// SSLcsPruAssociation identifies lcs-PruAssociation. Source: ss-24080-v19/modules/SS-Operations.asn; SHA-256 d3eba960d95875df7ffb757f3e944ee68d3172f407fb27cdeebec4e6e1317673.
	SSLcsPruAssociation SSOperationCode = 103
	// SSLcsPruDisassociation identifies lcs-PruDisassociation. Source: ss-24080-v19/modules/SS-Operations.asn; SHA-256 d3eba960d95875df7ffb757f3e944ee68d3172f407fb27cdeebec4e6e1317673.
	SSLcsPruDisassociation SSOperationCode = 102
	// SSLcsSLMOLR identifies lcs-SLMOLR. Source: ss-24080-v19/modules/SS-Operations.asn; SHA-256 d3eba960d95875df7ffb757f3e944ee68d3172f407fb27cdeebec4e6e1317673.
	SSLcsSLMOLR SSOperationCode = 101
	// SSLcsSLMTLR identifies lcs-SLMTLR. Source: ss-24080-v19/modules/SS-Operations.asn; SHA-256 d3eba960d95875df7ffb757f3e944ee68d3172f407fb27cdeebec4e6e1317673.
	SSLcsSLMTLR SSOperationCode = 100
	// SSLcsDLRSPPTransport identifies lcs-DLRSPPTransport. Source: ss-24080-v19/modules/SS-Operations.asn; SHA-256 d3eba960d95875df7ffb757f3e944ee68d3172f407fb27cdeebec4e6e1317673.
	SSLcsDLRSPPTransport SSOperationCode = 99
	// SSLcsULRSPPTransport identifies lcs-ULRSPPTransport. Source: ss-24080-v19/modules/SS-Operations.asn; SHA-256 d3eba960d95875df7ffb757f3e944ee68d3172f407fb27cdeebec4e6e1317673.
	SSLcsULRSPPTransport SSOperationCode = 98
)

// String returns the first source name for this code.
func (c SSOperationCode) String() string {
	switch c {
	case SSProcessUnstructuredSSData:
		return "processUnstructuredSS-Data"
	case SSNotifySS:
		return "notifySS"
	case SSForwardChargeAdvice:
		return "forwardChargeAdvice"
	case SSForwardCUGInfo:
		return "forwardCUG-Info"
	case SSBuildMPTY:
		return "buildMPTY"
	case SSHoldMPTY:
		return "holdMPTY"
	case SSRetrieveMPTY:
		return "retrieveMPTY"
	case SSSplitMPTY:
		return "splitMPTY"
	case SSExplicitCT:
		return "explicitCT"
	case SSAccessRegisterCCEntry:
		return "accessRegisterCCEntry"
	case SSCallDeflection:
		return "callDeflection"
	case SSUserUserService:
		return "userUserService"
	case SSLcsLocationNotification:
		return "lcs-LocationNotification"
	case SSLcsMOLR:
		return "lcs-MOLR"
	case SSLcsAreaEventRequest:
		return "lcs-AreaEventRequest"
	case SSLcsAreaEventReport:
		return "lcs-AreaEventReport"
	case SSLcsAreaEventCancellation:
		return "lcs-AreaEventCancellation"
	case SSLcsPeriodicLocationRequest:
		return "lcs-PeriodicLocationRequest"
	case SSLcsLocationUpdate:
		return "lcs-LocationUpdate"
	case SSLcsPeriodicLocationCancellation:
		return "lcs-PeriodicLocationCancellation"
	case SSLcsPeriodicTriggeredInvoke:
		return "lcs-PeriodicTriggeredInvoke"
	case SSLcsEventReport:
		return "lcs-EventReport"
	case SSLcsCancelDeferredLocation:
		return "lcs-CancelDeferredLocation"
	case SSLcsMSCancelDeferredLocation:
		return "lcs-MSCancelDeferredLocation"
	case SSLcsLocationPrivacySetting:
		return "lcs-LocationPrivacySetting"
	case SSLcsPruAssociation:
		return "lcs-PruAssociation"
	case SSLcsPruDisassociation:
		return "lcs-PruDisassociation"
	case SSLcsSLMOLR:
		return "lcs-SLMOLR"
	case SSLcsSLMTLR:
		return "lcs-SLMTLR"
	case SSLcsDLRSPPTransport:
		return "lcs-DLRSPPTransport"
	case SSLcsULRSPPTransport:
		return "lcs-ULRSPPTransport"
	default:
		return fmt.Sprintf("SSOperationCode(%d)", int64(c))
	}
}
