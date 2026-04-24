// Code generated from ASN.1. DO NOT EDIT.

package gsm_map

import "fmt"

// ErrorCode is a named type for gsm_map error codes.
type ErrorCode int64

const (
	// AbsentSubscriber is the error code for absentSubscriber.
	AbsentSubscriber ErrorCode = 27
	// AbsentSubscriberSM is the error code for absentSubscriberSM.
	AbsentSubscriberSM ErrorCode = 6
	// AtiNotAllowed is the error code for ati-NotAllowed.
	AtiNotAllowed ErrorCode = 49
	// AtmNotAllowed is the error code for atm-NotAllowed.
	AtmNotAllowed ErrorCode = 61
	// AtsiNotAllowed is the error code for atsi-NotAllowed.
	AtsiNotAllowed ErrorCode = 60
	// BearerServiceNotProvisioned is the error code for bearerServiceNotProvisioned.
	BearerServiceNotProvisioned ErrorCode = 10
	// BusySubscriber is the error code for busySubscriber.
	BusySubscriber ErrorCode = 45
	// CallBarred is the error code for callBarred.
	CallBarred ErrorCode = 13
	// CugReject is the error code for cug-Reject.
	CugReject ErrorCode = 15
	// DataMissing is the error code for dataMissing.
	DataMissing ErrorCode = 35
	// FacilityNotSupported is the error code for facilityNotSupported.
	FacilityNotSupported ErrorCode = 21
	// ForwardingFailed is the error code for forwardingFailed.
	ForwardingFailed ErrorCode = 47
	// ForwardingViolation is the error code for forwardingViolation.
	ForwardingViolation ErrorCode = 14
	// IllegalEquipment is the error code for illegalEquipment.
	IllegalEquipment ErrorCode = 12
	// IllegalSSOperation is the error code for illegalSS-Operation.
	IllegalSSOperation ErrorCode = 16
	// IllegalSubscriber is the error code for illegalSubscriber.
	IllegalSubscriber ErrorCode = 9
	// IncompatibleTerminal is the error code for incompatibleTerminal.
	IncompatibleTerminal ErrorCode = 28
	// InformationNotAvailable is the error code for informationNotAvailable.
	InformationNotAvailable ErrorCode = 62
	// LongTermDenial is the error code for longTermDenial.
	LongTermDenial ErrorCode = 30
	// MessageWaitingListFull is the error code for messageWaitingListFull.
	MessageWaitingListFull ErrorCode = 33
	// MmEventNotSupported is the error code for mm-EventNotSupported.
	MmEventNotSupported ErrorCode = 59
	// NegativePWCheck is the error code for negativePW-Check.
	NegativePWCheck ErrorCode = 38
	// NoGroupCallNumberAvailable is the error code for noGroupCallNumberAvailable.
	NoGroupCallNumberAvailable ErrorCode = 50
	// NoHandoverNumberAvailable is the error code for noHandoverNumberAvailable.
	NoHandoverNumberAvailable ErrorCode = 25
	// NoRoamingNumberAvailable is the error code for noRoamingNumberAvailable.
	NoRoamingNumberAvailable ErrorCode = 39
	// NoSubscriberReply is the error code for noSubscriberReply.
	NoSubscriberReply ErrorCode = 46
	// NumberChanged is the error code for numberChanged.
	NumberChanged ErrorCode = 44
	// NumberOfPWAttemptsViolation is the error code for numberOfPW-AttemptsViolation.
	NumberOfPWAttemptsViolation ErrorCode = 43
	// OngoingGroupCall is the error code for ongoingGroupCall.
	OngoingGroupCall ErrorCode = 22
	// OrNotAllowed is the error code for or-NotAllowed.
	OrNotAllowed ErrorCode = 48
	// PositionMethodFailure is the error code for positionMethodFailure.
	PositionMethodFailure ErrorCode = 54
	// PwRegistrationFailure is the error code for pw-RegistrationFailure.
	PwRegistrationFailure ErrorCode = 37
	// ResourceLimitation is the error code for resourceLimitation.
	ResourceLimitation ErrorCode = 51
	// RoamingNotAllowed is the error code for roamingNotAllowed.
	RoamingNotAllowed ErrorCode = 8
	// ShortTermDenial is the error code for shortTermDenial.
	ShortTermDenial ErrorCode = 29
	// SmDeliveryFailure is the error code for sm-DeliveryFailure.
	SmDeliveryFailure ErrorCode = 32
	// SsErrorStatus is the error code for ss-ErrorStatus.
	SsErrorStatus ErrorCode = 17
	// SsIncompatibility is the error code for ss-Incompatibility.
	SsIncompatibility ErrorCode = 20
	// SsNotAvailable is the error code for ss-NotAvailable.
	SsNotAvailable ErrorCode = 18
	// SsSubscriptionViolation is the error code for ss-SubscriptionViolation.
	SsSubscriptionViolation ErrorCode = 19
	// SubscriberBusyForMTSMS is the error code for subscriberBusyForMT-SMS.
	SubscriberBusyForMTSMS ErrorCode = 31
	// SubsequentHandoverFailure is the error code for subsequentHandoverFailure.
	SubsequentHandoverFailure ErrorCode = 26
	// SystemFailure is the error code for systemFailure.
	SystemFailure ErrorCode = 34
	// TargetCellOutsideGroupCallArea is the error code for targetCellOutsideGroupCallArea.
	TargetCellOutsideGroupCallArea ErrorCode = 42
	// TeleserviceNotProvisioned is the error code for teleserviceNotProvisioned.
	TeleserviceNotProvisioned ErrorCode = 11
	// TracingBufferFull is the error code for tracingBufferFull.
	TracingBufferFull ErrorCode = 40
	// UnauthorizedLCSClient is the error code for unauthorizedLCSClient.
	UnauthorizedLCSClient ErrorCode = 53
	// UnauthorizedRequestingNetwork is the error code for unauthorizedRequestingNetwork.
	UnauthorizedRequestingNetwork ErrorCode = 52
	// UnexpectedDataValue is the error code for unexpectedDataValue.
	UnexpectedDataValue ErrorCode = 36
	// UnidentifiedSubscriber is the error code for unidentifiedSubscriber.
	UnidentifiedSubscriber ErrorCode = 5
	// UnknownAlphabet is the error code for unknownAlphabet.
	UnknownAlphabet ErrorCode = 71
	// UnknownEquipment is the error code for unknownEquipment.
	UnknownEquipment ErrorCode = 7
	// UnknownMSC is the error code for unknownMSC.
	UnknownMSC ErrorCode = 3
	// UnknownOrUnreachableLCSClient is the error code for unknownOrUnreachableLCSClient.
	UnknownOrUnreachableLCSClient ErrorCode = 58
	// UnknownSubscriber is the error code for unknownSubscriber.
	UnknownSubscriber ErrorCode = 1
	// UssdBusy is the error code for ussd-Busy.
	UssdBusy ErrorCode = 72
	// Refuse is the error code for refuse.
	Refuse ErrorCode = -1
)

// String returns the ASN.1 name of the error code.
func (c ErrorCode) String() string {
	switch c {
	case AbsentSubscriber:
		return "absentSubscriber"
	case AbsentSubscriberSM:
		return "absentSubscriberSM"
	case AtiNotAllowed:
		return "ati-NotAllowed"
	case AtmNotAllowed:
		return "atm-NotAllowed"
	case AtsiNotAllowed:
		return "atsi-NotAllowed"
	case BearerServiceNotProvisioned:
		return "bearerServiceNotProvisioned"
	case BusySubscriber:
		return "busySubscriber"
	case CallBarred:
		return "callBarred"
	case CugReject:
		return "cug-Reject"
	case DataMissing:
		return "dataMissing"
	case FacilityNotSupported:
		return "facilityNotSupported"
	case ForwardingFailed:
		return "forwardingFailed"
	case ForwardingViolation:
		return "forwardingViolation"
	case IllegalEquipment:
		return "illegalEquipment"
	case IllegalSSOperation:
		return "illegalSS-Operation"
	case IllegalSubscriber:
		return "illegalSubscriber"
	case IncompatibleTerminal:
		return "incompatibleTerminal"
	case InformationNotAvailable:
		return "informationNotAvailable"
	case LongTermDenial:
		return "longTermDenial"
	case MessageWaitingListFull:
		return "messageWaitingListFull"
	case MmEventNotSupported:
		return "mm-EventNotSupported"
	case NegativePWCheck:
		return "negativePW-Check"
	case NoGroupCallNumberAvailable:
		return "noGroupCallNumberAvailable"
	case NoHandoverNumberAvailable:
		return "noHandoverNumberAvailable"
	case NoRoamingNumberAvailable:
		return "noRoamingNumberAvailable"
	case NoSubscriberReply:
		return "noSubscriberReply"
	case NumberChanged:
		return "numberChanged"
	case NumberOfPWAttemptsViolation:
		return "numberOfPW-AttemptsViolation"
	case OngoingGroupCall:
		return "ongoingGroupCall"
	case OrNotAllowed:
		return "or-NotAllowed"
	case PositionMethodFailure:
		return "positionMethodFailure"
	case PwRegistrationFailure:
		return "pw-RegistrationFailure"
	case ResourceLimitation:
		return "resourceLimitation"
	case RoamingNotAllowed:
		return "roamingNotAllowed"
	case ShortTermDenial:
		return "shortTermDenial"
	case SmDeliveryFailure:
		return "sm-DeliveryFailure"
	case SsErrorStatus:
		return "ss-ErrorStatus"
	case SsIncompatibility:
		return "ss-Incompatibility"
	case SsNotAvailable:
		return "ss-NotAvailable"
	case SsSubscriptionViolation:
		return "ss-SubscriptionViolation"
	case SubscriberBusyForMTSMS:
		return "subscriberBusyForMT-SMS"
	case SubsequentHandoverFailure:
		return "subsequentHandoverFailure"
	case SystemFailure:
		return "systemFailure"
	case TargetCellOutsideGroupCallArea:
		return "targetCellOutsideGroupCallArea"
	case TeleserviceNotProvisioned:
		return "teleserviceNotProvisioned"
	case TracingBufferFull:
		return "tracingBufferFull"
	case UnauthorizedLCSClient:
		return "unauthorizedLCSClient"
	case UnauthorizedRequestingNetwork:
		return "unauthorizedRequestingNetwork"
	case UnexpectedDataValue:
		return "unexpectedDataValue"
	case UnidentifiedSubscriber:
		return "unidentifiedSubscriber"
	case UnknownAlphabet:
		return "unknownAlphabet"
	case UnknownEquipment:
		return "unknownEquipment"
	case UnknownMSC:
		return "unknownMSC"
	case UnknownOrUnreachableLCSClient:
		return "unknownOrUnreachableLCSClient"
	case UnknownSubscriber:
		return "unknownSubscriber"
	case UssdBusy:
		return "ussd-Busy"
	case Refuse:
		return "refuse"
	default:
		return fmt.Sprintf("ErrorCode(%d)", int64(c))
	}
}

// OperationCode is a named type for gsm_map operation codes.
type OperationCode int64

const (
	// IstAlert is the operation code for ist-Alert.
	IstAlert OperationCode = 87
	// IstCommand is the operation code for ist-Command.
	IstCommand OperationCode = 88
	// ProvideRoamingNumber is the operation code for provideRoamingNumber.
	ProvideRoamingNumber OperationCode = 4
	// ReleaseResources is the operation code for releaseResources.
	ReleaseResources OperationCode = 20
	// RemoteUserFree is the operation code for remoteUserFree.
	RemoteUserFree OperationCode = 75
	// ResumeCallHandling is the operation code for resumeCallHandling.
	ResumeCallHandling OperationCode = 6
	// SendRoutingInfo is the operation code for sendRoutingInfo.
	SendRoutingInfo OperationCode = 22
	// SetReportingState is the operation code for setReportingState.
	SetReportingState OperationCode = 73
	// StatusReport is the operation code for statusReport.
	StatusReport OperationCode = 74
	// ForwardGroupCallSignalling is the operation code for forwardGroupCallSignalling.
	ForwardGroupCallSignalling OperationCode = 42
	// PrepareGroupCall is the operation code for prepareGroupCall.
	PrepareGroupCall OperationCode = 39
	// ProcessGroupCallSignalling is the operation code for processGroupCallSignalling.
	ProcessGroupCallSignalling OperationCode = 41
	// SendGroupCallEndSignal is the operation code for sendGroupCallEndSignal.
	SendGroupCallEndSignal OperationCode = 40
	// SendGroupCallInfo is the operation code for sendGroupCallInfo.
	SendGroupCallInfo OperationCode = 84
	// ProvideSubscriberLocation is the operation code for provideSubscriberLocation.
	ProvideSubscriberLocation OperationCode = 83
	// SendRoutingInfoForLCS is the operation code for sendRoutingInfoForLCS.
	SendRoutingInfoForLCS OperationCode = 85
	// SubscriberLocationReport is the operation code for subscriberLocationReport.
	SubscriberLocationReport OperationCode = 86
	// AnyTimeInterrogation is the operation code for anyTimeInterrogation.
	AnyTimeInterrogation OperationCode = 71
	// AnyTimeModification is the operation code for anyTimeModification.
	AnyTimeModification OperationCode = 65
	// AnyTimeSubscriptionInterrogation is the operation code for anyTimeSubscriptionInterrogation.
	AnyTimeSubscriptionInterrogation OperationCode = 62
	// AuthenticationFailureReport is the operation code for authenticationFailureReport.
	AuthenticationFailureReport OperationCode = 15
	// CancelLocation is the operation code for cancelLocation.
	CancelLocation OperationCode = 3
	// CancelVcsgLocation is the operation code for cancelVcsgLocation.
	CancelVcsgLocation OperationCode = 36
	// CheckIMEI is the operation code for checkIMEI.
	CheckIMEI OperationCode = 43
	// DeleteSubscriberData is the operation code for deleteSubscriberData.
	DeleteSubscriberData OperationCode = 8
	// FailureReport is the operation code for failureReport.
	FailureReport OperationCode = 25
	// ForwardAccessSignalling is the operation code for forwardAccessSignalling.
	ForwardAccessSignalling OperationCode = 34
	// ForwardCheckSSIndication is the operation code for forwardCheckSS-Indication.
	ForwardCheckSSIndication OperationCode = 38
	// InsertSubscriberData is the operation code for insertSubscriberData.
	InsertSubscriberData OperationCode = 7
	// NoteMMEvent is the operation code for noteMM-Event.
	NoteMMEvent OperationCode = 89
	// NoteMsPresentForGprs is the operation code for noteMsPresentForGprs.
	NoteMsPresentForGprs OperationCode = 26
	// NoteSubscriberDataModified is the operation code for noteSubscriberDataModified.
	NoteSubscriberDataModified OperationCode = 5
	// PrepareHandover is the operation code for prepareHandover.
	PrepareHandover OperationCode = 68
	// PrepareSubsequentHandover is the operation code for prepareSubsequentHandover.
	PrepareSubsequentHandover OperationCode = 69
	// ProcessAccessSignalling is the operation code for processAccessSignalling.
	ProcessAccessSignalling OperationCode = 33
	// ProvideSubscriberInfo is the operation code for provideSubscriberInfo.
	ProvideSubscriberInfo OperationCode = 70
	// PurgeMS is the operation code for purgeMS.
	PurgeMS OperationCode = 67
	// Reset is the operation code for reset.
	Reset OperationCode = 37
	// RestoreData is the operation code for restoreData.
	RestoreData OperationCode = 57
	// SendAuthenticationInfo is the operation code for sendAuthenticationInfo.
	SendAuthenticationInfo OperationCode = 56
	// SendEndSignal is the operation code for sendEndSignal.
	SendEndSignal OperationCode = 29
	// SendIdentification is the operation code for sendIdentification.
	SendIdentification OperationCode = 55
	// SendRoutingInfoForGprs is the operation code for sendRoutingInfoForGprs.
	SendRoutingInfoForGprs OperationCode = 24
	// UpdateGprsLocation is the operation code for updateGprsLocation.
	UpdateGprsLocation OperationCode = 23
	// UpdateLocation is the operation code for updateLocation.
	UpdateLocation OperationCode = 2
	// UpdateVcsgLocation is the operation code for updateVcsgLocation.
	UpdateVcsgLocation OperationCode = 53
	// ActivateTraceMode is the operation code for activateTraceMode.
	ActivateTraceMode OperationCode = 50
	// DeactivateTraceMode is the operation code for deactivateTraceMode.
	DeactivateTraceMode OperationCode = 51
	// SendIMSI is the operation code for sendIMSI.
	SendIMSI OperationCode = 58
	// AlertServiceCentre is the operation code for alertServiceCentre.
	AlertServiceCentre OperationCode = 64
	// InformServiceCentre is the operation code for informServiceCentre.
	InformServiceCentre OperationCode = 63
	// MoForwardSM is the operation code for mo-ForwardSM.
	MoForwardSM OperationCode = 46
	// MtForwardSM is the operation code for mt-ForwardSM.
	MtForwardSM OperationCode = 44
	// MtForwardSMVGCS is the operation code for mt-ForwardSM-VGCS.
	MtForwardSMVGCS OperationCode = 21
	// ReadyForSM is the operation code for readyForSM.
	ReadyForSM OperationCode = 66
	// ReportSMDeliveryStatus is the operation code for reportSM-DeliveryStatus.
	ReportSMDeliveryStatus OperationCode = 47
	// SendRoutingInfoForSM is the operation code for sendRoutingInfoForSM.
	SendRoutingInfoForSM OperationCode = 45
	// ActivateSS is the operation code for activateSS.
	ActivateSS OperationCode = 12
	// DeactivateSS is the operation code for deactivateSS.
	DeactivateSS OperationCode = 13
	// EraseCCEntry is the operation code for eraseCC-Entry.
	EraseCCEntry OperationCode = 77
	// EraseSS is the operation code for eraseSS.
	EraseSS OperationCode = 11
	// GetPassword is the operation code for getPassword.
	GetPassword OperationCode = 18
	// InterrogateSS is the operation code for interrogateSS.
	InterrogateSS OperationCode = 14
	// ProcessUnstructuredSSRequest is the operation code for processUnstructuredSS-Request.
	ProcessUnstructuredSSRequest OperationCode = 59
	// RegisterCCEntry is the operation code for registerCC-Entry.
	RegisterCCEntry OperationCode = 76
	// RegisterPassword is the operation code for registerPassword.
	RegisterPassword OperationCode = 17
	// RegisterSS is the operation code for registerSS.
	RegisterSS OperationCode = 10
	// SsInvocationNotification is the operation code for ss-InvocationNotification.
	SsInvocationNotification OperationCode = 72
	// UnstructuredSSNotify is the operation code for unstructuredSS-Notify.
	UnstructuredSSNotify OperationCode = 61
	// UnstructuredSSRequest is the operation code for unstructuredSS-Request.
	UnstructuredSSRequest OperationCode = 60
)

// String returns the ASN.1 name of the operation code.
func (c OperationCode) String() string {
	switch c {
	case IstAlert:
		return "ist-Alert"
	case IstCommand:
		return "ist-Command"
	case ProvideRoamingNumber:
		return "provideRoamingNumber"
	case ReleaseResources:
		return "releaseResources"
	case RemoteUserFree:
		return "remoteUserFree"
	case ResumeCallHandling:
		return "resumeCallHandling"
	case SendRoutingInfo:
		return "sendRoutingInfo"
	case SetReportingState:
		return "setReportingState"
	case StatusReport:
		return "statusReport"
	case ForwardGroupCallSignalling:
		return "forwardGroupCallSignalling"
	case PrepareGroupCall:
		return "prepareGroupCall"
	case ProcessGroupCallSignalling:
		return "processGroupCallSignalling"
	case SendGroupCallEndSignal:
		return "sendGroupCallEndSignal"
	case SendGroupCallInfo:
		return "sendGroupCallInfo"
	case ProvideSubscriberLocation:
		return "provideSubscriberLocation"
	case SendRoutingInfoForLCS:
		return "sendRoutingInfoForLCS"
	case SubscriberLocationReport:
		return "subscriberLocationReport"
	case AnyTimeInterrogation:
		return "anyTimeInterrogation"
	case AnyTimeModification:
		return "anyTimeModification"
	case AnyTimeSubscriptionInterrogation:
		return "anyTimeSubscriptionInterrogation"
	case AuthenticationFailureReport:
		return "authenticationFailureReport"
	case CancelLocation:
		return "cancelLocation"
	case CancelVcsgLocation:
		return "cancelVcsgLocation"
	case CheckIMEI:
		return "checkIMEI"
	case DeleteSubscriberData:
		return "deleteSubscriberData"
	case FailureReport:
		return "failureReport"
	case ForwardAccessSignalling:
		return "forwardAccessSignalling"
	case ForwardCheckSSIndication:
		return "forwardCheckSS-Indication"
	case InsertSubscriberData:
		return "insertSubscriberData"
	case NoteMMEvent:
		return "noteMM-Event"
	case NoteMsPresentForGprs:
		return "noteMsPresentForGprs"
	case NoteSubscriberDataModified:
		return "noteSubscriberDataModified"
	case PrepareHandover:
		return "prepareHandover"
	case PrepareSubsequentHandover:
		return "prepareSubsequentHandover"
	case ProcessAccessSignalling:
		return "processAccessSignalling"
	case ProvideSubscriberInfo:
		return "provideSubscriberInfo"
	case PurgeMS:
		return "purgeMS"
	case Reset:
		return "reset"
	case RestoreData:
		return "restoreData"
	case SendAuthenticationInfo:
		return "sendAuthenticationInfo"
	case SendEndSignal:
		return "sendEndSignal"
	case SendIdentification:
		return "sendIdentification"
	case SendRoutingInfoForGprs:
		return "sendRoutingInfoForGprs"
	case UpdateGprsLocation:
		return "updateGprsLocation"
	case UpdateLocation:
		return "updateLocation"
	case UpdateVcsgLocation:
		return "updateVcsgLocation"
	case ActivateTraceMode:
		return "activateTraceMode"
	case DeactivateTraceMode:
		return "deactivateTraceMode"
	case SendIMSI:
		return "sendIMSI"
	case AlertServiceCentre:
		return "alertServiceCentre"
	case InformServiceCentre:
		return "informServiceCentre"
	case MoForwardSM:
		return "mo-ForwardSM"
	case MtForwardSM:
		return "mt-ForwardSM"
	case MtForwardSMVGCS:
		return "mt-ForwardSM-VGCS"
	case ReadyForSM:
		return "readyForSM"
	case ReportSMDeliveryStatus:
		return "reportSM-DeliveryStatus"
	case SendRoutingInfoForSM:
		return "sendRoutingInfoForSM"
	case ActivateSS:
		return "activateSS"
	case DeactivateSS:
		return "deactivateSS"
	case EraseCCEntry:
		return "eraseCC-Entry"
	case EraseSS:
		return "eraseSS"
	case GetPassword:
		return "getPassword"
	case InterrogateSS:
		return "interrogateSS"
	case ProcessUnstructuredSSRequest:
		return "processUnstructuredSS-Request"
	case RegisterCCEntry:
		return "registerCC-Entry"
	case RegisterPassword:
		return "registerPassword"
	case RegisterSS:
		return "registerSS"
	case SsInvocationNotification:
		return "ss-InvocationNotification"
	case UnstructuredSSNotify:
		return "unstructuredSS-Notify"
	case UnstructuredSSRequest:
		return "unstructuredSS-Request"
	default:
		return fmt.Sprintf("OperationCode(%d)", int64(c))
	}
}
