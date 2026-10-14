// Code generated from ASN.1. DO NOT EDIT.

// Codes retain information-object provenance (X.880 §§8.2.13, 8.3.5, 8.8).
package v21_map_errors

import "fmt"

// HistoricalMAPErrorCode is a local INTEGER code.
type HistoricalMAPErrorCode int64

const (
	// HistoricalMAPErrorsSystemFailure identifies systemFailure. Source: map-29002-v21/modules/MAP-Errors.asn; SHA-256 0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054.
	HistoricalMAPErrorsSystemFailure HistoricalMAPErrorCode = 34
	// HistoricalMAPErrorsDataMissing identifies dataMissing. Source: map-29002-v21/modules/MAP-Errors.asn; SHA-256 0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054.
	HistoricalMAPErrorsDataMissing HistoricalMAPErrorCode = 35
	// HistoricalMAPErrorsUnexpectedDataValue identifies unexpectedDataValue. Source: map-29002-v21/modules/MAP-Errors.asn; SHA-256 0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054.
	HistoricalMAPErrorsUnexpectedDataValue HistoricalMAPErrorCode = 36
	// HistoricalMAPErrorsFacilityNotSupported identifies facilityNotSupported. Source: map-29002-v21/modules/MAP-Errors.asn; SHA-256 0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054.
	HistoricalMAPErrorsFacilityNotSupported HistoricalMAPErrorCode = 21
	// HistoricalMAPErrorsIncompatibleTerminal identifies incompatibleTerminal. Source: map-29002-v21/modules/MAP-Errors.asn; SHA-256 0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054.
	HistoricalMAPErrorsIncompatibleTerminal HistoricalMAPErrorCode = 28
	// HistoricalMAPErrorsResourceLimitation identifies resourceLimitation. Source: map-29002-v21/modules/MAP-Errors.asn; SHA-256 0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054.
	HistoricalMAPErrorsResourceLimitation HistoricalMAPErrorCode = 51
	// HistoricalMAPErrorsUnknownSubscriber identifies unknownSubscriber. Source: map-29002-v21/modules/MAP-Errors.asn; SHA-256 0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054.
	HistoricalMAPErrorsUnknownSubscriber HistoricalMAPErrorCode = 1
	// HistoricalMAPErrorsNumberChanged identifies numberChanged. Source: map-29002-v21/modules/MAP-Errors.asn; SHA-256 0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054.
	HistoricalMAPErrorsNumberChanged HistoricalMAPErrorCode = 44
	// HistoricalMAPErrorsUnknownMSC identifies unknownMSC. Source: map-29002-v21/modules/MAP-Errors.asn; SHA-256 0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054.
	HistoricalMAPErrorsUnknownMSC HistoricalMAPErrorCode = 3
	// HistoricalMAPErrorsUnidentifiedSubscriber identifies unidentifiedSubscriber. Source: map-29002-v21/modules/MAP-Errors.asn; SHA-256 0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054.
	HistoricalMAPErrorsUnidentifiedSubscriber HistoricalMAPErrorCode = 5
	// HistoricalMAPErrorsUnknownEquipment identifies unknownEquipment. Source: map-29002-v21/modules/MAP-Errors.asn; SHA-256 0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054.
	HistoricalMAPErrorsUnknownEquipment HistoricalMAPErrorCode = 7
	// HistoricalMAPErrorsRoamingNotAllowed identifies roamingNotAllowed. Source: map-29002-v21/modules/MAP-Errors.asn; SHA-256 0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054.
	HistoricalMAPErrorsRoamingNotAllowed HistoricalMAPErrorCode = 8
	// HistoricalMAPErrorsIllegalSubscriber identifies illegalSubscriber. Source: map-29002-v21/modules/MAP-Errors.asn; SHA-256 0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054.
	HistoricalMAPErrorsIllegalSubscriber HistoricalMAPErrorCode = 9
	// HistoricalMAPErrorsIllegalEquipment identifies illegalEquipment. Source: map-29002-v21/modules/MAP-Errors.asn; SHA-256 0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054.
	HistoricalMAPErrorsIllegalEquipment HistoricalMAPErrorCode = 12
	// HistoricalMAPErrorsBearerServiceNotProvisioned identifies bearerServiceNotProvisioned. Source: map-29002-v21/modules/MAP-Errors.asn; SHA-256 0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054.
	HistoricalMAPErrorsBearerServiceNotProvisioned HistoricalMAPErrorCode = 10
	// HistoricalMAPErrorsTeleserviceNotProvisioned identifies teleserviceNotProvisioned. Source: map-29002-v21/modules/MAP-Errors.asn; SHA-256 0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054.
	HistoricalMAPErrorsTeleserviceNotProvisioned HistoricalMAPErrorCode = 11
	// HistoricalMAPErrorsNoHandoverNumberAvailable identifies noHandoverNumberAvailable. Source: map-29002-v21/modules/MAP-Errors.asn; SHA-256 0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054.
	HistoricalMAPErrorsNoHandoverNumberAvailable HistoricalMAPErrorCode = 25
	// HistoricalMAPErrorsSubsequentHandoverFailure identifies subsequentHandoverFailure. Source: map-29002-v21/modules/MAP-Errors.asn; SHA-256 0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054.
	HistoricalMAPErrorsSubsequentHandoverFailure HistoricalMAPErrorCode = 26
	// HistoricalMAPErrorsTargetCellOutsideGroupCallArea identifies targetCellOutsideGroupCallArea. Source: map-29002-v21/modules/MAP-Errors.asn; SHA-256 0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054.
	HistoricalMAPErrorsTargetCellOutsideGroupCallArea HistoricalMAPErrorCode = 42
	// HistoricalMAPErrorsTracingBufferFull identifies tracingBufferFull. Source: map-29002-v21/modules/MAP-Errors.asn; SHA-256 0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054.
	HistoricalMAPErrorsTracingBufferFull HistoricalMAPErrorCode = 40
	// HistoricalMAPErrorsNoRoamingNumberAvailable identifies noRoamingNumberAvailable. Source: map-29002-v21/modules/MAP-Errors.asn; SHA-256 0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054.
	HistoricalMAPErrorsNoRoamingNumberAvailable HistoricalMAPErrorCode = 39
	// HistoricalMAPErrorsAbsentSubscriber identifies absentSubscriber. Source: map-29002-v21/modules/MAP-Errors.asn; SHA-256 0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054.
	HistoricalMAPErrorsAbsentSubscriber HistoricalMAPErrorCode = 27
	// HistoricalMAPErrorsBusySubscriber identifies busySubscriber. Source: map-29002-v21/modules/MAP-Errors.asn; SHA-256 0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054.
	HistoricalMAPErrorsBusySubscriber HistoricalMAPErrorCode = 45
	// HistoricalMAPErrorsNoSubscriberReply identifies noSubscriberReply. Source: map-29002-v21/modules/MAP-Errors.asn; SHA-256 0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054.
	HistoricalMAPErrorsNoSubscriberReply HistoricalMAPErrorCode = 46
	// HistoricalMAPErrorsCallBarred identifies callBarred. Source: map-29002-v21/modules/MAP-Errors.asn; SHA-256 0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054.
	HistoricalMAPErrorsCallBarred HistoricalMAPErrorCode = 13
	// HistoricalMAPErrorsForwardingViolation identifies forwardingViolation. Source: map-29002-v21/modules/MAP-Errors.asn; SHA-256 0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054.
	HistoricalMAPErrorsForwardingViolation HistoricalMAPErrorCode = 14
	// HistoricalMAPErrorsForwardingFailed identifies forwardingFailed. Source: map-29002-v21/modules/MAP-Errors.asn; SHA-256 0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054.
	HistoricalMAPErrorsForwardingFailed HistoricalMAPErrorCode = 47
	// HistoricalMAPErrorsCugReject identifies cug-Reject. Source: map-29002-v21/modules/MAP-Errors.asn; SHA-256 0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054.
	HistoricalMAPErrorsCugReject HistoricalMAPErrorCode = 15
	// HistoricalMAPErrorsOrNotAllowed identifies or-NotAllowed. Source: map-29002-v21/modules/MAP-Errors.asn; SHA-256 0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054.
	HistoricalMAPErrorsOrNotAllowed HistoricalMAPErrorCode = 48
	// HistoricalMAPErrorsAtiNotAllowed identifies ati-NotAllowed. Source: map-29002-v21/modules/MAP-Errors.asn; SHA-256 0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054.
	HistoricalMAPErrorsAtiNotAllowed HistoricalMAPErrorCode = 49
	// HistoricalMAPErrorsAtsiNotAllowed identifies atsi-NotAllowed. Source: map-29002-v21/modules/MAP-Errors.asn; SHA-256 0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054.
	HistoricalMAPErrorsAtsiNotAllowed HistoricalMAPErrorCode = 60
	// HistoricalMAPErrorsAtmNotAllowed identifies atm-NotAllowed. Source: map-29002-v21/modules/MAP-Errors.asn; SHA-256 0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054.
	HistoricalMAPErrorsAtmNotAllowed HistoricalMAPErrorCode = 61
	// HistoricalMAPErrorsInformationNotAvailable identifies informationNotAvailable. Source: map-29002-v21/modules/MAP-Errors.asn; SHA-256 0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054.
	HistoricalMAPErrorsInformationNotAvailable HistoricalMAPErrorCode = 62
	// HistoricalMAPErrorsIllegalSSOperation identifies illegalSS-Operation. Source: map-29002-v21/modules/MAP-Errors.asn; SHA-256 0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054.
	HistoricalMAPErrorsIllegalSSOperation HistoricalMAPErrorCode = 16
	// HistoricalMAPErrorsSsErrorStatus identifies ss-ErrorStatus. Source: map-29002-v21/modules/MAP-Errors.asn; SHA-256 0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054.
	HistoricalMAPErrorsSsErrorStatus HistoricalMAPErrorCode = 17
	// HistoricalMAPErrorsSsNotAvailable identifies ss-NotAvailable. Source: map-29002-v21/modules/MAP-Errors.asn; SHA-256 0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054.
	HistoricalMAPErrorsSsNotAvailable HistoricalMAPErrorCode = 18
	// HistoricalMAPErrorsSsSubscriptionViolation identifies ss-SubscriptionViolation. Source: map-29002-v21/modules/MAP-Errors.asn; SHA-256 0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054.
	HistoricalMAPErrorsSsSubscriptionViolation HistoricalMAPErrorCode = 19
	// HistoricalMAPErrorsSsIncompatibility identifies ss-Incompatibility. Source: map-29002-v21/modules/MAP-Errors.asn; SHA-256 0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054.
	HistoricalMAPErrorsSsIncompatibility HistoricalMAPErrorCode = 20
	// HistoricalMAPErrorsUnknownAlphabet identifies unknownAlphabet. Source: map-29002-v21/modules/MAP-Errors.asn; SHA-256 0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054.
	HistoricalMAPErrorsUnknownAlphabet HistoricalMAPErrorCode = 71
	// HistoricalMAPErrorsUssdBusy identifies ussd-Busy. Source: map-29002-v21/modules/MAP-Errors.asn; SHA-256 0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054.
	HistoricalMAPErrorsUssdBusy HistoricalMAPErrorCode = 72
	// HistoricalMAPErrorsPwRegistrationFailure identifies pw-RegistrationFailure. Source: map-29002-v21/modules/MAP-Errors.asn; SHA-256 0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054.
	HistoricalMAPErrorsPwRegistrationFailure HistoricalMAPErrorCode = 37
	// HistoricalMAPErrorsNegativePWCheck identifies negativePW-Check. Source: map-29002-v21/modules/MAP-Errors.asn; SHA-256 0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054.
	HistoricalMAPErrorsNegativePWCheck HistoricalMAPErrorCode = 38
	// HistoricalMAPErrorsNumberOfPWAttemptsViolation identifies numberOfPW-AttemptsViolation. Source: map-29002-v21/modules/MAP-Errors.asn; SHA-256 0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054.
	HistoricalMAPErrorsNumberOfPWAttemptsViolation HistoricalMAPErrorCode = 43
	// HistoricalMAPErrorsShortTermDenial identifies shortTermDenial. Source: map-29002-v21/modules/MAP-Errors.asn; SHA-256 0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054.
	HistoricalMAPErrorsShortTermDenial HistoricalMAPErrorCode = 29
	// HistoricalMAPErrorsLongTermDenial identifies longTermDenial. Source: map-29002-v21/modules/MAP-Errors.asn; SHA-256 0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054.
	HistoricalMAPErrorsLongTermDenial HistoricalMAPErrorCode = 30
	// HistoricalMAPErrorsSubscriberBusyForMTSMS identifies subscriberBusyForMT-SMS. Source: map-29002-v21/modules/MAP-Errors.asn; SHA-256 0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054.
	HistoricalMAPErrorsSubscriberBusyForMTSMS HistoricalMAPErrorCode = 31
	// HistoricalMAPErrorsSmDeliveryFailure identifies sm-DeliveryFailure. Source: map-29002-v21/modules/MAP-Errors.asn; SHA-256 0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054.
	HistoricalMAPErrorsSmDeliveryFailure HistoricalMAPErrorCode = 32
	// HistoricalMAPErrorsMessageWaitingListFull identifies messageWaitingListFull. Source: map-29002-v21/modules/MAP-Errors.asn; SHA-256 0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054.
	HistoricalMAPErrorsMessageWaitingListFull HistoricalMAPErrorCode = 33
	// HistoricalMAPErrorsAbsentSubscriberSM identifies absentSubscriberSM. Source: map-29002-v21/modules/MAP-Errors.asn; SHA-256 0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054.
	HistoricalMAPErrorsAbsentSubscriberSM HistoricalMAPErrorCode = 6
	// HistoricalMAPErrorsNoGroupCallNumberAvailable identifies noGroupCallNumberAvailable. Source: map-29002-v21/modules/MAP-Errors.asn; SHA-256 0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054.
	HistoricalMAPErrorsNoGroupCallNumberAvailable HistoricalMAPErrorCode = 50
	// HistoricalMAPErrorsOngoingGroupCall identifies ongoingGroupCall. Source: map-29002-v21/modules/MAP-Errors.asn; SHA-256 0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054.
	HistoricalMAPErrorsOngoingGroupCall HistoricalMAPErrorCode = 22
	// HistoricalMAPErrorsUnauthorizedRequestingNetwork identifies unauthorizedRequestingNetwork. Source: map-29002-v21/modules/MAP-Errors.asn; SHA-256 0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054.
	HistoricalMAPErrorsUnauthorizedRequestingNetwork HistoricalMAPErrorCode = 52
	// HistoricalMAPErrorsUnauthorizedLCSClient identifies unauthorizedLCSClient. Source: map-29002-v21/modules/MAP-Errors.asn; SHA-256 0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054.
	HistoricalMAPErrorsUnauthorizedLCSClient HistoricalMAPErrorCode = 53
	// HistoricalMAPErrorsPositionMethodFailure identifies positionMethodFailure. Source: map-29002-v21/modules/MAP-Errors.asn; SHA-256 0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054.
	HistoricalMAPErrorsPositionMethodFailure HistoricalMAPErrorCode = 54
	// HistoricalMAPErrorsUnknownOrUnreachableLCSClient identifies unknownOrUnreachableLCSClient. Source: map-29002-v21/modules/MAP-Errors.asn; SHA-256 0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054.
	HistoricalMAPErrorsUnknownOrUnreachableLCSClient HistoricalMAPErrorCode = 58
	// HistoricalMAPErrorsMmEventNotSupported identifies mm-EventNotSupported. Source: map-29002-v21/modules/MAP-Errors.asn; SHA-256 0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054.
	HistoricalMAPErrorsMmEventNotSupported HistoricalMAPErrorCode = 59
)

// String returns the first source name for this code.
func (c HistoricalMAPErrorCode) String() string {
	switch c {
	case HistoricalMAPErrorsSystemFailure:
		return "systemFailure"
	case HistoricalMAPErrorsDataMissing:
		return "dataMissing"
	case HistoricalMAPErrorsUnexpectedDataValue:
		return "unexpectedDataValue"
	case HistoricalMAPErrorsFacilityNotSupported:
		return "facilityNotSupported"
	case HistoricalMAPErrorsIncompatibleTerminal:
		return "incompatibleTerminal"
	case HistoricalMAPErrorsResourceLimitation:
		return "resourceLimitation"
	case HistoricalMAPErrorsUnknownSubscriber:
		return "unknownSubscriber"
	case HistoricalMAPErrorsNumberChanged:
		return "numberChanged"
	case HistoricalMAPErrorsUnknownMSC:
		return "unknownMSC"
	case HistoricalMAPErrorsUnidentifiedSubscriber:
		return "unidentifiedSubscriber"
	case HistoricalMAPErrorsUnknownEquipment:
		return "unknownEquipment"
	case HistoricalMAPErrorsRoamingNotAllowed:
		return "roamingNotAllowed"
	case HistoricalMAPErrorsIllegalSubscriber:
		return "illegalSubscriber"
	case HistoricalMAPErrorsIllegalEquipment:
		return "illegalEquipment"
	case HistoricalMAPErrorsBearerServiceNotProvisioned:
		return "bearerServiceNotProvisioned"
	case HistoricalMAPErrorsTeleserviceNotProvisioned:
		return "teleserviceNotProvisioned"
	case HistoricalMAPErrorsNoHandoverNumberAvailable:
		return "noHandoverNumberAvailable"
	case HistoricalMAPErrorsSubsequentHandoverFailure:
		return "subsequentHandoverFailure"
	case HistoricalMAPErrorsTargetCellOutsideGroupCallArea:
		return "targetCellOutsideGroupCallArea"
	case HistoricalMAPErrorsTracingBufferFull:
		return "tracingBufferFull"
	case HistoricalMAPErrorsNoRoamingNumberAvailable:
		return "noRoamingNumberAvailable"
	case HistoricalMAPErrorsAbsentSubscriber:
		return "absentSubscriber"
	case HistoricalMAPErrorsBusySubscriber:
		return "busySubscriber"
	case HistoricalMAPErrorsNoSubscriberReply:
		return "noSubscriberReply"
	case HistoricalMAPErrorsCallBarred:
		return "callBarred"
	case HistoricalMAPErrorsForwardingViolation:
		return "forwardingViolation"
	case HistoricalMAPErrorsForwardingFailed:
		return "forwardingFailed"
	case HistoricalMAPErrorsCugReject:
		return "cug-Reject"
	case HistoricalMAPErrorsOrNotAllowed:
		return "or-NotAllowed"
	case HistoricalMAPErrorsAtiNotAllowed:
		return "ati-NotAllowed"
	case HistoricalMAPErrorsAtsiNotAllowed:
		return "atsi-NotAllowed"
	case HistoricalMAPErrorsAtmNotAllowed:
		return "atm-NotAllowed"
	case HistoricalMAPErrorsInformationNotAvailable:
		return "informationNotAvailable"
	case HistoricalMAPErrorsIllegalSSOperation:
		return "illegalSS-Operation"
	case HistoricalMAPErrorsSsErrorStatus:
		return "ss-ErrorStatus"
	case HistoricalMAPErrorsSsNotAvailable:
		return "ss-NotAvailable"
	case HistoricalMAPErrorsSsSubscriptionViolation:
		return "ss-SubscriptionViolation"
	case HistoricalMAPErrorsSsIncompatibility:
		return "ss-Incompatibility"
	case HistoricalMAPErrorsUnknownAlphabet:
		return "unknownAlphabet"
	case HistoricalMAPErrorsUssdBusy:
		return "ussd-Busy"
	case HistoricalMAPErrorsPwRegistrationFailure:
		return "pw-RegistrationFailure"
	case HistoricalMAPErrorsNegativePWCheck:
		return "negativePW-Check"
	case HistoricalMAPErrorsNumberOfPWAttemptsViolation:
		return "numberOfPW-AttemptsViolation"
	case HistoricalMAPErrorsShortTermDenial:
		return "shortTermDenial"
	case HistoricalMAPErrorsLongTermDenial:
		return "longTermDenial"
	case HistoricalMAPErrorsSubscriberBusyForMTSMS:
		return "subscriberBusyForMT-SMS"
	case HistoricalMAPErrorsSmDeliveryFailure:
		return "sm-DeliveryFailure"
	case HistoricalMAPErrorsMessageWaitingListFull:
		return "messageWaitingListFull"
	case HistoricalMAPErrorsAbsentSubscriberSM:
		return "absentSubscriberSM"
	case HistoricalMAPErrorsNoGroupCallNumberAvailable:
		return "noGroupCallNumberAvailable"
	case HistoricalMAPErrorsOngoingGroupCall:
		return "ongoingGroupCall"
	case HistoricalMAPErrorsUnauthorizedRequestingNetwork:
		return "unauthorizedRequestingNetwork"
	case HistoricalMAPErrorsUnauthorizedLCSClient:
		return "unauthorizedLCSClient"
	case HistoricalMAPErrorsPositionMethodFailure:
		return "positionMethodFailure"
	case HistoricalMAPErrorsUnknownOrUnreachableLCSClient:
		return "unknownOrUnreachableLCSClient"
	case HistoricalMAPErrorsMmEventNotSupported:
		return "mm-EventNotSupported"
	default:
		return fmt.Sprintf("HistoricalMAPErrorCode(%d)", int64(c))
	}
}
