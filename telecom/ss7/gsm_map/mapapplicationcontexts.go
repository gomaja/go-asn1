// Code generated from ASN.1 module "MAP-ApplicationContexts". DO NOT EDIT.

package gsm_map

import (
	"github.com/gomaja/go-asn1/runtime"
	"github.com/gomaja/go-asn1/runtime/ber"
	"github.com/gomaja/go-asn1/runtime/tag"
)

// Ensure imports are used.
var (
	_ runtime.BitString
	_ = ber.EncodeTLV
	_ = tag.ClassUniversal
)

// MapAc returns the OID value for map-ac.
func MapAc() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x04\x00\x00\x01\x00")
}

// NetworkLocUpContextV3 returns the OID value for networkLocUpContext-v3.
func NetworkLocUpContextV3() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x04\x00\x00\x01\x00\x01\x03")
}

// LocationCancellationContextV3 returns the OID value for locationCancellationContext-v3.
func LocationCancellationContextV3() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x04\x00\x00\x01\x00\x02\x03")
}

// RoamingNumberEnquiryContextV3 returns the OID value for roamingNumberEnquiryContext-v3.
func RoamingNumberEnquiryContextV3() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x04\x00\x00\x01\x00\x03\x03")
}

// AuthenticationFailureReportContextV3 returns the OID value for authenticationFailureReportContext-v3.
func AuthenticationFailureReportContextV3() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x04\x00\x00\x01\x00\x27\x03")
}

// LocationInfoRetrievalContextV3 returns the OID value for locationInfoRetrievalContext-v3.
func LocationInfoRetrievalContextV3() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x04\x00\x00\x01\x00\x05\x03")
}

// ResetContextV3 returns the OID value for resetContext-v3.
func ResetContextV3() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x04\x00\x00\x01\x00\x0a\x03")
}

// HandoverControlContextV3 returns the OID value for handoverControlContext-v3.
func HandoverControlContextV3() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x04\x00\x00\x01\x00\x0b\x03")
}

// EquipmentMngtContextV3 returns the OID value for equipmentMngtContext-v3.
func EquipmentMngtContextV3() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x04\x00\x00\x01\x00\x0d\x03")
}

// InfoRetrievalContextV3 returns the OID value for infoRetrievalContext-v3.
func InfoRetrievalContextV3() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x04\x00\x00\x01\x00\x0e\x03")
}

// InterVlrInfoRetrievalContextV3 returns the OID value for interVlrInfoRetrievalContext-v3.
func InterVlrInfoRetrievalContextV3() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x04\x00\x00\x01\x00\x0f\x03")
}

// SubscriberDataMngtContextV3 returns the OID value for subscriberDataMngtContext-v3.
func SubscriberDataMngtContextV3() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x04\x00\x00\x01\x00\x10\x03")
}

// TracingContextV3 returns the OID value for tracingContext-v3.
func TracingContextV3() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x04\x00\x00\x01\x00\x11\x03")
}

// NetworkFunctionalSsContextV2 returns the OID value for networkFunctionalSsContext-v2.
func NetworkFunctionalSsContextV2() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x04\x00\x00\x01\x00\x12\x02")
}

// NetworkUnstructuredSsContextV2 returns the OID value for networkUnstructuredSsContext-v2.
func NetworkUnstructuredSsContextV2() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x04\x00\x00\x01\x00\x13\x02")
}

// ShortMsgGatewayContextV3 returns the OID value for shortMsgGatewayContext-v3.
func ShortMsgGatewayContextV3() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x04\x00\x00\x01\x00\x14\x03")
}

// ShortMsgMORelayContextV3 returns the OID value for shortMsgMO-RelayContext-v3.
func ShortMsgMORelayContextV3() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x04\x00\x00\x01\x00\x15\x03")
}

// ShortMsgAlertContextV2 returns the OID value for shortMsgAlertContext-v2.
func ShortMsgAlertContextV2() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x04\x00\x00\x01\x00\x17\x02")
}

// MwdMngtContextV3 returns the OID value for mwdMngtContext-v3.
func MwdMngtContextV3() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x04\x00\x00\x01\x00\x18\x03")
}

// ShortMsgMTRelayContextV3 returns the OID value for shortMsgMT-RelayContext-v3.
func ShortMsgMTRelayContextV3() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x04\x00\x00\x01\x00\x19\x03")
}

// ShortMsgMTRelayVGCSContextV3 returns the OID value for shortMsgMT-Relay-VGCS-Context-v3.
func ShortMsgMTRelayVGCSContextV3() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x04\x00\x00\x01\x00\x29\x03")
}

// ImsiRetrievalContextV2 returns the OID value for imsiRetrievalContext-v2.
func ImsiRetrievalContextV2() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x04\x00\x00\x01\x00\x1a\x02")
}

// MsPurgingContextV3 returns the OID value for msPurgingContext-v3.
func MsPurgingContextV3() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x04\x00\x00\x01\x00\x1b\x03")
}

// SubscriberInfoEnquiryContextV3 returns the OID value for subscriberInfoEnquiryContext-v3.
func SubscriberInfoEnquiryContextV3() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x04\x00\x00\x01\x00\x1c\x03")
}

// AnyTimeInfoEnquiryContextV3 returns the OID value for anyTimeInfoEnquiryContext-v3.
func AnyTimeInfoEnquiryContextV3() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x04\x00\x00\x01\x00\x1d\x03")
}

// CallControlTransferContextV4 returns the OID value for callControlTransferContext-v4.
func CallControlTransferContextV4() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x04\x00\x00\x01\x00\x06\x04")
}

// SsInvocationNotificationContextV3 returns the OID value for ss-InvocationNotificationContext-v3.
func SsInvocationNotificationContextV3() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x04\x00\x00\x01\x00\x24\x03")
}

// GroupCallControlContextV3 returns the OID value for groupCallControlContext-v3.
func GroupCallControlContextV3() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x04\x00\x00\x01\x00\x1f\x03")
}

// GroupCallInfoRetrievalContextV3 returns the OID value for groupCallInfoRetrievalContext-v3.
func GroupCallInfoRetrievalContextV3() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x04\x00\x00\x01\x00\x2d\x03")
}

// GprsLocationUpdateContextV3 returns the OID value for gprsLocationUpdateContext-v3.
func GprsLocationUpdateContextV3() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x04\x00\x00\x01\x00\x20\x03")
}

// GprsLocationInfoRetrievalContextV4 returns the OID value for gprsLocationInfoRetrievalContext-v4.
func GprsLocationInfoRetrievalContextV4() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x04\x00\x00\x01\x00\x21\x04")
}

// FailureReportContextV3 returns the OID value for failureReportContext-v3.
func FailureReportContextV3() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x04\x00\x00\x01\x00\x22\x03")
}

// GprsNotifyContextV3 returns the OID value for gprsNotifyContext-v3.
func GprsNotifyContextV3() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x04\x00\x00\x01\x00\x23\x03")
}

// ReportingContextV3 returns the OID value for reportingContext-v3.
func ReportingContextV3() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x04\x00\x00\x01\x00\x07\x03")
}

// CallCompletionContextV3 returns the OID value for callCompletionContext-v3.
func CallCompletionContextV3() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x04\x00\x00\x01\x00\x08\x03")
}

// IstAlertingContextV3 returns the OID value for istAlertingContext-v3.
func IstAlertingContextV3() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x04\x00\x00\x01\x00\x04\x03")
}

// ServiceTerminationContextV3 returns the OID value for serviceTerminationContext-v3.
func ServiceTerminationContextV3() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x04\x00\x00\x01\x00\x09\x03")
}

// LocationSvcGatewayContextV3 returns the OID value for locationSvcGatewayContext-v3.
func LocationSvcGatewayContextV3() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x04\x00\x00\x01\x00\x25\x03")
}

// LocationSvcEnquiryContextV3 returns the OID value for locationSvcEnquiryContext-v3.
func LocationSvcEnquiryContextV3() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x04\x00\x00\x01\x00\x26\x03")
}

// MmEventReportingContextV3 returns the OID value for mm-EventReportingContext-v3.
func MmEventReportingContextV3() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x04\x00\x00\x01\x00\x2a\x03")
}

// AnyTimeInfoHandlingContextV3 returns the OID value for anyTimeInfoHandlingContext-v3.
func AnyTimeInfoHandlingContextV3() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x04\x00\x00\x01\x00\x2b\x03")
}

// SubscriberDataModificationNotificationContextV3 returns the OID value for subscriberDataModificationNotificationContext-v3.
func SubscriberDataModificationNotificationContextV3() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x04\x00\x00\x01\x00\x16\x03")
}

// ResourceManagementContextV3 returns the OID value for resourceManagementContext-v3.
func ResourceManagementContextV3() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x04\x00\x00\x01\x00\x2c\x03")
}

// VcsgLocationUpdateContextV3 returns the OID value for vcsgLocationUpdateContext-v3.
func VcsgLocationUpdateContextV3() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x04\x00\x00\x01\x00\x2e\x03")
}

// VcsgLocationCancellationContextV3 returns the OID value for vcsgLocationCancellationContext-v3.
func VcsgLocationCancellationContextV3() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x04\x00\x00\x01\x00\x2f\x03")
}
