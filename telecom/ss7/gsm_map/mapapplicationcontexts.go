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

// MapAc returns the OID value for MapAc.
func MapAc() runtime.ObjectIdentifier { return runtime.ObjectIdentifier{0, 4, 0, 0, 1, 0} }

// NetworkLocUpContextV3 returns the OID value for NetworkLocUpContextV3.
func NetworkLocUpContextV3() runtime.ObjectIdentifier {
	return runtime.ObjectIdentifier{0, 4, 0, 0, 1, 0, 1, 3}
}

// LocationCancellationContextV3 returns the OID value for LocationCancellationContextV3.
func LocationCancellationContextV3() runtime.ObjectIdentifier {
	return runtime.ObjectIdentifier{0, 4, 0, 0, 1, 0, 2, 3}
}

// RoamingNumberEnquiryContextV3 returns the OID value for RoamingNumberEnquiryContextV3.
func RoamingNumberEnquiryContextV3() runtime.ObjectIdentifier {
	return runtime.ObjectIdentifier{0, 4, 0, 0, 1, 0, 3, 3}
}

// AuthenticationFailureReportContextV3 returns the OID value for AuthenticationFailureReportContextV3.
func AuthenticationFailureReportContextV3() runtime.ObjectIdentifier {
	return runtime.ObjectIdentifier{0, 4, 0, 0, 1, 0, 39, 3}
}

// LocationInfoRetrievalContextV3 returns the OID value for LocationInfoRetrievalContextV3.
func LocationInfoRetrievalContextV3() runtime.ObjectIdentifier {
	return runtime.ObjectIdentifier{0, 4, 0, 0, 1, 0, 5, 3}
}

// ResetContextV3 returns the OID value for ResetContextV3.
func ResetContextV3() runtime.ObjectIdentifier {
	return runtime.ObjectIdentifier{0, 4, 0, 0, 1, 0, 10, 3}
}

// HandoverControlContextV3 returns the OID value for HandoverControlContextV3.
func HandoverControlContextV3() runtime.ObjectIdentifier {
	return runtime.ObjectIdentifier{0, 4, 0, 0, 1, 0, 11, 3}
}

// EquipmentMngtContextV3 returns the OID value for EquipmentMngtContextV3.
func EquipmentMngtContextV3() runtime.ObjectIdentifier {
	return runtime.ObjectIdentifier{0, 4, 0, 0, 1, 0, 13, 3}
}

// InfoRetrievalContextV3 returns the OID value for InfoRetrievalContextV3.
func InfoRetrievalContextV3() runtime.ObjectIdentifier {
	return runtime.ObjectIdentifier{0, 4, 0, 0, 1, 0, 14, 3}
}

// InterVlrInfoRetrievalContextV3 returns the OID value for InterVlrInfoRetrievalContextV3.
func InterVlrInfoRetrievalContextV3() runtime.ObjectIdentifier {
	return runtime.ObjectIdentifier{0, 4, 0, 0, 1, 0, 15, 3}
}

// SubscriberDataMngtContextV3 returns the OID value for SubscriberDataMngtContextV3.
func SubscriberDataMngtContextV3() runtime.ObjectIdentifier {
	return runtime.ObjectIdentifier{0, 4, 0, 0, 1, 0, 16, 3}
}

// TracingContextV3 returns the OID value for TracingContextV3.
func TracingContextV3() runtime.ObjectIdentifier {
	return runtime.ObjectIdentifier{0, 4, 0, 0, 1, 0, 17, 3}
}

// NetworkFunctionalSsContextV2 returns the OID value for NetworkFunctionalSsContextV2.
func NetworkFunctionalSsContextV2() runtime.ObjectIdentifier {
	return runtime.ObjectIdentifier{0, 4, 0, 0, 1, 0, 18, 2}
}

// NetworkUnstructuredSsContextV2 returns the OID value for NetworkUnstructuredSsContextV2.
func NetworkUnstructuredSsContextV2() runtime.ObjectIdentifier {
	return runtime.ObjectIdentifier{0, 4, 0, 0, 1, 0, 19, 2}
}

// ShortMsgGatewayContextV3 returns the OID value for ShortMsgGatewayContextV3.
func ShortMsgGatewayContextV3() runtime.ObjectIdentifier {
	return runtime.ObjectIdentifier{0, 4, 0, 0, 1, 0, 20, 3}
}

// ShortMsgMORelayContextV3 returns the OID value for ShortMsgMORelayContextV3.
func ShortMsgMORelayContextV3() runtime.ObjectIdentifier {
	return runtime.ObjectIdentifier{0, 4, 0, 0, 1, 0, 21, 3}
}

// ShortMsgAlertContextV2 returns the OID value for ShortMsgAlertContextV2.
func ShortMsgAlertContextV2() runtime.ObjectIdentifier {
	return runtime.ObjectIdentifier{0, 4, 0, 0, 1, 0, 23, 2}
}

// MwdMngtContextV3 returns the OID value for MwdMngtContextV3.
func MwdMngtContextV3() runtime.ObjectIdentifier {
	return runtime.ObjectIdentifier{0, 4, 0, 0, 1, 0, 24, 3}
}

// ShortMsgMTRelayContextV3 returns the OID value for ShortMsgMTRelayContextV3.
func ShortMsgMTRelayContextV3() runtime.ObjectIdentifier {
	return runtime.ObjectIdentifier{0, 4, 0, 0, 1, 0, 25, 3}
}

// ShortMsgMTRelayVGCSContextV3 returns the OID value for ShortMsgMTRelayVGCSContextV3.
func ShortMsgMTRelayVGCSContextV3() runtime.ObjectIdentifier {
	return runtime.ObjectIdentifier{0, 4, 0, 0, 1, 0, 41, 3}
}

// ImsiRetrievalContextV2 returns the OID value for ImsiRetrievalContextV2.
func ImsiRetrievalContextV2() runtime.ObjectIdentifier {
	return runtime.ObjectIdentifier{0, 4, 0, 0, 1, 0, 26, 2}
}

// MsPurgingContextV3 returns the OID value for MsPurgingContextV3.
func MsPurgingContextV3() runtime.ObjectIdentifier {
	return runtime.ObjectIdentifier{0, 4, 0, 0, 1, 0, 27, 3}
}

// SubscriberInfoEnquiryContextV3 returns the OID value for SubscriberInfoEnquiryContextV3.
func SubscriberInfoEnquiryContextV3() runtime.ObjectIdentifier {
	return runtime.ObjectIdentifier{0, 4, 0, 0, 1, 0, 28, 3}
}

// AnyTimeInfoEnquiryContextV3 returns the OID value for AnyTimeInfoEnquiryContextV3.
func AnyTimeInfoEnquiryContextV3() runtime.ObjectIdentifier {
	return runtime.ObjectIdentifier{0, 4, 0, 0, 1, 0, 29, 3}
}

// CallControlTransferContextV4 returns the OID value for CallControlTransferContextV4.
func CallControlTransferContextV4() runtime.ObjectIdentifier {
	return runtime.ObjectIdentifier{0, 4, 0, 0, 1, 0, 6, 4}
}

// SsInvocationNotificationContextV3 returns the OID value for SsInvocationNotificationContextV3.
func SsInvocationNotificationContextV3() runtime.ObjectIdentifier {
	return runtime.ObjectIdentifier{0, 4, 0, 0, 1, 0, 36, 3}
}

// GroupCallControlContextV3 returns the OID value for GroupCallControlContextV3.
func GroupCallControlContextV3() runtime.ObjectIdentifier {
	return runtime.ObjectIdentifier{0, 4, 0, 0, 1, 0, 31, 3}
}

// GroupCallInfoRetrievalContextV3 returns the OID value for GroupCallInfoRetrievalContextV3.
func GroupCallInfoRetrievalContextV3() runtime.ObjectIdentifier {
	return runtime.ObjectIdentifier{0, 4, 0, 0, 1, 0, 45, 3}
}

// GprsLocationUpdateContextV3 returns the OID value for GprsLocationUpdateContextV3.
func GprsLocationUpdateContextV3() runtime.ObjectIdentifier {
	return runtime.ObjectIdentifier{0, 4, 0, 0, 1, 0, 32, 3}
}

// GprsLocationInfoRetrievalContextV4 returns the OID value for GprsLocationInfoRetrievalContextV4.
func GprsLocationInfoRetrievalContextV4() runtime.ObjectIdentifier {
	return runtime.ObjectIdentifier{0, 4, 0, 0, 1, 0, 33, 4}
}

// FailureReportContextV3 returns the OID value for FailureReportContextV3.
func FailureReportContextV3() runtime.ObjectIdentifier {
	return runtime.ObjectIdentifier{0, 4, 0, 0, 1, 0, 34, 3}
}

// GprsNotifyContextV3 returns the OID value for GprsNotifyContextV3.
func GprsNotifyContextV3() runtime.ObjectIdentifier {
	return runtime.ObjectIdentifier{0, 4, 0, 0, 1, 0, 35, 3}
}

// ReportingContextV3 returns the OID value for ReportingContextV3.
func ReportingContextV3() runtime.ObjectIdentifier {
	return runtime.ObjectIdentifier{0, 4, 0, 0, 1, 0, 7, 3}
}

// CallCompletionContextV3 returns the OID value for CallCompletionContextV3.
func CallCompletionContextV3() runtime.ObjectIdentifier {
	return runtime.ObjectIdentifier{0, 4, 0, 0, 1, 0, 8, 3}
}

// IstAlertingContextV3 returns the OID value for IstAlertingContextV3.
func IstAlertingContextV3() runtime.ObjectIdentifier {
	return runtime.ObjectIdentifier{0, 4, 0, 0, 1, 0, 4, 3}
}

// ServiceTerminationContextV3 returns the OID value for ServiceTerminationContextV3.
func ServiceTerminationContextV3() runtime.ObjectIdentifier {
	return runtime.ObjectIdentifier{0, 4, 0, 0, 1, 0, 9, 3}
}

// LocationSvcGatewayContextV3 returns the OID value for LocationSvcGatewayContextV3.
func LocationSvcGatewayContextV3() runtime.ObjectIdentifier {
	return runtime.ObjectIdentifier{0, 4, 0, 0, 1, 0, 37, 3}
}

// LocationSvcEnquiryContextV3 returns the OID value for LocationSvcEnquiryContextV3.
func LocationSvcEnquiryContextV3() runtime.ObjectIdentifier {
	return runtime.ObjectIdentifier{0, 4, 0, 0, 1, 0, 38, 3}
}

// MmEventReportingContextV3 returns the OID value for MmEventReportingContextV3.
func MmEventReportingContextV3() runtime.ObjectIdentifier {
	return runtime.ObjectIdentifier{0, 4, 0, 0, 1, 0, 42, 3}
}

// AnyTimeInfoHandlingContextV3 returns the OID value for AnyTimeInfoHandlingContextV3.
func AnyTimeInfoHandlingContextV3() runtime.ObjectIdentifier {
	return runtime.ObjectIdentifier{0, 4, 0, 0, 1, 0, 43, 3}
}

// SubscriberDataModificationNotificationContextV3 returns the OID value for SubscriberDataModificationNotificationContextV3.
func SubscriberDataModificationNotificationContextV3() runtime.ObjectIdentifier {
	return runtime.ObjectIdentifier{0, 4, 0, 0, 1, 0, 22, 3}
}

// ResourceManagementContextV3 returns the OID value for ResourceManagementContextV3.
func ResourceManagementContextV3() runtime.ObjectIdentifier {
	return runtime.ObjectIdentifier{0, 4, 0, 0, 1, 0, 44, 3}
}

// VcsgLocationUpdateContextV3 returns the OID value for VcsgLocationUpdateContextV3.
func VcsgLocationUpdateContextV3() runtime.ObjectIdentifier {
	return runtime.ObjectIdentifier{0, 4, 0, 0, 1, 0, 46, 3}
}

// VcsgLocationCancellationContextV3 returns the OID value for VcsgLocationCancellationContextV3.
func VcsgLocationCancellationContextV3() runtime.ObjectIdentifier {
	return runtime.ObjectIdentifier{0, 4, 0, 0, 1, 0, 47, 3}
}
