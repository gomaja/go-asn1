// Code generated from ASN.1 module "MAP-ApplicationContexts". DO NOT EDIT.

package gsm0902_v4_19_1

import (
	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime"
	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime/ber"
	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime/tag"
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

// NetworkLocUpContextV2 returns the OID value for networkLocUpContext-v2.
func NetworkLocUpContextV2() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x04\x00\x00\x01\x00\x01\x02")
}

// NetworkLocUpContextV1 returns the OID value for networkLocUpContext-v1.
func NetworkLocUpContextV1() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x04\x00\x00\x01\x00\x01\x01")
}

// LocationCancellationV2 returns the OID value for locationCancellation-v2.
func LocationCancellationV2() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x04\x00\x00\x01\x00\x02\x02")
}

// LocationCancellationV1 returns the OID value for locationCancellation-v1.
func LocationCancellationV1() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x04\x00\x00\x01\x00\x02\x01")
}

// RoamingNumberEnquiryContextV2 returns the OID value for roamingNumberEnquiryContext-v2.
func RoamingNumberEnquiryContextV2() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x04\x00\x00\x01\x00\x03\x02")
}

// RoamingNumberEnquiryContextV1 returns the OID value for roamingNumberEnquiryContext-v1.
func RoamingNumberEnquiryContextV1() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x04\x00\x00\x01\x00\x03\x01")
}

// LocationInfoRetrievalContextV2 returns the OID value for locationInfoRetrievalContext-v2.
func LocationInfoRetrievalContextV2() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x04\x00\x00\x01\x00\x05\x02")
}

// LocationInfoRetrievalContextV1 returns the OID value for locationInfoRetrievalContext-v1.
func LocationInfoRetrievalContextV1() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x04\x00\x00\x01\x00\x05\x01")
}

// ResetContextV2 returns the OID value for resetContext-v2.
func ResetContextV2() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x04\x00\x00\x01\x00\x0a\x02")
}

// ResetContextV1 returns the OID value for resetContext-v1.
func ResetContextV1() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x04\x00\x00\x01\x00\x0a\x01")
}

// HandoverControlContextV2 returns the OID value for handoverControlContext-v2.
func HandoverControlContextV2() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x04\x00\x00\x01\x00\x0b\x02")
}

// HandoverControlContextV1 returns the OID value for handoverControlContext-v1.
func HandoverControlContextV1() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x04\x00\x00\x01\x00\x0b\x01")
}

// EquipmentMngtContextV2 returns the OID value for equipmentMngtContext-v2.
func EquipmentMngtContextV2() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x04\x00\x00\x01\x00\x0d\x02")
}

// EquipmentMngtContextV1 returns the OID value for equipmentMngtContext-v1.
func EquipmentMngtContextV1() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x04\x00\x00\x01\x00\x0d\x01")
}

// InfoRetrievalContextV2 returns the OID value for infoRetrievalContext-v2.
func InfoRetrievalContextV2() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x04\x00\x00\x01\x00\x0e\x02")
}

// InfoRetrievalContextV1 returns the OID value for infoRetrievalContext-v1.
func InfoRetrievalContextV1() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x04\x00\x00\x01\x00\x0e\x01")
}

// InterVlrInfoRetrievalContextV2 returns the OID value for interVlrInfoRetrievalContext-v2.
func InterVlrInfoRetrievalContextV2() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x04\x00\x00\x01\x00\x0f\x02")
}

// SubscriberDataMngtContextV2 returns the OID value for subscriberDataMngtContext-v2.
func SubscriberDataMngtContextV2() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x04\x00\x00\x01\x00\x10\x02")
}

// SubscriberDataMngtContextV1 returns the OID value for subscriberDataMngtContext-v1.
func SubscriberDataMngtContextV1() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x04\x00\x00\x01\x00\x10\x01")
}

// TracingContextV2 returns the OID value for tracingContext-v2.
func TracingContextV2() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x04\x00\x00\x01\x00\x11\x02")
}

// TracingContextV1 returns the OID value for tracingContext-v1.
func TracingContextV1() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x04\x00\x00\x01\x00\x11\x01")
}

// NetworkFunctionalSsContextV2 returns the OID value for networkFunctionalSsContext-v2.
func NetworkFunctionalSsContextV2() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x04\x00\x00\x01\x00\x12\x02")
}

// NetworkFunctionalSsContextV1 returns the OID value for networkFunctionalSsContext-v1.
func NetworkFunctionalSsContextV1() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x04\x00\x00\x01\x00\x12\x01")
}

// NetworkUnstructuredSsContextV2 returns the OID value for networkUnstructuredSsContext-v2.
func NetworkUnstructuredSsContextV2() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x04\x00\x00\x01\x00\x13\x02")
}

// ShortMsgGatewayContextV2 returns the OID value for shortMsgGatewayContext-v2.
func ShortMsgGatewayContextV2() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x04\x00\x00\x01\x00\x14\x02")
}

// ShortMsgGatewayContextV1 returns the OID value for shortMsgGatewayContext-v1.
func ShortMsgGatewayContextV1() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x04\x00\x00\x01\x00\x14\x01")
}

// ShortMsgMORelayContextV2 returns the OID value for shortMsgMO-RelayContext-v2.
func ShortMsgMORelayContextV2() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x04\x00\x00\x01\x00\x15\x02")
}

// ShortMsgRelayContextV1 returns the OID value for shortMsgRelayContext-v1.
func ShortMsgRelayContextV1() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x04\x00\x00\x01\x00\x15\x01")
}

// ShortMsgAlertContextV2 returns the OID value for shortMsgAlertContext-v2.
func ShortMsgAlertContextV2() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x04\x00\x00\x01\x00\x17\x02")
}

// ShortMsgAlertContextV1 returns the OID value for shortMsgAlertContext-v1.
func ShortMsgAlertContextV1() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x04\x00\x00\x01\x00\x17\x01")
}

// MwdMngtContextV2 returns the OID value for mwdMngtContext-v2.
func MwdMngtContextV2() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x04\x00\x00\x01\x00\x18\x02")
}

// MwdMngtContextV1 returns the OID value for mwdMngtContext-v1.
func MwdMngtContextV1() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x04\x00\x00\x01\x00\x18\x01")
}

// ShortMsgMTRelayContextV2 returns the OID value for shortMsgMT-RelayContext-v2.
func ShortMsgMTRelayContextV2() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x04\x00\x00\x01\x00\x19\x02")
}

// ImsiRetrievalContextV2 returns the OID value for imsiRetrievalContext-v2.
func ImsiRetrievalContextV2() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x04\x00\x00\x01\x00\x1a\x02")
}

// MsPurgingContextV2 returns the OID value for msPurgingContext-v2.
func MsPurgingContextV2() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x04\x00\x00\x01\x00\x1b\x02")
}
