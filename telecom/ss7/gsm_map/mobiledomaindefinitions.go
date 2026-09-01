// Code generated from ASN.1 module "MobileDomainDefinitions". DO NOT EDIT.

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

const (

	// AcId is the integer constant for AcId.
	AcId int64 = 0

	// AsId is the integer constant for AsId.
	AsId int64 = 1

	// AseId is the integer constant for AseId.
	AseId int64 = 2

	// ModuleId is the integer constant for ModuleId.
	ModuleId int64 = 3

	// ErId is the integer constant for ErId.
	ErId int64 = 4
)

// MobileDomainId returns the OID value for MobileDomainId.
func MobileDomainId() runtime.ObjectIdentifier { return runtime.ObjectIdentifier{0, 4, 0, 0} }

// GsmNetworkId returns the OID value for GsmNetworkId.
func GsmNetworkId() runtime.ObjectIdentifier { return runtime.ObjectIdentifier{0, 4, 0, 0, 1} }

// GsmAccessId returns the OID value for GsmAccessId.
func GsmAccessId() runtime.ObjectIdentifier { return runtime.ObjectIdentifier{0, 4, 0, 0, 2} }

// GsmOperationAndMaintenanceId returns the OID value for GsmOperationAndMaintenanceId.
func GsmOperationAndMaintenanceId() runtime.ObjectIdentifier {
	return runtime.ObjectIdentifier{0, 4, 0, 0, 3}
}

// GsmMessagingId returns the OID value for GsmMessagingId.
func GsmMessagingId() runtime.ObjectIdentifier { return runtime.ObjectIdentifier{0, 4, 0, 0, 4} }

// CommonComponentId represents the ASN.1 type CommonComponentId (INTEGER).
type CommonComponentId = int64
