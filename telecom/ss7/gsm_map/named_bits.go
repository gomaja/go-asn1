// Code generated from ASN.1. DO NOT EDIT.

package gsm_map

import (
	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime/ber"
)

// NewServiceIndicator constructs ASN.1 MAP-SS-DataTypes.ServiceIndicator (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewServiceIndicator(set ...int) (ServiceIndicator, error) {
	value, err := ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 2, Max: 32}}}, set...)
	return namedBitBuilderResult(value, err, "MAP-SS-DataTypes.ServiceIndicator")
}

// NewTraceNETypeList constructs ASN.1 MAP-OM-DataTypes.TraceNE-TypeList (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewTraceNETypeList(set ...int) (TraceNETypeList, error) {
	value, err := ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 6, Max: 16}}}, set...)
	return namedBitBuilderResult(value, err, "MAP-OM-DataTypes.TraceNE-TypeList")
}

// NewMSCSInterfaceList constructs ASN.1 MAP-OM-DataTypes.MSC-S-InterfaceList (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewMSCSInterfaceList(set ...int) (MSCSInterfaceList, error) {
	value, err := ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 10, Max: 16}}}, set...)
	return namedBitBuilderResult(value, err, "MAP-OM-DataTypes.MSC-S-InterfaceList")
}

// NewMGWInterfaceList constructs ASN.1 MAP-OM-DataTypes.MGW-InterfaceList (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewMGWInterfaceList(set ...int) (MGWInterfaceList, error) {
	value, err := ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 3, Max: 8}}}, set...)
	return namedBitBuilderResult(value, err, "MAP-OM-DataTypes.MGW-InterfaceList")
}

// NewSGSNInterfaceList constructs ASN.1 MAP-OM-DataTypes.SGSN-InterfaceList (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewSGSNInterfaceList(set ...int) (SGSNInterfaceList, error) {
	value, err := ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 8, Max: 16}}}, set...)
	return namedBitBuilderResult(value, err, "MAP-OM-DataTypes.SGSN-InterfaceList")
}

// NewGGSNInterfaceList constructs ASN.1 MAP-OM-DataTypes.GGSN-InterfaceList (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewGGSNInterfaceList(set ...int) (GGSNInterfaceList, error) {
	value, err := ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 3, Max: 8}}}, set...)
	return namedBitBuilderResult(value, err, "MAP-OM-DataTypes.GGSN-InterfaceList")
}

// NewRNCInterfaceList constructs ASN.1 MAP-OM-DataTypes.RNC-InterfaceList (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewRNCInterfaceList(set ...int) (RNCInterfaceList, error) {
	value, err := ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 4, Max: 8}}}, set...)
	return namedBitBuilderResult(value, err, "MAP-OM-DataTypes.RNC-InterfaceList")
}

// NewBMSCInterfaceList constructs ASN.1 MAP-OM-DataTypes.BMSC-InterfaceList (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewBMSCInterfaceList(set ...int) (BMSCInterfaceList, error) {
	value, err := ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 1, Max: 8}}}, set...)
	return namedBitBuilderResult(value, err, "MAP-OM-DataTypes.BMSC-InterfaceList")
}

// NewMMEInterfaceList constructs ASN.1 MAP-OM-DataTypes.MME-InterfaceList (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewMMEInterfaceList(set ...int) (MMEInterfaceList, error) {
	value, err := ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 5, Max: 8}}}, set...)
	return namedBitBuilderResult(value, err, "MAP-OM-DataTypes.MME-InterfaceList")
}

// NewSGWInterfaceList constructs ASN.1 MAP-OM-DataTypes.SGW-InterfaceList (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewSGWInterfaceList(set ...int) (SGWInterfaceList, error) {
	value, err := ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 5, Max: 8}}}, set...)
	return namedBitBuilderResult(value, err, "MAP-OM-DataTypes.SGW-InterfaceList")
}

// NewPGWInterfaceList constructs ASN.1 MAP-OM-DataTypes.PGW-InterfaceList (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewPGWInterfaceList(set ...int) (PGWInterfaceList, error) {
	value, err := ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 8, Max: 16}}}, set...)
	return namedBitBuilderResult(value, err, "MAP-OM-DataTypes.PGW-InterfaceList")
}

// NewENBInterfaceList constructs ASN.1 MAP-OM-DataTypes.ENB-InterfaceList (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewENBInterfaceList(set ...int) (ENBInterfaceList, error) {
	value, err := ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 3, Max: 8}}}, set...)
	return namedBitBuilderResult(value, err, "MAP-OM-DataTypes.ENB-InterfaceList")
}

// NewMSCSEventList constructs ASN.1 MAP-OM-DataTypes.MSC-S-EventList (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewMSCSEventList(set ...int) (MSCSEventList, error) {
	value, err := ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 5, Max: 16}}}, set...)
	return namedBitBuilderResult(value, err, "MAP-OM-DataTypes.MSC-S-EventList")
}

// NewMGWEventList constructs ASN.1 MAP-OM-DataTypes.MGW-EventList (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewMGWEventList(set ...int) (MGWEventList, error) {
	value, err := ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 1, Max: 8}}}, set...)
	return namedBitBuilderResult(value, err, "MAP-OM-DataTypes.MGW-EventList")
}

// NewSGSNEventList constructs ASN.1 MAP-OM-DataTypes.SGSN-EventList (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewSGSNEventList(set ...int) (SGSNEventList, error) {
	value, err := ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 4, Max: 16}}}, set...)
	return namedBitBuilderResult(value, err, "MAP-OM-DataTypes.SGSN-EventList")
}

// NewGGSNEventList constructs ASN.1 MAP-OM-DataTypes.GGSN-EventList (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewGGSNEventList(set ...int) (GGSNEventList, error) {
	value, err := ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 2, Max: 8}}}, set...)
	return namedBitBuilderResult(value, err, "MAP-OM-DataTypes.GGSN-EventList")
}

// NewBMSCEventList constructs ASN.1 MAP-OM-DataTypes.BMSC-EventList (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewBMSCEventList(set ...int) (BMSCEventList, error) {
	value, err := ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 1, Max: 8}}}, set...)
	return namedBitBuilderResult(value, err, "MAP-OM-DataTypes.BMSC-EventList")
}

// NewMMEEventList constructs ASN.1 MAP-OM-DataTypes.MME-EventList (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewMMEEventList(set ...int) (MMEEventList, error) {
	value, err := ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 6, Max: 8}}}, set...)
	return namedBitBuilderResult(value, err, "MAP-OM-DataTypes.MME-EventList")
}

// NewSGWEventList constructs ASN.1 MAP-OM-DataTypes.SGW-EventList (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewSGWEventList(set ...int) (SGWEventList, error) {
	value, err := ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 3, Max: 8}}}, set...)
	return namedBitBuilderResult(value, err, "MAP-OM-DataTypes.SGW-EventList")
}

// NewPGWEventList constructs ASN.1 MAP-OM-DataTypes.PGW-EventList (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewPGWEventList(set ...int) (PGWEventList, error) {
	value, err := ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 3, Max: 8}}}, set...)
	return namedBitBuilderResult(value, err, "MAP-OM-DataTypes.PGW-EventList")
}

// NewSupportedRATTypes constructs ASN.1 MAP-MS-DataTypes.SupportedRAT-Types (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewSupportedRATTypes(set ...int) (SupportedRATTypes, error) {
	value, err := ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 2, Max: 8}}}, set...)
	return namedBitBuilderResult(value, err, "MAP-MS-DataTypes.SupportedRAT-Types")
}

// NewSupportedLCSCapabilitySets constructs ASN.1 MAP-MS-DataTypes.SupportedLCS-CapabilitySets (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewSupportedLCSCapabilitySets(set ...int) (SupportedLCSCapabilitySets, error) {
	value, err := ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 2, Max: 16}}}, set...)
	return namedBitBuilderResult(value, err, "MAP-MS-DataTypes.SupportedLCS-CapabilitySets")
}

// NewISRInformation constructs ASN.1 MAP-MS-DataTypes.ISR-Information (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewISRInformation(set ...int) (ISRInformation, error) {
	value, err := ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 3, Max: 8}}}, set...)
	return namedBitBuilderResult(value, err, "MAP-MS-DataTypes.ISR-Information")
}

// NewSupportedFeatures constructs ASN.1 MAP-MS-DataTypes.SupportedFeatures (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewSupportedFeatures(set ...int) (SupportedFeatures, error) {
	value, err := ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 26, Max: 40}}}, set...)
	return namedBitBuilderResult(value, err, "MAP-MS-DataTypes.SupportedFeatures")
}

// NewExtSupportedFeatures constructs ASN.1 MAP-MS-DataTypes.Ext-SupportedFeatures (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewExtSupportedFeatures(set ...int) (ExtSupportedFeatures, error) {
	value, err := ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 1, Max: 40}}}, set...)
	return namedBitBuilderResult(value, err, "MAP-MS-DataTypes.Ext-SupportedFeatures")
}

// NewLCLSNegotiation constructs ASN.1 MAP-MS-DataTypes.LCLS-Negotiation (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewLCLSNegotiation(set ...int) (LCLSNegotiation, error) {
	value, err := ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 2, Max: 8}}}, set...)
	return namedBitBuilderResult(value, err, "MAP-MS-DataTypes.LCLS-Negotiation")
}

// NewLCLSConfigurationPreference constructs ASN.1 MAP-MS-DataTypes.LCLS-ConfigurationPreference (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewLCLSConfigurationPreference(set ...int) (LCLSConfigurationPreference, error) {
	value, err := ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 4, Max: 8}}}, set...)
	return namedBitBuilderResult(value, err, "MAP-MS-DataTypes.LCLS-ConfigurationPreference")
}

// NewRequestedEquipmentInfo constructs ASN.1 MAP-MS-DataTypes.RequestedEquipmentInfo (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewRequestedEquipmentInfo(set ...int) (RequestedEquipmentInfo, error) {
	value, err := ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 2, Max: 8}}}, set...)
	return namedBitBuilderResult(value, err, "MAP-MS-DataTypes.RequestedEquipmentInfo")
}

// NewAccessRestrictionData constructs ASN.1 MAP-MS-DataTypes.AccessRestrictionData (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewAccessRestrictionData(set ...int) (AccessRestrictionData, error) {
	value, err := ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 2, Max: 8}}}, set...)
	return namedBitBuilderResult(value, err, "MAP-MS-DataTypes.AccessRestrictionData")
}

// NewExtAccessRestrictionData constructs ASN.1 MAP-MS-DataTypes.Ext-AccessRestrictionData (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewExtAccessRestrictionData(set ...int) (ExtAccessRestrictionData, error) {
	value, err := ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 1, Max: 32}}}, set...)
	return namedBitBuilderResult(value, err, "MAP-MS-DataTypes.Ext-AccessRestrictionData")
}

// NewODBGeneralData constructs ASN.1 MAP-MS-DataTypes.ODB-GeneralData (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewODBGeneralData(set ...int) (ODBGeneralData, error) {
	value, err := ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 15, Max: 32}}}, set...)
	return namedBitBuilderResult(value, err, "MAP-MS-DataTypes.ODB-GeneralData")
}

// NewODBHPLMNData constructs ASN.1 MAP-MS-DataTypes.ODB-HPLMN-Data (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewODBHPLMNData(set ...int) (ODBHPLMNData, error) {
	value, err := ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 4, Max: 32}}}, set...)
	return namedBitBuilderResult(value, err, "MAP-MS-DataTypes.ODB-HPLMN-Data")
}

// NewSpecificCSIWithdraw constructs ASN.1 MAP-MS-DataTypes.SpecificCSI-Withdraw (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewSpecificCSIWithdraw(set ...int) (SpecificCSIWithdraw, error) {
	value, err := ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 8, Max: 32}}}, set...)
	return namedBitBuilderResult(value, err, "MAP-MS-DataTypes.SpecificCSI-Withdraw")
}

// NewSupportedCamelPhases constructs ASN.1 MAP-MS-DataTypes.SupportedCamelPhases (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewSupportedCamelPhases(set ...int) (SupportedCamelPhases, error) {
	value, err := ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 1, Max: 16}}}, set...)
	return namedBitBuilderResult(value, err, "MAP-MS-DataTypes.SupportedCamelPhases")
}

// NewOfferedCamel4CSIs constructs ASN.1 MAP-MS-DataTypes.OfferedCamel4CSIs (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewOfferedCamel4CSIs(set ...int) (OfferedCamel4CSIs, error) {
	value, err := ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 7, Max: 16}}}, set...)
	return namedBitBuilderResult(value, err, "MAP-MS-DataTypes.OfferedCamel4CSIs")
}

// NewOfferedCamel4Functionalities constructs ASN.1 MAP-MS-DataTypes.OfferedCamel4Functionalities (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewOfferedCamel4Functionalities(set ...int) (OfferedCamel4Functionalities, error) {
	value, err := ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 15, Max: 64}}}, set...)
	return namedBitBuilderResult(value, err, "MAP-MS-DataTypes.OfferedCamel4Functionalities")
}

// NewAdditionalSubscriptions constructs ASN.1 MAP-MS-DataTypes.AdditionalSubscriptions (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewAdditionalSubscriptions(set ...int) (AdditionalSubscriptions, error) {
	value, err := ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 3, Max: 8}}}, set...)
	return namedBitBuilderResult(value, err, "MAP-MS-DataTypes.AdditionalSubscriptions")
}

// NewRequestedNodes constructs ASN.1 MAP-MS-DataTypes.RequestedNodes (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewRequestedNodes(set ...int) (RequestedNodes, error) {
	value, err := ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 1, Max: 8}}}, set...)
	return namedBitBuilderResult(value, err, "MAP-MS-DataTypes.RequestedNodes")
}

// NewRequestedServingNode constructs ASN.1 MAP-MS-DataTypes.RequestedServingNode (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewRequestedServingNode(set ...int) (RequestedServingNode, error) {
	value, err := ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 1, Max: 8}}}, set...)
	return namedBitBuilderResult(value, err, "MAP-MS-DataTypes.RequestedServingNode")
}

// NewServingNode constructs ASN.1 MAP-MS-DataTypes.ServingNode (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewServingNode(set ...int) (ServingNode, error) {
	value, err := ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 2, Max: 8}}}, set...)
	return namedBitBuilderResult(value, err, "MAP-MS-DataTypes.ServingNode")
}

// NewSuppressMTSS constructs ASN.1 MAP-CH-DataTypes.SuppressMTSS (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewSuppressMTSS(set ...int) (SuppressMTSS, error) {
	value, err := ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 2, Max: 16}}}, set...)
	return namedBitBuilderResult(value, err, "MAP-CH-DataTypes.SuppressMTSS")
}

// NewAllowedServices constructs ASN.1 MAP-CH-DataTypes.AllowedServices (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewAllowedServices(set ...int) (AllowedServices, error) {
	value, err := ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 2, Max: 8}}}, set...)
	return namedBitBuilderResult(value, err, "MAP-CH-DataTypes.AllowedServices")
}

// NewMWStatus constructs ASN.1 MAP-SM-DataTypes.MW-Status (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewMWStatus(set ...int) (MWStatus, error) {
	value, err := ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 6, Max: 16}}}, set...)
	return namedBitBuilderResult(value, err, "MAP-SM-DataTypes.MW-Status")
}

// NewDeferredLocationEventType constructs ASN.1 MAP-LCS-DataTypes.DeferredLocationEventType (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewDeferredLocationEventType(set ...int) (DeferredLocationEventType, error) {
	value, err := ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 1, Max: 16}}}, set...)
	return namedBitBuilderResult(value, err, "MAP-LCS-DataTypes.DeferredLocationEventType")
}

// NewSupportedGADShapes constructs ASN.1 MAP-LCS-DataTypes.SupportedGADShapes (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewSupportedGADShapes(set ...int) (SupportedGADShapes, error) {
	value, err := ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 7, Max: 16}}}, set...)
	return namedBitBuilderResult(value, err, "MAP-LCS-DataTypes.SupportedGADShapes")
}

// NewDeferredLocationExt constructs ASN.1 SS-DataTypes.DeferredLocationExt (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewDeferredLocationExt(set ...int) (DeferredLocationExt, error) {
	value, err := ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 1, Max: 16}}}, set...)
	return namedBitBuilderResult(value, err, "SS-DataTypes.DeferredLocationExt")
}

// NewRangingSlExt constructs ASN.1 SS-DataTypes.RangingSlExt (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewRangingSlExt(set ...int) (RangingSlExt, error) {
	value, err := ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 1, Max: 16}}}, set...)
	return namedBitBuilderResult(value, err, "SS-DataTypes.RangingSlExt")
}

// NewLocationInfo constructs ASN.1 SS-DataTypes.LocationInfo (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewLocationInfo(set ...int) (LocationInfo, error) {
	value, err := ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 1, Max: 32}}}, set...)
	return namedBitBuilderResult(value, err, "SS-DataTypes.LocationInfo")
}

// NewReportingAccessTypes constructs ASN.1 SS-DataTypes.ReportingAccessTypes (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewReportingAccessTypes(set ...int) (ReportingAccessTypes, error) {
	value, err := ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 1, Max: 16}}}, set...)
	return namedBitBuilderResult(value, err, "SS-DataTypes.ReportingAccessTypes")
}

// NewLCSPruUpdateTrigger constructs ASN.1 SS-DataTypes.LCS-PruUpdateTrigger (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewLCSPruUpdateTrigger(set ...int) (LCSPruUpdateTrigger, error) {
	value, err := ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 1, Max: 16}}}, set...)
	return namedBitBuilderResult(value, err, "SS-DataTypes.LCS-PruUpdateTrigger")
}
